//! Configuration maintenance: `-b` (beautify) and `-r` (recreate a clean configuration).
//!
//! Both commands work on the *physical* configuration: the root file plus every file it
//! reads through `include`, in load order ([`crate::core::source`]). The model is a tree
//! whose nodes are [`Ctx`] objects — the root file, or a file that replaces one `include`
//! directive:
//!
//! * an **expanded** node owns its file and can stand alone, so it is rendered as one file
//!   in the new tree and its `include` directives are rewritten to point at the new files;
//! * a **stub** node holds a fragment such as `server_tokens off;` or `listen 80;` that
//!   Nginx merges into the including block. It cannot stand alone, so the fragment is
//!   written inside the parent and the parent gets a `#vhosts-conf#` placeholder that names
//!   the original file, keeping the include site traceable.
//!
//! Rendering verifies itself: the new tree is parsed again and the effective directive tree
//! the server would compile must be identical to the original one, and every comment of the
//! original configuration must still exist.

use crate::core::layout::{self, DirectiveItem, IndentStyle, Item, SourceText};
use crate::core::source::{self, SourceFile};
use crate::core::syntax::Directive;
use anyhow::{Context, Result, bail};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Comment placeholder that stands in for an `include` merged into its parent.
pub const STUB_MARKER: &str = "#vhosts-conf#";

/// Options shared by `-b` and `-r`.
#[derive(Clone, Debug)]
#[derive(Default)]
pub struct BeautifyOptions {
    pub indent: IndentStyle,
    /// Rewrite files on disk; otherwise only report what would change.
    pub write: bool,
    /// Report the verification of every file.
    pub verbose: bool,
}


/// Outcome of a maintenance run.
#[derive(Default, Debug)]
pub struct Report {
    /// Files read from the source configuration.
    pub files_read: usize,
    /// Stand-alone files written (or that would be written).
    pub files_rendered: usize,
    /// Files whose rendered text differs from their current content.
    pub changed: Vec<PathBuf>,
    /// Merged fragments written (or that would be written).
    pub stubs: Vec<PathBuf>,
    /// Operator-facing lines.
    pub notes: Vec<String>,
}

impl Report {
    pub fn note(&mut self, line: impl Into<String>) {
        self.notes.push(line.into());
    }
}

// ---------------------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------------------

/// One entry of a node, in load order.
#[derive(Clone, Debug)]
pub enum Entry {
    /// An item owned by the node's own file.
    Item(Item),
    /// The content of a file included from this node.
    Child(Box<Ctx>),
}

/// One configuration file: the root, or a file that replaces an `include`.
#[derive(Clone, Debug)]
pub struct Ctx {
    /// Canonical path of the file on disk.
    pub path: PathBuf,
    /// Path relative to the output root. A merged fragment keeps its original path.
    pub rel: PathBuf,
    /// Directory the original `include` resolved against.
    pub original_dir: PathBuf,
    /// The file's own items, in order.
    pub source: SourceText,
    /// Files included from this node, in load order.
    pub children: Vec<Ctx>,
    /// `false` when the content cannot stand alone and is merged into its parent.
    pub expanded: bool,
    /// Whether this node is the root configuration.
    pub root: bool,
    /// Load order in the original tree.
    pub order: usize,
    /// The `include` argument in the parent that opened this file.
    pub include_argument: String,
}

/// Whether two directories name the same place, resolving symbolic links when possible.
fn same_dir(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

impl Ctx {
    pub fn file_name(&self) -> String {
        self.path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// The directive tree of this node with every `include` expanded, exactly the tree
    pub fn expanded(&self) -> Vec<Directive> {
        let mut out: Vec<Directive> = Vec::new();
        if !self.expanded {
            return self.fragment();
        }
        for item in &self.source.items {
            let Item::Directive(item) = item else {
                continue;
            };
            out.push(layout::standalone(item));
        }
        out
    }

    /// The directives a merged fragment hands to its including block, with its own
    /// `include` directives expanded exactly as [`crate::core::syntax::parse_file`] does.
    pub fn fragment(&self) -> Vec<Directive> {
        let mut out = Vec::new();
        for item in &self.source.items {
            let Item::Directive(item) = item else {
                continue;
            };
            if item.directive.has_block() {
                out.push(layout::standalone(item));
                continue;
            }
            if item.directive.name == "include"
                && let Some(argument) = item.directive.args.first().cloned()
            {
                for child in self.children_of(&argument) {
                    out.extend(child.fragment());
                }
                continue;
            }
            out.push(layout::standalone(item));
        }
        out
    }

    /// The tree the server sees, i.e. [`Ctx::expanded`].
    pub fn effective(&self) -> Vec<Directive> {
        self.expanded()
    }

    /// Every file of this subtree, in load order.
    pub fn files<'a>(&'a self, out: &mut Vec<&'a Ctx>) {
        out.push(self);
        for child in &self.children {
            child.files(out);
        }
    }

    /// Every comment of this node, including its children.
    pub fn comments(&self) -> Vec<String> {
        let mut out = self.source.comments();
        for child in &self.children {
            out.extend(child.comments());
        }
        out
    }

    /// The files an `include` of this file selects, in load order.
    pub fn children_of(&self, argument: &str) -> Vec<&Ctx> {
        let key = IncludeKey::of(&self.original_dir, argument);
        let mut selected: Vec<&Ctx> = self
            .children
            .iter()
            .filter(|child| IncludeKey::of(&self.original_dir, &child.include_argument) == key)
            .collect();
        selected.sort_by_key(|child| child.order);
        selected
    }

    /// Entries of this file, with the files its `include` directives select in the order
    /// they are read.
    pub fn entries(&self) -> Vec<Entry> {
        let mut entries = Vec::new();
        for item in &self.source.items {
            if let Item::Directive(directive) = item
                && directive.directive.name == "include"
                && let Some(argument) = directive.directive.args.first() {
                    for child in self.children_of(argument) {
                        entries.push(Entry::Child(Box::new(child.clone())));
                    }
                }
            entries.push(Entry::Item(item.clone()));
        }
        entries
    }

    /// Render this node for the output tree.
    ///
    /// A stand-alone file is rendered as it will be included; a merged fragment is written
    /// with a `#vhosts-conf#` marker on every line, so it is not loaded by the server but
    /// still shows the operator where its directives live.
    pub fn render(&self, indent: &IndentStyle) -> Result<String> {
        self.render_at(indent, &self.original_dir)
    }

    /// Render this node as it will be laid out below `root_dir`.
    ///
    /// [`Ctx::render`] assumes the file sits where it sits today; `-b` re-rendering a copy
    /// of the tree passes the directory the copy will live in, so relative `include`
    /// patterns that the new layout no longer satisfies are rewritten to the file they
    /// selected.
    pub fn render_at(&self, indent: &IndentStyle, root_dir: &Path) -> Result<String> {
        let mut stubs = Vec::new();
        let mut text = render_node(self, indent, 0, &mut stubs)?;
        // When the file keeps its place below the output root — the `-b` case — every
        // `include` is left exactly as it was written. A copy whose relative layout changed
        // passes the directory it will live in, and its patterns are then spelled with the
        // file each one selected.
        if !same_dir(root_dir, &self.original_dir) {
            for (written, selected) in self.match_includes_with(root_dir) {
                if written != selected {
                    text = replace_include(&text, &written, &selected);
                }
            }
        }
        if self.expanded {
            return Ok(text);
        }
        let mut out = String::new();
        for line in text.lines() {
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            out.push_str(STUB_MARKER);
            out.push_str(line);
            out.push('\n');
        }
        Ok(out)
    }

    /// `include` arguments of this file that its own directory does not satisfy, with the
    /// path that was actually loaded in the original tree.
    pub fn match_includes(&self) -> Vec<(String, String)> {
        self.match_includes_with(&self.original_dir)
    }

    /// Like [`Ctx::match_includes`], resolving relative patterns against `base`.
    pub fn match_includes_with(&self, base: &Path) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for item in &self.source.items {
            self.collect_include_rewrites(item, base, &mut out);
        }
        out
    }

    fn collect_include_rewrites(
        &self,
        item: &Item,
        base: &Path,
        out: &mut Vec<(String, String)>,
    ) {
        let Item::Directive(item) = item else {
            return;
        };
        if item.directive.children.is_some() {
            for child in &item.body {
                self.collect_include_rewrites(child, base, out);
            }
            return;
        }
        if item.directive.name != "include" {
            return;
        }
        let Some(argument) = item.directive.args.first() else {
            return;
        };
        let Ok(paths) = source::expand_include(base, argument) else {
            return;
        };
        let selected: Option<&Ctx> = self
            .children
            .iter()
            .find(|child| paths.iter().any(|path| path.canonicalize().ok() == Some(child.path.clone())));
        let Some(child) = selected else {
            return;
        };
        // The file is written below the output root. A relative pattern keeps working when
        // the including file keeps its name; when the new layout puts the includer
        // elsewhere the pattern is spelled with the path of the file it selected.
        let includer_dir = base.join(&self.rel);
        let includer_dir = includer_dir.parent().unwrap_or(base);
        let relative_still_works = source::expand_include(includer_dir, argument)
            .map(|paths| {
                paths
                    .iter()
                    .any(|path| path.canonicalize().ok() == Some(child.path.clone()))
            })
            .unwrap_or(false);
        if relative_still_works {
            return;
        }
        out.push((argument.clone(), child.rel.to_string_lossy().into_owned()));
    }
    /// `true` when this file can be included at a bare-block position in the new tree.
    ///
    /// The syntax parser joins files by concatenating top-level directives, so order is all
    /// that matters for a file read at a bare position. A file stands alone when every
    /// directive it writes is valid in some context *and* at least one of its top-level
    /// directives expects a block; a fragment such as `server_tokens off;` cannot appear at
    /// a bare position and is merged into its includer instead.
    fn stands_alone(&self) -> bool {
        let registry = crate::modules::registry::Registry::default_modules();
        let mut opens_a_block = false;
        for item in &self.source.items {
            let Item::Directive(item) = item else {
                continue;
            };
            let name = item.directive.name.as_str();
            // Only directives that open a block (`http`, `server`, `types`, ...) can be
            // included at a bare position. A file of bare statements is merged into the
            // block that includes it.
            if name == "include" {
                opens_a_block = true;
                continue;
            }
            if crate::modules::http_core::contexts_for(&registry, name).is_empty() {
                return false;
            }

            if item.directive.has_block() {
                opens_a_block = true;
            }
        }
        opens_a_block
    }
}


/// Normalised form of an `include` argument, used to match a directive to its children.
#[derive(Clone, Debug, PartialEq, Eq)]
struct IncludeKey {
    base: PathBuf,
    argument: String,
}

impl IncludeKey {
    fn of(base: &Path, argument: &str) -> Self {
        // Windows paths are case-insensitive; compare them the same way the filesystem does.
        Self {
            base: base.to_path_buf(),
            argument: normalize_argument(argument),
        }
    }
}

fn normalize_argument(argument: &str) -> String {
    let mut text = argument.replace('\\', "/");
    if cfg!(windows) {
        text = text.to_ascii_lowercase();
    }
    text
}



// ---------------------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------------------

/// Build the maintenance model from the physical include tree.
pub fn build(files: &[SourceFile]) -> Result<Ctx> {
    let Some(root) = files.first() else {
        bail!("the configuration has no file to maintain");
    };
    let mut children: HashMap<PathBuf, Vec<&SourceFile>> = HashMap::new();
    for file in files.iter().skip(1) {
        if let Some(parent) = &file.parent {
            children.entry(parent.clone()).or_default().push(file);
        }
    }
    let mut order = 0;
    let mut ctx = build_node(root, String::new(), &mut children, &mut order)?;
    finish_node(&mut ctx);
    Ok(ctx)
}

fn build_node(
    file: &SourceFile,
    argument: String,
    children: &mut HashMap<PathBuf, Vec<&SourceFile>>,
    order: &mut usize,
) -> Result<Ctx> {
    let text = std::fs::read_to_string(&file.path)
        .with_context(|| format!("cannot read configuration {}", file.path.display()))?;
    let source = SourceText::parse(&file.path, &text)?;
    *order += 1;
    let mut ctx = Ctx {
        rel: PathBuf::from(
            file.path
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("nginx.conf")),
        ),
        original_dir: file
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
        path: file.path.clone(),
        source,
        children: Vec::new(),
        expanded: true,
        root: file.is_root(),
        order: *order,
        include_argument: argument,
    };
    let included = children.remove(&file.path).unwrap_or_default();
    for child in included {
        let argument = ctx.argument_for(&child.path);
        let node = build_node(child, argument, children, order)?;
        ctx.children.push(node);
    }
    ctx.children.sort_by_key(|child| child.order);
    Ok(ctx)
}

fn finish_node(ctx: &mut Ctx) {
    for child in &mut ctx.children {
        finish_node(child);
    }
    // An included file stands alone unless it holds something that only has a meaning
    // inside its including block (a bare `server` that must be merged, an `include` whose
    // files cannot be resolved, ...). A file that cannot stand alone is merged instead.
    ctx.expanded = ctx.root || ctx.stands_alone();
}

impl Ctx {
    /// The `include` argument in this file that opened `target`.
    /// Directory the `include` arguments of this file resolve against.
    fn include_base(&self) -> PathBuf {
        self.original_dir.clone()
    }

    fn argument_for(&self, target: &Path) -> String {
        let mut found = String::new();
        fn walk(items: &[Item], base: &Path, target: &Path, found: &mut String) {
            for item in items {
                let Item::Directive(item) = item else {
                    continue;
                };
                if item.directive.children.is_none() && item.directive.name == "include"
                    && let Some(argument) = item.directive.args.first()
                        && source::expand_include(base, argument)
                            .map(|paths| {
                                paths
                                    .iter()
                                    .filter_map(|path| path.canonicalize().ok())
                                    .any(|path| path == target)
                            })
                            .unwrap_or(false)
                            && found.is_empty()
                        {
                            *found = argument.clone();
                        }
                walk(&item.body, base, target, found);
            }
        }
        walk(&self.source.items, &self.include_base(), target, &mut found);
        found
    }
}

// ---------------------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------------------

/// A rendered file: relative path in the output tree and its text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedFile {
    pub rel: PathBuf,
    pub text: String,
}

/// Render one node as a stand-alone file plus the stub placeholders it created.
pub fn render(ctx: &Ctx, indent: &IndentStyle) -> Result<(String, Vec<(String, String)>)> {
    let mut stubs = Vec::new();
    let text = render_node(ctx, indent, 0, &mut stubs)?;
    Ok((text, stubs))
}

fn render_node(
    ctx: &Ctx,
    indent: &IndentStyle,
    level: usize,
    stubs: &mut Vec<(String, String)>,
) -> Result<String> {
    let mut out = String::new();
    // A stand-alone file is not rendered here: its own file is written separately and the
    let mut written: HashSet<usize> = HashSet::new();
    // `include` that reads it is left in place, so `written` only has to stop a merged
    // fragment from being expanded twice.
    let newline = ctx.source.newline;
    // The root's directives live at level 0; a file included inside a block starts one
    // level further in, which is why Nginx allows files with unindented `server {` blocks
    // to be included either at the top of `http` or inside `server`.
    for entry in ctx.entries() {
        match entry {
            Entry::Item(item) => {
                let merge_here = matches!(&item, Item::Directive(directive)
                    if directive.directive.name == "include"
                        && !directive.directive.has_block()
                        && directive.leading.is_empty()
                        && directive.trailing.is_none());
                let argument = match &item {
                    Item::Directive(directive) => {
                        directive.directive.args.first().cloned().unwrap_or_default()
                    }
                    _ => String::new(),
                };
                let fragments: Vec<&Ctx> = if merge_here {
                    ctx.children_of(&argument)
                        .into_iter()
                        .filter(|child| !child.expanded)
                        .collect()
                } else {
                    Vec::new()
                };
                if !fragments.is_empty() {
                    for child in fragments {
                        if !written.insert(child.order) {
                            continue;
                        }
                        let stub = render_stub(child, indent, stubs)?;
                        if !stub.trim().is_empty() {
                            stubs.push((stub_path_for(ctx, child), stub));
                        }
                        push_stub_marker(&mut out, level, indent, &argument, newline);
                    }
                    continue;
                }
                render_item(&item, level, indent, newline, stubs, &mut written, &mut out)?
            }
            Entry::Child(child) => {
                if !child.expanded {
                    let stub = render_stub(&child, indent, stubs)?;
                    let directive = child.include_argument.clone();
                    if !stub.trim().is_empty() {
                        let stub_path = stub_path_for(ctx, &child);
                        stubs.push((stub_path, stub));
                    }
                    push_stub_marker(&mut out, level, indent, &directive, newline);
                    continue;
                }
                if !written.insert(child.order) {
                    continue;
                }
                let text = render_node(&child, indent, level, stubs)?;
                let text = reindent_markers(&text, level, indent);
                out.push_str(&text);
            }
        }
    }
    layout::finish(&mut out, newline, ctx.source.trailing_newline);
    Ok(out)
}

/// Render a merged fragment as a stub file: its statements, each guarded by a marker.
fn render_stub(
    ctx: &Ctx,
    indent: &IndentStyle,
    stubs: &mut Vec<(String, String)>,
) -> Result<String> {
    let mut body = String::new();
    let mut written = HashSet::new();
    for entry in ctx.entries() {
        match entry {
            Entry::Item(item) => render_item(&item, 0, indent, ctx.source.newline, stubs, &mut written, &mut body)?,
            Entry::Child(child) => {
                let text = render_node(&child, indent, 0, stubs)?;
                body.push_str(&text);
            }
        }
    }
    let mut out = String::new();
    for line in body.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        out.push_str(STUB_MARKER);
        out.push_str(line);
        out.push('\n');
    }
    Ok(out)
}

/// Where the stub file of a merged include is written: next to its parent, keeping the
/// relative path it had in the original tree.
fn stub_path_for(parent: &Ctx, child: &Ctx) -> String {
    let _ = parent;
    child.rel.to_string_lossy().into_owned()
}

fn push_stub_marker(
    out: &mut String,
    level: usize,
    indent: &IndentStyle,
    directive: &str,
    newline: &str,
) {
    out.push_str(&indent.prefix(level));
    out.push_str(STUB_MARKER);
    if !directive.is_empty() {
        out.push(' ');
        out.push_str(directive);
    }
    out.push_str(newline);
}

/// Stub markers written inside an included file point at the indentation of that file's
/// include site; a deeper splice moves them with the content.
fn reindent_markers(text: &str, level: usize, indent: &IndentStyle) -> String {
    if level == 0 {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let prefix = indent.prefix(level);
    for line in text.split_inclusive('\n') {
        if line.trim_start().starts_with(STUB_MARKER) {
            out.push_str(&prefix);
            out.push_str(line.trim_start());
        } else {
            out.push_str(&prefix);
            out.push_str(line);
        }
    }
    out
}

fn render_item(
    item: &Item,
    level: usize,
    indent: &IndentStyle,
    newline: &str,
    stubs: &mut Vec<(String, String)>,
    written: &mut HashSet<usize>,
    out: &mut String,
) -> Result<()> {
    match item {
        Item::Blank => out.push_str(newline),
        Item::Comment(text) => {
            out.push_str(&indent.prefix(level));
            out.push_str(text.trim_end());
            out.push_str(newline);
        }
        Item::Directive(item) => {
            render_statement(item, level, indent, newline, stubs, written, out)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn render_statement(
    item: &DirectiveItem,
    level: usize,
    indent: &IndentStyle,
    newline: &str,
    stubs: &mut Vec<(String, String)>,
    written: &mut HashSet<usize>,
    out: &mut String,
) -> Result<()> {
    let prefix = indent.prefix(level);
    for comment in &item.leading {
        out.push_str(&prefix);
        out.push_str(comment.trim_end());
        out.push_str(newline);
    }
    out.push_str(&prefix);
    out.push_str(&layout::format_directive(&item.directive));
    if item.directive.children.is_none() {
        out.push(';');
        layout::push_trailing(out, item.trailing.as_deref());
        out.push_str(newline);
        return Ok(());
    }
    if item.body.is_empty() {
        out.push_str(" {");
        out.push('}');
        layout::push_trailing(out, item.trailing.as_deref());
        out.push_str(newline);
        return Ok(());
    }
    out.push_str(" {");
    out.push_str(newline);
    for child in &item.body {
        render_item(child, level + 1, indent, newline, stubs, written, out)?;
    }
    out.push_str(&prefix);
    out.push('}');
    layout::push_trailing(out, item.trailing.as_deref());
    out.push_str(newline);
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Effective trees and verification
// ---------------------------------------------------------------------------------------

/// Strip file/line identity, which any layout change moves.
pub fn strip_identity(directive: &Directive) -> Directive {
    let mut copy = directive.clone();
    copy.line = 0;
    copy.file = PathBuf::new();
    if let Some(children) = copy.children.take() {
        copy.children = Some(children.iter().map(strip_identity).collect());
    }
    copy
}
/// Public alias of [`strip_identity`].
pub fn strip_identity_pub(directive: &Directive) -> Directive {
    strip_identity(directive)
}

/// Replace the `include <argument>` values inside `directives` with the directives of the
/// files they select, exactly as [`crate::core::syntax::parse_file`] expands them.
pub fn expand_includes(directives: &[Directive], files: &[SourceFile], base: &Path) -> Vec<Directive> {
    let mut out = Vec::new();
    for directive in directives {
        if let Some(children) = &directive.children {
            let mut expanded = directive.clone();
            expanded.children = Some(expand_includes(children, files, base));
            out.push(expanded);
            continue;
        }
        if directive.name != "include" {
            out.push(directive.clone());
            continue;
        }
        let Some(argument) = directive.args.first() else {
            out.push(directive.clone());
            continue;
        };
        let sel = selected_files(base, argument, files);
        eprintln!("SEL {:?} base={:?} -> {:?}", argument, base, sel.as_ref().map(|s| s.len()));
        if let Some(selected) = selected_files(base, argument, files) {
            for file in selected {
                let path = file.path.clone();
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                if let Ok(layout) = SourceText::parse(&path, &text) {
                    let inner = layout.directives();
                    let _ = inner;
                    out.extend(expand_includes(&layout.directives(), files, path.parent().unwrap_or(base)));
                }
            }
            continue;
        }
        out.push(directive.clone());
    }
    out
}

///`include` patterns do not contain `[`, so the sorted glob matches are reproduced by
/// comparing pattern segments against the known file names.
fn selected_files<'a>(base: &Path, argument: &str, files: &'a [SourceFile]) -> Option<Vec<&'a SourceFile>> {
    let pattern = base.join(argument);
    let pattern = if pattern.exists() { pattern.canonicalize().unwrap_or(pattern) } else { pattern };
    let text = normalize_argument(&pattern.to_string_lossy());
    let mut matches: Vec<&SourceFile> = files
        .iter()
        .filter(|file| {
            let candidate = normalize_argument(&file.path.to_string_lossy());
            glob_matches(&text, &candidate)
        })
        .collect();
    if matches.is_empty() {
        return None;
    }
    matches.sort_by(|left, right| left.path.cmp(&right.path));
    Some(matches)
}

/// Every file of `files` the configuration reads, in load order.
pub fn include_closure(base: &Path, files: &[SourceFile]) -> Vec<PathBuf> {
    let mut loaded: Vec<PathBuf> = Vec::new();
    let Some(root) = files.first() else {
        return loaded;
    };
    let mut pending: Vec<(PathBuf, PathBuf)> = vec![(root.path.clone(), base.to_path_buf())];
    while let Some((path, dir)) = pending.pop() {
        if loaded.contains(&path) {
            continue;
        }
        loaded.push(path.clone());
        let Some(file) = files.iter().find(|file| file.path == path) else {
            continue;
        };
        let mut arguments = Vec::new();
        include_arguments(&file.directives, &mut arguments);
        for argument in arguments {
            if let Some(found) = selected_files(&dir, &argument, files) {
                for file in found {
                    pending.push((file.path.clone(), dir.clone()));
                }
            }
        }
    }
    loaded
}

/// The directives of every file of `closure` as `(depth, name, args)` rows, sorted.
/// `true` for a file that only holds one `types` block (a `mime.types` table); such a file
/// is a value table read through its `include`, not a configuration fragment.
pub fn is_value_table(directives: &[Directive]) -> bool {
    directives.len() == 1 && directives[0].name == "types" && directives[0].has_block()
}
pub fn tree_signature(files: &[SourceFile]) -> Vec<(usize, String, Vec<String>)> {
    let mut rows = Vec::new();
    for (index, file) in files.iter().enumerate() {
        // A file that stands alone keeps its own tree. A merged fragment is not a tree:
        if index > 0 && file.parent.is_some() {
            // A value table (`mime.types`) or a file with blocks is a tree of its own;
            // anything else is a fragment whose statements belong to its includer.
            let standalone = is_value_table(&file.directives)
                || file.directives.iter().any(|directive| directive.has_block());
            if !standalone {
                continue;
            }
        }
        append_rows(&file.directives, 0, &mut rows);
    }
    rows.sort();
    rows
}
fn append_rows(directives: &[Directive], depth: usize, out: &mut Vec<(usize, String, Vec<String>)>) {
    for directive in directives {
        out.push((depth, directive.name.clone(), directive.args.clone()));
        if let Some(children) = &directive.children {
            append_rows(children, depth + 1, out);
        }
    }
}

/// Files a directive tree refers to that are not configuration (`content_by_lua_file`,
/// certificates, ...). They are copied so the new tree can be compiled and served.
pub fn referenced_resources(directives: &[Directive]) -> Vec<String> {
    let mut out = Vec::new();
    for directive in directives {
        let resource = matches!(
            directive.name.as_str(),
            "ssl_certificate"
                | "ssl_certificate_key"
                | "ssl_client_certificate"
                | "ssl_trusted_certificate"
                | "ssl_crl"
                | "ssl_dhparam"
                | "ssl_stapling_file"
                | "ssl_password_file"
                | "ssl_session_ticket_key"
                | "proxy_ssl_certificate"
                | "proxy_ssl_certificate_key"
                | "proxy_ssl_trusted_certificate"
                | "content_by_lua_file"
                | "access_by_lua_file"
                | "rewrite_by_lua_file"
                | "header_filter_by_lua_file"
                | "body_filter_by_lua_file"
        );
        if resource
            && let Some(path) = directive.args.first()
            && !path.contains('$')
        {
            out.push(path.clone());
        }
        if let Some(children) = &directive.children {
            out.extend(referenced_resources(children));
        }
    }
    out
}

/// The `include` arguments of a directive tree.
fn include_arguments(directives: &[Directive], out: &mut Vec<String>) {
    for directive in directives {
        if directive.name == "include"
            && let Some(argument) = directive.args.first()
        {
            out.push(argument.clone());
        }
        if let Some(children) = &directive.children {
            include_arguments(children, out);
        }
    }
}
/// Every file of `files` the configuration in `directives` reads, in load order.
pub fn referenced_files(directives: &[Directive], files: &[SourceFile], base: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for directive in directives {
        if let Some(children) = &directive.children {
            out.extend(referenced_files(children, files, base));
            continue;
        }
        if directive.name != "include" {
            continue;
        }
        if let Some(argument) = directive.args.first()
            && let Some(selected) = selected_files(base, argument, files)
        {
            out.extend(selected.iter().map(|file| file.path.clone()));
        }
    }
    out
}

pub fn same_shape(left: &[Directive], right: &[Directive]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| strip_identity(left) == strip_identity(right))
}

/// Statistics of one verification.
#[derive(Default, Debug)]
pub struct Verified {
    pub files: usize,
    pub directives: usize,
    pub comments: usize,
}

/// Parse rendered files the way the server would and compare them to the original tree.
///
/// `files` maps a relative path to its text; `root` is the entry file. The include expansion
/// below mirrors [`crate::core::syntax::parse_file`]: relative patterns resolve against the
/// including file, matches are sorted, and each file is read once.
pub fn verify_tree(
    root: &Path,
    files: &[(PathBuf, String)],
    expected: &[Directive],
    expected_comments: &[String],
) -> Result<Verified> {
    let mut writer = MemoryTree::new(files);
    let rendered = writer.expand(root)?;
    if !same_shape(expected, &rendered) {
        let at = expected
            .iter()
            .zip(&rendered)
            .position(|(left, right)| strip_identity(left) != strip_identity(right));
        let describe = |tree: &[Directive], index: Option<usize>| match index.and_then(|index| tree.get(index)) {
            Some(directive) => format!(
                "{} {:?}{}",
                directive.name,
                directive.args,
                if directive.has_block() { " {...}" } else { ";" }
            ),
            None => "end of file".to_string(),
        };
        let message = format!(
            "the rendered configuration does not reproduce the original directive tree ({} vs {} top-level directive(s); first difference: {} -> {})",
            expected.len(),
            rendered.len(),
            describe(expected, at),
            describe(&rendered, at)
        );
        return Err(anyhow::anyhow!(message));
    }
    let comments = writer.comments();
    let rendered_comments: HashSet<&String> = comments.iter().collect();
    let missing: Vec<&String> = expected_comments
        .iter()
        .filter(|comment| !rendered_comments.contains(comment))
        .collect();
    if !missing.is_empty() {
        return Err(anyhow::anyhow!(
            "comments were lost while rendering: {}",
            missing
                .iter()
                .map(|comment| comment.trim())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(Verified {
        files: files.len(),
        directives: rendered.len(),
        comments: comments.len(),
    })
}

/// The rendered files, served to the include expansion as if they were on disk.
pub struct MemoryTree<'a> {
    files: &'a [(PathBuf, String)],
    loaded: Vec<SourceText>,
    index: HashMap<String, &'a str>,
}

impl<'a> MemoryTree<'a> {
    pub fn new(files: &'a [(PathBuf, String)]) -> Self {
        let mut index = HashMap::new();
        for (path, text) in files {
            index.insert(normalize_argument(&path.to_string_lossy()), text.as_str());
        }
        Self {
            files,
            loaded: Vec::new(),
            index,
        }
    }

    fn text_of(&self, path: &Path) -> Option<&'a str> {
        self.index
            .get(&normalize_argument(&path.to_string_lossy()))
            .copied()
    }

    pub fn expand(&mut self, root: &Path) -> Result<Vec<Directive>> {
        let mut stack = Vec::new();
        self.expand_file(root, &mut stack)
    }

    fn expand_file(&mut self, path: &Path, stack: &mut Vec<PathBuf>) -> Result<Vec<Directive>> {
        if stack.iter().any(|seen| seen == path) {
            bail!("include cycle detected at {}", path.display());
        }
        let Some(text) = self.text_of(path) else {
            bail!("rendered configuration is missing {}", path.display());
        };
        let layout = SourceText::parse(path, text)?;
        self.loaded.push(layout.clone());
        let items = layout.items.clone();
        stack.push(path.to_path_buf());
        let mut out = Vec::new();
        let result = self.expand_items(&items, path, stack, &mut out);
        stack.pop();
        result.map(|()| out)
    }

    fn expand_items(
        &mut self,
        items: &[Item],
        path: &Path,
        stack: &mut Vec<PathBuf>,
        out: &mut Vec<Directive>,
    ) -> Result<()> {
        let base = path.parent().unwrap_or_else(|| Path::new(""));
        for item in items {
            let Item::Directive(item) = item else {
                continue;
            };
            if item.directive.children.is_some() {
                // A block: its body is expanded by the same rules as the file itself, so an
                // `include` written inside it is spliced in at that position.
                let mut directive = item.directive.clone();
                let mut children = Vec::new();
                self.expand_items(&item.body, path, stack, &mut children)?;
                directive.children = Some(children);
                out.push(directive);
                continue;
            }
            if item.directive.name == "include"
                && let Some(argument) = item.directive.args.first()
            {
                let mut matches = Vec::new();
                for entry in self.files {
                    let candidate = entry.0.clone();
                    let pattern = base.join(argument);
                    if glob_matches(
                        &normalize_argument(&pattern.to_string_lossy()),
                        &normalize_argument(&candidate.to_string_lossy()),
                    ) {
                        matches.push(candidate);
                    }
                }
                matches.sort();
                for candidate in matches {
                    let included = self.expand_file(&candidate, stack)?;
                    out.extend(included);
                }
                continue;
            }
            out.push(item.directive.clone());
        }
        Ok(())
    }

    pub fn loaded_count(&self) -> usize {
        self.loaded.len()
    }

    pub fn comments(&self) -> Vec<String> {
        let mut out = Vec::new();
        for layout in &self.loaded {
            out.extend(layout.comments());
        }
        out
    }
}

/// Match a path against an `include` argument containing `*` and `?`.
fn glob_matches(pattern: &str, path: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let path: Vec<char> = path.chars().collect();
    // `[` is handled by the glob crate for the real filesystem; for the in-memory tree a
    // literal comparison is enough because the renderer never rewrites patterns.
    fn matches(pattern: &[char], path: &[char]) -> bool {
        match pattern.split_first() {
            None => path.is_empty(),
            Some(('*', rest)) => (0..=path.len()).any(|skip| matches(rest, &path[skip..])),
            Some(('?', rest)) => !path.is_empty() && matches(rest, &path[1..]),
            Some((ch, rest)) => path.first() == Some(ch) && matches(rest, &path[1..]),
        }
    }
    matches(&pattern, &path)
}











/// Replace the value of an `include` line, keeping its indentation and trailing comment.
fn replace_include(text: &str, written: &str, selected: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let after = trimmed.strip_prefix("include ").map(str::trim_start);
        let replace = after.is_some_and(|after| {
            after == written
                || after.starts_with(&format!("{written} "))
                || after.starts_with(&format!("{written};"))
        });
        if !replace {
            out.push_str(line);
            continue;
        }
        let indent = &line[..line.len() - trimmed.len()];
        let after = trimmed["include ".len()..].trim_start();
        let tail = &after[written.len()..];
        out.push_str(indent);
        out.push_str("include ");
        out.push_str(&layout::quote_argument(selected));
        out.push_str(tail);
    }
    out
}











































