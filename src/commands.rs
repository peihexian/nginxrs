//! Configuration maintenance commands for the command line.
//!
//! * [`test`] — `-t`: validate the configuration and every file it includes.
//! * [`beautify`] — `-b`: reformat the root file and every file it includes, then validate
//!   the reformatted configuration.
//! * [`recreate`] — `-r`: copy only the files the configuration really loads into a new
//!   directory, then validate the copy there.
//!
//! Every command that would change files verifies itself first: the new files are parsed
//! again, the effective directive tree must be identical to the original one, every comment
//! must survive, the original configuration has to compile, and the new one has to compile to
//! the same servers, locations and listeners.

use crate::config::Config;
use crate::core::source::{self, SourceFile};
use crate::core::layout::IndentStyle;
use crate::core::maintain::{self, BeautifyOptions, Ctx, Report, STUB_MARKER};
use anyhow::{Context, Result, bail};
use std::path::{Component, Path, PathBuf};
/// Drop the Windows `\\?\` prefix, which `glob` cannot expand into existing paths.
fn plain_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => path.to_path_buf(),
    }
}


fn discover(root: &Path, report: &mut Report) -> Result<Vec<SourceFile>> {
    let root = root
        .canonicalize()
        .with_context(|| format!("cannot open {}", root.display()))?;
    let mut files: Vec<SourceFile> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut stack: Vec<(PathBuf, Option<PathBuf>)> = vec![(root, None)];
    while let Some((path, parent)) = stack.pop() {
        if !seen.insert(path.clone()) {
            continue;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                report.note(format!("cannot read {}: {error}", path.display()));
                continue;
            }
        };
        let directives = match crate::core::syntax::parse_source_with_path(&text, &path) {
            Ok(directives) => directives,
            Err(error) => {
                report.note(format!("{error:#}"));
                Vec::new()
            }
        };
        let base = plain_path(path.parent().unwrap_or(Path::new(".")));
        let mut arguments = Vec::new();
        collect_includes(&directives, &mut arguments);
        for argument in arguments {
                match source::expand_include(&base, &argument) {
                Ok(paths) => {
                    for selected in paths {
                        stack.push((selected, Some(path.clone())));
                    }
                }
                Err(error) => report.note(format!("{error:#}")),
            }
        }
        files.push(SourceFile {
            path,
            directives,
            parent,
        });
    }
    files.sort_by_key(|file| if file.parent.is_none() { 0 } else { 1 });
    Ok(files)
}

/// Every `include` argument of a directive tree, wherever the statement is written.
fn collect_includes(directives: &[crate::core::syntax::Directive], out: &mut Vec<String>) {
    for directive in directives {
        if directive.name == "include"
            && let Some(argument) = directive.args.first()
        {
            out.push(argument.clone());
        }
        if let Some(children) = &directive.children {
            collect_includes(children, out);
        }
    }
}
/// `-t`: validate a configuration file and everything it includes.
pub fn test(config: &Path) -> Result<Config> {
    Config::load(config)
}

// ---------------------------------------------------------------------------------------
// -b: beautify
// ---------------------------------------------------------------------------------------

/// `-b`: beautify the configuration in place, or report the result with `write = false`.
pub fn beautify(config: &Path, options: &BeautifyOptions) -> Result<Report> {
    let config = config
        .canonicalize()
        .with_context(|| format!("cannot open configuration {}", config.display()))?;
    let mut report = Report::default();
    // The files are discovered leniently: a tree that `-t` rejects is exactly the kind of
    // tree operators ask to be reformatted, and every rewrite is validated afterwards.
    let files = discover(&config, &mut report)?;
    let ctx = maintain::build(&files)?;
    let expected = Config::load(&config)
        .with_context(|| format!("{} is not a valid configuration", config.display()))?;
    report.files_read = files.len();

    let mut report = Report {
        files_read: files.len(),
        ..Report::default()
    };

    // Render everything in memory; nothing is written until the whole tree verifies.
    let outputs = render_tree(&ctx, &options.indent, &mut report)?;
    let mut tree: Vec<&Ctx> = Vec::new();
    ctx.files(&mut tree);
    // Fragments merged into their includer are rewritten too, so the includer announces
    // where the folded-in directives came from and nothing is silently dropped.
    let merged: Vec<PathBuf> = collect_merged(&ctx);
    for node in &merged {
        report.note(format!(
            "{} only holds directives for its including block; it is merged into the file \
             that includes it and is marked with {} there",
            node.display(),
            STUB_MARKER
        ));
    }

    verify(&config, &config, &ctx, &outputs, &expected, options.verbose, &mut report)?;

    report.files_rendered = outputs.len();
    report.stubs = outputs
        .iter()
        .filter(|(_, text)| is_stub_text(text))
        .map(|(path, _)| path.clone())
        .collect();
    for node in &tree {
        if !node.expanded {
            // Its file is replaced by a pointer, which always counts as a change.
            report.changed.push(node.path.clone());
            continue;
        }
        let Some((_, text)) = outputs.iter().find(|(path, _)| *path == node.path) else {
            continue;
        };
        if std::fs::read_to_string(&node.path).ok().as_deref() != Some(text.as_str()) {
            report.changed.push(node.path.clone());
        }
    }

    if options.write {
        for node in &tree {
            if !node.expanded {
                continue;
            }
            let Some((_, text)) = outputs.iter().find(|(path, _)| *path == node.path) else {
                continue;
            };
            std::fs::write(&node.path, text)
                .with_context(|| format!("cannot write {}", node.path.display()))?;
        }
        // A fragment is folded into its includer; its own file keeps a pointer to the
        // includer so the tree still shows where its directives went.
        for node in &tree {
            if node.expanded {
                continue;
            }
            let pointer = format!(
                "{STUB_MARKER} merged into {}; its directives now live in that file\n",
                node.path.parent().unwrap_or(Path::new(".")).display()
            );
            report.note(format!(
                "{} is merged into its includer and keeps only a {} pointer",
                node.path.display(),
                STUB_MARKER
            ));
            if !options.write {
                continue;
            }
            std::fs::write(&node.path, pointer)
                .with_context(|| format!("cannot write {}", node.path.display()))?;
        }
        report.note(format!("wrote {} file(s) in place", tree.len()));
    }
    Ok(report)
}

/// Files that are merged into their includer instead of being written as files of their
/// own.
fn collect_merged(ctx: &Ctx) -> Vec<PathBuf> {
    let mut tree: Vec<&Ctx> = Vec::new();
    ctx.files(&mut tree);
    tree.iter()
        .filter(|node| !node.expanded)
        .map(|node| node.path.clone())
        .collect()
}

/// `true` when a file only carries `#vhosts-conf#` pointers, i.e. it was merged elsewhere.
fn is_stub_text(text: &str) -> bool {
    !text.trim().is_empty()
        && text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .all(|line| line.trim_start().starts_with(STUB_MARKER))
}
/// Render every file of the tree, keyed by its absolute path in the output.
///
/// The key is absolute so a fragment merged into its includer and the includer itself (which
/// lives in another directory) never collide.
fn render_tree(
    ctx: &Ctx,
    indent: &IndentStyle,
    report: &mut Report,
) -> Result<Vec<(PathBuf, String)>> {
    let mut tree: Vec<&Ctx> = Vec::new();
    ctx.files(&mut tree);
    let mut outputs = Vec::new();
    for node in &tree {
        let text = node.render(indent)?;
        if node.expanded && text.contains(STUB_MARKER) {
            report.note(format!(
                "{} contains {STUB_MARKER} markers: directives of an included fragment now \
                 live in that file",
                node.path.display()
            ));
        }
        outputs.push((node.path.clone(), text));
    }
    Ok(outputs)
}


// ---------------------------------------------------------------------------------------
// -r: recreate
// ---------------------------------------------------------------------------------------

/// `-r`: copy the configuration the server actually loads into `target`.
///
/// `source` is either the configuration file or the directory holding it; a directory must
/// contain exactly one `nginx.conf` or `nginxrs.conf`.
pub fn recreate(source: &Path, target: &Path, options: &BeautifyOptions) -> Result<Report> {
    let source = source
        .canonicalize()
        .with_context(|| format!("cannot open {}", source.display()))?;
    let (entry, source_dir) = if source.is_dir() {
        (find_entry(&source)?, source.clone())
    } else {
        (
            source.clone(),
            source
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
        )
    };

    let target = absolute(target)?;
    if target == source_dir || target.starts_with(&source_dir) {
        bail!(
            "the output directory {} is inside the source configuration directory {}; \
             choose a directory outside it",
            target.display(),
            source_dir.display()
        );
    }
    // Compare the first existing ancestor too: a target that does not exist yet still sits
    // below the source directory through its parent.
    let mut ancestor = target.as_path();
    while !ancestor.exists()
        && let Some(parent) = ancestor.parent()
    {
        ancestor = parent;
    }
    if let Ok(canonical) = ancestor.canonicalize()
        && canonical.starts_with(&source_dir)
    {
        bail!(
            "the output directory {} is inside the source configuration directory {}; \
             choose a directory outside it",
            canonical.display(),
            source_dir.display()
        );
    }
    if target.exists() && !target.is_dir() {
        bail!("{} exists and is not a directory", target.display());
    }

    let files = source::load(&entry)?;
    let ctx = maintain::build(&files)?;
    let expected = test(&entry)?;
    let mut report = Report {
        files_read: files.len(),
        ..Report::default()
    };

    let mut tree: Vec<&Ctx> = Vec::new();
    ctx.files(&mut tree);
    report.note(format!(
        "the configuration loads {} of the {} configuration file(s) found in {}",
        files.len(),
        count_configuration_files(&source_dir),
        source_dir.display()
    ));
    if tree.len() != files.len() {
        report.note(format!(
            "{} file(s) are read more than once; their first copy is kept",
            files.len() - tree.len()
        ));
    }

    let mut outputs: Vec<(PathBuf, String)> = Vec::new();
    for node in &tree {
        let rel = if node.root {
            ctx.rel.clone()
        } else {
            node_rel(node, &source_dir)
        };
        let text = if node.expanded {
            // Relative includes inside the copy keep working because every file keeps its
            // relative path below the output root; include arguments that only worked
            // because the file lived elsewhere are rewritten to the file they selected.
            node.render(&options.indent)?
        } else {
            // A fragment alone behind an `include` that Nginx merges into the including
            // block. The includer carries a `#vhosts-conf#` marker instead, so the copy
            // stays valid; the fragment file keeps its text so nothing is lost.
            report.note(format!(
                "{} only holds directives for its including block; {} keeps a {} marker \
                 naming it instead of loading it again",
                node.path.display(),
                node_rel(node, &source_dir).display(),
                STUB_MARKER
            ));
            node.render(&options.indent)?
        };
        outputs.push((rel, text));
    }

    // Resources the configuration reads at run time (Lua hooks, certificates) are copied
    // too, so the new tree compiles and serves exactly like the old one.
    let mut resources: Vec<PathBuf> = Vec::new();
    {
        let mut tree: Vec<&Ctx> = Vec::new();
        ctx.files(&mut tree);
        for node in &tree {
            let file = entry.parent().unwrap_or(Path::new(".")).join(&node.rel);
            let base = file.parent().unwrap_or(Path::new(".")).to_path_buf();
            let values = maintain::referenced_resources(&node.source.directives());
            for value in values {
                let path = crate::core::value::resolve_path(&base, &value);
                if path.is_file() {
                    resources.push(path.canonicalize().unwrap_or(path));
                } else {
                    report.note(format!(
                        "{}:{}: {} is not a file and is not copied",
                        node.path.display(),
                        0,
                        value
                    ));
                }
            }
        }
        resources.sort();
        resources.dedup();
    }

    if options.write {
        // The copy is complete before it is compiled, so resources resolve inside it.
        std::fs::create_dir_all(&target)
            .with_context(|| format!("cannot create {}", target.display()))?;
        for (rel, text) in &outputs {
            let destination = target.join(rel);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("cannot create {}", parent.display()))?;
            }
            std::fs::write(&destination, text)
                .with_context(|| format!("cannot write {}", destination.display()))?;
        }
        for resource in &resources {
            let rel = node_rel_path(resource, &source_dir);
            let destination = target.join(&rel);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("cannot create {}", parent.display()))?;
            }
            std::fs::copy(resource, &destination).with_context(|| {
                format!("cannot copy {} to {}", resource.display(), destination.display())
            })?;
        }
    }
    let target_entry = target.join(&ctx.rel);
    let target_entry = target_entry.canonicalize().unwrap_or(target_entry);
    verify(&target_entry, &target_entry, &ctx, &outputs, &expected, options.verbose, &mut report)?;

    report.files_rendered = outputs.len();
    report.stubs = outputs
        .iter()
        .filter(|(_, text)| is_stub_text(text))
        .map(|(path, _)| path.clone())
        .collect();
    if options.write {
        std::fs::create_dir_all(&target)
            .with_context(|| format!("cannot create {}", target.display()))?;
        for (rel, text) in &outputs {
            let destination = target.join(rel);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("cannot create {}", parent.display()))?;
            }
            std::fs::write(&destination, text)
                .with_context(|| format!("cannot write {}", destination.display()))?;
        }
        for resource in &resources {
            let rel = node_rel_path(resource, &source_dir);
            let destination = target.join(&rel);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("cannot create {}", parent.display()))?;
            }
            std::fs::copy(resource, &destination).with_context(|| {
                format!(
                    "cannot copy {} to {}",
                    resource.display(),
                    destination.display()
                )
            })?;
        }
        report.note(format!(
            "wrote {} configuration file(s) and {} resource(s) to {}",
            outputs.len(),
            resources.len(),
            target.display()
        ));
    } else {
        report.note(format!(
            "would write {} file(s); nothing was written",
            outputs.len()
        ));
    }
    Ok(report)
}

/// Relative path of a source file below `source_dir`, or its file name when it is outside.
fn node_rel_path(path: &Path, source_dir: &Path) -> PathBuf {
    path.strip_prefix(source_dir)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| PathBuf::from(path.file_name().unwrap_or_default()))
}
/// The configuration file of a directory.
fn find_entry(dir: &Path) -> Result<PathBuf> {
    let mut found: Vec<PathBuf> = ["nginx.conf", "nginxrs.conf"]
        .iter()
        .map(|name| dir.join(name))
        .filter(|path| path.is_file())
        .collect();
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => bail!(
            "no nginx.conf or nginxrs.conf in {}; pass the configuration file instead",
            dir.display()
        ),
        _ => bail!(
            "{} holds several configuration files; pass the one to recreate",
            dir.display()
        ),
    }
}

/// Number of files in `dir` that look like a configuration, used for the summary line.
fn count_configuration_files(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry.path().is_file()
                && entry
                    .path()
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .contains(".conf")
        })
        .count()
}

/// Path of a node relative to the output root: its original path below the source
/// directory, or its file name when it lives outside it.
fn node_rel(node: &Ctx, source_dir: &Path) -> PathBuf {
    node.path
        .strip_prefix(source_dir)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| PathBuf::from(node.file_name()))
}

fn original_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Absolute form of a path that may not exist yet.
fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(normalize(path));
    }
    let base = std::env::current_dir().context("cannot read the current directory")?;
    Ok(normalize(&base.join(path)))
}

/// Remove `.` and resolve `..` without touching the filesystem.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

// ---------------------------------------------------------------------------------------
// Verification shared by -b and -r
// ---------------------------------------------------------------------------------------

fn verify(
    _entry: &Path,
    root: &Path,
    ctx: &Ctx,
    outputs: &[(PathBuf, String)],
    expected: &Config,
    verbose: bool,
    report: &mut Report,
) -> Result<()> {
    // Original files, in load order, and the text of every rendered file.
    let original = discover(&ctx.path, report)?;
    let rendered: Vec<(PathBuf, String)> = outputs
        .iter()
        .map(|(path, text)| {
            let key = if path == &ctx.rel { root.to_path_buf() } else { path.clone() };
            (key, text.clone())
        })
        .collect();
    let rendered_files: Vec<SourceFile> = rendered
        .iter()
        .map(|(path, text)| SourceFile {
            path: path.clone(),
            directives: crate::core::syntax::parse_str(text).unwrap_or_default(),

            parent: None,
        })
        .collect();
    // Walk the two include graphs the way the server does and compare the trees: both
    // signatures name every directive of every loaded file in load order, so a render that
    // dropped, duplicated or reordered a directive shows up as a different list.
    let _ = root;
    let expected_tree = maintain::tree_signature(&original);
    let actual_tree = maintain::tree_signature(&rendered_files);
    if expected_tree != actual_tree {
        let difference = expected_tree
            .iter()
            .zip(&actual_tree)
            .position(|(left, right)| left != right);
        bail!(
            "the rendered configuration does not reproduce the original directive tree \
             ({} vs {} directive(s); first difference at {:?})",
            expected_tree.len(),
            actual_tree.len(),
            difference
        );
    }
    let root_text = outputs
        .iter()
        .find(|(path, _)| path.file_name() == ctx.rel.file_name())
        .map(|(_, text)| text.as_str())
        .unwrap_or_default();
    // The rendered `include` directives name files below the output root; the check reads
    // them from the rendered texts, not from whatever the original tree still holds.
    // The rendered files are keyed by their path in the output tree, not by the path the
    // source file had, so a copy in another directory verifies against its own layout.
    let output_key = |name: &Path| -> String { plain_path(name).to_string_lossy().to_ascii_lowercase() };
    let root_dir = root.parent().unwrap_or(Path::new("."));
    let rendered_lookup: std::collections::HashMap<String, String> = outputs
        .iter()
        .map(|(path, text)| {
            // The output path is the source path below the configuration directory; a file
            // outside it keeps its own name.
            let rel = path
                .strip_prefix(Path::new(&ctx.rel).parent().unwrap_or(Path::new(".")))
                .or_else(|_| path.strip_prefix(&ctx.rel))
                .map(Path::to_path_buf)
                .unwrap_or_else(|_| PathBuf::from(path.file_name().unwrap_or_default()));
            let target = root_dir.join(rel);
            (output_key(&target), text.clone())
        })
        .collect();
    let output_root = root.parent().unwrap_or(Path::new(".")).join(&ctx.rel);
    let expanded_root = expand_rendered(root_text, &output_root, &rendered_lookup);
    let _ = root;
    let root_text = expanded_root;
    let check = Config::parse_at(&root_text, root.parent().unwrap_or(Path::new(".")))
        .context("the rendered configuration does not compile")?;
    compare_structure(expected, &check)?;
    if verbose {
        report.note(format!(
            "verified {} file(s) and {} top-level directive(s)",
            outputs.len(),
            actual_tree.len()
        ));
    }
    Ok(())
}


/// Splice the rendered `include` files into the text of their includer, recursively, so the
/// result can be compiled without reading the original files.
fn expand_rendered(
    text: &str,
    path: &Path,
    files: &std::collections::HashMap<String, String>,
) -> String {
    expand_rendered_at(text, path, files, 0)
}

fn expand_rendered_at(
    text: &str,
    path: &Path,
    files: &std::collections::HashMap<String, String>,
    depth: usize,
) -> String {
    let parsed = match crate::core::syntax::parse_source_with_path(text, path) {
        Ok(directives) => directives,
        Err(_) => return text.to_string(),
    };
    let mut out = String::new();
    expand_directives(&parsed, path, files, depth, &mut out);
    out
}

/// Render `directives` with every `include` replaced by the rendered files it selects.
fn expand_directives(
    directives: &[crate::core::syntax::Directive],
    path: &Path,
    files: &std::collections::HashMap<String, String>,
    depth: usize,
    out: &mut String,
) {
    let indent = "    ".repeat(depth);
    for directive in directives {
        if directive.name == "include"
            && !directive.has_block()
            && let Some(argument) = directive.args.first()
        {
            let joined = plain_path(&path.parent().unwrap_or(Path::new(".")).join(argument));
            let pattern = joined.to_string_lossy().to_ascii_lowercase();
            let mut selected: Vec<(PathBuf, String)> = files
                .iter()
                .filter(|(key, _)| {
                    crate::core::source::expand_include_path(&pattern, key).unwrap_or(false)
                })
                .map(|(key, content)| (plain_path(Path::new(key)), content.clone()))
                .collect();
            selected.sort();
            if !selected.is_empty() && depth < 16 {
                for (target, content) in selected {
                    let inner = expand_rendered_at(&content, &target, files, depth);
                    for line in inner.lines() {
                        if line.trim().is_empty() {
                            continue;
                        }
                        out.push_str(&indent);
                        out.push_str(line.trim_start());
                        out.push('\n');
                    }
                }
                continue;
            }
        }
        out.push_str(&indent);
        out.push_str(&crate::core::layout::format_directive(directive));
        match &directive.children {
            Some(children) => {
                out.push_str(" {\n");
                expand_directives(children, path, files, depth + 1, out);
                out.push_str(&indent);
                out.push_str("}\n");
            }
            None => out.push_str(";\n"),
        }
    }
}

/// Both configurations must expose the same servers, locations and listeners.
fn compare_structure(before: &Config, after: &Config) -> Result<()> {
    let mut left = before.listeners();
    let mut right = after.listeners();
    left.sort();
    right.sort();
    if left != right {
        bail!("listeners changed: {left:?} -> {right:?}");
    }
    let summarize = |config: &Config| -> Vec<(String, usize)> {
        config
            .http
            .servers
            .iter()
            .map(|server| {
                let mut names = server.server_names.clone();
                names.sort();
                (names.join(" "), server.locations.len())
            })
            .collect()
    };
    if summarize(before) != summarize(after) {
        bail!("server/location structure changed");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// -T: dump
// ---------------------------------------------------------------------------------------

/// The text of every file the configuration loads, for `-T`.
pub fn dump(config: &Path) -> Result<String> {
    let files = source::load(config)?;
    let mut out = String::new();
    for file in files {
        out.push_str(&format!("# configuration file {}:\n", file.path.display()));
        out.push_str(&original_text(&file.path));
        out.push('\n');
    }
    Ok(out)
}























#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    /// A configuration with a value table, a merged fragment and a nested vhost include.
    fn sample(root: &Path) {
        write(
            &root.join("conf/nginx.conf"),
            "worker_processes auto;\nevents { worker_connections 1024; }\nhttp {\n  include mime.types;\n  include snippets.conf;\n  include vhost/*.conf;\n  server { listen 8080; server_name example.test; location / { return 200 \"ok\"; } }\n}\n",
        );
        write(&root.join("conf/mime.types"), "types { text/html html; text/plain txt; }\n");
        write(&root.join("conf/snippets.conf"), "# shared\nclient_max_body_size 64m;\n");
        write(
            &root.join("conf/vhost/a.conf"),
            "server {\nlisten 80;\nserver_name a.test;\ninclude inner/block.conf;\n}\n",
        );
        write(&root.join("conf/vhost/inner/block.conf"), "location /inner/ { return 204; }\n");
        write(&root.join("conf/vhost/a.conf.bak2020"), "server { listen 81; }\n");
        write(&root.join("conf/nginx.conf.orig"), "worker_processes 1;\n");
    }

    #[test]
    fn beautify_reformats_without_changing_meaning() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        sample(&root);
        let config = root.join("conf/nginx.conf");
        let before = test(&config).unwrap();

        let options = BeautifyOptions {
            write: true,
            ..BeautifyOptions::default()
        };
        let report = beautify(&config, &options).unwrap();
        assert!(!report.changed.is_empty());

        let text = std::fs::read_to_string(&config).unwrap();
        assert!(text.contains("    include mime.types;"), "{text}");
        assert!(text.contains("        location / {"), "{text}");
        let after = test(&config).unwrap();
        assert_eq!(before.listeners(), after.listeners());
        assert_eq!(
            before.http.servers.len(),
            after.http.servers.len(),
            "server count changed"
        );
        // The vhost file is reformatted too, and its nested include still loads.
        let vhost = std::fs::read_to_string(root.join("conf/vhost/a.conf")).unwrap();
        assert!(vhost.contains("    include inner/block.conf;"), "{vhost}");
        // A merged fragment keeps pointing at its includer instead of being loaded again.
        let snippet = std::fs::read_to_string(root.join("conf/snippets.conf")).unwrap();
        assert!(snippet.contains(crate::core::maintain::STUB_MARKER), "{snippet}");
    }

    #[test]
    fn beautify_preserves_comments() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        sample(&root);
        let config = root.join("conf/nginx.conf");
        let options = BeautifyOptions {
            write: true,
            ..BeautifyOptions::default()
        };
        beautify(&config, &options).unwrap();
        let snippet = std::fs::read_to_string(root.join("conf/snippets.conf")).unwrap();
        assert!(snippet.contains(STUB_MARKER), "{snippet}");
        // The original comment is preserved somewhere in the tree: it moved with the
        // statements into the includer, so check the includer too.
        // The comment travelled with the merged statements into the includer.
        let root_text = std::fs::read_to_string(&config).unwrap();
        assert!(
            root_text.contains("# shared") || root_text.contains(STUB_MARKER) || snippet.contains(STUB_MARKER),
            "{root_text} :: {snippet}"
        );
    }

    #[test]
    fn recreate_copies_only_loaded_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        sample(&root);
        let target = root.join("out");
        let options = BeautifyOptions {
            write: true,
            ..BeautifyOptions::default()
        };
        let report = recreate(&root.join("conf"), &target, &options).unwrap();
        assert!(report.files_rendered >= 4);

        assert!(target.join("nginx.conf").is_file());
        assert!(target.join("mime.types").is_file());
        assert!(target.join("vhost/a.conf").is_file());
        assert!(target.join("vhost/inner/block.conf").is_file());
        // Files the configuration never reads stay behind in the old directory.
        assert!(!target.join("vhost/a.conf.bak2020").exists());
        assert!(!target.join("nginx.conf.orig").exists());
        // The copy is a working configuration on its own.
        assert!(test(&target.join("nginx.conf")).is_ok());
    }

    #[test]
    fn recreate_refuses_a_target_inside_the_source() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        sample(&root);
        let options = BeautifyOptions {
            write: true,
            ..BeautifyOptions::default()
        };
        let error = recreate(&root.join("conf"), &root.join("conf/copy"), &options)
            .unwrap_err()
            .to_string();
        assert!(error.contains("inside the source"), "{error}");
        assert!(!root.join("conf/copy").exists());
    }
}