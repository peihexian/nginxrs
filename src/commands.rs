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
    let files = source::load(&config)?;
    let ctx = maintain::build(&files)?;
    let expected = test(&config)?;

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

    verify(&config, &config.clone(), &ctx, &outputs, &expected, options.verbose, &mut report)?;

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
    if let Ok(canonical) = target.canonicalize()
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

    verify(&entry, &ctx.rel, &ctx, &outputs, &expected, options.verbose, &mut report)?;

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
        report.note(format!(
            "wrote {} file(s) to {}",
            outputs.len(),
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
    entry: &Path,
    root: &Path,
    ctx: &Ctx,
    outputs: &[(PathBuf, String)],
    expected: &Config,
    verbose: bool,
    report: &mut Report,
) -> Result<()> {
    // Original files, in load order, and the text of every rendered file.
    let original = source::load(&ctx.path)?;
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
    let rendered_lookup: std::collections::HashMap<String, String> = rendered
        .iter()
        .map(|(path, text)| (path.to_string_lossy().to_ascii_lowercase(), text.clone()))
        .collect();
    let output_root = root.to_path_buf();
    let expanded_root = expand_rendered(root_text, &output_root, &rendered_lookup);
    let _ = root;
    let root_text = expanded_root;
    std::fs::write("F:/temp/expanded_debug.conf", &root_text).ok();
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

/// Splice the rendered `include` files into the text of their includer, so the result can
/// be compiled without reading the original files.
fn expand_rendered(
    text: &str,
    path: &Path,
    files: &std::collections::HashMap<String, String>,
) -> String {
    let base = path.parent().unwrap_or(Path::new("."));
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let argument = trimmed
            .strip_prefix("include ")
            .map(|rest| rest.trim_start().trim_end().trim_end_matches(';').trim_end());
        let Some(argument) = argument else {
            out.push_str(line);
            continue;
        };
        let target = base.join(argument);
        let name = target.file_name().map(|name| name.to_string_lossy().to_ascii_lowercase());
        let replacement = name.and_then(|name| {
            files
                .iter()
                .find(|(key, _)| {
                    Path::new(key)
                        .file_name()
                        .map(|file| file.to_string_lossy().to_ascii_lowercase() == name)
                        .unwrap_or(false)
                })
                .map(|(_, content)| content.clone())
        });
        match replacement {
            Some(content) => {
                out.push_str(&content);
                if !content.ends_with('\n') {
                    out.push('\n');
                }
            }
            None => out.push_str(line),
        }
    }
    out
}
/// The directive tree of one file tree with its `include`s kept as written.
fn include_tree(files: &[SourceFile], root: &Path, base: &Path) -> Result<Vec<crate::core::syntax::Directive>> {
    let _ = base;
    let index: std::collections::HashMap<&PathBuf, &SourceFile> = files.iter().map(|f| (&f.path, f)).collect();
    // The root file of the walk is the one whose parent is unset and whose path is `root`,
    // or the first file when a caller supplies no parents.
    let entry = files
        .iter()
        .find(|file| &file.path == root)
        .or_else(|| files.iter().find(|file| file.parent.is_none()))
        .or_else(|| files.first());
    let _ = index;
    match entry {
        Some(file) => Ok(file.directives.clone()),
        None => Ok(Vec::new()),
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






















