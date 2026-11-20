//! Physical configuration sources: which files a running configuration actually reads.
//!
//! [`crate::core::syntax`] answers "what does this configuration *mean*" by expanding every
//! `include` into one directive tree. The maintenance commands (`-b`, `-r`) and `-T` need
//! the other half of that story: which files were read, in which order, and which
//! `include` produced each of them. This module walks the same include graph without
//! expanding it into a single tree, so a file keeps its own directives, comments and
//! position.
//!
//! The traversal mirrors Nginx's `ngx_conf_open_file` / `ngx_conf_read_token` split:
//!
//! * only `include` directives that the lexer sees at the top level of a file are opened;
//!   `include` inside a comment is not a directive, and a block value such as
//!   `content_by_lua_block { ... }` is a value, never a directive;
//! * a relative pattern is resolved against the directory of the file that contains the
//!   `include`, which is also where Nginx leaves the working directory after reading it;
//! * patterns are expanded with the same sorted `glob` call as
//!   [`crate::core::syntax::parse_file`], so both walkers select the same files;
//! * every file is opened at most once per root (`ngx_conf_file_t::line` behaviour);
//!   a second `include` of the same file is kept as a directive but not read again.

use crate::core::syntax::Directive;
use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// One regular file read while walking a configuration.
#[derive(Clone, Debug)]
pub struct SourceFile {
    /// Absolute, canonical path of the file that was read.
    pub path: PathBuf,
    /// The directive tree owned by this file alone (its `include`s are not expanded).
    pub directives: Vec<Directive>,
    /// Path of the parent file that opened this file; `None` for the root configuration.
    pub parent: Option<PathBuf>,
}

impl SourceFile {
    /// `true` for the configuration named on the command line.
    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }
}

/// Walk `root` and every file reachable through its `include` directives.
///
/// Files are returned in load order: a file comes before the files it includes.
pub fn load(root: &Path) -> Result<Vec<SourceFile>> {
    let root = open_path(root, "configuration")?;
    let mut walker = Walker {
        files: Vec::new(),
        opened: HashSet::new(),
        stack: Vec::new(),
    };
    walker.visit(&root, None)?;
    Ok(walker.files)
}

/// Read and lex one file without following its `include` directives.
pub fn read_directives(path: &Path) -> Result<Vec<Directive>> {
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read configuration {}", path.display()))?;
    crate::core::syntax::parse_source_with_path(&source, path)
        .with_context(|| format!("invalid configuration {}", path.display()))
}

/// Canonical form of a path that must exist, with a configuration-specific error.
pub fn open_path(path: &Path, what: &str) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("cannot open {what} {}", path.display()))
}

/// Files matched by an `include` argument, in the order Nginx loads them.
///
/// `base` is the directory of the file that contains the `include`. A plain path is
/// returned as-is; a pattern containing `*`, `?` or `[` is expanded and sorted the same way
/// [`crate::core::syntax::parse_file`] expands it.
pub fn expand_include(base: &Path, argument: &str) -> Result<Vec<PathBuf>> {
    let pattern = Path::new(argument);
    let pattern = if pattern.is_absolute() {
        pattern.to_path_buf()
    } else {
        base.join(pattern)
    };
    // `glob` treats `\` as an escape character, so Windows separators are converted to the
    // platform separator before matching; the returned paths keep the caller's form.
    let text = pattern.to_string_lossy().into_owned();
    if !text.contains(['*', '?', '[']) {
        return Ok(vec![pattern]);
    }
    let glob_text = if std::path::MAIN_SEPARATOR == '\\' {
        text.replace('\\', "/")
    } else {
        text.clone()
    };
    let mut paths = Vec::new();
    for entry in glob::glob(&glob_text).with_context(|| format!("invalid include pattern {text}"))? {
        let path = entry?;
        let mapped = if std::path::MAIN_SEPARATOR == '\\' {
            PathBuf::from(path.to_string_lossy().replace('/', "\\"))
        } else {
            path
        };
        paths.push(mapped);
    }
    paths.sort();
    Ok(paths)
}
/// Whether a file path matches an `include` pattern such as `vhost/*.conf`.
pub fn expand_include_path(pattern: &str, candidate: &str) -> Result<bool> {
    let normalized = |text: &str| -> Vec<String> {
        let text = match text.strip_prefix(r"\\?\") {
            Some(rest) => rest.to_string(),
            None => text.to_string(),
        };
        text.split(['\\', '/'])
            .filter(|part| !part.is_empty())
            .map(|part| part.to_ascii_lowercase())
            .collect()
    };
    let pattern = normalized(pattern);
    let candidate = normalized(candidate);
    Ok(segment_match(&pattern, &candidate))
}

/// Match one path against another where `*` and `?` may appear in any segment.
fn segment_match(pattern: &[String], candidate: &[String]) -> bool {
    match pattern.split_first() {
        None => candidate.is_empty(),
        Some((head, rest)) if head == "**" => {
            (0..=candidate.len()).any(|skip| segment_match(rest, &candidate[skip..]))
        }
        Some((head, rest)) => match candidate.split_first() {
            Some((first, tail)) if glob_match(head, first) => segment_match(rest, tail),
            _ => false,
        },
    }
}
/// One-segment `*` and `?` matching.
fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    fn walk(pattern: &[char], value: &[char]) -> bool {
        match pattern.split_first() {
            None => value.is_empty(),
            Some(('*', rest)) => (0..=value.len()).any(|skip| walk(rest, &value[skip..])),
            Some(('?', rest)) => !value.is_empty() && walk(rest, &value[1..]),
            Some((ch, rest)) => value.first() == Some(ch) && walk(rest, &value[1..]),
        }
    }
    walk(&pattern, &value)
}
struct Walker {
    files: Vec<SourceFile>,
    /// Canonical paths already read (Nginx opens each file once, `NGX_CONF_UNSET_UINT`).
    opened: HashSet<PathBuf>,
    /// Include chain used for cycle diagnostics.
    stack: Vec<PathBuf>,
}

impl Walker {
    fn visit(&mut self, path: &Path, parent: Option<&Path>) -> Result<()> {
        let directives = read_directives(path)?;
        let identity = path.to_path_buf();
        self.files.push(SourceFile {
            path: identity.clone(),
            directives: directives.clone(),
            parent: parent.map(Path::to_path_buf),
        });
        self.opened.insert(identity);
        self.stack.push(path.to_path_buf());
        let base = path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
        let result = self.walk_block(&directives, &base);
        self.stack.pop();
        result
    }

    fn walk_block(&mut self, directives: &[Directive], base: &Path) -> Result<()> {
        for directive in directives {
            if directive.has_block() {
                // An `include` is never a block, so a block can be searched directly.
                self.walk_block(directive.block()?, base)?;
                continue;
            }
            if directive.name != "include" {
                continue;
            }
            if directive.args.len() != 1 {
                bail!(
                    "{}:{}: invalid number of arguments in \"include\" directive",
                    directive.file.display(),
                    directive.line
                );
            }
            for included in expand_include(base, &directive.args[0])? {
                let included = match included.canonicalize() {
                    Ok(canonical) => canonical,
                    Err(error) => {
                        // An `include` pattern that matches nothing is a warning in Nginx
                        // and never reaches this point; a literal path that does not
                        // exist is an error with the directive's location.
                        return Err(anyhow::anyhow!(
                            "{}:{}: open() \"{}\" failed: {error}",
                            directive.file.display(),
                            directive.line,
                            included.display()
                        ));
                    }
                };
                if self.stack.contains(&included) {
                    bail!(
                        "include cycle detected: {} includes itself",
                        included.display()
                    );
                }
                if !self.opened.insert(included.clone()) {
                    // Already read once in this tree: Nginx keeps the directive but does
                    // not re-read the file, so its effective content is unchanged.
                    log::debug!("{} is already loaded; not reading it again", included.display());
                    continue;
                }
                self.visit(&included, Some(&directive.file))?;
            }
        }
        Ok(())
    }
}

/// The `include` arguments written in `directives`, including nested blocks.
pub fn include_arguments(directives: &[Directive], out: &mut Vec<String>) {
    for directive in directives {
        if let Some(children) = &directive.children {
            include_arguments(children, out);
        } else if directive.name == "include" {
            if let Some(argument) = directive.args.first() {
                out.push(argument.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn walks_include_tree_in_load_order() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        write(
            &root.join("nginx.conf"),
            "worker_processes 1;\nhttp {\n  include conf/vhost/*.conf;\n  server { listen 80; }\n}\n",
        );
        write(&root.join("conf/vhost/a.conf"), "server { listen 81; }\n");
        write(&root.join("conf/vhost/b.conf"), "server { listen 82; }\n");

        let files = load(&root.join("nginx.conf")).unwrap();
        let names: Vec<String> = files
            .iter()
            .map(|file| {
                file.path
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(
            names,
            vec!["nginx.conf", "conf/vhost/a.conf", "conf/vhost/b.conf"]
        );
        assert!(files[0].is_root());
        assert_eq!(files[1].parent.as_deref(), Some(files[0].path.as_path()));
    }

    #[test]
    fn a_file_included_twice_is_read_once() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            &root.join("nginx.conf"),
            "include shared.conf;\ninclude shared.conf;\nhttp { server { listen 80; } }\n",
        );
        write(&root.join("shared.conf"), "worker_processes 2;\n");
        let files = load(&root.join("nginx.conf")).unwrap();
        assert_eq!(files.len(), 2, "shared.conf must be walked once");
    }

    #[test]
    fn include_inside_a_comment_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            &root.join("nginx.conf"),
            "# include missing/*.conf;\nhttp { server { listen 80; } }\n",
        );
        let files = load(&root.join("nginx.conf")).unwrap();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn include_inside_a_lua_block_is_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            &root.join("nginx.conf"),
            "http { server { listen 80; location / { content_by_lua_block \"include x; ngx.say(1)\"; } } }\n",
        );
        let files = load(&root.join("nginx.conf")).unwrap();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn cycles_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(&root.join("nginx.conf"), "include loop.conf;\n");
        write(&root.join("loop.conf"), "include nginx.conf;\n");
        let error = load(&root.join("nginx.conf")).unwrap_err().to_string();
        assert!(error.contains("include cycle"), "{error}");
    }
}
