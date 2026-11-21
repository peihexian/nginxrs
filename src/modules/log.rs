//! `ngx_http_log_module`: `log_format` and `access_log`.

use crate::core::http::RequestState;
use crate::core::value::resolve_path;
use crate::core::variables::Template;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use anyhow::Result;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub const MODULE_NAME: &str = "ngx_http_log_module";

#[derive(Clone, Debug)]
pub struct LogFormat {
    pub name: String,
    pub template: Template,
}

#[derive(Clone, Debug)]
pub enum LogTarget {
    /// `access_log off`.
    Off,
    File(std::path::PathBuf),
    /// `access_log path format;` — the file plus the format it names.
    Formatted(std::path::PathBuf, String),
}

#[derive(Clone, Default)]
pub struct AccessLogConfig {
    pub formats: Vec<LogFormat>,
    pub target: Option<LogTarget>,
    /// `access_log file format;` declared per location (`ngx_http_log_loc_conf_t`).
    pub per_location: Vec<(Option<LogTarget>, Option<String>)>,
}

impl AccessLogConfig {
    /// The `combined` format.
    pub fn combined_template() -> Template {
        Template::parse(
            "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"",
        )
        .expect("built-in log format is valid")
    }

    pub fn format(&self, name: &str) -> Option<&Template> {
        self.formats
            .iter()
            .find(|format| format.name == name)
            .map(|format| &format.template)
    }

    /// The format attached to the configured target, if the statement named one.
    pub fn selected_format(&self) -> Option<&Template> {
        match self.target.as_ref()? {
            LogTarget::Formatted(_, name) => self.format(name),
            LogTarget::File(_) => self.format("main"),
            LogTarget::Off => None,
        }
    }

    /// Write one completed request line. Log failures never fail the request.
    pub fn log(
        &self,
        writer: Option<&AccessLogWriter>,
        state: &RequestState,
        status: u16,
        error: Option<&str>,
    ) {
        // `access_log ... format;` names the format; the `main` format is only the fallback
        // when the writer was configured without one.
        let template = self
            .selected_format()
            .cloned()
            .unwrap_or_else(Self::combined_template);
        let mut line = template.eval_with(&mut |name| {
            variable_with_status(state, name, status).or_else(|| state.variable(name))
        });
        if let Some(error) = error {
            line.push_str(&format!(" error=\"{error}\""));
        }
        match writer {
            Some(writer) => writer.write(&line),
            None => log::info!(target: "nginxrs::access", "{line}"),
        }
    }
}

/// Open log file shared by all worker threads.
pub struct AccessLogWriter {
    file: Arc<Mutex<File>>,
}

impl AccessLogWriter {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    pub fn write(&self, line: &str) {
        if let Ok(mut file) = self.file.lock() {
            let _ = writeln!(file, "{line}");
            let _ = file.flush();
        }
    }
}

fn variable_with_status(state: &RequestState, name: &str, status: u16) -> Option<String> {
    match name {
        "status" => Some(status.to_string()),
        "time_local" => Some(httpdate::fmt_http_date(std::time::SystemTime::now())),
        "remote_user" => Some("-".to_string()),
        "http_referer" => Some(
            state
                .headers
                .get("referer")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("-")
                .to_string(),
        ),
        "http_user_agent" => Some(
            state
                .headers
                .get("user-agent")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("-")
                .to_string(),
        ),
        _ => None,
    }
}

pub struct AccessLogModule;

impl Module for AccessLogModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn http_state(&self) -> Option<crate::core::StateInstance> {
        let config = AccessLogConfig {
            target: Some(LogTarget::Off),
            per_location: Vec::new(),
            formats: vec![LogFormat {
                name: "combined".to_string(),
                template: AccessLogConfig::combined_template(),
            }],
        };
        Some(crate::core::StateInstance::new(config))
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![
            DirectiveSpec {
                name: "log_format",
                contexts: &[Context::Http],
                handler: parse_log_format,
            },
            DirectiveSpec {
                name: "access_log",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_access_log,
            },
        ]
    }
}

fn parse_log_format(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.has_block() || directive.args.len() < 2 {
        return Err(directive.error("expected log_format name string ..."));
    }
    for argument in &directive.args[1..] {
        if argument.starts_with("escape=") {
            return Err(directive.error("log_format escape= is not implemented"));
        }
    }
    let template = Template::parse(&directive.args[1..].join(" "))
        .map_err(|error| directive.error(format!("invalid log_format: {error}")))?;
    let name = directive.args[0].clone();
    let config = view.state::<AccessLogConfig>()?;
    config.formats.retain(|format| format.name != name);
    config.formats.push(LogFormat { name, template });
    Ok(())
}

fn parse_access_log(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.has_block() || directive.args.is_empty() || directive.args.len() > 2 {
        return Err(directive.error("expected access_log path [format]; or access_log off;"));
    }
    let target = if directive.args[0] == "off" {
        LogTarget::Off
    } else {
        let path = resolve_path(view.base_dir, &directive.args[0]);
        match directive.args.get(1) {
            // `access_log path format;` keeps the format with the target.
            Some(format) => LogTarget::Formatted(path, format.clone()),
            None => LogTarget::File(path),
        }
    };
    if let Some(format) = directive.args.get(1) {
        let config = view.state::<AccessLogConfig>()?;
        if format != "combined" && config.format(format).is_none() {
            return Err(directive.error(format!("unknown log format \"{format}\"")));
        }
    }
    let format = directive.args.get(1).cloned();
    let scoped = matches!(view.context, Context::Server | Context::Location);
    let config = view.state::<AccessLogConfig>()?;
    // `http {}`-level statements select the process default; server/location statements are
    // recorded per location, as `ngx_http_log_loc_conf_t.logs` keeps them.
    if scoped {
        config.per_location.push((Some(target), format));
    } else {
        config.target = Some(target);
    }
    Ok(())
}
