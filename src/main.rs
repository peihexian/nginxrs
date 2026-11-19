use anyhow::{Context, Result, bail};
use clap::Parser;
use nginxrs::config::Config;
use nginxrs::core::http_core::{Engine, HttpCoreApp};
use nginxrs::core::reload::{self, Reloader};
use nginxrs::modules::balancer::Upstream;
use nginxrs::modules::log::{AccessLogConfig, AccessLogWriter, LogTarget};
use nginxrs::modules::stub_status::ServerStats;
use nginxrs::modules::{PROVIDERS, upstream};
use pingora_core::server::Server;
use pingora_core::server::configuration::ServerConf;
use pingora_core::services::ServiceWithDependents;
use pingora_core::services::background::background_service;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "nginxrs",
    version,
    about = "Nginx-style HTTP server powered by Pingora"
)]
struct Cli {
    /// Nginx-style configuration file.
    #[arg(short = 'c', long = "config", default_value = "conf/nginxrs.conf")]
    config: PathBuf,

    /// Validate configuration, Lua syntax and upstreams without listening.
    #[arg(short = 't', long = "test")]
    test: bool,

    /// Send a signal to a running instance: `reload` (like nginx -s reload) or `stop`.
    #[arg(short = 's', long = "signal")]
    signal: Option<String>,

    /// Pid file of the running instance, used with `-s`.
    #[arg(short = 'p', long = "pid-file")]
    pid_file: Option<PathBuf>,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();
    let cli = Cli::parse();

    if let Some(signal) = &cli.signal {
        let pid_file = cli
            .pid_file
            .clone()
            .unwrap_or_else(|| default_pid_file(&cli.config));
        return match signal.as_str() {
            "reload" => {
                let answer = reload::request_reload(&pid_file)?;
                println!("nginxrs: reload requested: {answer}");
                Ok(())
            }
            "stop" | "quit" => {
                let answer = reload::request_stop(&pid_file)?;
                println!("nginxrs: stop requested: {answer}");
                Ok(())
            }
            other => bail!("unknown signal \"{other}\"; expected reload or stop"),
        };
    }

    let config = Config::load(&cli.config)
        .with_context(|| format!("failed to load {}", cli.config.display()))?;
    for warning in &config.warnings {
        log::warn!("{warning}");
    }
    let pid_file = cli.pid_file.clone().unwrap_or_else(|| {
        config
            .module_states
            .get::<nginxrs::config::MainState>("main")
            .and_then(|state| state.pid_file.clone())
            .unwrap_or_else(|| default_pid_file(&cli.config))
    });
    let config_path = cli.config.clone();

    // Process counters survive reloads so `stub_status` keeps accumulating.
    let stats = config
        .module_states
        .get::<Arc<ServerStats>>(nginxrs::modules::stub_status::MODULE_NAME)
        .cloned()
        .unwrap_or_default();

    let (engine, services) = build_engine(&config, stats.clone())?;
    let engine = Arc::new(arc_swap::ArcSwap::from_pointee(engine));
    let listeners: Vec<String> = engine.load().listeners().map(str::to_string).collect();
    if listeners.is_empty() {
        bail!("configuration defines no listener");
    }

    if cli.test {
        println!(
            "nginxrs: configuration file {} syntax is ok",
            cli.config.display()
        );
        println!(
            "nginxrs: configuration test is successful ({} listener(s), {} server(s), {} location(s))",
            listeners.len(),
            config.http.servers.len(),
            config
                .http
                .servers
                .iter()
                .map(|server| server.locations.len())
                .sum::<usize>()
        );
        return Ok(());
    }

    // Reload: compile the file again and swap it in. A broken configuration is logged and
    // the current engine keeps serving, exactly like `nginx -s reload` with a bad file.
    let reload_target = engine.clone();
    let reload_config = config_path.clone();
    let reload_stats = stats.clone();
    let reloader = Arc::new(Reloader {
        config_path: config_path.clone(),
        swap: Arc::new(move || {
            let config = Config::load(&reload_config)
                .with_context(|| format!("cannot reload {}", reload_config.display()))?;
            let (engine, _services) = build_engine(&config, reload_stats.clone())
                .context("rejected reloaded configuration")?;
            let servers = engine.servers.len();
            reload_target.store(Arc::new(engine));
            log::info!("configuration reloaded from {}", reload_config.display());
            let _ = servers;
            Ok(())
        }),
    });

    // Control endpoint for `nginxrs -s reload|stop`; it also works on Windows, where
    // SIGHUP is unavailable.
    let control_listener = std::net::TcpListener::bind("127.0.0.1:0")
        .context("cannot bind the configuration control endpoint")?;
    let control_address = control_listener.local_addr()?.to_string();
    if let Some(parent) = pid_file.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&pid_file, std::process::id().to_string())
        .with_context(|| format!("cannot write pid file {}", pid_file.display()))?;
    reload::publish_control(&pid_file, &control_address)?;
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    reload::serve_control(control_listener, reloader.clone(), shutdown.clone())
        .context("cannot start the configuration control endpoint")?;

    // `SIGHUP` triggers a reload on Unix, matching Nginx.
    spawn_sighup_watcher(reloader);

    let mut server_conf = ServerConf::default();
    if let Some(threads) = config.worker_processes {
        server_conf.threads = threads;
    }
    let mut server = Server::new_with_opt_and_conf(None, server_conf);
    server.bootstrap();
    server.add_services(services);
    let tls_listeners: Vec<String> = config
        .module_states
        .get::<nginxrs::modules::ssl::TlsServers>(nginxrs::modules::ssl::MODULE_NAME)
        .map(|tls| tls.enabled_listeners().to_vec())
        .unwrap_or_default();
    for listen in listeners {
        let service = HttpCoreApp::new(Arc::clone(&engine), listen.clone());
        let mut service = pingora_proxy::http_proxy_service(&server.configuration, service);
        match config
            .module_states
            .get::<nginxrs::modules::ssl::TlsServers>(nginxrs::modules::ssl::MODULE_NAME)
            .and_then(|tls| tls.for_server(&listen))
        {
            Some(tls) if tls_listeners.contains(&listen) => {
                let certificate = tls
                    .certificate
                    .as_ref()
                    .context("TLS listener without a certificate")?;
                let key = tls
                    .certificate_key
                    .as_ref()
                    .context("TLS listener without a private key")?;
                let mut settings = pingora_core::listeners::tls::TlsSettings::intermediate(
                    &certificate.to_string_lossy(),
                    &key.to_string_lossy(),
                )
                .with_context(|| {
                    format!(
                        "cannot load the TLS certificate {} / {}",
                        certificate.display(),
                        key.display()
                    )
                })?;
                settings.enable_h2();
                service.add_tls_with_settings(&listen, None, settings);
                log::info!("nginxrs listening on https://{listen}");
            }
            _ => {
                service.add_tcp(&listen);
                log::info!("nginxrs listening on http://{listen}");
            }
        }
        server.add_service(service);
    }
    log::info!(
        "nginxrs control endpoint {control_address} (pid file {})",
        pid_file.display()
    );
    server.run_forever();
}

/// Build a runtime engine plus its upstream background services from a compiled config.
fn build_engine(
    config: &Config,
    stats: Arc<ServerStats>,
) -> Result<(Engine, Vec<Box<dyn ServiceWithDependents>>)> {
    let mut upstreams = HashMap::new();
    let mut services: Vec<Box<dyn ServiceWithDependents>> = Vec::new();
    if let Some(groups) = config
        .module_states
        .get::<upstream::Upstreams>(upstream::MODULE_NAME)
    {
        for group in &groups.groups {
            let runtime =
                Upstream::new(group).with_context(|| format!("upstream {}", group.name))?;
            let service = background_service(&format!("upstream {}", group.name), runtime);
            upstreams.insert(group.name.clone(), service.task());
            services.push(Box::new(service));
        }
    }

    let access_config = config
        .module_states
        .get::<AccessLogConfig>(nginxrs::modules::log::MODULE_NAME)
        .cloned()
        .unwrap_or_default();
    let access_writer = match &access_config.target {
        Some(LogTarget::File(path)) => Some(Arc::new(
            AccessLogWriter::open(path)
                .with_context(|| format!("cannot open access log {}", path.display()))?,
        )),
        _ => None,
    };
    let mime = config
        .module_states
        .get::<nginxrs::modules::http_core::HttpCoreState>(nginxrs::modules::http_core::MODULE_NAME)
        .cloned()
        .unwrap_or_default();
    let engine = Engine::new(
        &config.http,
        upstreams,
        PROVIDERS,
        mime,
        stats,
        Arc::new(access_config),
        access_writer,
    );
    Ok((engine, services))
}

fn default_pid_file(config: &Path) -> PathBuf {
    config
        .parent()
        .map(|parent| parent.join("nginxrs.pid"))
        .unwrap_or_else(|| PathBuf::from("nginxrs.pid"))
}

#[cfg(unix)]
fn spawn_sighup_watcher(reloader: Arc<Reloader>) {
    std::thread::spawn(move || {
        let Ok(mut signals) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        else {
            log::warn!("cannot install the SIGHUP handler; use `nginxrs -s reload` instead");
            return;
        };
        loop {
            if signals.recv().await.is_some() {
                match reloader.reload() {
                    Ok(()) => log::info!("SIGHUP: configuration reloaded"),
                    Err(error) => log::error!(
                        "SIGHUP: reload failed, keeping the old configuration: {error:#}"
                    ),
                }
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_sighup_watcher(_reloader: Arc<Reloader>) {
    // Windows has no SIGHUP; `nginxrs -s reload` drives the same code path.
}
