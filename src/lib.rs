//! nginxrs: an Nginx-compatible HTTP server on Cloudflare Pingora.
//!
//! # Architecture
//!
//! ```text
//! main.rs                process startup, Pingora services
//! └── config.rs          compile a directive tree into HttpConfig + module state
//!     ├── core/          module-agnostic building blocks
//!     │   ├── syntax     Nginx config language (lexer, parser, include)
//!     │   ├── value      duration/size/address parsers shared by modules
//!     │   ├── http       RequestState: connection/request facts + typed slots
//!     │   ├── variables  Template ($var) evaluation and the variable registry
//!     │   ├── state      type-erased module state storage
//!     │   ├── http_core  the request engine (phase order) and Pingora adapter
//!     │   └── runner     services started with the process
//!     └── modules/       one file per Nginx module
//!         ├── registry   directive ownership table (`ngx_command_t` equivalent)
//!         ├── location   per-location module configuration (`loc_conf`)
//!         └── realip, rewrite, proxy, upstream, balancer, static_files, headers,
//!             log, lua, body, http_core (servers/locations)
//! ```
//!
//! Adding a module means implementing [`core::Module`], registering it in
//! [`modules::registry::Registry::default_modules`], and using it from the phase engine
//! only through the configuration it places in [`modules::location::Location`].

pub mod commands;
pub mod config;
pub mod core;
pub mod modules;

pub const SERVER_NAME: &str = concat!("nginxrs/", env!("CARGO_PKG_VERSION"));

