//! Nginx-compatible HTTP modules.
//!
//! Each submodule mirrors one Nginx module and owns its directives, configuration,
//! request handlers and variables. The HTTP core orchestrates phases, so adding a new
//! Nginx module means adding one file here plus a line in [`Registry::default_modules`].
//!
//! | Nginx module | File |
//! |---|---|
//! | `ngx_http_core_module` | `http_core.rs` |
//! | `ngx_http_rewrite_module` | `rewrite.rs` |
//! | `ngx_http_realip_module` | `realip.rs` |
//! | `ngx_http_headers_module` | `headers.rs` |
//! | `ngx_http_log_module` | `log.rs` |
//! | `ngx_http_proxy_module` | `proxy.rs` |
//! | `ngx_http_upstream_module` | `upstream.rs` |
//! | backend selection | `balancer.rs` |
//! | `ngx_http_static_module` | `static_files.rs` + `static_files/file.rs` |
//! | `ngx_http_lua_module` | `lua.rs` |
//! | request body limits | `body.rs` |

pub mod access;
pub mod balancer;
pub mod body;
pub mod ctx;
pub mod error_page;
pub mod headers;
pub mod http_core;
pub mod limit_conn;
pub mod limit_req;
pub mod location;
pub mod log;
pub mod lua;
pub mod proxy;
pub mod proxy_buffer;
pub mod proxy_cache;
pub mod proxy_rewrite;
pub mod proxy_tls;
pub mod realip;
pub mod registry;
pub mod respond;
pub mod rewrite;
pub mod ssl;
pub mod static_files;
pub mod stub_status;
pub mod upstream;
pub mod uri;
pub mod writer;

pub use registry::{DirectiveView, Registry};

/// Variable providers contributed by the built-in modules, in Nginx module order.
///
/// The registry declares the same providers through [`crate::core::Module::variables`];
/// this table lets request-scoped helpers rebuild a [`crate::core::http::RequestState`]
/// without reaching into the registry.
pub const PROVIDERS: &[(&str, &dyn crate::core::variables::VariableProvider)] = &[
    ("realip_remote_addr", &realip::REALIP_REMOTE_ADDR),
    ("realip_remote_port", &realip::REALIP_REMOTE_PORT),
    ("upstream_cache_status", &proxy::CACHE_STATUS),
];
