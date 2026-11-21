//! `ngx_http_grpc_module`: proxy a request to a gRPC (HTTP/2) upstream.
//!
//! | nginx | here |
//! |---|---|
//! | `ngx_http_grpc_loc_conf_t` | [`conf::GrpcConf`] |
//! | `ngx_http_grpc_create_request` | [`request::build`] |
//! | the HTTP/2 frame machinery | the `h2` crate ([`client`]) |
//! | `ngx_http_grpc_process_header` | [`response::translate`] |
//!
//! ```nginx
//! grpc_pass grpc://127.0.0.1:50051;
//! grpc_pass grpcs://backend.example:443;
//! grpc_set_header X-Real-IP $remote_addr;
//! grpc_read_timeout 60s;
//! ```
//!
//! `grpc_pass` accepts `grpc://` (plaintext HTTP/2, "h2c prior knowledge") and `grpcs://`
//! (HTTP/2 over TLS), plus a bare `host:port` which nginx treats as `grpc://`. The upstream
//! name may be an `upstream` block; its peers are then load balanced exactly like
//! `proxy_pass`.

pub mod client;
pub mod conf;
pub mod request;
pub mod response;

use crate::core::{DirectiveSpec, Module, ModuleKind};

pub const MODULE_NAME: &str = "ngx_http_grpc_module";

pub struct GrpcModule;

impl Module for GrpcModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        conf::directives()
    }
}

/// The content handler is driven from the content phase like `proxy_pass`.
pub use conf::GrpcConf;
