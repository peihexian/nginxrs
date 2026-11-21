//! `ngx_http_ssi_filter_module`: server-side includes in generated response bodies.
//!
//! | File | Responsibility |
//! |---|---|
//! | [`conf`] | directives (`ssi`, `ssi_silent_errors`, …), defaults, command table |
//! | [`parser`] | the `<!--#…-->` tokenizer, a port of `ngx_http_ssi_parse` |
//! | [`expr`] | value expansion (`$var`, `${var}`, `$1`) and `if` expressions |
//! | [`strftime`] | `timefmt` formatting for `$date_local`/`$date_gmt` |
//! | [`filter`] | the renderer: command handlers and include resolution |
//!
//! Nginx wires the filter into the response header/body chain
//! (`ngx_http_ssi_header_filter` + `ngx_http_ssi_body_filter`). nginxrs runs the same chain
//! over a fully buffered body, so the renderer here produces the final bytes in one pass and
//! `include` is resolved through [`IncludeResolver`].

pub mod conf;
pub mod include;
pub mod expr;
pub mod filter;
pub mod parser;
pub mod strftime;

pub use conf::{MODULE_NAME, SsiConf, SsiModule};
pub use filter::{Encoding, IncludeResolver, Renderer};
pub use include::LocationIncludes;
