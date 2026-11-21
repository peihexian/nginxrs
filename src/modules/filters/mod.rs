//! Response filters, one directory per nginx filter module.
//!
//! nginx builds the response with a chain of header and body filters
//! (`ngx_http_top_header_filter` / `ngx_http_top_body_filter`). nginxrs keeps the same
//! module boundaries: every filter owns its configuration, its directive table and the
//! transformation it applies to a `(status, headers, body)` triple.
//!
//! | Nginx module | Directory |
//! |---|---|
//! | `ngx_http_ssi_filter_module` | [`ssi`] |

pub mod encode;
pub mod ssi;
