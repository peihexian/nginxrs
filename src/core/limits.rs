//! Request time limits derived from core directives.
//!
//! Nginx applies `client_header_timeout` to every read of the request line and header
//! (`ngx_http_wait_request_handler`, `ngx_http_process_request_headers`) and
//! `keepalive_timeout` to each read of a following keepalive request
//! (`ngx_http_keepalive_handler`). Both deadlines are recorded here so the session loop can
//! honour them without knowing which module declared the directive.

use std::time::Duration;

/// Per-request deadlines and link timeouts.
#[derive(Clone, Debug)]
pub struct RequestLimits {
    /// `client_header_timeout` (60s by default).
    pub header_timeout: Duration,
    /// `keepalive_timeout` (`75s` by default); `0` closes after every response.
    pub keepalive_timeout: Duration,
    /// `keepalive_requests`: how many requests one connection serves (`1000` by default).
    pub keepalive_requests: u32,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            header_timeout: Duration::from_secs(60),
            keepalive_timeout: Duration::from_secs(75),
            keepalive_requests: 1000,
        }
    }
}

impl RequestLimits {
    /// The `ngx_http_keepalive_handler` timer, or `None` when keepalive is disabled.
    pub fn keepalive(&self) -> Option<Duration> {
        (!self.keepalive_timeout.is_zero()).then_some(self.keepalive_timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_nginx() {
        let limits = RequestLimits::default();
        assert_eq!(limits.header_timeout, Duration::from_secs(60));
        assert_eq!(limits.keepalive(), Some(Duration::from_secs(75)));
        assert_eq!(limits.keepalive_requests, 1000);
    }

    #[test]
    fn zero_keepalive_disables_the_timer() {
        let limits = RequestLimits {
            keepalive_timeout: Duration::ZERO,
            ..RequestLimits::default()
        };
        assert_eq!(limits.keepalive(), None);
    }
}
