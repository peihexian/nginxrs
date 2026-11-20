//! Per-request state shared by every HTTP module.
//!
//! [`RequestState`] is the Rust counterpart of Nginx's `ngx_http_request_t`: it owns the
//! connection identity, current URI/args, headers, response status and typed slots that
//! modules use to attach data across phases.

use crate::core::variables::Template;
use http::{HeaderMap, Method, StatusCode, Version};
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Connection facts as seen before any module rewrites them.
#[derive(Clone, Debug, Default)]
pub struct ConnectionState {
    /// Listening socket, e.g. `127.0.0.1:8080`.
    pub listen: String,
    /// Address of the immediate TCP peer.
    pub peer_ip: Option<IpAddr>,
    pub peer_port: u16,
    pub local_ip: Option<IpAddr>,
    pub local_port: u16,
    pub scheme: String,
    pub tls: bool,
}

/// Client address after `realip` processing.
#[derive(Clone, Debug, Default)]
pub struct ClientState {
    pub original_addr: Option<IpAddr>,
    pub original_port: u16,
    pub addr: Option<IpAddr>,
    pub port: u16,
    pub rewritten: bool,
}

impl ClientState {
    pub fn from_connection(connection: &ConnectionState) -> Self {
        Self {
            original_addr: connection.peer_ip,
            original_port: connection.peer_port,
            addr: connection.peer_ip,
            port: connection.peer_port,
            rewritten: false,
        }
    }
}

/// Request-line facts. `uri` stays as received across internal redirects.
#[derive(Clone, Debug, Default)]
pub struct RequestLine {
    pub method: Method,
    pub version: Version,
    /// Original `$request_uri` (path + args as received).
    pub uri: String,
    /// Current `$uri` (decoded path, changed by rewrite modules).
    pub path: String,
    pub args: String,
    pub host: String,
}

impl RequestLine {
    pub fn from_header(request: &pingora_http::RequestHeader) -> Self {
        let path = request.uri.path().to_string();
        let args = request.uri.query().unwrap_or_default().to_string();
        let uri = if args.is_empty() {
            path.clone()
        } else {
            format!("{path}?{args}")
        };
        let host = request
            .headers
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .or_else(|| request.uri.authority().map(|authority| authority.as_str()))
            .unwrap_or_default()
            .to_string();
        Self {
            method: request.method.clone(),
            version: request.version,
            uri,
            path,
            args,
            host,
        }
    }
}

/// The per-request object handed to modules.
pub struct RequestState {
    pub connection: ConnectionState,
    pub client: ClientState,
    pub request: RequestLine,
    pub headers: HeaderMap,
    /// Primary server name (`$server_name`).
    pub server_name: String,
    pub status: Option<StatusCode>,
    pub started: Instant,
    pub body_bytes_sent: usize,
    pub upstream_addr: String,
    providers: &'static [(
        &'static str,
        &'static dyn crate::core::variables::VariableProvider,
    )],
    slots: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl RequestState {
    pub fn new(
        connection: ConnectionState,
        request: RequestLine,
        headers: HeaderMap,
        providers: &'static [(
            &'static str,
            &'static dyn crate::core::variables::VariableProvider,
        )],
    ) -> Self {
        let client = ClientState::from_connection(&connection);
        Self {
            connection,
            client,
            request,
            headers,
            server_name: String::new(),
            status: None,
            started: Instant::now(),
            body_bytes_sent: 0,
            upstream_addr: String::new(),
            providers,
            slots: HashMap::new(),
        }
    }

    pub fn get<T: Any + Send + Sync>(&self) -> Option<&T> {
        self.slots
            .get(&TypeId::of::<T>())
            .and_then(|slot| slot.downcast_ref())
    }

    pub fn get_mut<T: Any + Send + Sync>(&mut self) -> Option<&mut T> {
        self.slots
            .get_mut(&TypeId::of::<T>())
            .and_then(|slot| slot.downcast_mut())
    }

    pub fn insert<T: Any + Send + Sync>(&mut self, value: T) {
        self.slots.insert(TypeId::of::<T>(), Box::new(value));
    }

    pub fn take<T: Any + Send + Sync>(&mut self) -> Option<T> {
        self.slots
            .remove(&TypeId::of::<T>())
            .and_then(|slot| slot.downcast::<T>().ok())
            .map(|boxed| *boxed)
    }

    /// Evaluate a built-in variable. Module variables are consulted by
    /// [`RequestState::variable`] afterwards.
    pub fn builtin_variable(&self, name: &str) -> Option<String> {
        let value = match name {
            "uri" | "document_uri" => self.request.path.clone(),
            "request_uri" => self.request.uri.clone(),
            "args" | "query_string" => self.request.args.clone(),
            "is_args" => if self.request.args.is_empty() {
                ""
            } else {
                "?"
            }
            .to_string(),
            "host" => self.request.host.clone(),
            "http_host" => self
                .headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string(),
            "request_method" => self.request.method.to_string(),
            "scheme" => self.connection.scheme.clone(),
            // `$proxy_host`/`$proxy_port` come from `ngx_http_proxy_module` and default to
            // the request `Host`; they appear in the default `proxy_cache_key`.
            "proxy_host" => self.request.host.clone(),
            "proxy_port" => self.connection.local_port.to_string(),
            "https" => if self.connection.tls { "on" } else { "" }.to_string(),
            "server_name" => self.server_name.clone(),
            "server_addr" => self
                .connection
                .local_ip
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            "server_port" => self.connection.local_port.to_string(),
            "hostname" => hostname(),
            "remote_addr" => self
                .client
                .addr
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            "remote_port" => self.client.port.to_string(),
            // Nginx exposes the packed address bytes; a Latin-1 string keeps the same
            // cardinality and uniqueness for `limit_*_zone` keys.
            "binary_remote_addr" => match self.client.addr {
                Some(IpAddr::V4(address)) => address
                    .octets()
                    .iter()
                    .map(|byte| char::from(*byte))
                    .collect(),
                Some(IpAddr::V6(address)) => address
                    .octets()
                    .iter()
                    .map(|byte| char::from(*byte))
                    .collect(),
                None => String::new(),
            },
            "realip_remote_addr" => self
                .client
                .original_addr
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            "realip_remote_port" => self.client.original_port.to_string(),
            "request" => format!(
                "{} {} {}",
                self.request.method,
                self.request.uri,
                version_str(self.request.version)
            ),
            "request_time" => format!("{:.3}", self.started.elapsed().as_secs_f64()),
            "msec" => format!(
                "{:.3}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs_f64()
            ),
            "body_bytes_sent" => self.body_bytes_sent.to_string(),
            "status" => self
                .status
                .map_or(String::new(), |status| status.as_u16().to_string()),
            "upstream_addr" => self.upstream_addr.clone(),
            "limit_req_status" => self
                .limit_req_status()
                .map(|status| status.as_str())
                .unwrap_or_default()
                .to_string(),
            "limit_conn_status" => self
                .get::<crate::modules::limit_conn::LimitConnStatusSlot>()
                .map(|slot| slot.0.as_str())
                .unwrap_or_default()
                .to_string(),
            "server_protocol" => version_str(self.request.version).to_string(),
            name if name.starts_with("http_") => {
                let header = name[5..].replace('_', "-");
                self.headers
                    .get(header)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string()
            }
            _ => return None,
        };
        Some(value)
    }

    /// Resolve a variable through built-ins and module providers. Unset variables
    /// resolve to `None`, which templates render as an empty string.
    pub fn variable(&self, name: &str) -> Option<String> {
        if let Some(value) = self.builtin_variable(name) {
            return Some(value);
        }
        self.providers
            .iter()
            .find(|(registered, _)| *registered == name)
            .and_then(|(_, provider)| provider.get(self))
    }

    pub fn eval(&self, template: &Template) -> String {
        template.eval_with(&mut |name| self.variable(name))
    }

    /// `$limit_req_status` for this request (`PASSED`, `DELAYED`, `REJECTED`, ...).
    pub fn limit_req_status(&self) -> Option<crate::modules::limit_req::LimitStatus> {
        self.get::<crate::modules::limit_req::LimitReqOutcome>()
            .map(|outcome| outcome.status)
    }

    /// Record the `limit_req` outcome, like `r->main->limit_req_status`.
    pub fn set_limit_req_status(&mut self, status: crate::modules::limit_req::LimitStatus) {
        self.insert(crate::modules::limit_req::LimitReqOutcome { status, zone: "" });
    }

    /// Whether a `limit_req` handler already ran for this request.
    pub fn limit_req_evaluated(&self) -> bool {
        self.get::<crate::modules::limit_req::LimitReqOutcome>()
            .is_some()
    }

    /// A snapshot usable by header filters that cannot borrow the live state.
    pub fn clone_for_headers(&self) -> RequestStateView {
        RequestStateView {
            request: self.request.clone(),
            client: self.client.clone(),
            connection: self.connection.clone(),
            headers: self.headers.clone(),
            server_name: self.server_name.clone(),
            status: self.status,
            started: self.started,
            upstream_addr: self.upstream_addr.clone(),
            body_bytes_sent: self.body_bytes_sent,
            limit_req_status: self.limit_req_status().map(|status| status.as_str()),
            cache_status: self
                .get::<crate::modules::proxy_cache::CacheState>()
                .and_then(|cache| cache.status)
                .map(|status| status.as_str()),
        }
    }
}

/// Owned snapshot of request facts for code paths without access to the live session.
#[derive(Clone)]
pub struct RequestStateView {
    pub request: RequestLine,
    pub client: ClientState,
    pub connection: ConnectionState,
    pub headers: HeaderMap,
    pub server_name: String,
    pub status: Option<StatusCode>,
    pub started: Instant,
    pub upstream_addr: String,
    pub body_bytes_sent: usize,
    pub limit_req_status: Option<&'static str>,
    /// `$upstream_cache_status` captured from the proxy exchange.
    pub cache_status: Option<&'static str>,
}

impl RequestStateView {
    /// Resolve a built-in variable against this snapshot.
    pub fn builtin_variable(&self, name: &str) -> Option<String> {
        let value = match name {
            "uri" | "document_uri" => self.request.path.clone(),
            "request_uri" => self.request.uri.clone(),
            "args" | "query_string" => self.request.args.clone(),
            "is_args" => if self.request.args.is_empty() {
                ""
            } else {
                "?"
            }
            .to_string(),
            "host" => self.request.host.clone(),
            "request_method" => self.request.method.to_string(),
            "scheme" => self.connection.scheme.clone(),
            "https" => if self.connection.tls { "on" } else { "" }.to_string(),
            "server_name" => self.server_name.clone(),
            "server_port" => self.connection.local_port.to_string(),
            "remote_addr" => self
                .client
                .addr
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            "remote_port" => self.client.port.to_string(),
            // Nginx exposes the packed address bytes; a Latin-1 string keeps the same
            // cardinality and uniqueness for `limit_*_zone` keys.
            "binary_remote_addr" => match self.client.addr {
                Some(IpAddr::V4(address)) => address
                    .octets()
                    .iter()
                    .map(|byte| char::from(*byte))
                    .collect(),
                Some(IpAddr::V6(address)) => address
                    .octets()
                    .iter()
                    .map(|byte| char::from(*byte))
                    .collect(),
                None => String::new(),
            },
            "realip_remote_addr" => self
                .client
                .original_addr
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            "realip_remote_port" => self.client.original_port.to_string(),
            "upstream_addr" => self.upstream_addr.clone(),
            "body_bytes_sent" => self.body_bytes_sent.to_string(),
            "limit_req_status" => self.limit_req_status.unwrap_or_default().to_string(),
            "request_time" => format!("{:.3}", self.started.elapsed().as_secs_f64()),
            name if name.starts_with("http_") => {
                let header = name[5..].replace('_', "-");
                self.headers
                    .get(header)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string()
            }
            _ => return None,
        };
        Some(value)
    }

    /// Resolve a variable. Module providers are not consulted for snapshots; the
    /// `realip_*` variables are built in and therefore always available.
    pub fn variable(&self, name: &str) -> Option<String> {
        match name {
            // `$upstream_cache_status` is kept in the snapshot because the cache decision
            // happens after the header filter needs the value.
            "upstream_cache_status" => Some(self.cache_status.unwrap_or_default().to_string()),
            _ => self.builtin_variable(name),
        }
    }

    /// Rebuild a full request state (used when a filter needs module variables).
    pub fn into_state(
        self,
        providers: &'static [(
            &'static str,
            &'static dyn crate::core::variables::VariableProvider,
        )],
    ) -> RequestState {
        let mut state = RequestState {
            connection: self.connection,
            client: self.client,
            request: self.request,
            headers: self.headers,
            server_name: self.server_name,
            status: self.status,
            started: self.started,
            body_bytes_sent: self.body_bytes_sent,
            upstream_addr: self.upstream_addr,
            providers,
            slots: HashMap::new(),
        };
        if let Some(cache_status) = self.cache_status {
            let status = match cache_status {
                "HIT" => crate::modules::proxy_cache::CacheStatus::Hit,
                "MISS" => crate::modules::proxy_cache::CacheStatus::Miss,
                "BYPASS" => crate::modules::proxy_cache::CacheStatus::Bypass,
                "EXPIRED" => crate::modules::proxy_cache::CacheStatus::Expired,
                "STALE" => crate::modules::proxy_cache::CacheStatus::Stale,
                "UPDATING" => crate::modules::proxy_cache::CacheStatus::Updating,
                "REVALIDATED" => crate::modules::proxy_cache::CacheStatus::Revalidated,
                _ => crate::modules::proxy_cache::CacheStatus::Scarce,
            };
            state.insert(crate::modules::proxy_cache::CacheState {
                status: Some(status),
                ..Default::default()
            });
        }
        state
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_default()
}

fn version_str(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> RequestState {
        let request = pingora_http::RequestHeader::build("GET", b"/index.html?x=1", None).unwrap();
        let connection = ConnectionState {
            listen: "127.0.0.1:8080".into(),
            peer_ip: Some("203.0.113.9".parse().unwrap()),
            peer_port: 55123,
            local_ip: Some("127.0.0.1".parse().unwrap()),
            local_port: 8080,
            scheme: "http".into(),
            tls: false,
        };
        RequestState::new(
            connection,
            RequestLine::from_header(&request),
            request.headers.clone(),
            &[],
        )
    }

    #[test]
    fn builtin_variables() {
        let state = state();
        assert_eq!(state.builtin_variable("uri").unwrap(), "/index.html");
        assert_eq!(state.builtin_variable("args").unwrap(), "x=1");
        assert_eq!(
            state.builtin_variable("request_uri").unwrap(),
            "/index.html?x=1"
        );
        assert_eq!(
            state.builtin_variable("remote_addr").unwrap(),
            "203.0.113.9"
        );
        assert_eq!(state.builtin_variable("remote_port").unwrap(), "55123");
        assert_eq!(state.builtin_variable("is_args").unwrap(), "?");
        assert_eq!(state.builtin_variable("unknown_thing"), None);
    }

    #[test]
    fn slots_are_typed() {
        #[derive(Debug, PartialEq)]
        struct Marker(&'static str);
        let mut state = state();
        state.insert(Marker("realip"));
        assert_eq!(state.get::<Marker>(), Some(&Marker("realip")));
        assert_eq!(state.take::<Marker>(), Some(Marker("realip")));
        assert_eq!(state.get::<Marker>(), None);
    }
}

#[cfg(test)]
mod binary_addr_tests {
    use super::*;
    use crate::core::variables::Template;

    #[test]
    fn binary_remote_addr_is_non_empty_and_sized() {
        let request = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut state = RequestState::new(
            ConnectionState {
                listen: "127.0.0.1:80".into(),
                peer_ip: Some("203.0.113.9".parse().unwrap()),
                peer_port: 1000,
                local_ip: None,
                local_port: 80,
                scheme: "http".into(),
                tls: false,
            },
            RequestLine::from_header(&request),
            request.headers.clone(),
            &[],
        );
        let binary = state.variable("binary_remote_addr").unwrap();
        assert_eq!(binary.chars().count(), 4);
        let template = Template::parse("$binary_remote_addr").unwrap();
        assert_eq!(state.eval(&template), binary);
        state.client.addr = Some("10.0.0.1".parse().unwrap());
        assert_ne!(state.eval(&template), binary);
    }
}
