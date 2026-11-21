//! `ngx_http_auth_basic_module`: HTTP Basic authentication against an htpasswd file.
//!
//! Mirrors `c/nginx/src/http/modules/ngx_http_auth_basic_module.c`:
//!
//! * `auth_basic` is a complex value: the realm, or `off`, evaluated per request.
//! * `auth_basic_user_file` names the credential file, also a complex value.
//! * The handler runs in `NGX_HTTP_ACCESS_PHASE`; a missing or wrong `Authorization` header
//!   answers `401`/`407` with `WWW-Authenticate: Basic realm="…"`, an unreadable file answers
//!   `403` (missing) or `500` (other I/O errors), matching `ngx_http_auth_basic_handler`.
//! * Passwords are compared by re-encrypting the client password with the stored hash
//!   ([`crate::core::crypt`]) and comparing the strings.

use crate::core::crypt::{self, VerifyOutcome};
use crate::core::http::RequestState;
use crate::core::variables::Template;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::location::LocationConf;
use anyhow::Result;
use std::path::PathBuf;

pub const MODULE_NAME: &str = "ngx_http_auth_basic_module";

/// `ngx_http_auth_basic_loc_conf_t`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthBasicConf {
    /// `auth_basic`: the realm template, or `off`.
    pub realm: Option<Template>,
    /// `auth_basic_user_file`: the htpasswd path, or a template resolving to one.
    pub user_file: Option<Template>,
    /// The path as written, for diagnostics.
    pub user_file_source: Option<String>,
}

impl LocationConf for AuthBasicConf {}

impl AuthBasicConf {
    /// Whether authentication applies to a request (`realm == NULL` → `NGX_DECLINED`).
    pub fn enabled(&self) -> bool {
        self.realm.is_some() && self.user_file.is_some()
    }

    /// `ngx_http_auth_basic_handler`'s first decisions: the evaluated realm, or `None`.
    pub fn realm(&self, state: &RequestState) -> Option<String> {
        let realm = self.realm.as_ref()?.eval(state);
        // `realm.len == 3 && realm == "off"` declines authentication.
        if realm == "off" { None } else { Some(realm) }
    }
}

pub struct AuthBasicModule;

impl Module for AuthBasicModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![
            DirectiveSpec {
                name: "auth_basic",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_realm,
            },
            DirectiveSpec {
                name: "auth_basic_user_file",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_user_file,
            },
        ]
    }
}

fn parse_realm(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let realm = Template::parse(&directive.args[0])
        .map_err(|error| directive.error(format!("invalid auth_basic realm: {error}")))?;
    view.update_conf::<AuthBasicConf>(|conf| conf.realm = Some(realm))
}

fn parse_user_file(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    if view.location_conf::<AuthBasicConf>().is_some_and(|conf| conf.user_file.is_some()) {
        return Err(directive.error("auth_basic_user_file is duplicate"));
    }
    // A literal relative path resolves against the configuration directory
    // (`ccv.conf_prefix = 1`); a path with variables is resolved per request.
    let source = directive.args[0].clone();
    let resolved = if source.contains('$') {
        source.clone()
    } else {
        view.path(&source).to_string_lossy().replace('\\', "/")
    };
    let template = Template::parse(&resolved)
        .map_err(|error| directive.error(format!("invalid auth_basic_user_file: {error}")))?;
    view.update_conf::<AuthBasicConf>(|conf| {
        conf.user_file = Some(template);
        conf.user_file_source = Some(source)
    })
}

/// Why a request could not be authenticated; the caller turns this into a response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthFailure {
    /// No usable `Authorization: Basic` credentials (`NGX_DECLINED` from the parser).
    Missing,
    /// The user is not in the file, or the password does not match.
    Denied,
    /// `ngx_open_file` failed with `ENOENT` → `403`.
    FileMissing(PathBuf),
    /// Any other file error → `500`.
    FileError(String),
    /// The digest format is not supported by this build (libc `crypt(3)`).
    UnsupportedFormat(String),
}

impl AuthFailure {
    /// The status nginx answers with (`ngx_http_auth_basic_handler`).
    pub fn status(&self) -> u16 {
        match self {
            AuthFailure::Missing | AuthFailure::Denied => 401,
            AuthFailure::FileMissing(_) => 403,
            AuthFailure::FileError(_) => 500,
            AuthFailure::UnsupportedFormat(_) => 500,
        }
    }
}

/// Result of running the access-phase handler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Authentication does not apply (`realm off`, or no directives).
    Skip,
    /// The request is authenticated.
    Allowed,
    /// Answer with this failure.
    Rejected(AuthFailure),
}

/// `ngx_http_auth_basic_handler`: check the request against the htpasswd file.
pub async fn handle(conf: &AuthBasicConf, state: &RequestState) -> AuthOutcome {
    if !conf.enabled() {
        return AuthOutcome::Skip;
    }
    // `realm off` disables authentication for this request; the realm itself is only
    // echoed in the challenge the caller builds.
    if conf.realm(state).is_none() {
        return AuthOutcome::Skip;
    }
    let realm = conf.realm(state).unwrap_or_default();
    let _ = &realm;
    // `ngx_http_auth_basic_user` declines when the header is absent or malformed.
    let Some((user, password)) = credentials(state) else {
        log::info!("no user/password was provided for basic authentication");
        return AuthOutcome::Rejected(AuthFailure::Missing);
    };
    let path = conf
        .user_file
        .as_ref()
        .map(|template| template.eval(state))
        .unwrap_or_default();
    let contents = match tokio::fs::read(&path).await {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            log::error!("open() \"{path}\" failed (2: No such file or directory)");
            return AuthOutcome::Rejected(AuthFailure::FileMissing(PathBuf::from(path)));
        }
        Err(error) => {
            log::error!("open() \"{path}\" failed: {error}");
            return AuthOutcome::Rejected(AuthFailure::FileError(error.to_string()));
        }
    };
    let Some(stored) = lookup(&contents, &user) else {
        log::error!("user \"{user}\" was not found in \"{path}\"");
        return AuthOutcome::Rejected(AuthFailure::Denied);
    };
    match crypt::verify(password.as_bytes(), stored.as_bytes()) {
        VerifyOutcome::Match => AuthOutcome::Allowed,
        VerifyOutcome::Mismatch => {
            log::error!("user \"{user}\": password mismatch");
            AuthOutcome::Rejected(AuthFailure::Denied)
        }
        VerifyOutcome::Invalid => {
            log::error!("user \"{user}\": malformed password entry in \"{path}\"");
            AuthOutcome::Rejected(AuthFailure::Denied)
        }
        VerifyOutcome::Unsupported => {
            log::error!(
                "user \"{user}\": the password format in \"{path}\" is not supported by this build"
            );
            AuthOutcome::Rejected(AuthFailure::UnsupportedFormat(path))
        }
    }
}

/// `WWW-Authenticate` value for a realm (`ngx_http_auth_basic_set_realm`).
pub fn challenge(realm: &str) -> String {
    format!("Basic realm=\"{realm}\"")
}

/// Parse `Authorization: Basic base64(user:pass)` like `ngx_http_auth_basic_user`.
///
/// An empty user (`:pass`), a missing colon or invalid base64 all count as "no credentials".
pub fn credentials(state: &RequestState) -> Option<(String, String)> {
    use base64::Engine as _;
    let header = state.headers.get(http::header::AUTHORIZATION)?;
    let raw = header.to_str().ok()?;
    let (scheme, encoded) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let encoded = encoded.trim_start_matches(' ');
    if encoded.is_empty() {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let separator = decoded.iter().position(|byte| *byte == b':')?;
    if separator == 0 || separator == decoded.len() {
        // `len == 0 || len == auth.len` → NGX_DECLINED (no password or no user).
        if separator == 0 {
            return None;
        }
    }
    let user = String::from_utf8_lossy(&decoded[..separator]).into_owned();
    let password = String::from_utf8_lossy(&decoded[separator + 1..]).into_owned();
    Some((user, password))
}

/// Find `user`'s hash in an htpasswd file (`ngx_http_auth_basic_handler`'s scan loop).
///
/// A line is `user:hash`, `user:hash:comment`, or starts with `#`/CR for comments; the first
/// match wins, exactly like the streaming scan of the C handler.
pub fn lookup(contents: &[u8], user: &str) -> Option<String> {
    for line in contents.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() || line[0] == b'#' || line[0] == b'\r' {
            continue;
        }
        let mut parts = line.splitn(3, |byte| *byte == b':');
        let name = parts.next().unwrap_or_default();
        if name != user.as_bytes() {
            continue;
        }
        // `sw_passwd` ends at LF, CR or `:`.
        let hash = parts.next().unwrap_or_default();
        return Some(String::from_utf8_lossy(hash).into_owned());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::http::{ConnectionState, RequestLine, RequestState};
    use base64::Engine as _;
    use http::HeaderMap;

    fn state(authorization: Option<&str>) -> RequestState {
        let request = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut headers = HeaderMap::new();
        if let Some(value) = authorization {
            headers.insert(http::header::AUTHORIZATION, value.parse().unwrap());
        }
        RequestState::new(
            ConnectionState {
                listen: "127.0.0.1:80".into(),
                peer_ip: Some("203.0.113.9".parse().unwrap()),
                peer_port: 1000,
                local_ip: Some("127.0.0.1".parse().unwrap()),
                local_port: 80,
                scheme: "http".into(),
                tls: false,
            },
            RequestLine::from_header(&request),
            headers,
            &[],
        )
    }

    fn basic(user: &str, password: &str) -> String {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        format!("Basic {encoded}")
    }

    #[test]
    fn credentials_follow_nginx_rules() {
        let value = basic("alice", "secret");
        assert_eq!(
            credentials(&state(Some(&value))),
            Some(("alice".to_string(), "secret".to_string()))
        );
        // Case-insensitive scheme, extra spaces after it.
        let spaced = format!("bAsIc   {}", value.split_once(' ').unwrap().1);
        assert!(credentials(&state(Some(&spaced))).is_some());
        // A missing header, a non-Basic scheme, an empty user and invalid base64 all decline.
        assert_eq!(credentials(&state(None)), None);
        assert_eq!(credentials(&state(Some("Bearer abc"))), None);
        assert_eq!(credentials(&state(Some(&basic("", "x")))), None);
        assert_eq!(credentials(&state(Some("Basic !!!"))), None);
    }

    #[test]
    fn lookup_scans_the_file_like_the_c_loop() {
        let file = b"# comment\r\nalice:$apr1$aaa$bbb\r\nbob:{PLAIN}pw:comment\r\n";
        assert_eq!(lookup(file, "alice").as_deref(), Some("$apr1$aaa$bbb"));
        // The third field after `:` is a comment and never part of the hash.
        assert_eq!(lookup(file, "bob").as_deref(), Some("{PLAIN}pw"));
        assert_eq!(lookup(file, "carol"), None);
        // A user whose name is a prefix of another entry does not match.
        assert_eq!(lookup(file, "ali"), None);
    }

    #[test]
    fn realm_off_disables_authentication() {
        let conf = AuthBasicConf {
            realm: Some(Template::parse("off").unwrap()),
            user_file: Some(Template::parse("/x").unwrap()),
            user_file_source: None,
        };
        assert_eq!(conf.realm(&state(None)), None);
        let conf = AuthBasicConf {
            realm: Some(Template::parse("Admin Area").unwrap()),
            user_file: Some(Template::parse("/x").unwrap()),
            user_file_source: None,
        };
        assert_eq!(conf.realm(&state(None)).as_deref(), Some("Admin Area"));
        assert_eq!(challenge("Admin Area"), "Basic realm=\"Admin Area\"");
    }

    #[test]
    fn failure_statuses_match_nginx() {
        assert_eq!(AuthFailure::Missing.status(), 401);
        assert_eq!(AuthFailure::Denied.status(), 401);
        assert_eq!(AuthFailure::FileMissing(PathBuf::from("/x")).status(), 403);
        assert_eq!(AuthFailure::FileError("io".into()).status(), 500);
    }

    #[tokio::test]
    async fn handler_allows_matching_and_rejects_other_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("htpasswd");
        // `openssl passwd -apr1 -plaintext secret`-style entry; the salt is fixed so the test
        // checks the comparison path, not the algorithm (covered by `core::crypt`).
        let hash = crate::core::crypt::encrypt_for_test(b"secret", b"testsalt");
        std::fs::write(&file, format!("alice:{hash}\n")).unwrap();
        let conf = AuthBasicConf {
            realm: Some(Template::parse("main").unwrap()),
            user_file: Some(Template::parse(&file.to_string_lossy()).unwrap()),
            user_file_source: None,
        };
        assert_eq!(
            handle(&conf, &state(Some(&basic("alice", "secret")))).await,
            AuthOutcome::Allowed
        );
        assert_eq!(
            handle(&conf, &state(Some(&basic("alice", "wrong")))).await,
            AuthOutcome::Rejected(AuthFailure::Denied)
        );
        assert_eq!(
            handle(&conf, &state(Some(&basic("bob", "secret")))).await,
            AuthOutcome::Rejected(AuthFailure::Denied)
        );
        assert_eq!(
            handle(&conf, &state(None)).await,
            AuthOutcome::Rejected(AuthFailure::Missing)
        );
        let missing = AuthBasicConf {
            user_file: Some(Template::parse(&dir.path().join("nope").to_string_lossy()).unwrap()),
            ..conf
        };
        assert!(matches!(
            handle(&missing, &state(Some(&basic("alice", "secret")))).await,
            AuthOutcome::Rejected(AuthFailure::FileMissing(_))
        ));
    }
}
