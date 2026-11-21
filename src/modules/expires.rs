//! `expires` (`ngx_http_headers_filter_module`): `Expires` and `Cache-Control` headers.
//!
//! Mirrors `ngx_http_set_expires` and `ngx_http_parse_expires` in
//! `c/nginx/src/http/modules/ngx_http_headers_filter_module.c`:
//!
//! * `expires 30d` is relative to the response time (`NGX_HTTP_EXPIRES_ACCESS`).
//! * `expires modified 30d` is relative to `Last-Modified` (`NGX_HTTP_EXPIRES_MODIFIED`).
//! * `@15h30m` is the next occurrence of a time of day (`NGX_HTTP_EXPIRES_DAILY`).
//! * `epoch`/`max`/`off` set the fixed forms.
//! * A negative value or a past date yields `Cache-Control: no-cache`.
//!
//! The filter only runs for the response statuses nginx considers "safe" (`2xx`, `3xx`,
//! `304`, `206`), exactly like `ngx_http_headers_filter`.

use crate::core::value::parse_time;
use crate::core::variables::Template;
use anyhow::Result;
use http::StatusCode;
use pingora_http::ResponseHeader;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `ngx_http_expires_t`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expires {
    /// `off` (default when unset): no header is generated.
    Off,
    /// `epoch`: `Thu, 01 Jan 1970 00:00:01 GMT` + `no-cache`.
    Epoch,
    /// `max`: `Thu, 31 Dec 2037 23:55:55 GMT` + `max-age=315360000`.
    Max,
    /// `expires <time>`: relative to the response time.
    Access(i64),
    /// `expires modified <time>`: relative to `Last-Modified`.
    Modified(i64),
    /// `expires @<time>`: the next time of day, in seconds.
    Daily(u32),
    /// A complex value evaluated per request.
    Value {
        base: Box<Expires>,
        template: Template,
    },
}

impl Expires {
    pub fn is_off(&self) -> bool {
        matches!(self, Expires::Off)
    }
}

/// `ngx_http_parse_expires`: parse the literal value (without variables).
///
/// `modified` is true for `expires modified …`; `daily` values are rejected there.
pub fn parse(value: &str, modified: bool, error: &mut Option<String>) -> Option<Expires> {
    if !modified {
        if value == "epoch" {
            return Some(Expires::Epoch);
        }
        if value == "max" {
            return Some(Expires::Max);
        }
        if value == "off" {
            return Some(Expires::Off);
        }
    }
    let mut rest = value;
    let daily = rest.starts_with('@');
    let mut minus = false;
    if let Some(stripped) = rest.strip_prefix('@') {
        rest = stripped;
        if rest.is_empty() {
            *error = Some("invalid value".to_string());
            return None;
        }
    } else if let Some(stripped) = rest.strip_prefix('-') {
        rest = stripped;
        minus = true;
    } else if let Some(stripped) = rest.strip_prefix('+') {
        rest = stripped;
    }
    // `ngx_parse_time` with `sec = 1`: a bare number means seconds.
    let Ok(duration) = parse_plain_time(rest) else {
        *error = Some("invalid value".to_string());
        return None;
    };
    let seconds = duration.as_secs() as i64;
    if daily {
        if modified {
            *error = Some("daily time cannot be used with \"modified\" parameter".to_string());
            return None;
        }
        if seconds as u64 > 24 * 60 * 60 {
            *error = Some("daily time value must be less than 24 hours".to_string());
            return None;
        }
        return Some(Expires::Daily(seconds as u32));
    }
    let seconds = if minus { -seconds } else { seconds };
    Some(if modified {
        Expires::Modified(seconds)
    } else {
        Expires::Access(seconds)
    })
}

/// `ngx_parse_time(&value, 1)` without a `Directive` to attribute an error to.
fn parse_plain_time(value: &str) -> Result<Duration> {
    if value.is_empty() {
        anyhow::bail!("empty time");
    }
    // Reuse the shared parser through a synthetic node.
    let node = crate::core::syntax::Directive {
        name: "expires".to_string(),
        args: vec![value.to_string()],
        children: None,
        file: std::path::PathBuf::from("<expires>"),
        line: 0,
    };
    parse_time(&node, value)
}

/// Apply the headers of `expires` to a response (`ngx_http_set_expires`).
///
/// `now` is the response time; `last_modified` is the response's `Last-Modified`, used by the
/// `modified` form. Returns `Ok(())` when the header was written or skipped.
pub fn apply(
    expires: &Expires,
    response: &mut ResponseHeader,
    now: SystemTime,
    last_modified: Option<SystemTime>,
) -> Result<()> {
    if !is_safe_status(response.status) {
        return Ok(());
    }
    let effective = match expires {
        Expires::Value { base, template } => {
            // `expires_value`: a broken value silently disables the filter
            // (`ngx_http_set_expires` returns NGX_OK on a parse error).
            let evaluated = template.eval_once().unwrap_or_default();
            let mut error = None;
            match parse(&evaluated, matches!(**base, Expires::Modified(_)), &mut error) {
                Some(parsed) => parsed,
                None => return Ok(()),
            }
        }
        other => other.clone(),
    };
    let (expires_value, cache_control) = match effective {
        Expires::Off => return Ok(()),
        Expires::Epoch => (
            "Thu, 01 Jan 1970 00:00:01 GMT".to_string(),
            "no-cache".to_string(),
        ),
        Expires::Max => (
            "Thu, 31 Dec 2037 23:55:55 GMT".to_string(),
            "max-age=315360000".to_string(),
        ),
        Expires::Daily(time) => {
            let base = next_daily(now, time);
            (fmt(base), format!("max-age={}", max_age(base, now)))
        }
        Expires::Access(seconds) => {
            let at = now + duration(seconds);
            let max_age = seconds;
            (fmt(at), cache_control_value(max_age))
        }
        Expires::Modified(seconds) => {
            let Some(modified) = last_modified else {
                // `last_modified_time == -1`: treated like the access form.
                let at = now + duration(seconds);
                return set_headers(response, &fmt(at), &cache_control_value(seconds));
            };
            let at = modified + duration(seconds);
            let max_age = max_age(at, now);
            let control = if seconds < 0 || max_age < 0 {
                "no-cache".to_string()
            } else {
                format!("max-age={max_age}")
            };
            (fmt(at), control)
        }
        Expires::Value { .. } => unreachable!("complex values were resolved above"),
    };
    set_headers(response, &expires_value, &cache_control)
}

fn set_headers(response: &mut ResponseHeader, expires: &str, cache_control: &str) -> Result<()> {
    // `expires` and `ngx_http_set_expires` reuse an existing header, dropping duplicates.
    response.remove_header("expires");
    response.insert_header("Expires", expires.to_string())?;
    response.remove_header("cache-control");
    response.insert_header("Cache-Control", cache_control.to_string())?;
    Ok(())
}

/// `max-age=0` for a non-positive value, `no-cache` for a negative one.
fn cache_control_value(seconds: i64) -> String {
    if seconds < 0 {
        "no-cache".to_string()
    } else {
        format!("max-age={seconds}")
    }
}

/// The next occurrence of `time` (seconds since midnight) after `now`.
fn next_daily(now: SystemTime, time: u32) -> SystemTime {
    let seconds = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let day = seconds - seconds % 86_400;
    let mut target = day + u64::from(time);
    if target <= seconds {
        target += 86_400;
    }
    UNIX_EPOCH + Duration::from_secs(target)
}

fn max_age(at: SystemTime, now: SystemTime) -> i64 {
    match at.duration_since(now) {
        Ok(ahead) => ahead.as_secs() as i64,
        Err(behind) => -(behind.duration().as_secs() as i64),
    }
}

fn duration(seconds: i64) -> Duration {
    if seconds >= 0 {
        Duration::from_secs(seconds as u64)
    } else {
        Duration::ZERO
    }
}

fn fmt(time: SystemTime) -> String {
    httpdate::fmt_http_date(time)
}

/// `ngx_http_headers_filter` only adds headers for these statuses.
pub fn is_safe_status(status: StatusCode) -> bool {
    matches!(
        status.as_u16(),
        200 | 201 | 204 | 206 | 301 | 302 | 303 | 304 | 307 | 308
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(value: &str, modified: bool) -> Expires {
        let mut error = None;
        let parsed = parse(value, modified, &mut error);
        assert!(error.is_none(), "{value}: {error:?}");
        parsed.unwrap()
    }

    #[test]
    fn literal_forms() {
        assert_eq!(parse_ok("off", false), Expires::Off);
        assert_eq!(parse_ok("epoch", false), Expires::Epoch);
        assert_eq!(parse_ok("max", false), Expires::Max);
        assert_eq!(parse_ok("30d", false), Expires::Access(30 * 86_400));
        assert_eq!(parse_ok("-1h", false), Expires::Access(-3600));
        // The `modified` keyword is consumed by the directive handler, so `parse` sees only
        // the time value; `ngx_http_parse_expires` receives `value[n]`.
        assert_eq!(parse_ok("1h", true), Expires::Modified(3600));
        assert_eq!(parse_ok("@15h30m", false), Expires::Daily(15 * 3600 + 1800));
    }

    #[test]
    fn invalid_values_are_reported() {
        let mut error = None;
        assert_eq!(parse("1x", false, &mut error), None);
        assert_eq!(error.as_deref(), Some("invalid value"));
        let mut error = None;
        assert_eq!(parse("@25h", false, &mut error), None);
        assert_eq!(
            error.as_deref(),
            Some("daily time value must be less than 24 hours")
        );
        let mut error = None;
        assert_eq!(parse("@1h", true, &mut error), None);
        assert_eq!(
            error.as_deref(),
            Some("daily time cannot be used with \"modified\" parameter")
        );
    }

    fn response(status: u16) -> ResponseHeader {
        ResponseHeader::build(StatusCode::from_u16(status).unwrap(), None).unwrap()
    }

    #[test]
    fn access_form_sets_both_headers() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mut header = response(200);
        apply(&Expires::Access(3600), &mut header, now, None).unwrap();
        assert_eq!(
            header.headers.get("expires").unwrap(),
            "Tue, 14 Nov 2023 23:13:20 GMT"
        );
        assert_eq!(header.headers.get("cache-control").unwrap(), "max-age=3600");
    }

    #[test]
    fn negative_value_means_no_cache() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mut header = response(200);
        apply(&Expires::Access(-60), &mut header, now, None).unwrap();
        assert_eq!(header.headers.get("cache-control").unwrap(), "no-cache");
    }

    #[test]
    fn modified_form_uses_last_modified() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let modified = now - Duration::from_secs(1000);
        let mut header = response(200);
        apply(&Expires::Modified(3600), &mut header, now, Some(modified)).unwrap();
        assert_eq!(header.headers.get("cache-control").unwrap(), "max-age=2600");
    }

    #[test]
    fn fixed_forms_and_status_gate() {
        let now = UNIX_EPOCH;
        let mut header = response(304);
        apply(&Expires::Epoch, &mut header, now, None).unwrap();
        assert_eq!(
            header.headers.get("expires").unwrap(),
            "Thu, 01 Jan 1970 00:00:01 GMT"
        );
        assert_eq!(header.headers.get("cache-control").unwrap(), "no-cache");
        // Error responses keep their headers untouched.
        let mut header = response(502);
        apply(&Expires::Max, &mut header, now, None).unwrap();
        assert!(header.headers.get("expires").is_none());
    }
}
