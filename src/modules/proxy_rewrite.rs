//! Response rewriting for `ngx_http_proxy_module`: `proxy_redirect`, `proxy_cookie_domain`,
//! `proxy_cookie_path` and `proxy_cookie_flags`.
//!
//! The behaviour mirrors `ngx_http_proxy_rewrite_redirect`,
//! `ngx_http_proxy_rewrite_cookie`, `ngx_http_proxy_edit_cookie_flags` and
//! `ngx_http_proxy_rewrite_complex_handler` in `c/nginx/src/http/modules/ngx_http_proxy_module.c`.

use crate::core::variables::Template;
use anyhow::{Result, bail};
use regex::Regex;

/// A `proxy_redirect`/`proxy_cookie_*` replacement pair (`ngx_http_proxy_rewrite_t`).
#[derive(Clone, Debug)]
pub struct Rewrite {
    pub pattern: Pattern,
    pub replacement: Replacement,
}

/// How the *left* side matches (`ngx_http_proxy_rewrite_regex` vs a prefix test).
#[derive(Clone, Debug)]
pub enum Pattern {
    /// A literal prefix (also the default pattern derived from `proxy_pass`).
    Literal(String),
    /// `~` prefixed PCRE, matched case-insensitively when `~*` is used.
    Regex { regex: Regex, source: String },
}

/// How the matched text is replaced.
#[derive(Clone, Debug)]
pub enum Replacement {
    /// A plain string, or `default`/`off` markers handled by the caller.
    Text(Template),
    /// Capture-group substitution (`replacement` of a regex rewrite).
    RegexHold(Template),
}

impl Rewrite {
    /// Parse one `proxy_redirect|proxy_cookie_domain|proxy_cookie_path` argument pair.
    ///
    /// `kind` is `redirect`, `domain` or `path`; Nginx uses the same grammar for all three:
    /// the right side may be a plain string or a quoted value with variables.
    pub fn parse(left: &str, right: Option<&str>, case_sensitive: bool) -> Result<Self> {
        let pattern = if let Some(pattern) = left.strip_prefix('~') {
            let (case_insensitive, pattern) = match pattern.strip_prefix('*') {
                Some(rest) => (true, rest),
                None => (false, pattern),
            };
            let regex = regex::RegexBuilder::new(pattern)
                .case_insensitive(case_insensitive || !case_sensitive)
                .build()
                .map_err(|error| anyhow::anyhow!("invalid regular expression \"{left}\": {error}"))?;
            Pattern::Regex {
                regex,
                source: left.to_string(),
            }
        } else {
            Pattern::Literal(left.to_string())
        };
        let replacement = match (right, &pattern) {
            (None, Pattern::Literal(literal)) => Replacement::Text(
                Template::parse(literal).map_err(|error| anyhow::anyhow!("{error}"))?,
            ),
            (None, Pattern::Regex { source, .. }) => Replacement::RegexHold(
                Template::parse(source).map_err(|error| anyhow::anyhow!("{error}"))?,
            ),
            (Some(value), _) => Replacement::Text(
                Template::parse(value).map_err(|error| anyhow::anyhow!("{error}"))?,
            ),
        };
        Ok(Self {
            pattern,
            replacement,
        })
    }

    /// `ngx_http_proxy_rewrite_regex_handler` / `ngx_http_proxy_rewrite_complex_handler`.
    ///
    /// Returns the rewritten value when this rule matched, otherwise `None`.
    pub fn apply(&self, value: &str, evaluate: &mut dyn FnMut(&Template) -> String) -> Option<String> {
        match &self.pattern {
            Pattern::Literal(prefix) => {
                // `ngx_http_proxy_rewrite_complex_handler` copies everything after the
                // matched prefix, and the prefix keeps its trailing `/`, so the rewritten
                // value must not lose it either.
                let rest = value.strip_prefix(prefix.as_str())?;
                let Replacement::Text(template) = &self.replacement else {
                    return None;
                };
                let replacement = evaluate(template);
                let separator = if prefix.ends_with('/') && !replacement.ends_with('/') {
                    "/"
                } else {
                    ""
                };
                Some(format!("{replacement}{separator}{rest}"))
            }
            Pattern::Regex { regex, .. } => {
                let captures = regex.captures(value)?;
                let template = match &self.replacement {
                    Replacement::Text(template) | Replacement::RegexHold(template) => template,
                };
                Some(template.eval_with(&mut |name| {
                    name.parse::<usize>()
                        .ok()
                        .and_then(|index| {
                            captures
                                .get(index)
                                .map(|matched| matched.as_str().to_string())
                        })
                }))
            }
        }
    }
}

/// A cookie attribute after `ngx_http_proxy_parse_cookie`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CookiePart {
    /// `key=value` (the cookie name/value or an attribute with a value).
    Attribute { key: String, value: Option<String> },
    /// A bare flag such as `Secure` or `HttpOnly`.
    Flag(String),
    /// Literal separator kept verbatim (`; ` or `, `).
    Separator(String),
}

/// Split a `Set-Cookie` value into attributes, exactly like `ngx_http_proxy_parse_cookie`.
pub fn parse_cookie(value: &str) -> Vec<CookiePart> {
    let mut parts = Vec::new();
    let bytes: Vec<char> = value.chars().collect();
    let mut index = 0;
    let mut first = true;
    while index < bytes.len() {
        // Skip leading whitespace on each attribute.
        while index < bytes.len() && bytes[index].is_whitespace() {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        let start = index;
        while index < bytes.len() && bytes[index] != '=' && bytes[index] != ';' && bytes[index] != ',' {
            index += 1;
        }
        let key: String = bytes[start..index].iter().collect();
        if index < bytes.len() && bytes[index] == '=' {
            index += 1;
            let value_start = index;
            while index < bytes.len() && bytes[index] != ';' && bytes[index] != ',' {
                index += 1;
            }
            let raw: String = bytes[value_start..index].iter().collect();
            parts.push(CookiePart::Attribute {
                key,
                value: Some(raw.trim().to_string()),
            });
        } else if first {
            // A cookie without `=` is not a valid `Set-Cookie`: leave it untouched.
            return vec![CookiePart::Flag(value.to_string())];
        } else if !key.is_empty() {
            parts.push(CookiePart::Flag(key));
        }
        // Keep the separator so the original formatting survives a round trip.
        if index < bytes.len() {
            let separator_start = index;
            while index < bytes.len() && (bytes[index] == ';' || bytes[index] == ',' || bytes[index] == ' ') {
                index += 1;
            }
            let separator: String = bytes[separator_start..index].iter().collect();
            if !separator.is_empty() {
                parts.push(CookiePart::Separator(separator));
            }
        }
        first = false;
    }
    parts
}

/// Render parsed cookie parts back into a `Set-Cookie` value.
pub fn render_cookie(parts: &[CookiePart]) -> String {
    let mut output = String::new();
    for part in parts {
        match part {
            CookiePart::Attribute { key, value } => {
                output.push_str(key);
                if let Some(value) = value {
                    output.push('=');
                    output.push_str(value);
                }
            }
            CookiePart::Flag(flag) => output.push_str(flag),
            CookiePart::Separator(separator) => output.push_str(separator),
        }
    }
    output
}

/// `proxy_cookie_flags` value (`ngx_http_proxy_cookie_flags_masks`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CookieFlag {
    SecureOn,
    SecureOff,
    HttpOnlyOn,
    HttpOnlyOff,
    SameSiteStrict,
    SameSiteLax,
    SameSiteNone,
    SameSiteOff,
}

impl CookieFlag {
    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value.to_ascii_lowercase().as_str() {
            "secure" => Self::SecureOn,
            "nosecure" => Self::SecureOff,
            "httponly" => Self::HttpOnlyOn,
            "nohttponly" => Self::HttpOnlyOff,
            "samesite=strict" => Self::SameSiteStrict,
            "samesite=lax" => Self::SameSiteLax,
            "samesite=none" => Self::SameSiteNone,
            "samesite=off" => Self::SameSiteOff,
            other => bail!("invalid proxy_cookie_flags flag \"{other}\""),
        })
    }
}

/// `ngx_http_proxy_edit_cookie_flags`.
pub fn edit_cookie_flags(parts: &mut Vec<CookiePart>, flags: &[CookieFlag]) {
    let mut remaining: Vec<CookieFlag> = flags.to_vec();
    let mut next = 0;
    while next < parts.len() {
        let part = parts[next].clone();
        match part {
            CookiePart::Flag(key) | CookiePart::Attribute { key, .. } => {
                let lower = key.to_ascii_lowercase();
                if lower == "secure" {
                    if let Some(flag) = take(&mut remaining, CookieFlag::SecureOn) {
                        let _ = flag;
                        next += 1;
                        continue;
                    }
                    if take(&mut remaining, CookieFlag::SecureOff).is_some() {
                        parts.remove(next);
                        continue;
                    }
                } else if lower == "httponly" {
                    if take(&mut remaining, CookieFlag::HttpOnlyOn).is_some() {
                        next += 1;
                        continue;
                    }
                    if take(&mut remaining, CookieFlag::HttpOnlyOff).is_some() {
                        parts.remove(next);
                        continue;
                    }
                } else if lower == "samesite" {
                    let wanted = [
                        (CookieFlag::SameSiteStrict, "Strict"),
                        (CookieFlag::SameSiteLax, "Lax"),
                        (CookieFlag::SameSiteNone, "None"),
                    ];
                    let mut handled = false;
                    for (flag, name) in wanted {
                        if take(&mut remaining, flag).is_some() {
                            if let CookiePart::Attribute { key, value } = &mut parts[next] {
                                *key = "SameSite".to_string();
                                match value {
                                    Some(current) if current.eq_ignore_ascii_case(name) => {}
                                    _ => *value = Some(name.to_string()),
                                }
                            }
                            handled = true;
                            break;
                        }
                    }
                    if handled {
                        next += 1;
                        continue;
                    }
                    if take(&mut remaining, CookieFlag::SameSiteOff).is_some() {
                        parts.remove(next);
                        continue;
                    }
                }
                next += 1;
            }
            CookiePart::Separator(_) => next += 1,
        }
    }
    // Append the flags that were not present yet (`ngx_http_proxy_edit_cookie_flags` tail).
    for flag in remaining {
        let (key, value) = match flag {
            CookieFlag::SecureOn => ("Secure", None),
            CookieFlag::HttpOnlyOn => ("HttpOnly", None),
            CookieFlag::SameSiteStrict => ("SameSite", Some("Strict".to_string())),
            CookieFlag::SameSiteLax => ("SameSite", Some("Lax".to_string())),
            CookieFlag::SameSiteNone => ("SameSite", Some("None".to_string())),
            CookieFlag::SecureOff | CookieFlag::HttpOnlyOff | CookieFlag::SameSiteOff => continue,
        };
        if !parts.is_empty() {
            parts.push(CookiePart::Separator("; ".to_string()));
        }
        parts.push(CookiePart::Attribute {
            key: key.to_string(),
            value,
        });
    }
}

fn take(remaining: &mut Vec<CookieFlag>, flag: CookieFlag) -> Option<CookieFlag> {
    let index = remaining.iter().position(|candidate| *candidate == flag)?;
    Some(remaining.remove(index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_parts_round_trip() {
        let value = "sid=abc; Path=/; Domain=backend.local; Secure; HttpOnly";
        let parts = parse_cookie(value);
        assert_eq!(render_cookie(&parts), value);
        assert!(matches!(
            parts.first(),
            Some(CookiePart::Attribute { key, value }) if key == "sid" && value.as_deref() == Some("abc")
        ));
    }

    #[test]
    fn secure_and_httponly_flags_are_added() {
        let mut parts = parse_cookie("sid=1; Path=/");
        edit_cookie_flags(&mut parts, &[CookieFlag::SecureOn, CookieFlag::HttpOnlyOn]);
        let rendered = render_cookie(&parts);
        assert!(rendered.contains("Secure"), "{rendered}");
        assert!(rendered.contains("HttpOnly"), "{rendered}");
    }

    #[test]
    fn nosecure_removes_the_flag() {
        let mut parts = parse_cookie("sid=1; Secure; Path=/");
        edit_cookie_flags(&mut parts, &[CookieFlag::SecureOff]);
        let rendered = render_cookie(&parts);
        assert!(!rendered.contains("Secure"), "{rendered}");
        assert!(rendered.contains("Path=/"), "{rendered}");
    }

    #[test]
    fn samesite_is_normalised() {
        let mut parts = parse_cookie("sid=1; SameSite=lax");
        edit_cookie_flags(&mut parts, &[CookieFlag::SameSiteStrict]);
        let rendered = render_cookie(&parts);
        assert!(rendered.contains("SameSite=Strict"), "{rendered}");
    }

    #[test]
    fn samesite_off_drops_the_attribute() {
        let mut parts = parse_cookie("sid=1; SameSite=Lax; Path=/");
        edit_cookie_flags(&mut parts, &[CookieFlag::SameSiteOff]);
        let rendered = render_cookie(&parts);
        assert!(!rendered.to_ascii_lowercase().contains("samesite"), "{rendered}");
    }

    #[test]
    fn literal_rewrite_replaces_the_prefix() {
        let rewrite = Rewrite::parse("http://backend/", Some("http://$host/"), true).unwrap();
        let value = rewrite
            .apply("http://backend/login", &mut |template| {
                if template.source() == "http://$host/" {
                    "https://front/".to_string()
                } else {
                    template.source().to_string()
                }
            })
            .unwrap();
        assert_eq!(value, "https://front/login");
    }

    #[test]
    fn regex_rewrite_substitutes_captures() {
        let rewrite = Rewrite::parse(r"~^http://backend(/.*)$", Some("/new$1"), true).unwrap();
        let value = rewrite
            .apply("http://backend/a/b", &mut |template| template.source().to_string())
            .unwrap();
        assert_eq!(value, "/new/a/b");
    }

    #[test]
    fn regex_rewrite_without_right_side_keeps_the_match() {
        let rewrite = Rewrite::parse(r"~^/old", None, true).unwrap();
        let value = rewrite
            .apply("/old/page", &mut |template| template.source().to_string())
            .unwrap();
        assert_eq!(value, "~^/old");
    }

    #[test]
    fn non_matching_rewrite_declines() {
        let rewrite = Rewrite::parse("http://backend/", Some("/new/"), true).unwrap();
        assert!(
            rewrite
                .apply("http://other/x", &mut |template| template.source().to_string())
                .is_none()
        );
    }
}
