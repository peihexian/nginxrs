//! Nginx-compatible byte-string helpers shared by modules.
//!
//! Nginx works on raw bytes (`ngx_str_t`), and several modules — the SSI filter, the
//! `expires` filter, `auth_basic` — reproduce escaping tables from `ngx_string.c`. They live
//! here so each module only owns its own semantics.

/// Nginx `ngx_escape_html`: escapes `<`, `>`, `&` and `"` as entities.
pub fn escape_html(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    for byte in value {
        match byte {
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'&' => out.extend_from_slice(b"&amp;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            byte => out.push(*byte),
        }
    }
    out
}

/// Nginx `ngx_escape_uri(…, NGX_ESCAPE_HTML)`.
///
/// The table is the one `ngx_string.c` uses for the `html` escape class: control bytes,
/// space, `"`, `#`, `%`, `'`, `<`, `>`, `\`, `^`, `` ` ``, `{`, `|`, `}` and 0x7F–0xFF are
/// percent-encoded, everything else is copied.
pub fn escape_uri_html(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    for byte in value {
        if needs_uri_html_escape(*byte) {
            out.push(b'%');
            out.extend_from_slice(format!("{byte:02X}").as_bytes());
        } else {
            out.push(*byte);
        }
    }
    out
}

/// Whether `byte` is percent-encoded by `NGX_ESCAPE_HTML`.
fn needs_uri_html_escape(byte: u8) -> bool {
    match byte {
        // " " # " # % # ' # < # > # \ # ^ # ` # { # | # } # DEL
        0x00..=0x1F | 0x7F..=0xFF => true,
        b' ' | b'"' | b'#' | b'%' | b'\'' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'{'
        | b'|' | b'}' => true,
        _ => false,
    }
}

/// Nginx `ngx_hash_strlow`-style ASCII lowercasing used by SSI variable lookups.
pub fn to_lower_ascii(value: &[u8]) -> Vec<u8> {
    value.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_entities_cover_the_four_characters() {
        assert_eq!(escape_html(b"a<b>&\"c"), b"a&lt;b&gt;&amp;&quot;c".to_vec());
        assert_eq!(escape_html(b"plain"), b"plain".to_vec());
    }

    #[test]
    fn uri_escape_matches_the_nginx_html_class() {
        assert_eq!(escape_uri_html(b"a b"), b"a%20b".to_vec());
        assert_eq!(escape_uri_html(b"x'y"), b"x%27y".to_vec());
        assert_eq!(escape_uri_html(b"100%"), b"100%25".to_vec());
        // `$`, `&` and `=` are not escaped in this class.
        assert_eq!(escape_uri_html(b"$a=1&b"), b"$a=1&b".to_vec());
        assert_eq!(escape_uri_html(&[0xffu8, b'a']), b"%FFa".to_vec());
    }
}
