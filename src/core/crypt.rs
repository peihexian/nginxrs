//! Password hashing compatible with `ngx_crypt.c`.
//!
//! `ngx_http_auth_basic_module` compares the client password with the stored entry by
//! re-encrypting the password with the stored salt and comparing the result byte for byte
//! (`ngx_crypt` → `ngx_http_auth_basic_crypt_handler`). The formats nginx supports without a
//! system `crypt_r` are:
//!
//! | Prefix | Algorithm | Source |
//! |---|---|---|
//! | `$apr1$` | Apache MD5 crypt | `ngx_crypt_apr1` |
//! | `{PLAIN}` | the plain password | `ngx_crypt_plain` |
//! | `{SSHA}` | salted SHA-1, base64 | `ngx_crypt_ssha` |
//! | `{SHA}` | SHA-1, base64 | `ngx_crypt_sha` |
//!
//! A salt without one of those prefixes falls back to libc `crypt(3)` (`$1$`, `$5$`, `$6$`,
//! DES/`crypt`). Those system formats are intentionally not reimplemented: [`verify`]
//! returns [`VerifyOutcome::Unsupported`] so callers can reject the request with a clear log
//! line instead of silently accepting or denying.

use md5::{Digest, Md5};
use sha1::Sha1;

/// Result of comparing a client password with a stored hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The stored entry and the client password encrypt identically.
    Match,
    /// The password does not match the stored entry it was compared with.
    Mismatch,
    /// The stored entry uses a format this build cannot verify (libc `crypt(3)`).
    Unsupported,
    /// The stored entry is malformed (for example `{SSHA}` with bad base64).
    Invalid,
}

const ITOA64: &[u8; 64] =
    b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Encrypt `password` with a fixed `$apr1$` salt, for tests and diagnostics.
pub fn encrypt_for_test(password: &[u8], salt: &[u8]) -> String {
    String::from_utf8_lossy(&apr1(password, salt)).into_owned()
}

/// Compare `password` with the stored hash `stored`, mirroring `ngx_crypt` + `strcmp`.
pub fn verify(password: &[u8], stored: &[u8]) -> VerifyOutcome {
    let Some((expected, outcome_override)) = encrypt(password, stored) else {
        return VerifyOutcome::Unsupported;
    };
    if expected == stored {
        VerifyOutcome::Match
    } else {
        outcome_override
    }
}

/// Encrypt `password` using the algorithm and salt named by `stored`.
///
/// Returns `None` for formats delegated to libc `crypt(3)`.
fn encrypt(password: &[u8], stored: &[u8]) -> Option<(Vec<u8>, VerifyOutcome)> {
    if let Some(rest) = stored.strip_prefix(b"$apr1$") {
        let salt = apr1_salt(rest);
        return Some((apr1(password, salt), VerifyOutcome::Mismatch));
    }
    if stored.starts_with(b"{PLAIN}") {
        let mut value = b"{PLAIN}".to_vec();
        value.extend_from_slice(password);
        return Some((value, VerifyOutcome::Mismatch));
    }
    if let Some(rest) = stored.strip_prefix(b"{SSHA}") {
        return Some(match ssha(password, rest) {
            Some(value) => (value, VerifyOutcome::Mismatch),
            None => (Vec::new(), VerifyOutcome::Invalid),
        });
    }
    if stored.starts_with(b"{SHA}") {
        let mut value = b"{SHA}".to_vec();
        value.extend_from_slice(base64(&sha1(password)).as_bytes());
        return Some((value, VerifyOutcome::Mismatch));
    }
    None
}

/// `ngx_crypt_apr1`: the salt ends at the first `$` or after eight bytes.
fn apr1_salt(rest: &[u8]) -> &[u8] {
    let end = rest
        .iter()
        .take(8)
        .position(|byte| *byte == b'$')
        .unwrap_or(rest.len().min(8));
    &rest[..end]
}

/// Apache's `apr1` MD5 crypt (`ngx_crypt_apr1`).
fn apr1(password: &[u8], salt: &[u8]) -> Vec<u8> {
    // hash = md5(password "$apr1$" salt)
    let mut initial = Md5::new();
    initial.update(password);
    initial.update(b"$apr1$");
    initial.update(salt);

    // ctx1 = md5(password salt password)
    let mut context = Md5::new();
    context.update(password);
    context.update(salt);
    context.update(password);
    let mut final_digest = context.finalize();

    let mut remaining = password.len();
    while remaining > 0 {
        initial.update(&final_digest[..remaining.min(16)]);
        remaining = remaining.saturating_sub(16);
    }
    final_digest.copy_from_slice(&[0; 16]);

    let mut bits = password.len();
    while bits > 0 {
        if bits & 1 == 1 {
            initial.update(&final_digest[..1]);
        } else {
            initial.update(&password[..1]);
        }
        bits >>= 1;
    }
    final_digest.copy_from_slice(initial.finalize().as_slice());

    for round in 0..1000_u32 {
        let mut context = Md5::new();
        if round & 1 == 1 {
            context.update(password);
        } else {
            context.update(final_digest);
        }
        if round % 3 != 0 {
            context.update(salt);
        }
        if round % 7 != 0 {
            context.update(password);
        }
        if round & 1 == 1 {
            context.update(final_digest);
        } else {
            context.update(password);
        }
        final_digest.copy_from_slice(context.finalize().as_slice());
    }

    let d = final_digest;
    let mut out = Vec::with_capacity(6 + salt.len() + 1 + 22);
    out.extend_from_slice(b"$apr1$");
    out.extend_from_slice(salt);
    out.push(b'$');
    to64(
        &mut out,
        (u32::from(d[0]) << 16) | (u32::from(d[6]) << 8) | u32::from(d[12]),
        4,
    );
    to64(
        &mut out,
        (u32::from(d[1]) << 16) | (u32::from(d[7]) << 8) | u32::from(d[13]),
        4,
    );
    to64(
        &mut out,
        (u32::from(d[2]) << 16) | (u32::from(d[8]) << 8) | u32::from(d[14]),
        4,
    );
    to64(
        &mut out,
        (u32::from(d[3]) << 16) | (u32::from(d[9]) << 8) | u32::from(d[15]),
        4,
    );
    to64(
        &mut out,
        (u32::from(d[4]) << 16) | (u32::from(d[10]) << 8) | u32::from(d[5]),
        4,
    );
    to64(&mut out, u32::from(d[11]), 2);
    out
}

/// `ngx_crypt_to64`: little-endian base64 with the `itoa64` alphabet.
fn to64(out: &mut Vec<u8>, mut value: u32, count: usize) {
    for _ in 0..count {
        out.push(ITOA64[(value & 0x3f) as usize]);
        value >>= 6;
    }
}

/// `ngx_crypt_ssha`: `{SSHA}` base64(SHA1(password + salt) + salt).
///
/// nginx decodes the stored value, hashes `password` with the trailing salt bytes, and
/// compares the re-encoding with the stored string; the salt itself ends up in the output
/// just like the digest, so the lengths always agree.
fn ssha(password: &[u8], encoded: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = decode_base64(encoded)?;
    if decoded.len() < 20 {
        decoded.resize(20, 0);
    }
    let salt = decoded[20..].to_vec();
    let mut hasher = <Sha1 as sha1::Digest>::new();
    hasher.update(password);
    hasher.update(&salt);
    let digest = hasher.finalize();
    decoded[..20].copy_from_slice(&digest);
    let mut value = b"{SSHA}".to_vec();
    value.extend_from_slice(base64(&decoded).as_bytes());
    Some(value)
}

fn sha1(value: &[u8]) -> [u8; 20] {
    let mut hasher = <Sha1 as sha1::Digest>::new();
    hasher.update(value);
    hasher.finalize().into()
}

/// Standard alphabet base64 without padding (nginx `ngx_encode_base64`).
fn base64(value: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(value)
}

/// Decode standard base64, tolerating missing padding and whitespace.
fn decode_base64(value: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let text: Vec<u8> = value
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&text) {
        return Some(decoded);
    }
    let trimmed = String::from_utf8_lossy(&text)
        .trim_end_matches(['=', '\r', '\n'])
        .to_string();
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(trimmed.as_bytes())
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apr1_matches_openssl_vectors() {
        // `openssl passwd -apr1 -salt <salt> <password>`, which is the same algorithm nginx
        // uses in `ngx_crypt_apr1`.
        assert_eq!(
            apr1(b"password", b"abcdefgh"),
            b"$apr1$abcdefgh$FBwExRW4dCc8aL.OvjpIE1".to_vec()
        );
        assert_eq!(apr1(b"", b"salt"), b"$apr1$salt$AnXM5PAEa9T4ruYbwPoUh/".to_vec());
        assert_eq!(
            apr1(b"admin", b"7T5sTMj0"),
            b"$apr1$7T5sTMj0$.VZ6E78vPYUrAxFHFWOph1".to_vec()
        );
    }

    #[test]
    fn verify_round_trips_every_supported_format() {
        let hash = apr1(b"secret", b"testsalt");
        assert_eq!(verify(b"secret", &hash), VerifyOutcome::Match);
        assert_eq!(verify(b"other", &hash), VerifyOutcome::Mismatch);

        assert_eq!(verify(b"plain", b"{PLAIN}plain"), VerifyOutcome::Match);
        assert_eq!(verify(b"plain", b"{PLAIN}other"), VerifyOutcome::Mismatch);

        let sha = format!("{{SHA}}{}", base64(&sha1(b"secret")));
        assert_eq!(verify(b"secret", sha.as_bytes()), VerifyOutcome::Match);

        // `{SSHA}` entries are base64(SHA1(password + salt) + salt), exactly the digest the
        // verifier recomputes; nginx compares the whole stored string.
        let mut stored = sha1(b"secretsalt").to_vec();
        stored.extend_from_slice(b"salt");
        let digest = base64(&stored);
        // nginx re-encodes a digest-only buffer, so an unpadded `{SSHA}` matches the stored
        // unpadded string; compare the canonical form (no `=` padding).
        let ssha = format!("{{SSHA}}{digest}");
        assert_eq!(verify(b"secret", ssha.as_bytes()), VerifyOutcome::Match);
        assert_eq!(verify(b"nope", ssha.as_bytes()), VerifyOutcome::Mismatch);
    }

    #[test]
    fn libc_formats_are_reported_as_unsupported() {
        assert_eq!(
            verify(b"x", b"$1$abcdefgh$0123456789abcdef01234"),
            VerifyOutcome::Unsupported
        );
        assert_eq!(
            verify(b"x", b"$6$rounds=5000$abc$def"),
            VerifyOutcome::Unsupported
        );
    }

    #[test]
    fn salt_stops_at_dollar_and_eight_bytes() {
        assert_eq!(apr1_salt(b"abcdefgh$ignored"), b"abcdefgh");
        assert_eq!(apr1_salt(b"abc$def"), b"abc");
        assert_eq!(apr1_salt(b"short"), b"short");
    }
}




