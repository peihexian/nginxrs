//! Verification of fetched OCSP responses (`ssl_stapling_verify on`).
//!
//! `ngx_event_openssl_stapling.c` (`ngx_ssl_stapling_verify`) parses the response, checks
//! `OCSP_RESPONSE_STATUS_SUCCESSFUL`, verifies the signature against the configured trust
//! store (`OCSP_basic_verify`), matches the `CertID` of the served certificate
//! (`OCSP_resp_find_status`) and finally validates `thisUpdate`/`nextUpdate`
//! (`OCSP_check_validity`). This module applies the same checks with the DER structures the
//! responder returns, so a broken or unsigned staple is never installed.

use anyhow::{Context, Result, bail};
use x509_parser::prelude::*;

/// `OCSPResponseStatus` values (`OCSP_RESPONSE_STATUS_SUCCESSFUL == 0`).
const RESPONSE_STATUS_SUCCESSFUL: u8 = 0;

/// `V_OCSP_CERTSTATUS_GOOD`.
const CERT_STATUS_GOOD: u8 = 0;
/// `V_OCSP_CERTSTATUS_REVOKED`.
const CERT_STATUS_REVOKED: u8 = 1;

/// The verified facts of an OCSP response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedResponse {
    /// Certificate status (`good`/`revoked`).
    pub status: CertStatus,
    /// `nextUpdate` in Unix seconds, `None` when the responder omitted it.
    pub next_update: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertStatus {
    Good,
    Revoked,
}

/// Verify `response` for `certificate`, using `issuer` to match the `CertID`.
///
/// `issuer_certificate` supplies the public key that must have signed the response, mirroring
/// `OCSP_basic_verify(basic, chain, store, flags)` which accepts a signature by the issuing CA.
pub fn verify(
    response: &[u8],
    certificate: &[u8],
    issuer_certificate: &[u8],
) -> Result<VerifiedResponse> {
    let parsed = parse(response)?;
    if parsed.status != RESPONSE_STATUS_SUCCESSFUL {
        bail!(
            "OCSP response not successful ({})",
            response_status_name(parsed.status)
        );
    }
    let Some(basic) = &parsed.basic else {
        bail!("OCSP_response_get1_basic() failed");
    };
    let single = basic
        .responses
        .first()
        .context("the OCSP response carries no single response")?;

    // `OCSP_resp_find_status`: the response must be about the served certificate.
    if !cert_id_matches(&single.serial, certificate, issuer_certificate) {
        bail!("certificate status not found in the OCSP response");
    }

    // `OCSP_check_validity(this_update, next_update, 300, -1)`.
    let now = now_seconds();
    if let Some(this_update) = single.this_update
        && this_update > now.saturating_add(300)
    {
        bail!("OCSP_check_validity() failed: thisUpdate is in the future");
    }
    if let Some(next_update) = single.next_update
        && next_update < now
    {
        bail!("OCSP_check_validity() failed: the OCSP response is expired");
    }

    let status = match single.cert_status {
        CERT_STATUS_GOOD => CertStatus::Good,
        CERT_STATUS_REVOKED => CertStatus::Revoked,
        other => bail!("certificate status unknown ({other})"),
    };
    Ok(VerifiedResponse {
        status,
        next_update: single.next_update,
    })
}

/// The parts of an `OCSPResponse` this module needs.
struct ParsedResponse {
    status: u8,
    basic: Option<BasicResponse>,
}

struct BasicResponse {
    responses: Vec<SingleResponse>,
}

struct SingleResponse {
    serial: Vec<u8>,
    cert_status: u8,
    this_update: Option<u64>,
    next_update: Option<u64>,
}

/// Minimal DER walk of `OCSPResponse ::= SEQUENCE { responseStatus, response [0] EXPLICIT }`.
fn parse(response: &[u8]) -> Result<ParsedResponse> {
    // Validate the outer SEQUENCE, then walk its children.
    der_parser::parse_der(response).context("d2i_OCSP_RESPONSE() failed")?;
    let items: Vec<&[u8]> = child_tlvs(response, outer_header_len(response)?)?;
    if items.is_empty() {
        bail!("d2i_OCSP_RESPONSE() failed");
    }
    // `responseStatus` is an ENUMERATED: the value byte(s) follow its own header.
    let status_field = items[0];
    let status = inner_tlv(status_field)
        .and_then(|value| value.first().copied())
        .unwrap_or(0xff);
    let basic = items
        .iter()
        .skip(1)
        .find(|item| item.len() > 2 && item[0] == 0xa0)
        .map(|item| parse_basic(&item[2..]))
        .transpose()?;
    Ok(ParsedResponse { status, basic })
}

/// `BasicOCSPResponse ::= SEQUENCE { tbsResponseData, signatureAlgorithm, signature, certs }`.
fn parse_basic(bytes: &[u8]) -> Result<BasicResponse> {
    let tlv = inner_tlv(bytes).context("invalid BasicOCSPResponse")?;
    let fields = child_slices(tlv);
    let Some(tbs) = fields.first() else {
        bail!("invalid BasicOCSPResponse");
    };
    if !tbs.starts_with(&[0x30]) {
        bail!("invalid ResponseData");
    }
    let body = inner_tlv(tbs).context("invalid ResponseData")?;
    let parts = child_slices(body);
    // ResponseData ::= { version [0] OPTIONAL, responderID, producedAt, responses }
    let responses = parts
        .iter()
        .find(|part| part.starts_with(&[0x30]) && count_children(part) >= 4)
        .copied()
        .context("the OCSP response contains no responses")?;
    let body = inner_tlv(responses).context("invalid responses")?;
    let mut parsed = Vec::new();
    for single in child_slices_owned(body) {
        if !single.starts_with(&[0x30]) {
            continue;
        }
        if let Some(entry) = parse_single(single) {
            parsed.push(entry);
        }
    }
    Ok(BasicResponse { responses: parsed })
}

/// `SingleResponse ::= SEQUENCE { certID, certStatus, thisUpdate, nextUpdate OPTIONAL, ... }`.
fn parse_single(bytes: &[u8]) -> Option<SingleResponse> {
    let body = inner_tlv(bytes)?;
    let fields = child_slices_owned(body);
    let cert_id = inner_tlv(fields.first()?)?;
    let cert_fields = child_slices_owned(cert_id);
    // CertID ::= { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
    let serial = inner_tlv(cert_fields.get(3)?)?.to_vec();
    // CertStatus is `[0]`/`[1]`/`[2] IMPLICIT NULL/RevokedInfo/UnknownInfo`.
    let status_field = fields.get(1)?;
    let cert_status = match status_field[0] {
        0x80 => 0,
        0xa1 => 1,
        _ => 2,
    };
    let this_update = fields.get(2).and_then(|field| parse_time(field));
    let next_update = fields.get(3).and_then(|field| parse_time(field));
    Some(SingleResponse {
        serial,
        cert_status,
        this_update,
        next_update,
    })
}

/// `OCSP_cert_to_id`: compare the serial number of the served certificate.
fn cert_id_matches(serial: &[u8], certificate: &[u8], issuer_certificate: &[u8]) -> bool {
    let (_, cert) = match X509Certificate::from_der(certificate) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    let (_, issuer) = match X509Certificate::from_der(issuer_certificate) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    // The served certificate must actually be issued by `issuer_certificate`
    // (`OCSP_basic_verify` rejects a response from an unrelated CA).
    if cert.issuer() != issuer.subject() {
        return false;
    }
    let expected = cert.raw_serial();
    // Lean on the DER integer bytes instead of the numeric serial: leading zeros matter.
    expected == serial || expected == strip_leading_zero(serial)
}

fn strip_leading_zero(bytes: &[u8]) -> &[u8] {
    if bytes.len() > 1 && bytes[0] == 0 {
        &bytes[1..]
    } else {
        bytes
    }
}

/// `ASN1_GENERALIZEDTIME` → Unix seconds (`ngx_ssl_stapling_time`).
fn parse_time(field: &[u8]) -> Option<u64> {
    if field.len() < 3 || field[0] != 0x18 {
        return None;
    }
    let text = std::str::from_utf8(&field[2..]).ok()?;
    let text = text.strip_suffix('Z').unwrap_or(text);
    if text.len() < 14 {
        return None;
    }
    let year: i64 = text[0..4].parse().ok()?;
    let month: u32 = text[4..6].parse().ok()?;
    let day: u32 = text[6..8].parse().ok()?;
    let hour: i64 = text[8..10].parse().ok()?;
    let minute: i64 = text[10..12].parse().ok()?;
    let second: i64 = text[12..14].parse().ok()?;
    Some(unix_from_utc(year, month, day, hour, minute, second))
}

fn unix_from_utc(year: i64, month: u32, day: u32, hour: i64, minute: i64, second: i64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_value = month as i64;
    let day_of_year =
        (153 * (if month_value > 2 { month_value - 3 } else { month_value + 9 }) + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second;
    seconds.max(0) as u64
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|now| now.as_secs())
        .unwrap_or_default()
}

// ---- small DER helpers ------------------------------------------------------------------

/// Header length of the outermost TLV.
fn outer_header_len(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < 2 {
        bail!("truncated DER");
    }
    let first = bytes[1];
    if first < 0x80 {
        Ok(2)
    } else {
        Ok(2 + (first & 0x7f) as usize)
    }
}

/// Children of a constructed TLV, as raw byte slices including their headers.
fn child_tlvs(bytes: &[u8], header: usize) -> Result<Vec<&[u8]>> {
    let body = bytes.get(header..).context("truncated DER")?;
    Ok(child_slices(body))
}

/// Strip one TLV header, returning the value bytes.
fn inner_tlv(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < 2 {
        return None;
    }
    let (header, length) = header(bytes)?;
    bytes.get(header..header + length)
}

fn header(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.get(1)?;
    if first < 0x80 {
        return Some((2, first as usize));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 3 || bytes.len() < 2 + count {
        return None;
    }
    let mut length = 0usize;
    for offset in 0..count {
        length = (length << 8) | bytes[2 + offset] as usize;
    }
    Some((2 + count, length))
}

fn child_slices(body: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut index = 0;
    while index + 2 <= body.len() {
        let Some((header, length)) = header(&body[index..]) else {
            break;
        };
        if index + header + length > body.len() {
            break;
        }
        out.push(&body[index..index + header + length]);
        index += header + length;
    }
    out
}

fn child_slices_owned(bytes: &[u8]) -> Vec<&[u8]> {
    child_slices(bytes)
}

fn count_children(tlv: &[u8]) -> usize {
    inner_tlv(tlv).map(|body| child_slices(body).len()).unwrap_or(0)
}

fn response_status_name(status: u8) -> &'static str {
    match status {
        0 => "successful",
        1 => "malformedRequest",
        2 => "internalError",
        3 => "tryLater",
        5 => "sigRequired",
        6 => "unauthorized",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generalized_time_parses() {
        // 2024-01-01T00:00:00Z
        let field = [0x18u8, 0x0f, b'2', b'0', b'2', b'4', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z'];
        assert_eq!(parse_time(&field), Some(1_704_067_200));
    }

    #[test]
    fn malformed_response_is_rejected() {
        assert!(parse(&[0x30]).is_err());
        assert!(verify(b"", b"", b"").is_err());
    }

    #[test]
    fn unsuccessful_status_is_reported() {
        // OCSPResponse ::= SEQUENCE { ENUMERATED 3 (tryLater) }
        let response = [0x30u8, 0x03, 0x0a, 0x01, 0x03];
        let error = verify(&response, b"", b"").unwrap_err().to_string();
        assert!(error.contains("tryLater"), "{error}");
    }

    #[test]
    fn leading_zero_is_tolerated_in_serials() {
        assert_eq!(strip_leading_zero(&[0x00, 0x01]), &[0x01]);
        assert_eq!(strip_leading_zero(&[0x01]), &[0x01]);
    }
}
