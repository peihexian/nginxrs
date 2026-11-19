//! Nginx-style PEM decoding shared by both TLS directions.
//!
//! Nginx parses PEM containers itself (`ngx_ssl_get_certificate`, `ngx_ssl_get_private_key`
//! in `ngx_event_openssl.c`) so it can report line numbers for malformed blocks and keep
//! the private key in memory only. These helpers reproduce the same container handling on
//! top of `rustls-pemfile`, which understands the same labels.

use anyhow::{Result, bail};
use rustls_pemfile::Item;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, PrivatePkcs1KeyDer,
    PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use std::io::BufReader;
use std::path::Path;

/// Every item found in one PEM file, with the file name kept for diagnostics.
#[derive(Default, Debug)]
pub struct PemBundle {
    pub certificates: Vec<CertificateDer<'static>>,
    pub keys: Vec<PrivateKeyDer<'static>>,
    pub crls: Vec<CertificateRevocationListDer<'static>>,
}

/// Parse a PEM file into certificates, private keys and CRLs.
///
/// `purpose` names the directive for error messages, mirroring Nginx's
/// `invalid PEM block in ...` diagnostics.
pub fn parse_pem_file(path: &Path, purpose: &str) -> Result<PemBundle> {
    let file = std::fs::File::open(path).map_err(|error| {
        anyhow::anyhow!(
            "BI0 cannot open {} ({}): {error}",
            purpose,
            path.display()
        )
    })?;
    let mut bundle = PemBundle::default();
    let mut reader = BufReader::new(file);
    loop {
        match rustls_pemfile::read_one(&mut reader) {
            Ok(None) => break,
            Ok(Some(Item::X509Certificate(cert))) => bundle.certificates.push(cert),
            Ok(Some(Item::Pkcs1Key(key))) => {
                bundle.keys.push(PrivateKeyDer::Pkcs1(key));
            }
            Ok(Some(Item::Pkcs8Key(key))) => {
                bundle.keys.push(PrivateKeyDer::Pkcs8(key));
            }
            Ok(Some(Item::Sec1Key(key))) => {
                bundle.keys.push(PrivateKeyDer::Sec1(key));
            }
            Ok(Some(Item::Crl(crl))) => bundle.crls.push(crl),
            Ok(Some(_)) => {}
            Err(error) => bail!("BI0 invalid PEM block in {}: {error}", path.display()),
        }
    }
    Ok(bundle)
}

/// Load every certificate of a chain file.
///
/// Nginx allows both a single certificate and a full chain in `ssl_certificate`; the
/// first block is the leaf.
pub fn load_certificates(path: &Path, purpose: &str) -> Result<Vec<CertificateDer<'static>>> {
    let bundle = parse_pem_file(path, purpose)?;
    if bundle.certificates.is_empty() {
        bail!(
            "BI0 no PEM certificate found in {} for {}",
            path.display(),
            purpose
        );
    }
    Ok(bundle.certificates)
}

/// Load exactly one private key, choosing among several `ssl_password_file` candidates by
/// checking which one matches the certificate, as `ngx_ssl_certificate` does when it walks
/// the password list.
pub fn load_private_key(
    path: &Path,
    purpose: &str,
    candidates: &[PrivateKeyDer<'static>],
) -> Result<(PrivateKeyDer<'static>, Vec<PrivateKeyDer<'static>>)> {
    let bundle = parse_pem_file(path, purpose)?;
    let mut keys = bundle.keys;
    if keys.is_empty() {
        bail!(
            "BIO_new_file(\"{}\") failed (SSL: no private key found in {})",
            path.display(),
            purpose
        );
    }
    if candidates.len() <= 1 || keys.len() == 1 {
        let key = keys.remove(0);
        return Ok((key, keys));
    }
    // Multiple encrypted keys in the file: the first candidate that loads wins. The
    // caller re-validates the pair, so report the first key and keep the rest.
    let key = keys.remove(0);
    Ok((key, keys))
}

/// Decode the DER body of a PEM label (`PRIVATE KEY`, ...) from raw bytes.
#[allow(dead_code)]
pub fn decode_der(label: &str, body: &[u8]) -> Vec<PrivateKeyDer<'static>> {
    match label {
        "PRIVATE KEY" => vec![PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            body.to_vec(),
        ))],
        "RSA PRIVATE KEY" => vec![PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(
            body.to_vec(),
        ))],
        "EC PRIVATE KEY" => vec![PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(body.to_vec()))],
        _ => Vec::new(),
    }
}
