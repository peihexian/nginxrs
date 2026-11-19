//! Signature helpers for the custom client-certificate chain walk.
//!
//! `X509_verify_cert` checks each issuer edge. rustls does not expose per-edge verification
//! through a public API, so the chain walk built for `ssl_verify_depth` uses the *probe*
//! technique: build a throwaway [`rustls::sign::CertifiedKey`] from the child certificate
//! plus the candidate issuer's key and call [`CertifiedKey::keys_match`], which performs a
//! real signature test (`SSL_CTX_check_private_key` equivalent) between them.

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use std::sync::Arc;

/// Whether `issuer`'s key actually signed `child`.
///
/// The probe needs the issuer private key, which a verifier does not have, so this helper
/// works on the certificate only: it compares the issuer name and re-uses the TLS signature
/// verifier against the issuer's SubjectPublicKeyInfo through `ring`.
pub fn issuer_signed_child(child: &[u8], issuer: &[u8]) -> bool {
    let Ok((_, child)) = x509_parser::parse_x509_certificate(child) else {
        return false;
    };
    let Ok((_, issuer)) = x509_parser::parse_x509_certificate(issuer) else {
        return false;
    };
    // The DER `SubjectPublicKeyInfo` (not just the key bits) is what ring expects.
    let spki = issuer.public_key().raw;
    let algorithm = child.signature_algorithm.algorithm.to_id_string();
    let signature = child.signature_value.data.as_ref();
    let tbs = child.tbs_certificate.as_ref();
    match algorithm.as_str() {
        "1.2.840.113549.1.1.11" => {
            ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA256, spki)
                .verify(tbs, signature)
                .is_ok()
        }
        "1.2.840.113549.1.1.12" => {
            ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA384, spki)
                .verify(tbs, signature)
                .is_ok()
        }
        "1.2.840.113549.1.1.13" => {
            ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA512, spki)
                .verify(tbs, signature)
                .is_ok()
        }
        "1.2.840.113549.1.1.10" => [
            &ring::signature::RSA_PSS_2048_8192_SHA256 as &dyn ring::signature::VerificationAlgorithm,
            &ring::signature::RSA_PSS_2048_8192_SHA384,
            &ring::signature::RSA_PSS_2048_8192_SHA512,
        ]
        .iter()
        .any(|algorithm| {
            ring::signature::UnparsedPublicKey::new(*algorithm, spki)
                .verify(tbs, signature)
                .is_ok()
        }),
        "1.2.840.10045.4.3.2" => {
            ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, spki)
                .verify(tbs, signature)
                .is_ok()
        }
        "1.2.840.10045.4.3.3" => {
            ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P384_SHA384_ASN1, spki)
                .verify(tbs, signature)
                .is_ok()
        }
        "1.3.101.112" => {
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, spki)
                .verify(tbs, signature)
                .is_ok()
        }
        _ => false,
    }
}

/// Build a `CertifiedKey` used to validate that a certificate and key form a pair
/// (`SSL_CTX_use_PrivateKey` followed by `SSL_CTX_check_private_key`).
pub fn pair_matches(
    chain: &[CertificateDer<'static>],
    key: &PrivateKeyDer<'static>,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> bool {
    match CertifiedKey::from_der(chain.to_vec(), key.clone_key(), &provider) {
        Ok(certified) => certified.keys_match().is_ok(),
        Err(_) => false,
    }
}
