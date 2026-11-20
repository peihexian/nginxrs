//! Throwaway certificates for TLS tests.
//!
//! Certificates are produced with the `openssl` command line tool. CI images without it skip
//! the TLS tests instead of failing, so [`OpenSsl::available`] guards every caller.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The `openssl` CLI, or a note that it is missing.
pub struct OpenSsl;

impl OpenSsl {
    /// Whether `openssl` can run in this environment.
    pub fn available() -> bool {
        Command::new("openssl")
            .arg("version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    /// Print why a TLS test was skipped.
    pub fn skip(test: &str) {
        eprintln!("skipping {test}: openssl is unavailable");
    }

    fn run(args: &[&str]) -> bool {
        Command::new("openssl")
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
}

/// A self-signed leaf certificate plus its private key.
pub struct Certificate {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl Certificate {
    /// File name of the certificate, as written in a configuration.
    pub fn cert_name(&self) -> String {
        file_name(&self.cert)
    }

    /// File name of the private key, as written in a configuration.
    pub fn key_name(&self) -> String {
        file_name(&self.key)
    }

    /// The two `ssl_certificate` lines for a `server` block.
    pub fn directive(&self) -> String {
        format!(
            "ssl_certificate {};\nssl_certificate_key {};",
            self.cert_name(),
            self.key_name()
        )
    }
}

/// A CA certificate and a leaf signed by it, for client-certificate tests.
pub struct SignedCertificate {
    pub ca: PathBuf,
    pub leaf: Certificate,
}

/// Certificate generation rooted in one test directory.
pub struct Certificates<'a> {
    dir: &'a Path,
}

impl<'a> Certificates<'a> {
    pub fn new(dir: &'a Path) -> Self {
        Self { dir }
    }

    /// A self-signed certificate for `cn`; `None` when openssl is missing or fails.
    pub fn self_signed(&self, name: &str, cn: &str) -> Option<(PathBuf, PathBuf)> {
        let cert = self.dir.join(format!("{name}.crt"));
        let key = self.dir.join(format!("{name}.key"));
        let ok = OpenSsl::run(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            cert.to_str().unwrap(),
            "-days",
            "1",
            "-subj",
            &format!("/CN={cn}"),
            "-addext",
            &format!("subjectAltName=DNS:{cn}"),
        ]);
        ok.then_some((cert, key))
    }

    /// A self-signed certificate, or `None` when openssl is unavailable.
    pub fn self_signed_or_skip(&self, test: &str, name: &str, cn: &str) -> Option<Certificate> {
        match self.self_signed(name, cn) {
            Some((cert, key)) => Some(Certificate { cert, key }),
            None => {
                OpenSsl::skip(test);
                None
            }
        }
    }

    /// Build a CA plus a leaf certificate signed by it.
    pub fn signed(&self, name: &str, cn: &str) -> Option<(PathBuf, PathBuf, PathBuf)> {
        let ca_key = self.dir.join(format!("{name}-ca.key"));
        let ca_pem = self.dir.join(format!("{name}-ca.crt"));
        let ok = OpenSsl::run(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            ca_key.to_str().unwrap(),
            "-out",
            ca_pem.to_str().unwrap(),
            "-days",
            "1",
            "-subj",
            "/CN=nginxrs-test-ca",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ]);
        if !ok {
            return None;
        }
        let leaf_key = self.dir.join(format!("{name}.key"));
        let csr = self.dir.join(format!("{name}.csr"));
        let leaf_cert = self.dir.join(format!("{name}.crt"));
        let ok = OpenSsl::run(&[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            leaf_key.to_str().unwrap(),
            "-out",
            csr.to_str().unwrap(),
            "-subj",
            &format!("/CN={cn}"),
            "-addext",
            &format!("subjectAltName=DNS:{cn}"),
        ]);
        if !ok {
            return None;
        }
        let ok = OpenSsl::run(&[
            "x509",
            "-req",
            "-in",
            csr.to_str().unwrap(),
            "-CA",
            ca_pem.to_str().unwrap(),
            "-CAkey",
            ca_key.to_str().unwrap(),
            "-CAcreateserial",
            "-out",
            leaf_cert.to_str().unwrap(),
            "-days",
            "1",
        ]);
        if !ok {
            return None;
        }
        Some((ca_pem, leaf_cert, leaf_key))
    }

    /// A signed pair, or `None` when openssl is unavailable.
    pub fn signed_or_skip(&self, test: &str, name: &str, cn: &str) -> Option<SignedCertificate> {
        match self.signed(name, cn) {
            Some((ca, cert, key)) => Some(SignedCertificate {
                ca,
                leaf: Certificate { cert, key },
            }),
            None => {
                OpenSsl::skip(test);
                None
            }
        }
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default()
}
