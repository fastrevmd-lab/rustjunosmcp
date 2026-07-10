//! PEM loader for the SRX rustls listener.

#![cfg(feature = "tls")]

use anyhow::{anyhow, Context, Result};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;

fn ensure_default_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub fn load(cert: &Path, key: &Path) -> Result<Arc<rustls::ServerConfig>> {
    ensure_default_provider();

    let cert_bytes = std::fs::read(cert).with_context(|| format!("read {}", cert.display()))?;
    let key_bytes = std::fs::read(key).with_context(|| format!("read {}", key.display()))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<std::result::Result<_, _>>()
        .context("parse cert PEM")?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in {}", cert.display()));
    }
    let private_key = PrivateKeyDer::from_pem_slice(&key_bytes)
        .with_context(|| format!("parse key PEM from {}", key.display()))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .context("rustls server config")?;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_self_signed_pair() {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, issued.cert.pem()).unwrap();
        std::fs::write(&key, issued.signing_key.serialize_pem()).unwrap();
        load(&cert, &key).unwrap();
    }

    #[test]
    fn missing_certificate_errors() {
        let dir = tempfile::tempdir().unwrap();
        let error = load(&dir.path().join("missing.pem"), &dir.path().join("key.pem")).unwrap_err();
        assert!(error.to_string().contains("read "));
    }

    #[test]
    fn empty_certificate_errors() {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, b"").unwrap();
        std::fs::write(&key, issued.signing_key.serialize_pem()).unwrap();
        let error = load(&cert, &key).unwrap_err();
        assert!(error.to_string().contains("no certificates"));
    }
}
