//! Minimal PEM loader for rustls 0.23.
//!
//! Reads a cert chain and private key from disk and builds a
//! `rustls::ServerConfig` (no client auth). The crypto provider is fixed to
//! `ring` via the workspace feature flags on rustls — we install it as the
//! process-default on first call so `ServerConfig::builder()` can resolve a
//! provider deterministically (rustls 0.23 panics if neither a process
//! default nor explicit provider is supplied).

#![cfg(feature = "tls")]

use anyhow::{anyhow, Context, Result};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;

/// Idempotently install rustls's `ring` crypto provider as the process default.
/// `CryptoProvider::install_default` is a one-shot — calling it twice returns
/// `Err`, which we ignore (a provider is already installed).
fn ensure_default_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        // The Err arm just means another caller raced us; that's fine.
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

    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .context("rustls server config")?;
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_self_signed_pair() {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, issued.cert.pem()).unwrap();
        std::fs::write(&key_path, issued.signing_key.serialize_pem()).unwrap();

        let cfg = load(&cert_path, &key_path).expect("load self-signed pair");
        // Sanity: server config built; nothing more we can introspect cheaply.
        let _ = cfg;
    }

    #[test]
    fn load_missing_cert_errors() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("nope-cert.pem");
        let key_path = dir.path().join("nope-key.pem");
        let err = load(&cert_path, &key_path).unwrap_err();
        assert!(err.to_string().contains("read "));
    }

    #[test]
    fn load_empty_cert_errors() {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, b"").unwrap();
        std::fs::write(&key_path, issued.signing_key.serialize_pem()).unwrap();
        let err = load(&cert_path, &key_path).unwrap_err();
        assert!(err.to_string().contains("no certificates"));
    }
}
