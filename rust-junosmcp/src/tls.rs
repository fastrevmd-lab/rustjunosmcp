//! Hardened TLS loader from mecmcp-transport.
//!
//! This is a thin shim over `mecmcp_transport::tls::load` that installs the
//! `ring` crypto provider and delegates the actual loading. The hardened
//! loader from mecmcp-transport enforces:
//! - O_NOFOLLOW (defeats symlink swap attacks)
//! - mode ≤ 0600 for private keys (refuses world-readable keys)
//! - owner check (effective UID or root only)
//! - size caps (1 MiB cert, 128 KiB key)
//! - Zeroizing wrappers for key bytes
//!
//! **Breaking change from the old loader:** A deployment whose key file is
//! looser than 0600 will refuse to start. That is the correct outcome, but it
//! is operator-visible. The error message names the file, its mode, and the
//! remedy (`chmod 0600 <path>`).

#![cfg(feature = "tls")]

use anyhow::{Context, Result};
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

/// Load TLS cert and key using the hardened loader from mecmcp-transport.
///
/// This delegates to `mecmcp_transport::tls::load` with the `ring` crypto
/// provider. The loader enforces strict security checks — see module docs.
pub fn load(cert: &Path, key: &Path) -> Result<Arc<rustls::ServerConfig>> {
    ensure_default_provider();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    mecmcp_transport::tls::load(cert, key, provider)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| {
            format!(
                "loading TLS cert {} and key {}",
                cert.display(),
                key.display()
            )
        })
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

        // Set key to 0600 as the hardened loader requires.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&key_path).unwrap().permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&key_path, perms).unwrap();
        }

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
        // mecmcp-transport TlsError::Io wraps filesystem errors
        let msg = err.to_string();
        assert!(msg.contains("TLS") || msg.contains("No such file"));
    }

    #[test]
    fn load_empty_cert_errors() {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, b"").unwrap();
        std::fs::write(&key_path, issued.signing_key.serialize_pem()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&key_path).unwrap().permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&key_path, perms).unwrap();
        }

        let err = load(&cert_path, &key_path).unwrap_err();
        // The wrapper adds context; mecmcp-transport's TlsError shows through :?
        let msg = format!("{:?}", err);
        // The error chain contains both the context and the underlying TLS error
        assert!(msg.contains("certificate") || msg.contains("PEM") || msg.contains("TLS"));
    }

    #[test]
    #[cfg(unix)]
    fn refuses_world_readable_key() {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, issued.cert.pem()).unwrap();
        std::fs::write(&key_path, issued.signing_key.serialize_pem()).unwrap();

        // Set key to 0644 (world-readable) — the hardened loader must refuse this.
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&key_path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&key_path, perms).unwrap();

        let err = load(&cert_path, &key_path).unwrap_err();
        let msg = format!("{:?}", err);
        // mecmcp-transport TlsError::UnsafeFile includes the mode in octal and remedy
        assert!(msg.contains("644") && msg.contains("chmod") && msg.contains("0600"));
    }
}
