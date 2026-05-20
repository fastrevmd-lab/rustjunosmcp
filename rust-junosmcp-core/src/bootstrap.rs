//! Process bootstrap helpers shared by `rust-junosmcp` and `rust-srxmcp`.
//!
//! These are byte-for-byte extractions of code that used to live inline in
//! the rust-junosmcp binary's `main.rs`. The function bodies are unchanged;
//! only the call sites move into helper-call form so the same setup logic
//! is reused by both binaries.

use tracing_subscriber::EnvFilter;

/// Initialize the global tracing subscriber.
///
/// Reads `RUST_LOG` via env-filter, defaults to `info`. Writes to stderr so
/// stdout stays clean for stdio-mode MCP transport.
///
/// Idempotent: calling twice silently no-ops the second call (uses
/// `try_init` instead of `init` so the second call's "global default has
/// already been set" error is discarded).
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

use crate::{HostKeyVerification, Inventory};
use std::path::{Path, PathBuf};
use std::sync::Arc;

// Error-shape choice: Shape A variant using JmcpError.
// Both Inventory::load (returns JmcpError directly) and hash_file (returns
// std::io::Error, which JmcpError implements From for via the Io variant)
// convert cleanly via `?`. No anyhow dep needed in rust-junosmcp-core.

/// Load and hash the device inventory JSON file in one call.
///
/// Returns the Arc-wrapped inventory and its content sha256 for the
/// inventory-mutation provenance chain. Errors propagate from the
/// underlying `Inventory::load` / `inventory::hash_file` calls; the binary's
/// main.rs is responsible for any user-facing context (path display etc.).
pub fn load_inventory(path: &Path) -> Result<(Arc<Inventory>, [u8; 32]), crate::JmcpError> {
    let inventory = Arc::new(Inventory::load(path)?);
    let hash = crate::inventory::hash_file(path)?;
    Ok((inventory, hash))
}

/// Build the host-key verification policy for NETCONF SSH.
///   - `accept_new = true`  → `AcceptAll` (lab/TOFU mode)
///   - `accept_new = false` → `KnownHosts(known_hosts_file)` (strict, default)
pub fn build_host_key_policy(accept_new: bool, known_hosts_file: PathBuf) -> HostKeyVerification {
    if accept_new {
        HostKeyVerification::AcceptAll
    } else {
        HostKeyVerification::KnownHosts(known_hosts_file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_tracing_is_idempotent() {
        init_tracing();
        init_tracing(); // must not panic on second call
    }

    #[test]
    fn build_host_key_policy_strict_default() {
        let policy = build_host_key_policy(false, std::path::PathBuf::from("/tmp/kh"));
        match policy {
            HostKeyVerification::KnownHosts(p) => {
                assert_eq!(p, std::path::PathBuf::from("/tmp/kh"))
            }
            _ => panic!("expected KnownHosts variant"),
        }
    }

    #[test]
    fn build_host_key_policy_accept_all_when_opted_in() {
        let policy = build_host_key_policy(true, std::path::PathBuf::from("/tmp/kh"));
        assert!(matches!(policy, HostKeyVerification::AcceptAll));
    }

    #[test]
    fn load_inventory_reads_file_and_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        std::fs::write(
            &path,
            r#"{"r1":{"ip":"1.2.3.4","username":"u","auth":{"type":"password","password":"x"}}}"#,
        )
        .unwrap();
        let (inv, hash) = load_inventory(&path).unwrap();
        assert!(!inv.names().is_empty());
        assert_eq!(hash.len(), 32);
        // Hash is deterministic for same content
        let (_, hash2) = load_inventory(&path).unwrap();
        assert_eq!(hash, hash2);
    }
}
