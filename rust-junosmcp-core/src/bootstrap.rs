//! Process bootstrap helpers for `rust-junosmcp`.
//!
//! These are byte-for-byte extractions of code that used to live inline in
//! the rust-junosmcp binary's `main.rs` so startup concerns stay reusable and
//! testable.

use tracing_subscriber::EnvFilter;

/// Initialize the global tracing subscriber.
///
/// Reads `RUST_LOG` via env-filter, defaults to `info`. Writes to stderr so
/// stdout stays clean for stdio-mode MCP transport.
///
/// Idempotent: calling twice silently no-ops the second call (uses
/// `try_init` instead of `init` so the second call's "global default has
/// already been set" error is discarded).
///
/// Colour is enabled only when stderr is a terminal. `tracing_subscriber::fmt`
/// defaults ANSI on whenever the feature is compiled in, without asking whether
/// anything can render it, so piping stderr to a file, to journald, or to a
/// parent process previously embedded escape sequences in every line. That
/// makes a field like `tool=execute` unmatchable by a plain substring search --
/// the emitted bytes are `tool\x1b[0m\x1b[2m=\x1b[0mexecute` -- which breaks
/// log greps and any caller parsing this stream.
///
/// This does not affect the JSON audit sink, which never carried ANSI.
pub fn init_tracing() {
    use std::io::IsTerminal as _;

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
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
/// inventory-mutation provenance chain. When the inventory file does not
/// exist, returns a clear actionable error. Other errors propagate from the
/// underlying `Inventory::load` / `inventory::hash_file` calls.
pub fn load_inventory(path: &Path) -> Result<(Arc<Inventory>, [u8; 32]), crate::JmcpError> {
    use std::io::ErrorKind;

    match Inventory::load(path) {
        Ok(inv) => {
            let hash = crate::inventory::hash_file(path)?;
            Ok((Arc::new(inv), hash))
        }
        Err(crate::JmcpError::Io(io_err)) if io_err.kind() == ErrorKind::NotFound => {
            Err(crate::JmcpError::InventoryRead(format!(
                "devices.json not found at {}; copy devices.json.example and edit it",
                path.display()
            )))
        }
        Err(e) => Err(e),
    }
}

/// Build the host-key verification policy for NETCONF SSH connections.
///
/// Returns either strict known-hosts checking (production default) or
/// accept-all mode (lab/TOFU setups only).
///
/// - `accept_new = true` → `HostKeyVerification::AcceptAll` (lab/TOFU mode)
/// - `accept_new = false` → `HostKeyVerification::KnownHosts(known_hosts_file)` (strict, production default)
///
/// Production callers should pass `false` and supply a known_hosts file path.
/// Lab setups may pass `true` to skip host-key validation, accepting any key
/// on first connect (TOFU).
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
        crate::helpers::write_restricted_fixture(
            &path,
            r#"{"r1":{"ip":"1.2.3.4","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let (inv, hash) = load_inventory(&path).unwrap();
        assert!(!inv.names().is_empty());
        assert_eq!(hash.len(), 32);
        // Hash is deterministic for same content
        let (_, hash2) = load_inventory(&path).unwrap();
        assert_eq!(hash, hash2);
    }
}
