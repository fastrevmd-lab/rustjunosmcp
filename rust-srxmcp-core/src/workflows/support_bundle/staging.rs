//! LXC-side staging for bundles fetched from devices via `fetch_file`.
//!
//! Layout:
//! ```text
//! $JMCP_SRX_STAGING_DIR/
//!     <router>/
//!         srxmcp-<request_id>.tgz   # the on-device tarball, pulled via fetch_file
//!         srxmcp-<request_id>.json  # sidecar manifest (request_id, router, problem_types, sha256, size)
//! ```
//!
//! Env vars (resolved at orchestrator startup):
//! * `JMCP_SRX_STAGING_DIR` — default `/var/lib/rust-srxmcp/staging/bundles/`
//! * `JMCP_SRX_STAGING_MAX_BYTES` — default `524_288_000` (500 MiB)
//!
//! When a new bundle would push the staging dir over the cap, the
//! oldest-mtime sibling bundle is evicted (LRU). If evicting every
//! evictable bundle still leaves the new one over the cap, the orchestrator
//! returns [`crate::error::SrxError::BundleStagingFull`].

use std::path::PathBuf;

/// Default staging directory if `JMCP_SRX_STAGING_DIR` is unset.
pub const DEFAULT_STAGING_DIR: &str = "/var/lib/rust-srxmcp/staging/bundles";

/// Default staging cap if `JMCP_SRX_STAGING_MAX_BYTES` is unset (500 MiB).
pub const DEFAULT_STAGING_MAX_BYTES: u64 = 500 * 1024 * 1024;

/// Resolves the effective staging directory from the environment, falling
/// back to [`DEFAULT_STAGING_DIR`].
pub fn staging_dir_from_env() -> PathBuf {
    std::env::var("JMCP_SRX_STAGING_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_STAGING_DIR))
}

/// Resolves the effective staging cap from the environment, falling back
/// to [`DEFAULT_STAGING_MAX_BYTES`]. Invalid values fall back to the
/// default (orchestrator should log a warning).
pub fn staging_max_bytes_from_env() -> u64 {
    std::env::var("JMCP_SRX_STAGING_MAX_BYTES")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(DEFAULT_STAGING_MAX_BYTES)
}

/// Per-router subdirectory path under [`staging_dir_from_env`].
pub fn router_staging_dir(router: &str) -> PathBuf {
    staging_dir_from_env().join(router)
}

/// Canonical on-LXC path for a bundle's tarball, given `request_id`.
pub fn bundle_tarball_path(router: &str, request_id: &str) -> PathBuf {
    router_staging_dir(router).join(format!("srxmcp-{request_id}.tgz"))
}

/// Canonical on-LXC path for a bundle's sidecar manifest.
pub fn bundle_manifest_path(router: &str, request_id: &str) -> PathBuf {
    router_staging_dir(router).join(format!("srxmcp-{request_id}.json"))
}

/// Canonical on-device staging path for the tarball (under `/var/tmp` so it
/// survives `rmcp` client-disconnect per issue #44 and is re-fetchable via
/// the documented `fetch_file` chain).
pub fn device_tarball_path(request_id: &str) -> String {
    format!("/var/tmp/srxmcp-{request_id}.tgz")
}

/// LRU eviction stub. Will scan `staging_dir_from_env()`, compute total
/// bytes, and evict oldest-mtime `.tgz` + `.json` pairs until under cap.
/// Implementation lands in Task #13 (orchestrator).
pub fn enforce_staging_cap(_cap_bytes: u64) -> std::io::Result<()> {
    // TODO(task-13): walk dir, collect (path, mtime, size), sort by mtime
    // ascending, remove until cumulative_remaining <= cap.
    Ok(())
}
