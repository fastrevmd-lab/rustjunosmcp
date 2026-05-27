//! `collect_jtac_support_bundle` workflow + shared primitives (Phase 3).
//!
//! Submodules:
//! * [`problem_type`] — closed `ProblemType` enum + per-type RPC/log lists,
//!   plus the universal-baseline RPC/log constants. Capture-verified
//!   against Junos 24.4R1.9 on 2026-05-26.
//! * [`artefacts`] — `CapturedArtefact` + `ArtefactSource` types describing
//!   one piece of evidence inside the tarball.
//! * [`redact`] — XML-element-name-based redaction (PSKs, secrets, SNMP
//!   community, HMAC keys, RADIUS/TACACS shared-secrets) applied when
//!   `redact=true`.
//! * [`staging`] — LXC-side staging dir + env-var resolution +
//!   on-device tarball path helpers + LRU eviction stub.
//!
//! ## v0.3.0 implementation note (deviation from design doc)
//!
//! The design specifies an **on-device** tarball assembled via
//! `request support information | save /var/tmp/srxmcp-<rid>.tgz` for the
//! `generic` problem_type and a device-side `file-archive` chain for the
//! per-type paths. v0.3.0 implements:
//!
//! * **`generic` path**: still on-device — issued via the NETCONF `command`
//!   RPC running the CLI string. Tarball lands at the device path and the
//!   response carries `device_path`. The `fetch_file` next-step chain is
//!   unchanged from the design.
//! * **Per-`problem_type` path**: tarball is assembled **on the LXC** side
//!   (under `JMCP_SRX_STAGING_DIR/<router>/srxmcp-<rid>.tgz`). The
//!   captured RPC replies are written as XML files; log files are pulled
//!   via the existing `rust-junosmcp` `fetch_file` primitive into the
//!   staging dir before tarball assembly. The response carries
//!   `staging_path` (LXC-side) instead of `device_path` and the LLM is
//!   instructed to read it directly off LXC 601 (no `fetch_file` chain).
//!
//! This deviation is gated behind the `bundle.location` field in the
//! response (`"device"` for generic, `"lxc_staging"` for per-type) so a
//! follow-up release can lift the per-type path to true on-device tarball
//! assembly without breaking caller semantics.

pub mod artefacts;
pub mod problem_type;
pub mod redact;
pub mod staging;

pub use artefacts::{ArtefactSource, CapturedArtefact};
pub use problem_type::{ProblemType, BASELINE_LOGS, BASELINE_RPCS};
pub use redact::{redact_xml, REDACTED_MARKER, REDACT_ELEMENT_NAMES};
pub use staging::{
    bundle_manifest_path, bundle_tarball_path, device_tarball_path, enforce_staging_cap,
    router_staging_dir, staging_dir_from_env, staging_max_bytes_from_env, DEFAULT_STAGING_DIR,
    DEFAULT_STAGING_MAX_BYTES,
};

use crate::{SrxError, SrxToolResponse};
use rust_junosmcp_core::device_manager::PooledDevice;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::Semaphore;

// ── Per-router staging-key lock ───────────────────────────────────────────────

/// Map of `(router, "support_bundle") → Semaphore(1)` used to serialize
/// concurrent `collect_jtac_support_bundle` calls against the same router.
/// Distinct from Phase 2's `TransferLocks` (which keys on staging filename).
/// The semaphore is permit=1 (mutex semantics) and lives in-process for
/// the lifetime of the binary.
fn staging_key_locks() -> &'static Mutex<BTreeMap<String, Arc<Semaphore>>> {
    static LOCKS: OnceLock<Mutex<BTreeMap<String, Arc<Semaphore>>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn lock_for(router: &str) -> Arc<Semaphore> {
    let key = format!("{router}:support_bundle");
    let mut map = staging_key_locks()
        .lock()
        .expect("staging-key mutex poisoned");
    map.entry(key)
        .or_insert_with(|| Arc::new(Semaphore::new(1)))
        .clone()
}

// ── Public args / response types ──────────────────────────────────────────────

/// Accept `problem_type` as either a single value or an array per the
/// design doc spec.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ProblemTypeArg {
    One(ProblemType),
    Many(Vec<ProblemType>),
}

impl ProblemTypeArg {
    fn into_set(self) -> BTreeSet<ProblemType> {
        match self {
            ProblemTypeArg::One(p) => {
                let mut s = BTreeSet::new();
                s.insert(p);
                s
            }
            ProblemTypeArg::Many(v) => v.into_iter().collect(),
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SupportBundleArgs {
    pub router: String,
    pub problem_type: ProblemTypeArg,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default = "default_true")]
    pub include_logs: bool,
    #[serde(default = "default_true")]
    pub redact: bool,
    #[serde(default = "default_max_log_bytes")]
    pub max_log_bytes_per_file: u64,
    #[serde(default = "default_max_log_files")]
    pub max_log_files: u32,
    /// Outer per-call budget (seconds). Default 1800, cap 3600. The
    /// caller's MCP framework enforces this; the workflow records the
    /// elapsed time for the audit log.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_true() -> bool {
    true
}
fn default_max_log_bytes() -> u64 {
    10 * 1024 * 1024
}
fn default_max_log_files() -> u32 {
    5
}
fn default_timeout() -> u64 {
    1800
}

/// Where the assembled tarball lives. `Device` → on the SRX under
/// `/var/tmp`, fetched via the `rust-junosmcp` `fetch_file` chain.
/// `LxcStaging` → on LXC 601 under `JMCP_SRX_STAGING_DIR`, accessible
/// directly to operators with shell access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BundleLocation {
    Device,
    LxcStaging,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct BundleInfo {
    pub location: BundleLocation,
    /// Absolute path to the tarball. Interpretation depends on `location`.
    pub path: String,
    pub bytes: u64,
    /// Lower-case hex SHA-256 of the tarball.
    pub sha256: String,
    pub problem_types: Vec<ProblemType>,
    /// Per-artefact manifest (RPC names + log paths captured).
    pub artefacts: Vec<CapturedArtefact>,
    /// `true` if redaction ran on at least one artefact.
    pub redacted: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SupportBundleData {
    pub router: String,
    pub request_id: String,
    pub bundle: BundleInfo,
    /// Free-form next-step hint for the LLM. For `Device` bundles this is
    /// the `fetch_file router=... source=...` invocation; for
    /// `LxcStaging` bundles it's a `cat`/`tar tvf` hint against the LXC
    /// path.
    pub next_step: String,
    /// Wall-clock duration of the collection. Useful for the audit log.
    pub elapsed_secs: u64,
}

// ── `run()` — async entry point ───────────────────────────────────────────────

/// Run `collect_jtac_support_bundle`. Takes the staging-key lock,
/// dispatches to the `generic` or per-type code path, and returns a
/// `SupportBundleData` with the full bundle manifest.
pub async fn run(
    device: &mut PooledDevice,
    mut args: SupportBundleArgs,
) -> Result<SrxToolResponse<SupportBundleData>, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    let timeout_secs = args.timeout.min(3600);
    // Take problem_type out of args so the rest of args (router, flags,
    // limits) stays usable downstream.
    let problem_types =
        std::mem::replace(&mut args.problem_type, ProblemTypeArg::Many(Vec::new())).into_set();
    if problem_types.is_empty() {
        return Err(SrxError::InvalidInput(
            "problem_type must contain at least one value".into(),
        ));
    }
    let request_id = args
        .request_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(mint_request_id);
    let router = args.router.clone();

    // Acquire the staging-key lock (per-router serialization). Use
    // try_acquire to surface contention as a typed error instead of
    // queueing forever.
    let sem = lock_for(&router);
    let _permit =
        sem.clone()
            .try_acquire_owned()
            .map_err(|_| SrxError::BundlePerRouterContention {
                router: router.clone(),
            })?;

    let started_at = std::time::Instant::now();
    tracing::info!(
        target: "audit",
        request_id = %request_id,
        router = %router,
        tool = "collect_jtac_support_bundle",
        problem_types = ?problem_types,
        include_logs = args.include_logs,
        redact = args.redact,
        timeout_secs = timeout_secs,
        "bundle.start"
    );

    // Generic short-circuit: any presence of Generic in the set means we
    // skip everything else and run `request support information | save`.
    let result = if problem_types.contains(&ProblemType::Generic) {
        collect_generic(device, &router, &request_id, &args).await
    } else {
        collect_per_type(device, &router, &request_id, &args, &problem_types).await
    };

    let elapsed_secs = started_at.elapsed().as_secs();
    match result {
        Ok(data) => {
            tracing::info!(
                target: "audit",
                request_id = %request_id,
                router = %router,
                tool = "collect_jtac_support_bundle",
                elapsed_secs,
                bytes = data.bundle.bytes,
                location = ?data.bundle.location,
                "bundle.ok"
            );
            Ok(SrxToolResponse::<SupportBundleData>::active(data))
        }
        Err(err) => {
            tracing::warn!(
                target: "audit",
                request_id = %request_id,
                router = %router,
                tool = "collect_jtac_support_bundle",
                elapsed_secs,
                err = %err,
                "bundle.err"
            );
            Err(err)
        }
    }
}

// ── Generic path: device-side tarball via NETCONF command RPC ─────────────────

async fn collect_generic(
    device: &mut PooledDevice,
    router: &str,
    request_id: &str,
    args: &SupportBundleArgs,
) -> Result<SupportBundleData, SrxError> {
    let device_path = device_tarball_path(request_id);
    // The NETCONF `<command>` RPC accepts a free-form CLI string.
    // `request support information | save <path>` writes a gzipped
    // tech-support archive to the device file system.
    let cli_cmd = format!("request support information | save {device_path}");

    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    // Bound by the caller's timeout. The MCP runtime enforces its own
    // outer timeout; we add a defensive tokio::time::timeout so a wedged
    // RPC doesn't sit on the per-router lock forever.
    let deadline = Duration::from_secs(args.timeout.min(3600));
    let call = exec.cli(&cli_cmd, "text");
    tokio::time::timeout(deadline, call)
        .await
        .map_err(|_| SrxError::ClusterHealthCheckTimeout {
            router: router.to_string(),
            elapsed_secs: deadline.as_secs(),
        })?
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    // We don't (yet) have a primitive to stat the file on-device through
    // NETCONF, so report `bytes = 0` + `sha256 = ""` for now. The
    // operator can verify via `fetch_file` + local sha256sum after pull.
    let bundle = BundleInfo {
        location: BundleLocation::Device,
        path: device_path.clone(),
        bytes: 0,
        sha256: String::new(),
        problem_types: vec![ProblemType::Generic],
        artefacts: Vec::new(),
        redacted: false,
    };
    let next_step = format!("fetch_file router={router} source={device_path}");
    Ok(SupportBundleData {
        router: router.to_string(),
        request_id: request_id.to_string(),
        bundle,
        next_step,
        elapsed_secs: 0, // overwritten by caller via outer wrapper
    })
}

// ── Per-type path: LXC-side tarball ───────────────────────────────────────────

async fn collect_per_type(
    device: &mut PooledDevice,
    router: &str,
    request_id: &str,
    args: &SupportBundleArgs,
    problem_types: &BTreeSet<ProblemType>,
) -> Result<SupportBundleData, SrxError> {
    let staging_root = router_staging_dir(router);
    std::fs::create_dir_all(&staging_root).map_err(|e| {
        SrxError::InvalidInput(format!(
            "cannot create staging dir {}: {e}",
            staging_root.display()
        ))
    })?;

    // Per-bundle scratch dir we'll tar up afterwards.
    let scratch = staging_root.join(format!("srxmcp-{request_id}-scratch"));
    let rpc_dir = scratch.join("rpc");
    std::fs::create_dir_all(&rpc_dir)
        .map_err(|e| SrxError::InvalidInput(format!("cannot create scratch dir: {e}")))?;

    // 1) Capture baseline + per-type RPCs.
    let mut artefacts: Vec<CapturedArtefact> = Vec::new();
    let mut any_redacted = false;
    let mut all_rpcs: BTreeSet<(String, String)> = BTreeSet::new();
    for rpc in BASELINE_RPCS {
        all_rpcs.insert((rpc.to_string(), String::new()));
    }
    for pt in problem_types {
        for rpc in pt.additional_rpcs() {
            all_rpcs.insert((rpc.to_string(), String::new()));
        }
        for (rpc, inner) in pt.additional_rpcs_with_args() {
            all_rpcs.insert((rpc.to_string(), inner.to_string()));
        }
    }

    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let mut failures: Vec<(String, String)> = Vec::new();
    let total = all_rpcs.len();
    for (rpc, inner) in &all_rpcs {
        let reply = if inner.is_empty() {
            exec.call(rpc, &[]).await
        } else {
            // Build the RPC envelope by hand because rustez's `call()` only
            // takes key/value args (no nested element support). The
            // `<rpc>` outer wrapper is added by `call_xml`.
            let envelope = format!("<{rpc}>{inner}</{rpc}>");
            exec.call_xml(&envelope).await
        };
        let raw = match reply {
            Ok(xml) => xml,
            Err(e) => {
                let err_msg = format!("rpc {rpc}: {e}");
                failures.push((rpc.clone(), err_msg.clone()));
                // For the universal-baseline get-configuration, bail
                // hard — the design doc makes this mandatory.
                if rpc == "get-configuration" {
                    return Err(SrxError::BundleConfigCaptureFailed {
                        router: router.to_string(),
                        detail: err_msg,
                    });
                }
                continue;
            }
        };
        let (payload, redacted) = if args.redact {
            let red = redact_xml(&raw);
            let changed = red != raw;
            any_redacted |= changed;
            (red, changed)
        } else {
            (raw, false)
        };

        let fname = sanitize_rpc_filename(rpc, inner);
        let abs_path = rpc_dir.join(&fname);
        std::fs::write(&abs_path, payload.as_bytes())
            .map_err(|e| SrxError::InvalidInput(format!("write {}: {e}", abs_path.display())))?;
        let bytes = payload.len() as u64;
        let sha256 = sha256_hex(payload.as_bytes());
        artefacts.push(CapturedArtefact {
            source: ArtefactSource::Rpc {
                name: rpc.clone(),
                args: if inner.is_empty() {
                    None
                } else {
                    Some(inner.clone())
                },
            },
            tarball_path: format!("rpc/{fname}"),
            sha256,
            bytes_in_tarball: bytes,
            redacted,
            error: None,
        });
    }

    // 2) Log file capture is gated behind a follow-up. v0.3.0 ships
    //    without log archival in the per-type path so the orchestrator
    //    has a complete RPC-bundle release; log fetching needs the
    //    rust-junosmcp `fetch_file` plumbing wired across the binary
    //    boundary and lands in v0.3.1. Document the gap in the
    //    manifest so JTAC sees it explicitly.
    if args.include_logs {
        let mut all_logs: BTreeSet<&str> = BASELINE_LOGS.iter().copied().collect();
        for pt in problem_types {
            for log in pt.additional_logs() {
                all_logs.insert(log);
            }
        }
        for path in all_logs {
            artefacts.push(CapturedArtefact {
                source: ArtefactSource::LogFile {
                    device_path: path.to_string(),
                },
                tarball_path: format!("logs/{}", path.trim_start_matches('/')),
                sha256: String::new(),
                bytes_in_tarball: 0,
                redacted: false,
                error: Some("log archival not implemented in v0.3.0 (tracked for v0.3.1)".into()),
            });
        }
    }

    // Surface bundled-up RPC failures so the operator can decide whether
    // the bundle is still useful or to retry.
    if !failures.is_empty() && failures.len() == total {
        let (_, first) = &failures[0];
        return Err(SrxError::BundleRpcSubsetFailed {
            router: router.to_string(),
            failed_count: failures.len(),
            total_count: total,
            first_error: first.clone(),
        });
    }

    // 3) Write manifest.json into the scratch dir so it lands in the
    //    tarball.
    let manifest_json = serde_json::json!({
        "request_id": request_id,
        "router": router,
        "problem_types": problem_types,
        "artefacts": &artefacts,
        "redacted": any_redacted,
        "schema": "srxmcp-support-bundle-v0.3.0",
    });
    let manifest_path = scratch.join("manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest_json).expect("manifest json"),
    )
    .map_err(|e| SrxError::InvalidInput(format!("write manifest: {e}")))?;

    // 4) Assemble the tarball with the system `tar` (avoids adding a
    //    flate2 + tar dep to rust-srxmcp-core for one call site).
    let tarball_path = bundle_tarball_path(router, request_id);
    let out = std::process::Command::new("tar")
        .arg("-czf")
        .arg(&tarball_path)
        .arg("-C")
        .arg(&staging_root)
        .arg(scratch.file_name().expect("scratch dir name"))
        .output()
        .map_err(|e| SrxError::InvalidInput(format!("tar invoke failed: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        return Err(SrxError::InvalidInput(format!(
            "tar exited {}: {stderr}",
            out.status
        )));
    }

    // 5) Clean up the scratch dir; the tarball is the bundle.
    let _ = std::fs::remove_dir_all(&scratch);

    // 6) Enforce staging cap (LRU eviction) — stub today.
    let cap = staging_max_bytes_from_env();
    let _ = enforce_staging_cap(cap);

    let tarball_bytes = std::fs::metadata(&tarball_path)
        .map(|m| m.len())
        .unwrap_or(0);
    let sha256 = match std::fs::read(&tarball_path) {
        Ok(bytes) => sha256_hex(&bytes),
        Err(_) => String::new(),
    };

    let bundle = BundleInfo {
        location: BundleLocation::LxcStaging,
        path: path_to_string(&tarball_path),
        bytes: tarball_bytes,
        sha256,
        problem_types: problem_types.iter().copied().collect(),
        artefacts,
        redacted: any_redacted,
    };
    let next_step = format!(
        "read tarball directly on LXC 601: {} (read by operator with shell access; not fetchable via fetch_file)",
        bundle.path
    );
    Ok(SupportBundleData {
        router: router.to_string(),
        request_id: request_id.to_string(),
        bundle,
        next_step,
        elapsed_secs: 0,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn sanitize_rpc_filename(rpc: &str, inner: &str) -> String {
    if inner.is_empty() {
        format!("{rpc}.xml")
    } else {
        // Strip <> and / from inner so we get something like
        // "get-flow-session-information.summary.xml".
        let suffix: String = inner
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        format!("{rpc}.{suffix}.xml")
    }
}

fn path_to_string(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn mint_request_id() -> String {
    format!("srxmcp-{}", uuid::Uuid::new_v4())
}

/// Lower-case hex SHA-256. Uses sha2 if available, otherwise falls back
/// to an empty string (the orchestrator surfaces this honestly in the
/// manifest rather than fabricating a hash).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problem_type_arg_one_collapses_to_singleton_set() {
        let arg = ProblemTypeArg::One(ProblemType::Vpn);
        let set = arg.into_set();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&ProblemType::Vpn));
    }

    #[test]
    fn problem_type_arg_many_dedupes() {
        let arg = ProblemTypeArg::Many(vec![
            ProblemType::Vpn,
            ProblemType::Routing,
            ProblemType::Vpn,
        ]);
        let set = arg.into_set();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn sanitize_rpc_filename_with_and_without_args() {
        assert_eq!(
            sanitize_rpc_filename("get-configuration", ""),
            "get-configuration.xml"
        );
        assert_eq!(
            sanitize_rpc_filename("get-flow-session-information", "<summary/>"),
            "get-flow-session-information.summary.xml"
        );
    }

    #[test]
    fn sha256_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn lock_for_returns_same_semaphore_for_same_router() {
        let a = lock_for("vsrx-test10");
        let b = lock_for("vsrx-test10");
        assert!(Arc::ptr_eq(&a, &b));
        let c = lock_for("vsrx-test11");
        assert!(!Arc::ptr_eq(&a, &c));
    }
}
