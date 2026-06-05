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
//! ## Implementation note (deviation from design doc)
//!
//! The design specifies an **on-device** tarball assembled via
//! `request support information | save /var/tmp/srxmcp-<rid>.tgz` for the
//! `generic` problem_type and a device-side `file-archive` chain for the
//! per-type paths. Both paths instead assemble the tarball **on the LXC**
//! side under `JMCP_SRX_STAGING_DIR/<router>/srxmcp-<rid>.tgz`:
//!
//! * **`generic` path**: `request support information` is issued (without
//!   the `| save` pipe) via the NETCONF `command` RPC; the full
//!   tech-support text comes back INLINE and is written into the staging
//!   scratch dir, then tarred. The `| save <path>` redirection is NOT
//!   honoured over the NETCONF `command` RPC (it writes nothing on-device
//!   while still returning the payload inline), so the earlier device-side
//!   variant reported success but produced no file — see issue #81.
//! * **Per-`problem_type` path**: the captured RPC replies are written as
//!   XML files; `/var/log/*` files are pulled inline via `file show <path>`
//!   over the same pooled `command` RPC (the `fetch_file` SCP primitive
//!   only serves basenames out of `/var/tmp`, so it cannot reach the log
//!   dir), size-capped by `max_log_bytes_per_file` and count-capped by
//!   `max_log_files`, then staged into `logs/<device-path>`.
//!
//! Both paths share [`finalize_lxc_bundle`] for manifest write + tarball
//! assembly + sha256, and both report `bundle.location = "lxc_staging"`.
//! The response carries an LXC-side `path` and the LLM is instructed to
//! read it directly off LXC 601 (no `fetch_file` chain).

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
    // skip everything else and run `request support information`.
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

// ── Generic path: LXC-side tarball from inline `request support information` ───

async fn collect_generic(
    device: &mut PooledDevice,
    router: &str,
    request_id: &str,
    args: &SupportBundleArgs,
) -> Result<SupportBundleData, SrxError> {
    let staging_root = router_staging_dir(router);
    std::fs::create_dir_all(&staging_root).map_err(|e| {
        SrxError::InvalidInput(format!(
            "cannot create staging dir {}: {e}",
            staging_root.display()
        ))
    })?;
    let scratch = staging_root.join(format!("srxmcp-{request_id}-scratch"));
    std::fs::create_dir_all(&scratch)
        .map_err(|e| SrxError::InvalidInput(format!("cannot create scratch dir: {e}")))?;

    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    // `request support information` over the NETCONF `command` RPC returns
    // the full tech-support text INLINE — the `| save <path>` pipe is NOT
    // honoured on the wire (it writes nothing on-device while still
    // returning the payload), so we capture the payload here and assemble
    // the tarball on the LXC side, exactly like the per-type path. The
    // defensive tokio::time::timeout keeps a wedged RPC off the per-router
    // lock. See issue #81.
    let deadline = Duration::from_secs(args.timeout.min(3600));
    let call = exec.cli("request support information", "text");
    let payload = tokio::time::timeout(deadline, call)
        .await
        .map_err(|_| SrxError::ClusterHealthCheckTimeout {
            router: router.to_string(),
            elapsed_secs: deadline.as_secs(),
        })?
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    if payload.trim().is_empty() {
        let _ = std::fs::remove_dir_all(&scratch);
        return Err(SrxError::BundleConfigCaptureFailed {
            router: router.to_string(),
            detail: "`request support information` returned no output".into(),
        });
    }

    let (payload, redacted) = if args.redact {
        let red = redact_xml(&payload);
        let changed = red != payload;
        (red, changed)
    } else {
        (payload, false)
    };

    let fname = "request-support-information.txt";
    let abs_path = scratch.join(fname);
    std::fs::write(&abs_path, payload.as_bytes())
        .map_err(|e| SrxError::InvalidInput(format!("write {}: {e}", abs_path.display())))?;

    let artefacts = vec![CapturedArtefact {
        source: ArtefactSource::Rpc {
            name: "request support information".into(),
            args: None,
        },
        tarball_path: fname.into(),
        sha256: sha256_hex(payload.as_bytes()),
        bytes_in_tarball: payload.len() as u64,
        redacted,
        error: None,
    }];

    let mut problem_types = BTreeSet::new();
    problem_types.insert(ProblemType::Generic);
    finalize_lxc_bundle(
        router,
        request_id,
        &staging_root,
        &scratch,
        artefacts,
        &problem_types,
        redacted,
    )
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

    // 2) Log file capture. Junos serves `/var/log/*` over the NETCONF
    //    `command` RPC via `file show <path>`, returning the file content
    //    INLINE as text (the `| save` redirect is unavailable here — see
    //    #81 — and the `fetch_file` SCP primitive only pulls basenames out
    //    of `/var/tmp`, so neither applies). We capture inline, enforce the
    //    `max_log_bytes_per_file` size cap and the `max_log_files` count
    //    cap, and stage each log into `logs/<device-path>` in the tarball.
    if args.include_logs {
        let mut all_logs: BTreeSet<&str> = BASELINE_LOGS.iter().copied().collect();
        for pt in problem_types {
            for log in pt.additional_logs() {
                all_logs.insert(log);
            }
        }
        let cap_bytes = args.max_log_bytes_per_file as usize;
        let mut captured: u32 = 0;
        for path in all_logs {
            let rel = format!("logs/{}", path.trim_start_matches('/'));
            // Enforce the count cap: record a skip marker so JTAC sees
            // which logs were intentionally omitted.
            if captured >= args.max_log_files {
                artefacts.push(CapturedArtefact {
                    source: ArtefactSource::LogFile {
                        device_path: path.to_string(),
                    },
                    tarball_path: rel,
                    sha256: String::new(),
                    bytes_in_tarball: 0,
                    redacted: false,
                    error: Some(format!(
                        "skipped: max_log_files={} reached",
                        args.max_log_files
                    )),
                });
                continue;
            }

            let raw = match exec.cli(&format!("file show {path}"), "text").await {
                Ok(text) => text,
                Err(e) => {
                    artefacts.push(CapturedArtefact {
                        source: ArtefactSource::LogFile {
                            device_path: path.to_string(),
                        },
                        tarball_path: rel,
                        sha256: String::new(),
                        bytes_in_tarball: 0,
                        redacted: false,
                        error: Some(format!("file show {path}: {e}")),
                    });
                    continue;
                }
            };
            // Junos emits a plain `error: ...` line (not an rpc-error) when
            // a file is absent or unreadable; treat that as a per-artefact
            // error rather than archiving the error text as log data.
            if raw.trim_start().starts_with("error:") {
                artefacts.push(CapturedArtefact {
                    source: ArtefactSource::LogFile {
                        device_path: path.to_string(),
                    },
                    tarball_path: rel,
                    sha256: String::new(),
                    bytes_in_tarball: 0,
                    redacted: false,
                    error: Some(raw.trim().to_string()),
                });
                continue;
            }

            let mut content = raw;
            let truncated = truncate_to_char_boundary(&mut content, cap_bytes);

            // Redaction is wired here for parity with the RPC loop. Log files
            // are plain text, so `redact_xml` fails its well-formedness gate
            // and returns them unchanged (`redacted` stays false); secrets
            // embedded in log lines need a separate text-pattern pass (#85).
            let (payload, redacted) = if args.redact {
                let red = redact_xml(&content);
                let changed = red != content;
                any_redacted |= changed;
                (red, changed)
            } else {
                (content, false)
            };

            let abs_path = scratch.join(&rel);
            if let Some(parent) = abs_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    SrxError::InvalidInput(format!("create log dir {}: {e}", parent.display()))
                })?;
            }
            std::fs::write(&abs_path, payload.as_bytes()).map_err(|e| {
                SrxError::InvalidInput(format!("write {}: {e}", abs_path.display()))
            })?;

            artefacts.push(CapturedArtefact {
                source: ArtefactSource::LogFile {
                    device_path: path.to_string(),
                },
                tarball_path: rel,
                sha256: sha256_hex(payload.as_bytes()),
                bytes_in_tarball: payload.len() as u64,
                redacted,
                error: if truncated {
                    Some(format!(
                        "truncated to max_log_bytes_per_file={}",
                        args.max_log_bytes_per_file
                    ))
                } else {
                    None
                },
            });
            captured += 1;
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

    // 3) Write the manifest, assemble the tarball, and compute its digest.
    finalize_lxc_bundle(
        router,
        request_id,
        &staging_root,
        &scratch,
        artefacts,
        problem_types,
        any_redacted,
    )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Write `manifest.json` into the scratch dir, tar the scratch dir into the
/// per-router LXC staging area, clean up the scratch dir, enforce the
/// staging cap, and compute the tarball's size + sha256. Shared by the
/// `generic` and per-type collection paths so both land an identical
/// `lxc_staging` bundle layout.
fn finalize_lxc_bundle(
    router: &str,
    request_id: &str,
    staging_root: &Path,
    scratch: &Path,
    artefacts: Vec<CapturedArtefact>,
    problem_types: &BTreeSet<ProblemType>,
    any_redacted: bool,
) -> Result<SupportBundleData, SrxError> {
    // Write manifest.json into the scratch dir so it lands in the tarball.
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

    // Assemble the tarball with the system `tar` (avoids adding a
    // flate2 + tar dep to rust-srxmcp-core for one call site).
    let tarball_path = bundle_tarball_path(router, request_id);
    let out = std::process::Command::new("tar")
        .arg("-czf")
        .arg(&tarball_path)
        .arg("-C")
        .arg(staging_root)
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

    // Clean up the scratch dir; the tarball is the bundle.
    let _ = std::fs::remove_dir_all(scratch);

    // Enforce staging cap (LRU eviction) — stub today.
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

/// Truncate `s` in place to at most `cap` bytes, backing up to the nearest
/// UTF-8 char boundary so the result stays valid UTF-8. Returns `true` if
/// any bytes were dropped.
fn truncate_to_char_boundary(s: &mut String, cap: usize) -> bool {
    if s.len() <= cap {
        return false;
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    true
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
    fn truncate_to_char_boundary_respects_utf8_and_cap() {
        // Under cap: untouched.
        let mut s = "hello".to_string();
        assert!(!truncate_to_char_boundary(&mut s, 10));
        assert_eq!(s, "hello");

        // Exactly at cap: untouched.
        let mut s = "hello".to_string();
        assert!(!truncate_to_char_boundary(&mut s, 5));
        assert_eq!(s, "hello");

        // Over cap on ASCII: trims to cap.
        let mut s = "hello world".to_string();
        assert!(truncate_to_char_boundary(&mut s, 5));
        assert_eq!(s, "hello");

        // Multi-byte: "é" is 2 bytes — a cap of 1 must back up to 0 rather
        // than split the char (which would otherwise panic).
        let mut s = "é".to_string();
        assert!(truncate_to_char_boundary(&mut s, 1));
        assert_eq!(s, "");
        assert!(s.is_empty());
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

    // Regression for #81: the generic path used to report success with a
    // zero-byte/empty-hash bundle because `request support information |
    // save` wrote nothing on-device. The path now stages the inline payload
    // and assembles a real tarball — `finalize_lxc_bundle` must produce a
    // non-empty, hashed `lxc_staging` bundle.
    #[test]
    fn finalize_lxc_bundle_produces_nonempty_tarball() {
        let tmp = std::env::temp_dir().join(format!("srxmcp-test-{}", mint_request_id()));
        std::fs::create_dir_all(&tmp).expect("tmp dir");
        // Safe under edition 2021; no other test mutates this var.
        std::env::set_var("JMCP_SRX_STAGING_DIR", &tmp);

        let router = "vSRX-finalize-unit";
        let request_id = "srxmcp-unit-0001";
        let staging_root = router_staging_dir(router);
        std::fs::create_dir_all(&staging_root).expect("staging root");
        let scratch = staging_root.join(format!("srxmcp-{request_id}-scratch"));
        std::fs::create_dir_all(&scratch).expect("scratch");
        let payload = b"hello tech-support output";
        std::fs::write(scratch.join("request-support-information.txt"), payload).expect("write");

        let artefacts = vec![CapturedArtefact {
            source: ArtefactSource::Rpc {
                name: "request support information".into(),
                args: None,
            },
            tarball_path: "request-support-information.txt".into(),
            sha256: sha256_hex(payload),
            bytes_in_tarball: payload.len() as u64,
            redacted: false,
            error: None,
        }];
        let mut problem_types = BTreeSet::new();
        problem_types.insert(ProblemType::Generic);

        let data = finalize_lxc_bundle(
            router,
            request_id,
            &staging_root,
            &scratch,
            artefacts,
            &problem_types,
            false,
        )
        .expect("finalize");

        assert_eq!(data.bundle.location, BundleLocation::LxcStaging);
        assert!(
            data.bundle.bytes > 0,
            "tarball must be non-empty (regression for #81)"
        );
        assert_eq!(data.bundle.sha256.len(), 64);
        assert!(Path::new(&data.bundle.path).exists());
        assert!(!scratch.exists(), "scratch dir should be cleaned up");

        std::env::remove_var("JMCP_SRX_STAGING_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
