//! `manage_idp_security_package` — IDP signature-package lifecycle.
//!
//! Scope this file ships **today (Task 4, v0.2.0 milestone 1)**:
//! * Full args / action surface so callers can wire the MCP tool now.
//! * The `check_server` verb end-to-end (read-only, single-call,
//!   not audited — see design doc §"Two-call confirmation protocol").
//! * Pure parsers for the two RPCs `check_server` needs.
//!
//! Out of scope for Task 4 (lands in Tasks 5+):
//! * `download_and_install` verb (call 1 plan emission + call 2 destructive path).
//! * `rollback` verb.
//! * The pre-flight device-touching wrappers (`license_active`,
//!   `cluster_topology`, `signatures_server_reachable`).
//!
//! # Live-captured RPC contract (see design Appendix A)
//!
//! * `get-idp-security-package-information` →
//!   `<idp-security-package-information>` (standalone) or
//!   `<multi-routing-engine-results>` wrapping one per node.
//!   `<security-package-version>` carries the full text (e.g.
//!   `"3910(Minor, Thu May 21 …)"`) or `"N/A(N/A)"` on fresh devices.
//! * `request-idp-security-package-check-server` →
//!   `<secpack-download-status>` with free-text
//!   `<secpack-download-status-detail>`. The version is regex-extracted
//!   from `Version info:NNNN(...)`. If the configured signature URL
//!   is unreachable, the reply is `<xnm:error>` with message
//!   `"Fetching signed manifest.xml failed, error: Server not reachable"`.

use crate::workflows::signature_package::Service;
use crate::SrxError;
use rust_junosmcp_core::device_manager::PooledDevice;
use rust_junosmcp_core::tools::transfer_file::TransferLocks;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ── RPC names (live-verified, see design Appendix A) ──────────────────────────
//
// Module constants so a future Junos rename only edits one place per RPC.

const RPC_PACKAGE_INFORMATION: &str = "get-idp-security-package-information";
const RPC_CHECK_SERVER: &str = "request-idp-security-package-download-check-server";
const RPC_DOWNLOAD: &str = "request-idp-security-package-download";
const RPC_DOWNLOAD_STATUS: &str = "get-idp-security-package-download-status";
const RPC_INSTALL: &str = "request-idp-security-package-install";
const RPC_INSTALL_STATUS: &str = "get-idp-security-package-install-status";
// Used by Task 6 `rollback` verb.
#[allow(dead_code)]
const RPC_ROLLBACK: &str = "request-idp-security-package-rollback";

// Defaults for the destructive workflow. Per design §"Workflow phases":
// poll every 5s; outer budget 600s default, capped at 1800s.
const POLL_INTERVAL_SECS: u64 = 5;
const DEFAULT_TIMEOUT_SECS: u64 = 600;
const MAX_TIMEOUT_SECS: u64 = 1800;

// ── Public arg surface ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdpAction {
    CheckServer,
    DownloadAndInstall,
    Rollback,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct IdpPackageArgs {
    pub router: String,
    pub action: IdpAction,
    /// Pin to a specific package version (e.g. `"3714"`). Only meaningful
    /// for `download_and_install`; ignored otherwise.
    #[serde(default)]
    pub version: Option<String>,
    /// Required for destructive actions (`download_and_install`, `rollback`).
    /// Ignored for `check_server`.
    #[serde(default)]
    pub confirm: bool,
    /// Per-call outer budget in seconds (download poll + install poll combined).
    /// Default 600s (10 min), cap 1800s (30 min).
    #[serde(default)]
    pub timeout: Option<u64>,
    /// Append raw RPC replies to the response for debugging.
    #[serde(default)]
    pub include_raw: bool,
}

// ── `check_server` response types ─────────────────────────────────────────────

/// One row of the `nodes` array on the `check_server` response.
///
/// `re_name` is `""` for standalone devices, `"node0"` / `"node1"` for clusters.
/// `current_package_version` is the raw `<security-package-version>` text from
/// the device — `None` only when the element is missing or its text is
/// `"N/A(N/A)"` (fresh device with no signatures ever installed).
/// `current_detector_version` is the raw `<detector-version>` text — `None`
/// when absent or `"N/A"` (fresh device).
#[derive(Debug, Serialize, JsonSchema, Clone, PartialEq, Eq)]
pub struct IdpCheckServerNode {
    pub re_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_package_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_detector_version: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema, Clone, PartialEq, Eq)]
pub struct IdpCheckServerData {
    pub router: String,
    pub service: Service,
    pub topology: crate::workflows::signature_package::Topology,
    /// Leading numeric version reported by the Juniper signatures server
    /// (e.g. `"3910"`). Pulled from the `Version info:NNNN(...)` line in
    /// the `<secpack-download-status-detail>` free text.
    pub latest_version: String,
    pub nodes: Vec<IdpCheckServerNode>,
    /// True iff any node's `current_package_version` leading numeric does
    /// not match `latest_version`. A fresh device (`current = None`) counts
    /// as "needs update".
    pub update_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_xml: Option<String>,
}

// ── `check_server` — async entry point ────────────────────────────────────────

/// Run the read-only `check_server` verb. Issues two RPCs back-to-back:
/// 1. `get-idp-security-package-information` for the current installed version(s)
/// 2. `request-idp-security-package-download-check-server` for the latest
///    version published by `signatures.juniper.net`.
pub async fn check_server(
    device: &mut PooledDevice,
    args: &IdpPackageArgs,
) -> Result<IdpCheckServerData, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let info_xml = exec
        .call(RPC_PACKAGE_INFORMATION, &[])
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let check_xml = exec
        .call(RPC_CHECK_SERVER, &[])
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let nodes = parse_package_information(&info_xml)?;
    let latest_version = parse_check_server_reply(&check_xml, &args.router)?;

    let topology = if nodes.len() > 1 {
        crate::workflows::signature_package::Topology::ChassisCluster
    } else {
        crate::workflows::signature_package::Topology::Standalone
    };

    let update_available = nodes.iter().any(|n| {
        match n.current_package_version.as_deref() {
            None => true, // fresh device — always upgradeable
            Some(v) => leading_version_number(v) != leading_version_number(&latest_version),
        }
    });

    let raw_xml = if args.include_raw {
        Some(format!(
            "<!-- package-information -->\n{info_xml}\n<!-- check-server -->\n{check_xml}"
        ))
    } else {
        None
    };

    Ok(IdpCheckServerData {
        router: args.router.clone(),
        service: Service::Idp,
        topology,
        latest_version,
        nodes,
        update_available,
        raw_xml,
    })
}

// ── Parsers (pure, unit-testable) ─────────────────────────────────────────────

/// Parse a `<idp-security-package-information>` reply (standalone) or a
/// `<multi-routing-engine-results>` envelope wrapping one
/// `<idp-security-package-information>` per node (cluster).
///
/// Returns one [`IdpCheckServerNode`] per RE. `current_package_version` is
/// `None` when the device reports `"N/A(N/A)"` (fresh device, no signatures
/// ever installed) or the element is absent.
pub fn parse_package_information(reply_xml: &str) -> Result<Vec<IdpCheckServerNode>, SrxError> {
    let split = crate::xml::multi_re_split(reply_xml)?;
    if split.is_empty() {
        return Err(SrxError::schema_mismatch(
            RPC_PACKAGE_INFORMATION,
            "multi-routing-engine-item",
        ));
    }

    let mut out = Vec::with_capacity(split.len());
    for node in split {
        let info_xml = &node.inner_xml;
        // Standalone replies already start with <idp-security-package-information>;
        // for multi-RE, inner_xml contains that element directly too.
        let version_text = crate::xml::text_of(info_xml, "security-package-version");
        let normalized = version_text.and_then(|v| normalize_version_text(&v));
        let detector_text = crate::xml::text_of(info_xml, "detector-version");
        let normalized_detector = detector_text.and_then(|v| normalize_version_text(&v));
        out.push(IdpCheckServerNode {
            re_name: node.re_name,
            current_package_version: normalized,
            current_detector_version: normalized_detector,
        });
    }
    Ok(out)
}

/// Extract the latest-version string from a `check-server` reply.
///
/// Happy-path reply shape:
/// ```xml
/// <secpack-download-status format="xml">
///   <secpack-download-status-detail>Successfully retrieved from(https://signatures.juniper.net/cgi-bin/index.cgi).
/// Version info:3910(Minor, Detector=12.6.180250827, Templates=3910)</secpack-download-status-detail>
/// </secpack-download-status>
/// ```
///
/// Returns `"3910"`.
///
/// If the reply is an `<xnm:error>` with `"Server not reachable"` in the
/// message text, returns [`SrxError::SignaturePackageServerUnreachable`].
pub fn parse_check_server_reply(reply_xml: &str, router: &str) -> Result<String, SrxError> {
    // xnm:error channel first (see design Appendix A.2).
    if reply_xml.contains("<xnm:error") || reply_xml.contains("xmlns:xnm") {
        let msg = crate::xml::text_of(reply_xml, "message").unwrap_or_default();
        if !msg.is_empty() {
            return Err(SrxError::SignaturePackageServerUnreachable {
                router: router.to_string(),
                detail: msg,
            });
        }
    }

    let detail =
        crate::xml::text_of(reply_xml, "secpack-download-status-detail").ok_or_else(|| {
            SrxError::schema_mismatch(RPC_CHECK_SERVER, "secpack-download-status-detail")
        })?;

    // In-band "Done;...Failed;..." channel (rare on check-server but possible
    // — Junos uses the literal "Failed;" token per design Appendix A.2).
    if detail.contains("Failed;") {
        return Err(SrxError::SignaturePackageServerUnreachable {
            router: router.to_string(),
            detail,
        });
    }

    // Regex out "Version info:NNNN".
    extract_version_info(&detail).ok_or_else(|| {
        SrxError::Parse(format!(
            "{RPC_CHECK_SERVER}: missing 'Version info:NNNN' in detail text: {detail:?}"
        ))
    })
}

/// Normalise a `<security-package-version>` text:
/// * `"N/A(N/A)"` / `"N/A"` / empty / whitespace → `None`.
/// * Anything else → `Some(trimmed)`.
fn normalize_version_text(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("n/a") || t.starts_with("N/A(") {
        return None;
    }
    Some(t.to_string())
}

/// Extract the leading numeric token from a `Version info:NNNN(...)` line
/// in a free-text detail string. Returns `None` if no such pattern is found.
fn extract_version_info(detail: &str) -> Option<String> {
    let idx = detail.find("Version info:")?;
    let tail = &detail[idx + "Version info:".len()..];
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        Some(digits)
    }
}

/// Strip the parenthesised suffix from a version string for comparison:
/// `"3910(Minor, Thu …)"` → `"3910"`. Already-stripped values pass through.
fn leading_version_number(v: &str) -> &str {
    match v.find('(') {
        Some(i) => v[..i].trim(),
        None => v.trim(),
    }
}

// ── Async status parser (download + install share this contract) ─────────────

/// Terminal vs in-progress signal returned by an IDP async status RPC reply.
///
/// Junos's `<secpack-download-status-detail>` / `<secpack-status-detail>`
/// free-text field encodes phases inline per design Appendix A.2:
/// * `"Will be processed in async mode. ..."`  → still kicking off → Pending
/// * `"In progress:..."`                       → still working       → Pending
/// * `"Done;..."`                              → terminal success    → Done
/// * `"Failed;..."` (or text containing it)    → terminal failure    → Failed
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsyncStatusOutcome {
    Pending,
    Done,
    Failed(String),
}

/// Parse the free-text content of a status reply's detail element into a
/// phase signal. The `detail` string is expected to be the trimmed content
/// of either `<secpack-download-status-detail>` (download path) or
/// `<secpack-status-detail>` (install path).
///
/// Decision rules (order matters — "Failed;" beats "Done;" because the
/// "Done;Failed;..." compound shape exists per Appendix A.2):
/// 1. `"Failed;"` substring → `Failed(detail)`
/// 2. starts with `"Done;"` → `Done`
/// 3. starts with `"Will be processed"` → `Pending`
/// 4. starts with `"In progress:"` → `Pending`
/// 5. anything else → `Pending` (conservative — assume the device is still
///    working rather than erroring on an unfamiliar phrase)
pub fn parse_async_status_detail(detail: &str) -> AsyncStatusOutcome {
    let t = detail.trim();
    if t.contains("Failed;") {
        return AsyncStatusOutcome::Failed(t.to_string());
    }
    if t.starts_with("Done;") {
        return AsyncStatusOutcome::Done;
    }
    // Both "Will be processed" and "In progress:" map to Pending, as does
    // any text we don't recognise — Junos has never returned a terminal
    // state without one of the recognised tokens in the live captures.
    AsyncStatusOutcome::Pending
}

// ── Plan builder (pure) ───────────────────────────────────────────────────────

/// What `download_and_install` call 1 produces from the parsed pre-flight
/// snapshot: either a short-circuit "already at target" success or a plan
/// that needs the operator to re-call with `confirm=true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanOutcome {
    /// Every node already runs the target version — no destructive RPC will fire.
    AlreadyAtTarget(crate::workflows::signature_package::AlreadyAtTargetResponse),
    /// One or more nodes still need the target — emit the plan to the caller.
    NeedsConfirmation(crate::workflows::signature_package::ConfirmationPlan),
}

/// Build the call-1 response from a check_server snapshot + pinned-version
/// argument. Pure: no device I/O.
///
/// * `pinned` — `args.version` from the caller; when `Some(v)`, the target
///   becomes `v` and `target_source = "pinned"`; the value from
///   `check_server` is preserved in `latest_from_check_server` for visibility.
/// * `blockers` — pre-flight findings that should be surfaced in the plan
///   without escalating to an error. Used today only for the
///   commit-confirmed audit warn (carried as informational); reserved
///   for future warnings that don't quite reach `SrxError`.
///
/// Version comparison uses `leading_version_number` so `"3714(4.1)"`
/// equals `"3714"` (closes C1).
pub fn build_plan(
    snapshot: &IdpCheckServerData,
    pinned: Option<&str>,
    blockers: &[String],
) -> PlanOutcome {
    use crate::workflows::signature_package::{
        ConfirmationPlan, ConfirmationRequiredTag, DownloadAndInstallAction,
        DownloadAndInstallPlan, NodeVersionInfo, TargetSource,
    };

    let (target, target_source, latest_visibility) = match pinned {
        Some(v) if !v.trim().is_empty() => (
            v.trim().to_string(),
            TargetSource::Pinned,
            Some(snapshot.latest_version.clone()),
        ),
        _ => (
            snapshot.latest_version.clone(),
            TargetSource::LatestFromCheckServer,
            None,
        ),
    };
    let target_lead = leading_version_number(&target).to_string();

    // already_at_target short-circuit: every node already on the target.
    // A `None` current_package_version (fresh device) is NEVER at-target,
    // so the short-circuit doesn't fire.
    let all_at_target = !snapshot.nodes.is_empty()
        && snapshot
            .nodes
            .iter()
            .all(|n| match &n.current_package_version {
                None => false,
                Some(v) => leading_version_number(v) == target_lead,
            });

    if all_at_target {
        // Use the first node's current version as the response's "current"
        // (cluster nodes are normally in lockstep, so picking node0 is fine).
        let current = snapshot.nodes[0]
            .current_package_version
            .clone()
            .unwrap_or_default();
        return PlanOutcome::AlreadyAtTarget(
            crate::workflows::signature_package::AlreadyAtTargetResponse::new(
                snapshot.router.clone(),
                snapshot.service,
                current,
                target,
            ),
        );
    }

    let nodes = snapshot
        .nodes
        .iter()
        .map(|n| NodeVersionInfo {
            re_name: n.re_name.clone(),
            current_package_version: n
                .current_package_version
                .clone()
                .unwrap_or_else(|| "N/A".to_string()),
            current_detector_version: n.current_detector_version.clone(),
        })
        .collect();

    let warning = format!(
        "Will download IDP signature package {target} and install it on {router} ({topology}). \
         This briefly suspends IDP processing during attack-DB swap.",
        target = target,
        router = snapshot.router,
        topology = match snapshot.topology {
            crate::workflows::signature_package::Topology::Standalone => "standalone",
            crate::workflows::signature_package::Topology::ChassisCluster => "chassis cluster",
        }
    );

    let plan = DownloadAndInstallPlan {
        code: ConfirmationRequiredTag::ConfirmationRequired,
        router: snapshot.router.clone(),
        action: DownloadAndInstallAction::DownloadAndInstall,
        service: snapshot.service,
        topology: snapshot.topology,
        nodes,
        target_package_version: target,
        target_source,
        latest_from_check_server: latest_visibility,
        estimated_package_size_bytes: None,
        estimated_install_duration_seconds: None,
        preflight_blockers: blockers.to_vec(),
        warning,
    };
    PlanOutcome::NeedsConfirmation(ConfirmationPlan::DownloadAndInstall(plan))
}

// ── `download_and_install` — destructive workflow ─────────────────────────────

/// Terminal success payload returned by call 2 of `download_and_install`.
#[derive(Debug, Serialize, JsonSchema, Clone, PartialEq, Eq)]
pub struct DownloadAndInstallCompletedData {
    pub status: CompletedTag,
    pub router: String,
    pub service: Service,
    pub topology: crate::workflows::signature_package::Topology,
    pub target_package_version: String,
    pub installed_package_version: String,
    pub elapsed_seconds: u64,
}

#[derive(Debug, Serialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompletedTag {
    Completed,
}

/// Union returned to the MCP caller — either a call-1 `already_at_target`
/// short-circuit (no destructive RPC fired) or a call-2 `completed`
/// terminal success.
///
/// `confirmation_required` is **not** a variant here: it flows back as
/// `SrxError::SignaturePackageConfirmationRequired { plan }` so MCP
/// callers can pattern-match the bracketed `[code=confirmation_required]`
/// token on the error string.
#[derive(Debug, Serialize, JsonSchema, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum DownloadAndInstallResponse {
    AlreadyAtTarget(crate::workflows::signature_package::AlreadyAtTargetResponse),
    Completed(DownloadAndInstallCompletedData),
}

/// Run the `download_and_install` verb. Two-call protocol:
///
/// * `args.confirm == false`:
///   * Pre-flight runs (license + cluster + reachability + commit-confirmed warn).
///   * On `already_at_target`, returns `Ok(AlreadyAtTarget(...))`.
///   * Otherwise, builds the plan and returns
///     `Err(SignaturePackageConfirmationRequired { plan })` so the caller
///     can re-call with `confirm=true`.
/// * `args.confirm == true`:
///   * Per-router lock acquired **first** (closes TOCTOU per design D4),
///     then pre-flight re-runs under the lock.
///   * 12-phase pipeline: download → poll → install → poll → verify.
///   * Returns `Ok(Completed(...))` on terminal success.
pub async fn download_and_install(
    device: &mut PooledDevice,
    transfer_locks: &TransferLocks,
    args: &IdpPackageArgs,
    caller: Option<&str>,
    request_id: &str,
) -> Result<DownloadAndInstallResponse, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }

    // Call 1 — no lock yet, just preview + plan.
    if !args.confirm {
        let (snapshot, _blockers) = preflight(device, args).await?;
        match build_plan(&snapshot, args.version.as_deref(), &[]) {
            PlanOutcome::AlreadyAtTarget(resp) => {
                Ok(DownloadAndInstallResponse::AlreadyAtTarget(resp))
            }
            PlanOutcome::NeedsConfirmation(plan) => {
                let plan_value = serde_json::to_value(&plan)
                    .map_err(|e| SrxError::Parse(format!("serializing ConfirmationPlan: {e}")))?;
                Err(SrxError::SignaturePackageConfirmationRequired {
                    router: args.router.clone(),
                    plan: plan_value,
                })
            }
        }
    } else {
        // Call 2 — lock-first, then re-run pre-flight under the lock.
        let _permit = transfer_locks.acquire(&args.router).await;
        run_destructive(device, args, caller, request_id).await
    }
}

/// Pre-flight pipeline. Returns the `check_server` snapshot and a list of
/// non-fatal blockers (used today only for the commit-confirmed audit warn,
/// reserved for future warnings that surface in the plan without erroring).
async fn preflight(
    device: &mut PooledDevice,
    args: &IdpPackageArgs,
) -> Result<(IdpCheckServerData, Vec<String>), SrxError> {
    // License gate (escalates to SignaturePackageLicenseInactive on miss).
    crate::workflows::signature_package::preflight::license_active(
        device,
        &args.router,
        crate::workflows::license::SrxLicensedFeature::Idp,
    )
    .await?;

    // Cluster topology (escalates to SignaturePackageClusterDesynced on
    // non-{primary, secondary} member status).
    let topology =
        crate::workflows::signature_package::preflight::cluster_topology(device, &args.router)
            .await?;

    // Commit-confirmed window — non-blocking, just audit-warn if open.
    let mut blockers: Vec<String> = Vec::new();
    if let Ok(mut exec) = device.rpc() {
        if let Ok(commit_xml) = exec.call("get-commit-information", &[]).await {
            if let Ok(true) =
                crate::workflows::signature_package::preflight::detect_commit_confirmed(&commit_xml)
            {
                tracing::warn!(
                    target: "audit",
                    event = "sigpkg_commit_confirmed_window_active",
                    router = %args.router,
                    "commit-confirmed window open; proceeding because sig-package install is op-mode"
                );
                blockers.push("commit-confirmed window open (informational)".to_string());
            }
        }
    }

    // Server reachability + current-version snapshot.
    // check_server's own parser maps unreachable → SignaturePackageServerUnreachable.
    let mut snapshot = check_server(device, args).await?;
    // Pre-flight may have learnt a more accurate topology than check_server's
    // node-count heuristic — use the cluster RPC's verdict.
    snapshot.topology = topology;
    Ok((snapshot, blockers))
}

/// Destructive 12-phase workflow. Caller MUST hold the per-router lock.
async fn run_destructive(
    device: &mut PooledDevice,
    args: &IdpPackageArgs,
    caller: Option<&str>,
    request_id: &str,
) -> Result<DownloadAndInstallResponse, SrxError> {
    let started = tokio::time::Instant::now();
    let outer_budget = clamp_timeout(args.timeout);

    // Phase 3: re-run pre-flight under the lock (TOCTOU guard per design D4).
    let (snapshot, _blockers) = preflight(device, args).await?;

    // Resolve target: pinned wins over check_server's latest.
    let target = match args.version.as_deref() {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => snapshot.latest_version.clone(),
    };
    let target_lead = leading_version_number(&target).to_string();

    // If post-preflight we discover all nodes are already at target,
    // short-circuit (this can happen when call 1 said "needs confirm" but
    // someone else installed it between call 1 and call 2).
    let all_at_target = !snapshot.nodes.is_empty()
        && snapshot
            .nodes
            .iter()
            .all(|n| match &n.current_package_version {
                None => false,
                Some(v) => leading_version_number(v) == target_lead,
            });
    if all_at_target {
        let current = snapshot.nodes[0]
            .current_package_version
            .clone()
            .unwrap_or_default();
        return Ok(DownloadAndInstallResponse::AlreadyAtTarget(
            crate::workflows::signature_package::AlreadyAtTargetResponse::new(
                args.router.clone(),
                Service::Idp,
                current,
                target,
            ),
        ));
    }

    let current_version_for_audit = snapshot
        .nodes
        .iter()
        .find_map(|n| n.current_package_version.clone())
        .unwrap_or_else(|| "N/A".to_string());

    // Phase 4: audit preflight_passed.
    audit_phase(
        "preflight_passed",
        args,
        caller,
        request_id,
        &current_version_for_audit,
        &target,
        None,
    );

    // Phase 5-6: fire download + poll status.
    if let Err(e) = download_and_poll(device, args, &target, outer_budget, started).await {
        audit_phase(
            "failed",
            args,
            caller,
            request_id,
            &current_version_for_audit,
            &target,
            Some(&e),
        );
        return Err(e);
    }

    // Phase 7: audit download_complete.
    audit_phase(
        "download_complete",
        args,
        caller,
        request_id,
        &current_version_for_audit,
        &target,
        None,
    );

    // Phase 8-9: fire install + poll status.
    if let Err(e) = install_and_poll(device, args, &target, outer_budget, started).await {
        audit_phase(
            "failed",
            args,
            caller,
            request_id,
            &current_version_for_audit,
            &target,
            Some(&e),
        );
        return Err(e);
    }

    // Phase 10: audit install_complete.
    audit_phase(
        "install_complete",
        args,
        caller,
        request_id,
        &current_version_for_audit,
        &target,
        None,
    );

    // Phase 11: verify post-install version matches target.
    let installed = verify_installed_version(device, args, &target)
        .await
        .inspect_err(|e| {
            audit_phase(
                "failed",
                args,
                caller,
                request_id,
                &current_version_for_audit,
                &target,
                Some(e),
            );
        })?;

    // Phase 12: audit verified (terminal success).
    audit_phase(
        "verified", args, caller, request_id, &installed, &target, None,
    );

    let elapsed = started.elapsed().as_secs();
    Ok(DownloadAndInstallResponse::Completed(
        DownloadAndInstallCompletedData {
            status: CompletedTag::Completed,
            router: args.router.clone(),
            service: Service::Idp,
            topology: snapshot.topology,
            target_package_version: target,
            installed_package_version: installed,
            elapsed_seconds: elapsed,
        },
    ))
}

fn clamp_timeout(t: Option<u64>) -> Duration {
    let secs = t.unwrap_or(DEFAULT_TIMEOUT_SECS).min(MAX_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// Phase 5-6: fire `request-idp-security-package-download`, then poll
/// `get-idp-security-package-download-status` every 5s until terminal.
async fn download_and_poll(
    device: &mut PooledDevice,
    args: &IdpPackageArgs,
    _target: &str,
    outer_budget: Duration,
    started: tokio::time::Instant,
) -> Result<(), SrxError> {
    {
        let mut exec = device
            .rpc()
            .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
        // Kick off the download (async on the device's side — we get an
        // "async mode" ack back immediately).
        let _ack = exec
            .call(RPC_DOWNLOAD, &[])
            .await
            .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    }

    let deadline = started + outer_budget;
    poll_status(
        device,
        &args.router,
        RPC_DOWNLOAD_STATUS,
        "secpack-download-status-detail",
        "download",
        deadline,
        started,
    )
    .await
    .map_err(|e| convert_poll_failure(e, &args.router, "download"))
}

/// Phase 8-9: fire `request-idp-security-package-install`, then poll
/// `get-idp-security-package-install-status` every 5s until terminal.
async fn install_and_poll(
    device: &mut PooledDevice,
    args: &IdpPackageArgs,
    _target: &str,
    outer_budget: Duration,
    started: tokio::time::Instant,
) -> Result<(), SrxError> {
    {
        let mut exec = device
            .rpc()
            .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
        let _ack = exec
            .call(RPC_INSTALL, &[])
            .await
            .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    }

    let deadline = started + outer_budget;
    poll_status(
        device,
        &args.router,
        RPC_INSTALL_STATUS,
        "secpack-status-detail",
        "install",
        deadline,
        started,
    )
    .await
    .map_err(|e| convert_poll_failure(e, &args.router, "install"))
}

/// Shared poll loop driver. Returns one of:
/// * `Ok(())` on terminal Done
/// * `Err(PollFailure::Timeout)` when the outer deadline fires
/// * `Err(PollFailure::Failed(detail))` when the device returns a "Failed;" token
/// * `Err(PollFailure::Transport(_))` on RPC error
async fn poll_status(
    device: &mut PooledDevice,
    _router: &str,
    rpc: &str,
    detail_element: &str,
    _action: &str,
    deadline: tokio::time::Instant,
    started: tokio::time::Instant,
) -> Result<(), PollFailure> {
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(PollFailure::Timeout {
                elapsed_secs: now.saturating_duration_since(started).as_secs(),
            });
        }

        let reply = {
            let mut exec = device.rpc().map_err(|e| {
                PollFailure::Transport(Box::new(SrxError::Transport(
                    rust_junosmcp_core::JmcpError::from(e),
                )))
            })?;
            exec.call(rpc, &[]).await.map_err(|e| {
                PollFailure::Transport(Box::new(SrxError::Transport(
                    rust_junosmcp_core::JmcpError::from(e),
                )))
            })?
        };

        let detail = crate::xml::text_of(&reply, detail_element).unwrap_or_default();
        match parse_async_status_detail(&detail) {
            AsyncStatusOutcome::Done => return Ok(()),
            AsyncStatusOutcome::Failed(d) => return Err(PollFailure::Failed(d)),
            AsyncStatusOutcome::Pending => {
                let after = tokio::time::Instant::now() + Duration::from_secs(POLL_INTERVAL_SECS);
                if after >= deadline {
                    return Err(PollFailure::Timeout {
                        elapsed_secs: tokio::time::Instant::now()
                            .saturating_duration_since(started)
                            .as_secs(),
                    });
                }
                tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
            }
        }
    }
}

/// Internal poll failure shape — converted to the public per-action
/// `SrxError` variant by the caller.
enum PollFailure {
    Timeout { elapsed_secs: u64 },
    Failed(String),
    Transport(Box<SrxError>),
}

fn convert_poll_failure(f: PollFailure, router: &str, action: &str) -> SrxError {
    match f {
        PollFailure::Timeout { elapsed_secs } => SrxError::SignaturePackagePollTimeout {
            router: router.to_string(),
            action: action.to_string(),
            elapsed_secs,
        },
        PollFailure::Failed(detail) => match action {
            "download" => SrxError::SignaturePackageDownloadFailed {
                router: router.to_string(),
                detail,
            },
            _ => SrxError::SignaturePackageInstallFailed {
                router: router.to_string(),
                detail,
            },
        },
        PollFailure::Transport(boxed) => *boxed,
    }
}

/// Phase 11: read `get-idp-security-package-information` and verify the
/// installed version matches the target. Returns the installed version
/// string on success; `SignaturePackageVerificationFailed` on mismatch.
async fn verify_installed_version(
    device: &mut PooledDevice,
    args: &IdpPackageArgs,
    target: &str,
) -> Result<String, SrxError> {
    let info_xml = {
        let mut exec = device
            .rpc()
            .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
        exec.call(RPC_PACKAGE_INFORMATION, &[])
            .await
            .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?
    };

    let nodes = parse_package_information(&info_xml)?;
    let target_lead = leading_version_number(target);
    for node in &nodes {
        match &node.current_package_version {
            Some(v) if leading_version_number(v) == target_lead => continue,
            other => {
                return Err(SrxError::SignaturePackageVerificationFailed {
                    router: args.router.clone(),
                    expected: target.to_string(),
                    got: other.clone().unwrap_or_else(|| "N/A".to_string()),
                });
            }
        }
    }
    let installed = nodes
        .iter()
        .find_map(|n| n.current_package_version.clone())
        .unwrap_or_else(|| target.to_string());
    Ok(installed)
}

/// Emit one structured audit line. Field set documented in design doc
/// §"Audit log entries" — also surfaces `error_code` + `error_detail` on
/// the `failed` phase.
fn audit_phase(
    phase: &str,
    args: &IdpPackageArgs,
    caller: Option<&str>,
    request_id: &str,
    current_version: &str,
    target_version: &str,
    failure: Option<&SrxError>,
) {
    let caller_str = caller.unwrap_or("unknown");
    if let Some(err) = failure {
        let s = err.to_string();
        // Extract the bracketed [code=...] token if present.
        let code = s
            .strip_prefix('[')
            .and_then(|tail| tail.split_once(']'))
            .and_then(|(inner, _)| inner.strip_prefix("code="))
            .unwrap_or("internal");
        tracing::info!(
            target: "audit",
            tool = "manage_idp_security_package",
            router = %args.router,
            action = "download_and_install",
            service = "idp",
            caller = %caller_str,
            request_id = %request_id,
            phase = %phase,
            current_version = %current_version,
            target_version = %target_version,
            error_code = %code,
            error_detail = %s,
            "audit"
        );
    } else {
        tracing::info!(
            target: "audit",
            tool = "manage_idp_security_package",
            router = %args.router,
            action = "download_and_install",
            service = "idp",
            caller = %caller_str,
            request_id = %request_id,
            phase = %phase,
            current_version = %current_version,
            target_version = %target_version,
            "audit"
        );
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/signature_package")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()))
    }

    // ── parse_package_information ────────────────────────────────────────────

    #[test]
    fn fresh_device_returns_single_node_with_none_version() {
        let xml = fixture("idp_package_information_fresh.xml");
        let nodes = parse_package_information(&xml).expect("parse");
        assert_eq!(nodes.len(), 1, "standalone => single node");
        assert_eq!(nodes[0].re_name, "", "standalone re_name is empty");
        assert_eq!(
            nodes[0].current_package_version, None,
            "N/A(N/A) normalises to None"
        );
    }

    #[test]
    fn post_install_returns_full_version_text() {
        let xml = fixture("idp_package_information_post_install.xml");
        let nodes = parse_package_information(&xml).expect("parse");
        assert_eq!(nodes.len(), 1);
        let v = nodes[0]
            .current_package_version
            .as_deref()
            .expect("present");
        assert!(v.starts_with("3910"), "version starts with 3910: {v:?}");
        assert!(v.contains("Minor"), "carries Minor tag: {v:?}");
        // Detector version is populated post-install.
        assert_eq!(
            nodes[0].current_detector_version.as_deref(),
            Some("12.6.180250827"),
            "detector populated from <detector-version>"
        );
    }

    #[test]
    fn fresh_device_returns_none_for_detector_too() {
        let xml = fixture("idp_package_information_fresh.xml");
        let nodes = parse_package_information(&xml).expect("parse");
        assert_eq!(
            nodes[0].current_detector_version, None,
            "N/A detector normalises to None"
        );
    }

    #[test]
    fn clustered_returns_two_nodes() {
        let xml = fixture("idp_package_information_clustered.xml");
        let nodes = parse_package_information(&xml).expect("parse");
        assert_eq!(nodes.len(), 2, "cluster => two nodes");
        let names: Vec<&str> = nodes.iter().map(|n| n.re_name.as_str()).collect();
        assert!(names.contains(&"node0"), "names={names:?}");
        assert!(names.contains(&"node1"), "names={names:?}");
        // Both nodes are fresh in this fixture.
        assert!(nodes.iter().all(|n| n.current_package_version.is_none()));
    }

    // ── parse_check_server_reply ─────────────────────────────────────────────

    #[test]
    fn check_server_update_available_extracts_version() {
        let xml = fixture("idp_check_server_update_available.xml");
        let v = parse_check_server_reply(&xml, "vsrx-ci-tester").expect("parse");
        assert_eq!(v, "3910");
    }

    #[test]
    fn check_server_at_latest_extracts_same_wire_shape() {
        // Per design Appendix A.3: at_latest and update_available share
        // the same wire shape; only the caller can distinguish them by
        // comparing against current_package_version.
        let xml = fixture("idp_check_server_at_latest.xml");
        let v = parse_check_server_reply(&xml, "vsrx-ci-tester").expect("parse");
        assert_eq!(v, "3910");
    }

    #[test]
    fn check_server_unreachable_returns_server_unreachable_variant() {
        let xml = fixture("idp_check_server_unreachable.xml");
        let err =
            parse_check_server_reply(&xml, "vsrx-ci-tester").expect_err("unreachable must error");
        match err {
            SrxError::SignaturePackageServerUnreachable { router, detail } => {
                assert_eq!(router, "vsrx-ci-tester");
                assert!(
                    detail.contains("Server not reachable"),
                    "detail should carry Junos's message: got {detail:?}"
                );
            }
            other => panic!("expected SignaturePackageServerUnreachable, got {other:?}"),
        }
    }

    #[test]
    fn check_server_missing_version_info_returns_parse_error() {
        let xml = r#"<secpack-download-status format="xml">
            <secpack-download-status-detail>some text without the magic line</secpack-download-status-detail>
        </secpack-download-status>"#;
        let err = parse_check_server_reply(xml, "vsrx-foo").expect_err("missing Version info");
        match err {
            SrxError::Parse(msg) => assert!(
                msg.contains("Version info"),
                "parse error should mention the missing token: {msg:?}"
            ),
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn check_server_missing_detail_element_is_schema_mismatch() {
        let xml = r#"<secpack-download-status format="xml"></secpack-download-status>"#;
        let err = parse_check_server_reply(xml, "vsrx-foo").expect_err("missing detail");
        match err {
            SrxError::SchemaMismatch { rpc, element } => {
                assert_eq!(rpc, RPC_CHECK_SERVER);
                assert_eq!(element, "secpack-download-status-detail");
            }
            other => panic!("expected SchemaMismatch, got {other:?}"),
        }
    }

    // ── normalize_version_text ───────────────────────────────────────────────

    #[test]
    fn normalize_version_handles_n_a_variants() {
        assert_eq!(normalize_version_text("N/A(N/A)"), None);
        assert_eq!(normalize_version_text("N/A"), None);
        assert_eq!(normalize_version_text("n/a"), None);
        assert_eq!(normalize_version_text(""), None);
        assert_eq!(normalize_version_text("   "), None);
        assert_eq!(
            normalize_version_text("3910(Minor, Thu …)"),
            Some("3910(Minor, Thu …)".to_string())
        );
    }

    // ── leading_version_number ───────────────────────────────────────────────

    #[test]
    fn leading_version_strips_parens() {
        assert_eq!(leading_version_number("3910(Minor, Thu …)"), "3910");
        assert_eq!(leading_version_number("3910"), "3910");
        assert_eq!(leading_version_number("3712(4.1)"), "3712");
    }

    // ── extract_version_info ─────────────────────────────────────────────────

    #[test]
    fn extract_version_info_pulls_digits_after_colon() {
        let detail = "Successfully retrieved from(https://…).\nVersion info:3910(Minor, …)";
        assert_eq!(extract_version_info(detail).as_deref(), Some("3910"));
    }

    #[test]
    fn extract_version_info_returns_none_when_absent() {
        assert_eq!(extract_version_info("not a check-server reply"), None);
    }

    // ── parse_async_status_detail ────────────────────────────────────────────

    #[test]
    fn async_status_will_be_processed_is_pending() {
        let xml = fixture("idp_download_request.xml");
        let detail = crate::xml::text_of(&xml, "secpack-download-status-detail").expect("detail");
        assert_eq!(
            parse_async_status_detail(&detail),
            AsyncStatusOutcome::Pending
        );
    }

    #[test]
    fn async_status_in_progress_is_pending() {
        let xml = fixture("idp_download_status_running.xml");
        let detail = crate::xml::text_of(&xml, "secpack-download-status-detail").expect("detail");
        assert_eq!(
            parse_async_status_detail(&detail),
            AsyncStatusOutcome::Pending
        );
    }

    #[test]
    fn async_status_download_done_is_done() {
        let xml = fixture("idp_download_status_complete.xml");
        let detail = crate::xml::text_of(&xml, "secpack-download-status-detail").expect("detail");
        assert_eq!(parse_async_status_detail(&detail), AsyncStatusOutcome::Done);
    }

    #[test]
    fn async_status_install_done_is_done() {
        let xml = fixture("idp_install_status_complete.xml");
        let detail = crate::xml::text_of(&xml, "secpack-status-detail").expect("detail");
        assert_eq!(parse_async_status_detail(&detail), AsyncStatusOutcome::Done);
    }

    #[test]
    fn async_status_install_noop_same_version_is_done() {
        // Junos returns Done; with "not performed due to same version" —
        // semantically terminal success (callers shouldn't retry).
        let xml = fixture("idp_install_status_noop_same_version.xml");
        let detail = crate::xml::text_of(&xml, "secpack-status-detail").expect("detail");
        assert_eq!(parse_async_status_detail(&detail), AsyncStatusOutcome::Done);
    }

    #[test]
    fn async_status_failed_token_short_circuits_done() {
        // Per Appendix A.2: Junos can return "Done;...Failed;..." compound
        // — Failed; wins so the orchestrator surfaces the failure.
        let outcome =
            parse_async_status_detail("Done;Attack DB update : Failed;parser error at line 42");
        match outcome {
            AsyncStatusOutcome::Failed(d) => {
                assert!(d.contains("parser error"), "carries detail: {d:?}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // ── build_plan ───────────────────────────────────────────────────────────

    fn fresh_snapshot(target: &str) -> IdpCheckServerData {
        IdpCheckServerData {
            router: "vsrx-test10".into(),
            service: Service::Idp,
            topology: crate::workflows::signature_package::Topology::Standalone,
            latest_version: target.into(),
            nodes: vec![IdpCheckServerNode {
                re_name: String::new(),
                current_package_version: None,
                current_detector_version: None,
            }],
            update_available: true,
            raw_xml: None,
        }
    }

    fn at_version_snapshot(current: &str, latest: &str) -> IdpCheckServerData {
        IdpCheckServerData {
            router: "vsrx-test10".into(),
            service: Service::Idp,
            topology: crate::workflows::signature_package::Topology::Standalone,
            latest_version: latest.into(),
            nodes: vec![IdpCheckServerNode {
                re_name: String::new(),
                current_package_version: Some(current.into()),
                current_detector_version: Some("12.6.180250827".into()),
            }],
            update_available: false,
            raw_xml: None,
        }
    }

    #[test]
    fn plan_emits_needs_confirmation_on_fresh_device() {
        let snap = fresh_snapshot("3910");
        let outcome = build_plan(&snap, None, &[]);
        match outcome {
            PlanOutcome::NeedsConfirmation(plan) => {
                let j = serde_json::to_value(&plan).unwrap();
                assert_eq!(j["code"], "confirmation_required");
                assert_eq!(j["target_package_version"], "3910");
                assert_eq!(j["target_source"], "latest_from_check_server");
                assert_eq!(j["service"], "idp");
                // Fresh node carries "N/A" as current_package_version on the wire.
                assert_eq!(j["nodes"][0]["current_package_version"], "N/A");
            }
            other => panic!("expected NeedsConfirmation, got {other:?}"),
        }
    }

    #[test]
    fn plan_short_circuits_when_all_nodes_at_target() {
        // Closes T1 — exact version match must skip the destructive RPC.
        let snap = at_version_snapshot("3910(Minor)", "3910");
        let outcome = build_plan(&snap, None, &[]);
        match outcome {
            PlanOutcome::AlreadyAtTarget(resp) => {
                let j = serde_json::to_value(&resp).unwrap();
                assert_eq!(j["status"], "already_at_target");
                assert_eq!(j["target_package_version"], "3910");
                assert_eq!(j["current_package_version"], "3910(Minor)");
            }
            other => panic!("expected AlreadyAtTarget, got {other:?}"),
        }
    }

    #[test]
    fn plan_version_normalization_treats_parens_as_equal() {
        // Closes C1 — current="3714(4.1)" target="3714" must short-circuit.
        let snap = at_version_snapshot("3714(4.1)", "3714");
        let outcome = build_plan(&snap, None, &[]);
        assert!(
            matches!(outcome, PlanOutcome::AlreadyAtTarget(_)),
            "expected version-normalized short-circuit"
        );
    }

    #[test]
    fn plan_pinned_version_overrides_check_server() {
        // Closes T2 — when caller pins version, target_source must flip to
        // "pinned" and the check_server-reported latest must still appear
        // for visibility.
        let snap = fresh_snapshot("3910");
        let outcome = build_plan(&snap, Some("3714"), &[]);
        match outcome {
            PlanOutcome::NeedsConfirmation(plan) => {
                let j = serde_json::to_value(&plan).unwrap();
                assert_eq!(j["target_package_version"], "3714");
                assert_eq!(j["target_source"], "pinned");
                assert_eq!(j["latest_from_check_server"], "3910");
            }
            other => panic!("expected NeedsConfirmation, got {other:?}"),
        }
    }

    #[test]
    fn plan_pinned_does_not_short_circuit_when_target_differs_from_current() {
        // Pinning to 3710 with current 3714 must NOT short-circuit on the
        // basis of "current matches latest from check_server".
        let snap = at_version_snapshot("3714(4.1)", "3714");
        let outcome = build_plan(&snap, Some("3710"), &[]);
        assert!(
            matches!(outcome, PlanOutcome::NeedsConfirmation(_)),
            "pinned-to-different-version must not short-circuit"
        );
    }

    #[test]
    fn plan_blockers_propagate_into_preflight_blockers_field() {
        let snap = fresh_snapshot("3910");
        let outcome = build_plan(&snap, None, &["commit-confirmed window open".to_string()]);
        match outcome {
            PlanOutcome::NeedsConfirmation(plan) => {
                let j = serde_json::to_value(&plan).unwrap();
                assert_eq!(j["preflight_blockers"][0], "commit-confirmed window open");
            }
            other => panic!("expected NeedsConfirmation, got {other:?}"),
        }
    }
}
