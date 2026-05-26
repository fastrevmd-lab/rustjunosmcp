//! `manage_appid_signature_package` — AppID signature-package lifecycle.
//!
//! Phase 2 / v0.2.1 — sibling of [`idp_package`]. Structurally parallel to
//! the IDP workflow, but the RPC layout is different:
//!
//! * **All AppID RPCs are flat single-element** — no composite parent/child
//!   payloads like IDP's `<request-idp-security-package-download><check-server/></...>`.
//! * **No XML schema for async-status detail tokens** — Junos emits plain
//!   English instead of IDP's `Done;…` / `Failed;…` token vocabulary.
//! * **No rollback verb** — replaced by `uninstall` (the active AppID
//!   package is removed wholesale; there is no preserved "previous"
//!   package on the device).
//!
//! # Live-captured RPC contract (audited 2026-05-26 against vSRX-test3)
//!
//! Each RPC name was confirmed by piping the matching CLI through
//! `| display xml rpc` on the live device.
//!
//! * `<get-appid-package-version/>` (flat) →
//!   `<appid-package-version>` (standalone) or `<multi-routing-engine-results>`
//!   wrapping one per node. `<version-detail>` carries the human text
//!   (`"3910 (Minor)"`) or `"N/A"` on a fresh device.
//! * `<request-appid-application-package-download-check-server/>` (flat) →
//!   `<apppack-server-status>` with free-text `<apppack-server-status-detail>`
//!   in the same `Version info:NNNN(...)` shape IDP uses. Note: the
//!   check-server envelope uses `apppack-server-status*` element names,
//!   distinct from the `apppack-download-status*` envelope used by the
//!   download/download-status RPCs.
//! * `<request-appid-application-package-download/>` (flat) → async ack;
//!   real progress lives behind `-download-status`.
//! * `<request-appid-application-package-download-status/>` (flat) →
//!   `<apppack-download-status><apppack-download-status-detail>` with
//!   one of: `"Please run … first"`, `"Downloading … in progress"`,
//!   `"Downloaded\n\tApplication package N (Minor) … successfully"`, or a
//!   `"…failed (…)"` string.
//! * `<request-appid-application-package-install/>` (flat) → async ack.
//! * `<request-appid-application-package-install-status/>` (flat) →
//!   `<apppack-install-status><apppack-install-status-detail>` with the
//!   same shape as download-status above.
//! * `<request-appid-application-package-uninstall/>` (flat) → ack.
//! * `<request-appid-application-package-uninstall-status/>` (flat) →
//!   `<apppack-uninstall-status><apppack-uninstall-status-detail>`.

use crate::workflows::signature_package::Service;
use crate::SrxError;
use rust_junosmcp_core::device_manager::PooledDevice;
use rust_junosmcp_core::tools::transfer_file::TransferLocks;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ── RPC names (all flat, see module docs) ────────────────────────────────────

const RPC_PACKAGE_VERSION: &str = "get-appid-package-version";
const RPC_CHECK_SERVER: &str = "request-appid-application-package-download-check-server";
const RPC_DOWNLOAD: &str = "request-appid-application-package-download";
const RPC_DOWNLOAD_STATUS: &str = "request-appid-application-package-download-status";
const RPC_INSTALL: &str = "request-appid-application-package-install";
const RPC_INSTALL_STATUS: &str = "request-appid-application-package-install-status";
const RPC_UNINSTALL: &str = "request-appid-application-package-uninstall";
const RPC_UNINSTALL_STATUS: &str = "request-appid-application-package-uninstall-status";

// Element names in the status replies. Confirmed by live capture against
// vSRX-test3 (Junos 24.4R1) on 2026-05-26 — check-server uses a different
// envelope (`<apppack-server-status><apppack-server-status-detail>`) than
// the download/install/uninstall workflows.
const EL_SERVER_STATUS_DETAIL: &str = "apppack-server-status-detail";
const EL_DOWNLOAD_STATUS_DETAIL: &str = "apppack-download-status-detail";
const EL_INSTALL_STATUS_DETAIL: &str = "apppack-install-status-detail";
const EL_UNINSTALL_STATUS_DETAIL: &str = "apppack-uninstall-status-detail";

const POLL_INTERVAL_SECS: u64 = 5;
const DEFAULT_TIMEOUT_SECS: u64 = 600;
const MAX_TIMEOUT_SECS: u64 = 1800;

// ── Public arg surface ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppidAction {
    CheckServer,
    DownloadAndInstall,
    Uninstall,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct AppidPackageArgs {
    pub router: String,
    pub action: AppidAction,
    /// Pin to a specific package version. Only meaningful for
    /// `download_and_install`; ignored otherwise.
    #[serde(default)]
    pub version: Option<String>,
    /// Required for destructive actions (`download_and_install`, `uninstall`).
    #[serde(default)]
    pub confirm: bool,
    /// Per-call outer budget in seconds. Default 600s, cap 1800s.
    #[serde(default)]
    pub timeout: Option<u64>,
    /// Append raw RPC replies to the response for debugging.
    #[serde(default)]
    pub include_raw: bool,
}

// ── `check_server` response types ─────────────────────────────────────────────

/// One row of the `nodes` array on the `check_server` response.
///
/// `re_name` is `""` for standalone, `"node0"`/`"node1"` for clusters.
/// `current_package_version` is the raw `<version-detail>` text, or `None`
/// when the device reports `"N/A"` (fresh) or the element is absent.
///
/// AppID has no "detector version" or "rollback version" peers — the
/// device reply for `get-appid-package-version` only carries version-detail
/// plus a release-date string.
#[derive(Debug, Serialize, JsonSchema, Clone, PartialEq, Eq)]
pub struct AppidCheckServerNode {
    pub re_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_package_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_date: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema, Clone, PartialEq, Eq)]
pub struct AppidCheckServerData {
    pub router: String,
    pub service: Service,
    pub topology: crate::workflows::signature_package::Topology,
    pub latest_version: String,
    pub nodes: Vec<AppidCheckServerNode>,
    pub update_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_xml: Option<String>,
}

// ── `check_server` — async entry point ────────────────────────────────────────

/// Run the read-only `check_server` verb.
pub async fn check_server(
    device: &mut PooledDevice,
    args: &AppidPackageArgs,
) -> Result<AppidCheckServerData, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let info_xml = exec
        .call(RPC_PACKAGE_VERSION, &[])
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let check_xml = exec
        .call(RPC_CHECK_SERVER, &[])
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let nodes = parse_package_version(&info_xml)?;
    let latest_version = parse_check_server_reply(&check_xml, &args.router)?;

    let topology = if nodes.len() > 1 {
        crate::workflows::signature_package::Topology::ChassisCluster
    } else {
        crate::workflows::signature_package::Topology::Standalone
    };

    let update_available = nodes
        .iter()
        .any(|n| match n.current_package_version.as_deref() {
            None => true,
            Some(v) => leading_version_number(v) != leading_version_number(&latest_version),
        });

    let raw_xml = if args.include_raw {
        Some(format!(
            "<!-- package-version -->\n{info_xml}\n<!-- check-server -->\n{check_xml}"
        ))
    } else {
        None
    };

    Ok(AppidCheckServerData {
        router: args.router.clone(),
        service: Service::Appid,
        topology,
        latest_version,
        nodes,
        update_available,
        raw_xml,
    })
}

// ── Parsers (pure, unit-testable) ─────────────────────────────────────────────

/// Parse a `<appid-package-version>` reply (standalone) or a
/// `<multi-routing-engine-results>` envelope wrapping one
/// `<appid-package-version>` per node (cluster).
pub fn parse_package_version(reply_xml: &str) -> Result<Vec<AppidCheckServerNode>, SrxError> {
    let split = crate::xml::multi_re_split(reply_xml)?;
    if split.is_empty() {
        return Err(SrxError::schema_mismatch(
            RPC_PACKAGE_VERSION,
            "multi-routing-engine-item",
        ));
    }

    let mut out = Vec::with_capacity(split.len());
    for node in split {
        let inner = &node.inner_xml;
        let version_text = crate::xml::text_of(inner, "version-detail");
        let normalized_version = version_text.and_then(|v| normalize_version_text(&v));
        let release_text = crate::xml::text_of(inner, "release-date");
        let normalized_release = release_text.and_then(|v| normalize_version_text(&v));
        out.push(AppidCheckServerNode {
            re_name: node.re_name,
            current_package_version: normalized_version,
            release_date: normalized_release,
        });
    }
    Ok(out)
}

/// Extract the latest-version string from a `check-server` reply.
///
/// Happy-path shape:
/// ```xml
/// <apppack-server-status>
///   <apppack-server-status-detail>Successfully retrieved from(https://...).
/// Version info:3914(Minor, Detector=...)</apppack-server-status-detail>
/// </apppack-server-status>
/// ```
///
/// On lab/upstream unreachability Junos emits a free-text reply like
/// `"Server certificate verification failed or server not reachable"` —
/// surfaced as [`SrxError::SignaturePackageServerUnreachable`].
pub fn parse_check_server_reply(reply_xml: &str, router: &str) -> Result<String, SrxError> {
    if reply_xml.contains("<xnm:error") || reply_xml.contains("xmlns:xnm") {
        let msg = crate::xml::text_of(reply_xml, "message").unwrap_or_default();
        if !msg.is_empty() {
            return Err(SrxError::SignaturePackageServerUnreachable {
                router: router.to_string(),
                detail: msg,
            });
        }
    }

    let detail = crate::xml::text_of(reply_xml, EL_SERVER_STATUS_DETAIL).ok_or_else(|| {
        SrxError::schema_mismatch(RPC_CHECK_SERVER, "apppack-server-status-detail")
    })?;
    let dlower = detail.to_lowercase();

    if dlower.contains("not reachable")
        || dlower.contains("verification failed")
        || dlower.contains("failed;")
        || dlower.contains("could not connect")
    {
        return Err(SrxError::SignaturePackageServerUnreachable {
            router: router.to_string(),
            detail,
        });
    }

    extract_version_info(&detail).ok_or_else(|| {
        SrxError::Parse(format!(
            "{RPC_CHECK_SERVER}: missing 'Version info:NNNN' in detail text: {detail:?}"
        ))
    })
}

/// `"N/A"`, empty, whitespace, or `"0"` → `None`; anything else → trimmed
/// `Some`. The `"0"` case is the observed post-uninstall response from
/// `get-appid-package-version` on vSRX 24.4R1 — Junos reports a literal
/// `"0"` in `<version-detail>` rather than `"N/A"` once the AppID package
/// has been removed.
fn normalize_version_text(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("n/a") || t.starts_with("N/A(") || t == "0" {
        return None;
    }
    Some(t.to_string())
}

/// Extract `NNNN` from a `Version info:NNNN(...)` line.
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

/// Strip the parenthesised suffix: `"3910 (Minor)"` → `"3910"`.
fn leading_version_number(v: &str) -> &str {
    // Trim trailing whitespace + space before `(` too: `"3910 (Minor)"` → `"3910"`.
    let trimmed = v.trim();
    match trimmed.find(['(', ' ']) {
        Some(i) => trimmed[..i].trim(),
        None => trimmed,
    }
}

// ── Async status parser ──────────────────────────────────────────────────────

/// Terminal vs in-progress signal returned by an AppID async status RPC.
///
/// Unlike IDP (which uses literal `Done;` / `Failed;` tokens), AppID emits
/// plain English. Decision rules:
/// 1. Contains case-insensitive `"failed"` → Failed(detail)
/// 2. Starts with `"Downloaded"` / `"Installed"` / `"Uninstalled"` → Done
/// 3. Contains `"in progress"` → Pending
/// 4. Contains `"Please run"` (pre-run prompt) → Pending
/// 5. Anything else → Pending (conservative)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsyncStatusOutcome {
    Pending,
    Done,
    Failed(String),
}

pub fn parse_async_status_detail(detail: &str) -> AsyncStatusOutcome {
    let t = detail.trim();
    let lower = t.to_lowercase();
    if lower.contains("failed") {
        return AsyncStatusOutcome::Failed(t.to_string());
    }
    if lower.starts_with("downloaded")
        || lower.starts_with("installed")
        || lower.starts_with("uninstalled")
    {
        return AsyncStatusOutcome::Done;
    }
    AsyncStatusOutcome::Pending
}

// ── Plan builders (pure) ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanOutcome {
    AlreadyAtTarget(crate::workflows::signature_package::AlreadyAtTargetResponse),
    NeedsConfirmation(crate::workflows::signature_package::ConfirmationPlan),
}

pub fn build_plan(
    snapshot: &AppidCheckServerData,
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
            current_detector_version: None,
        })
        .collect();

    let warning = format!(
        "Will download AppID application package {target} and install it on {router} ({topology}). \
         This briefly suspends application identification during package swap.",
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

/// Build the `uninstall` call-1 response. Errors with
/// [`SrxError::SignaturePackageNoUninstallTarget`] if no node reports a
/// currently installed AppID package.
pub fn build_uninstall_plan(
    snapshot: &AppidCheckServerData,
    blockers: &[String],
) -> Result<crate::workflows::signature_package::ConfirmationPlan, SrxError> {
    use crate::workflows::signature_package::{
        ConfirmationPlan, ConfirmationRequiredTag, UninstallAction, UninstallPlan,
    };

    let current = snapshot
        .nodes
        .iter()
        .find_map(|n| n.current_package_version.clone())
        .ok_or_else(|| SrxError::SignaturePackageNoUninstallTarget {
            router: snapshot.router.clone(),
        })?;

    let warning = format!(
        "Will uninstall the active AppID signature package ({current}) on {router} ({topology}). \
         Application identification will be disabled until a fresh package is installed.",
        current = current,
        router = snapshot.router,
        topology = match snapshot.topology {
            crate::workflows::signature_package::Topology::Standalone => "standalone",
            crate::workflows::signature_package::Topology::ChassisCluster => "chassis cluster",
        }
    );

    Ok(ConfirmationPlan::Uninstall(UninstallPlan {
        code: ConfirmationRequiredTag::ConfirmationRequired,
        router: snapshot.router.clone(),
        action: UninstallAction::Uninstall,
        service: snapshot.service,
        topology: snapshot.topology,
        current_package_version: current,
        preflight_blockers: blockers.to_vec(),
        warning,
    }))
}

// ── Unified verb dispatcher ───────────────────────────────────────────────────

#[derive(Debug, Serialize, JsonSchema, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum AppidPackageResponse {
    CheckServer(AppidCheckServerData),
    DownloadAndInstall(DownloadAndInstallResponse),
    Uninstall(UninstallResponse),
}

pub async fn run(
    device: &mut PooledDevice,
    transfer_locks: &TransferLocks,
    args: &AppidPackageArgs,
    caller: Option<&str>,
    request_id: &str,
) -> Result<AppidPackageResponse, SrxError> {
    match args.action {
        AppidAction::CheckServer => check_server(device, args)
            .await
            .map(AppidPackageResponse::CheckServer),
        AppidAction::DownloadAndInstall => {
            download_and_install(device, transfer_locks, args, caller, request_id)
                .await
                .map(AppidPackageResponse::DownloadAndInstall)
        }
        AppidAction::Uninstall => uninstall(device, transfer_locks, args, caller, request_id)
            .await
            .map(AppidPackageResponse::Uninstall),
    }
}

// ── `download_and_install` — destructive workflow ─────────────────────────────

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

#[derive(Debug, Serialize, JsonSchema, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum DownloadAndInstallResponse {
    AlreadyAtTarget(crate::workflows::signature_package::AlreadyAtTargetResponse),
    Completed(DownloadAndInstallCompletedData),
}

pub async fn download_and_install(
    device: &mut PooledDevice,
    transfer_locks: &TransferLocks,
    args: &AppidPackageArgs,
    caller: Option<&str>,
    request_id: &str,
) -> Result<DownloadAndInstallResponse, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }

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
        let _permit = transfer_locks.acquire(&args.router).await;
        run_install_destructive(device, args, caller, request_id).await
    }
}

/// Shared pre-flight: license + cluster topology + commit-confirmed warn +
/// upstream check-server snapshot.
async fn preflight(
    device: &mut PooledDevice,
    args: &AppidPackageArgs,
) -> Result<(AppidCheckServerData, Vec<String>), SrxError> {
    crate::workflows::signature_package::preflight::license_active(
        device,
        &args.router,
        crate::workflows::license::SrxLicensedFeature::AppId,
    )
    .await?;

    let topology =
        crate::workflows::signature_package::preflight::cluster_topology(device, &args.router)
            .await?;

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

    let mut snapshot = check_server(device, args).await?;
    snapshot.topology = topology;
    Ok((snapshot, blockers))
}

/// Pre-flight for `uninstall`. Skips the upstream check-server probe — the
/// workflow is local-only.
async fn preflight_uninstall(
    device: &mut PooledDevice,
    args: &AppidPackageArgs,
) -> Result<(AppidCheckServerData, Vec<String>), SrxError> {
    crate::workflows::signature_package::preflight::license_active(
        device,
        &args.router,
        crate::workflows::license::SrxLicensedFeature::AppId,
    )
    .await?;

    let topology =
        crate::workflows::signature_package::preflight::cluster_topology(device, &args.router)
            .await?;

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
                    "commit-confirmed window open; proceeding because sig-package uninstall is op-mode"
                );
                blockers.push("commit-confirmed window open (informational)".to_string());
            }
        }
    }

    let info_xml = {
        let mut exec = device
            .rpc()
            .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
        exec.call(RPC_PACKAGE_VERSION, &[])
            .await
            .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?
    };
    let nodes = parse_package_version(&info_xml)?;

    let snapshot = AppidCheckServerData {
        router: args.router.clone(),
        service: Service::Appid,
        topology,
        latest_version: String::new(),
        nodes,
        update_available: false,
        raw_xml: None,
    };
    Ok((snapshot, blockers))
}

async fn run_install_destructive(
    device: &mut PooledDevice,
    args: &AppidPackageArgs,
    caller: Option<&str>,
    request_id: &str,
) -> Result<DownloadAndInstallResponse, SrxError> {
    let started = tokio::time::Instant::now();
    let outer_budget = clamp_timeout(args.timeout);

    let (snapshot, _blockers) = preflight(device, args).await?;

    let target = match args.version.as_deref() {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => snapshot.latest_version.clone(),
    };
    let target_lead = leading_version_number(&target).to_string();

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
                Service::Appid,
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

    audit_phase(
        "preflight_passed",
        "download_and_install",
        args,
        caller,
        request_id,
        &current_version_for_audit,
        &target,
        None,
    );

    if let Err(e) = download_and_poll(device, args, outer_budget, started).await {
        audit_phase(
            "failed",
            "download_and_install",
            args,
            caller,
            request_id,
            &current_version_for_audit,
            &target,
            Some(&e),
        );
        return Err(e);
    }

    audit_phase(
        "download_complete",
        "download_and_install",
        args,
        caller,
        request_id,
        &current_version_for_audit,
        &target,
        None,
    );

    if let Err(e) = install_and_poll(device, args, outer_budget, started).await {
        audit_phase(
            "failed",
            "download_and_install",
            args,
            caller,
            request_id,
            &current_version_for_audit,
            &target,
            Some(&e),
        );
        return Err(e);
    }

    audit_phase(
        "install_complete",
        "download_and_install",
        args,
        caller,
        request_id,
        &current_version_for_audit,
        &target,
        None,
    );

    let installed = verify_installed_version(device, args, &target)
        .await
        .inspect_err(|e| {
            audit_phase(
                "failed",
                "download_and_install",
                args,
                caller,
                request_id,
                &current_version_for_audit,
                &target,
                Some(e),
            );
        })?;

    audit_phase(
        "verified",
        "download_and_install",
        args,
        caller,
        request_id,
        &installed,
        &target,
        None,
    );

    let elapsed = started.elapsed().as_secs();
    Ok(DownloadAndInstallResponse::Completed(
        DownloadAndInstallCompletedData {
            status: CompletedTag::Completed,
            router: args.router.clone(),
            service: Service::Appid,
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

async fn download_and_poll(
    device: &mut PooledDevice,
    args: &AppidPackageArgs,
    outer_budget: Duration,
    started: tokio::time::Instant,
) -> Result<(), SrxError> {
    {
        let mut exec = device
            .rpc()
            .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
        let _ack = exec
            .call(RPC_DOWNLOAD, &[])
            .await
            .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    }

    let deadline = started + outer_budget;
    poll_status(
        device,
        RPC_DOWNLOAD_STATUS,
        EL_DOWNLOAD_STATUS_DETAIL,
        deadline,
        started,
    )
    .await
    .map_err(|e| convert_poll_failure(e, &args.router, "download"))
}

async fn install_and_poll(
    device: &mut PooledDevice,
    args: &AppidPackageArgs,
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
        RPC_INSTALL_STATUS,
        EL_INSTALL_STATUS_DETAIL,
        deadline,
        started,
    )
    .await
    .map_err(|e| convert_poll_failure(e, &args.router, "install"))
}

async fn poll_status(
    device: &mut PooledDevice,
    rpc_name: &str,
    detail_element: &str,
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
            exec.call(rpc_name, &[]).await.map_err(|e| {
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

async fn verify_installed_version(
    device: &mut PooledDevice,
    args: &AppidPackageArgs,
    target: &str,
) -> Result<String, SrxError> {
    let info_xml = {
        let mut exec = device
            .rpc()
            .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
        exec.call(RPC_PACKAGE_VERSION, &[])
            .await
            .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?
    };

    let nodes = parse_package_version(&info_xml)?;
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

// ── `uninstall` — destructive workflow ────────────────────────────────────────

#[derive(Debug, Serialize, JsonSchema, Clone, PartialEq, Eq)]
pub struct UninstallCompletedData {
    pub status: CompletedTag,
    pub router: String,
    pub service: Service,
    pub topology: crate::workflows::signature_package::Topology,
    pub previous_package_version: String,
    pub elapsed_seconds: u64,
}

#[derive(Debug, Serialize, JsonSchema, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum UninstallResponse {
    Completed(UninstallCompletedData),
}

/// Run the `uninstall` verb. Mirror of IDP `rollback` semantics:
/// * call 1 (confirm=false) → preflight + plan emission as
///   `SrxError::SignaturePackageConfirmationRequired { plan }`.
/// * call 2 (confirm=true) → lock-first, fire `request-appid-application-package-uninstall`,
///   poll the matching `-uninstall-status`, then re-read
///   `get-appid-package-version` and verify it now reports `N/A`.
pub async fn uninstall(
    device: &mut PooledDevice,
    transfer_locks: &TransferLocks,
    args: &AppidPackageArgs,
    caller: Option<&str>,
    request_id: &str,
) -> Result<UninstallResponse, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }

    if !args.confirm {
        let (snapshot, _blockers) = preflight_uninstall(device, args).await?;
        let plan = build_uninstall_plan(&snapshot, &[])?;
        let plan_value = serde_json::to_value(&plan)
            .map_err(|e| SrxError::Parse(format!("serializing ConfirmationPlan: {e}")))?;
        Err(SrxError::SignaturePackageConfirmationRequired {
            router: args.router.clone(),
            plan: plan_value,
        })
    } else {
        let _permit = transfer_locks.acquire(&args.router).await;
        run_uninstall_destructive(device, args, caller, request_id).await
    }
}

async fn run_uninstall_destructive(
    device: &mut PooledDevice,
    args: &AppidPackageArgs,
    caller: Option<&str>,
    request_id: &str,
) -> Result<UninstallResponse, SrxError> {
    let started = tokio::time::Instant::now();
    let outer_budget = clamp_timeout(args.timeout);

    let (snapshot, _blockers) = preflight_uninstall(device, args).await?;

    let previous = snapshot
        .nodes
        .iter()
        .find_map(|n| n.current_package_version.clone())
        .ok_or_else(|| SrxError::SignaturePackageNoUninstallTarget {
            router: args.router.clone(),
        })?;

    audit_phase(
        "preflight_passed",
        "uninstall",
        args,
        caller,
        request_id,
        &previous,
        "(none)",
        None,
    );

    // Fire uninstall.
    {
        let mut exec = device
            .rpc()
            .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
        if let Err(e) = exec.call(RPC_UNINSTALL, &[]).await {
            let err = SrxError::Transport(rust_junosmcp_core::JmcpError::from(e));
            audit_phase(
                "failed",
                "uninstall",
                args,
                caller,
                request_id,
                &previous,
                "(none)",
                Some(&err),
            );
            return Err(err);
        }
    }

    // Poll uninstall-status.
    let deadline = started + outer_budget;
    if let Err(e) = poll_status(
        device,
        RPC_UNINSTALL_STATUS,
        EL_UNINSTALL_STATUS_DETAIL,
        deadline,
        started,
    )
    .await
    .map_err(|e| convert_poll_failure(e, &args.router, "uninstall"))
    {
        audit_phase(
            "failed",
            "uninstall",
            args,
            caller,
            request_id,
            &previous,
            "(none)",
            Some(&e),
        );
        return Err(e);
    }

    audit_phase(
        "install_complete",
        "uninstall",
        args,
        caller,
        request_id,
        &previous,
        "(none)",
        None,
    );

    // Verify version-detail is now N/A.
    let post = {
        let mut exec = device
            .rpc()
            .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
        exec.call(RPC_PACKAGE_VERSION, &[])
            .await
            .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?
    };
    let post_nodes = parse_package_version(&post)?;
    if let Some(v) = post_nodes
        .iter()
        .find_map(|n| n.current_package_version.clone())
    {
        let err = SrxError::SignaturePackageVerificationFailed {
            router: args.router.clone(),
            expected: "N/A".to_string(),
            got: v,
        };
        audit_phase(
            "failed",
            "uninstall",
            args,
            caller,
            request_id,
            &previous,
            "(none)",
            Some(&err),
        );
        return Err(err);
    }

    audit_phase(
        "verified",
        "uninstall",
        args,
        caller,
        request_id,
        "(none)",
        "(none)",
        None,
    );

    let elapsed = started.elapsed().as_secs();
    Ok(UninstallResponse::Completed(UninstallCompletedData {
        status: CompletedTag::Completed,
        router: args.router.clone(),
        service: Service::Appid,
        topology: snapshot.topology,
        previous_package_version: previous,
        elapsed_seconds: elapsed,
    }))
}

// ── Audit emit ────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn audit_phase(
    phase: &str,
    action: &str,
    args: &AppidPackageArgs,
    caller: Option<&str>,
    request_id: &str,
    current_version: &str,
    target_version: &str,
    failure: Option<&SrxError>,
) {
    let caller_str = caller.unwrap_or("unknown");
    if let Some(err) = failure {
        let s = err.to_string();
        let code = s
            .strip_prefix('[')
            .and_then(|tail| tail.split_once(']'))
            .and_then(|(inner, _)| inner.strip_prefix("code="))
            .unwrap_or("internal");
        tracing::info!(
            target: "audit",
            tool = "manage_appid_signature_package",
            router = %args.router,
            action = %action,
            service = "appid",
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
            tool = "manage_appid_signature_package",
            router = %args.router,
            action = %action,
            service = "appid",
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

    // ── parse_package_version ────────────────────────────────────────────────

    #[test]
    fn fresh_device_returns_none_version() {
        let xml = fixture("appid_package_version_fresh.xml");
        let nodes = parse_package_version(&xml).expect("parse");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].re_name, "");
        assert_eq!(nodes[0].current_package_version, None);
    }

    #[test]
    fn post_install_returns_version_text() {
        let xml = fixture("appid_package_version_post_install.xml");
        let nodes = parse_package_version(&xml).expect("parse");
        assert_eq!(nodes.len(), 1);
        assert_eq!(
            nodes[0].current_package_version.as_deref(),
            Some("3910 (Minor)")
        );
        assert!(nodes[0].release_date.is_some());
    }

    #[test]
    fn clustered_returns_two_nodes() {
        let xml = fixture("appid_package_version_clustered.xml");
        let nodes = parse_package_version(&xml).expect("parse");
        assert_eq!(nodes.len(), 2);
        let names: Vec<&str> = nodes.iter().map(|n| n.re_name.as_str()).collect();
        assert!(names.contains(&"node0"));
        assert!(names.contains(&"node1"));
        assert!(nodes
            .iter()
            .all(|n| n.current_package_version.as_deref() == Some("3910 (Minor)")));
    }

    // ── parse_check_server_reply ─────────────────────────────────────────────

    #[test]
    fn check_server_update_available_extracts_version() {
        let xml = fixture("appid_check_server_update_available.xml");
        let v = parse_check_server_reply(&xml, "vsrx-test3").expect("parse");
        assert_eq!(v, "3914");
    }

    #[test]
    fn check_server_at_latest_extracts_version() {
        let xml = fixture("appid_check_server_at_latest.xml");
        let v = parse_check_server_reply(&xml, "vsrx-test3").expect("parse");
        assert_eq!(v, "3910");
    }

    #[test]
    fn check_server_unreachable_returns_server_unreachable_variant() {
        let xml = fixture("appid_check_server_unreachable.xml");
        let err = parse_check_server_reply(&xml, "vsrx-test3").expect_err("unreachable must error");
        match err {
            SrxError::SignaturePackageServerUnreachable { router, detail } => {
                assert_eq!(router, "vsrx-test3");
                assert!(
                    detail.to_lowercase().contains("not reachable")
                        || detail.to_lowercase().contains("verification failed"),
                    "detail should carry Junos's message: {detail:?}"
                );
            }
            other => panic!("expected SignaturePackageServerUnreachable, got {other:?}"),
        }
    }

    #[test]
    fn check_server_missing_detail_element_is_schema_mismatch() {
        let xml = r#"<apppack-server-status></apppack-server-status>"#;
        let err = parse_check_server_reply(xml, "vsrx-test3").expect_err("missing detail");
        match err {
            SrxError::SchemaMismatch { rpc, element } => {
                assert_eq!(rpc, RPC_CHECK_SERVER);
                assert_eq!(element, "apppack-server-status-detail");
            }
            other => panic!("expected SchemaMismatch, got {other:?}"),
        }
    }

    // ── normalize_version_text + leading_version_number ──────────────────────

    #[test]
    fn normalize_version_handles_n_a_variants() {
        assert_eq!(normalize_version_text("N/A"), None);
        assert_eq!(normalize_version_text("n/a"), None);
        assert_eq!(normalize_version_text("N/A(N/A)"), None);
        assert_eq!(normalize_version_text(""), None);
        assert_eq!(normalize_version_text("   "), None);
        // Post-uninstall observed on vSRX 24.4R1: `<version-detail>0</...>`.
        assert_eq!(normalize_version_text("0"), None);
        assert_eq!(
            normalize_version_text("3910 (Minor)"),
            Some("3910 (Minor)".to_string())
        );
    }

    #[test]
    fn leading_version_strips_space_and_parens() {
        assert_eq!(leading_version_number("3910 (Minor)"), "3910");
        assert_eq!(leading_version_number("3910"), "3910");
        assert_eq!(leading_version_number("3914(Minor)"), "3914");
    }

    // ── parse_async_status_detail ────────────────────────────────────────────

    #[test]
    fn async_status_in_progress_is_pending() {
        let xml = fixture("appid_download_status_running.xml");
        let detail = crate::xml::text_of(&xml, EL_DOWNLOAD_STATUS_DETAIL).expect("detail");
        assert_eq!(
            parse_async_status_detail(&detail),
            AsyncStatusOutcome::Pending
        );
    }

    #[test]
    fn async_status_please_run_first_is_pending() {
        let xml = fixture("appid_download_status_pending.xml");
        let detail = crate::xml::text_of(&xml, EL_DOWNLOAD_STATUS_DETAIL).expect("detail");
        assert_eq!(
            parse_async_status_detail(&detail),
            AsyncStatusOutcome::Pending
        );
    }

    #[test]
    fn async_status_downloaded_is_done() {
        let xml = fixture("appid_download_status_complete.xml");
        let detail = crate::xml::text_of(&xml, EL_DOWNLOAD_STATUS_DETAIL).expect("detail");
        assert_eq!(parse_async_status_detail(&detail), AsyncStatusOutcome::Done);
    }

    #[test]
    fn async_status_installed_is_done() {
        let xml = fixture("appid_install_status_complete.xml");
        let detail = crate::xml::text_of(&xml, EL_INSTALL_STATUS_DETAIL).expect("detail");
        assert_eq!(parse_async_status_detail(&detail), AsyncStatusOutcome::Done);
    }

    #[test]
    fn async_status_uninstalled_is_done() {
        let xml = fixture("appid_uninstall_status_complete.xml");
        let detail = crate::xml::text_of(&xml, EL_UNINSTALL_STATUS_DETAIL).expect("detail");
        assert_eq!(parse_async_status_detail(&detail), AsyncStatusOutcome::Done);
    }

    #[test]
    fn async_status_failed_word_short_circuits_done() {
        let xml = fixture("appid_install_status_failed_missing_package.xml");
        let detail = crate::xml::text_of(&xml, EL_INSTALL_STATUS_DETAIL).expect("detail");
        match parse_async_status_detail(&detail) {
            AsyncStatusOutcome::Failed(d) => {
                assert!(d.to_lowercase().contains("failed"), "carries detail: {d:?}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // ── build_plan ───────────────────────────────────────────────────────────

    fn fresh_snapshot(target: &str) -> AppidCheckServerData {
        AppidCheckServerData {
            router: "vsrx-test3".into(),
            service: Service::Appid,
            topology: crate::workflows::signature_package::Topology::Standalone,
            latest_version: target.into(),
            nodes: vec![AppidCheckServerNode {
                re_name: String::new(),
                current_package_version: None,
                release_date: None,
            }],
            update_available: true,
            raw_xml: None,
        }
    }

    fn at_version_snapshot(current: &str, latest: &str) -> AppidCheckServerData {
        AppidCheckServerData {
            router: "vsrx-test3".into(),
            service: Service::Appid,
            topology: crate::workflows::signature_package::Topology::Standalone,
            latest_version: latest.into(),
            nodes: vec![AppidCheckServerNode {
                re_name: String::new(),
                current_package_version: Some(current.into()),
                release_date: Some("Thu May 21 13:50:42 2026 UTC".into()),
            }],
            update_available: false,
            raw_xml: None,
        }
    }

    #[test]
    fn plan_emits_needs_confirmation_on_fresh_device() {
        let snap = fresh_snapshot("3914");
        let outcome = build_plan(&snap, None, &[]);
        match outcome {
            PlanOutcome::NeedsConfirmation(plan) => {
                let j = serde_json::to_value(&plan).unwrap();
                assert_eq!(j["code"], "confirmation_required");
                assert_eq!(j["target_package_version"], "3914");
                assert_eq!(j["target_source"], "latest_from_check_server");
                assert_eq!(j["service"], "appid");
                assert_eq!(j["nodes"][0]["current_package_version"], "N/A");
            }
            other => panic!("expected NeedsConfirmation, got {other:?}"),
        }
    }

    #[test]
    fn plan_short_circuits_when_already_at_target() {
        // current "3910 (Minor)" vs target "3910" → leading-version match.
        let snap = at_version_snapshot("3910 (Minor)", "3910");
        let outcome = build_plan(&snap, None, &[]);
        match outcome {
            PlanOutcome::AlreadyAtTarget(resp) => {
                let j = serde_json::to_value(&resp).unwrap();
                assert_eq!(j["status"], "already_at_target");
                assert_eq!(j["target_package_version"], "3910");
                assert_eq!(j["current_package_version"], "3910 (Minor)");
                assert_eq!(j["service"], "appid");
            }
            other => panic!("expected AlreadyAtTarget, got {other:?}"),
        }
    }

    #[test]
    fn plan_pinned_version_overrides_check_server() {
        let snap = fresh_snapshot("3914");
        let outcome = build_plan(&snap, Some("3910"), &[]);
        match outcome {
            PlanOutcome::NeedsConfirmation(plan) => {
                let j = serde_json::to_value(&plan).unwrap();
                assert_eq!(j["target_package_version"], "3910");
                assert_eq!(j["target_source"], "pinned");
                assert_eq!(j["latest_from_check_server"], "3914");
            }
            other => panic!("expected NeedsConfirmation, got {other:?}"),
        }
    }

    #[test]
    fn plan_blockers_propagate() {
        let snap = fresh_snapshot("3914");
        let outcome = build_plan(&snap, None, &["commit-confirmed window open".into()]);
        match outcome {
            PlanOutcome::NeedsConfirmation(plan) => {
                let j = serde_json::to_value(&plan).unwrap();
                assert_eq!(j["preflight_blockers"][0], "commit-confirmed window open");
            }
            other => panic!("expected NeedsConfirmation, got {other:?}"),
        }
    }

    // ── build_uninstall_plan ─────────────────────────────────────────────────

    #[test]
    fn uninstall_plan_returns_needs_confirmation_with_current() {
        let snap = at_version_snapshot("3910 (Minor)", "");
        let plan = build_uninstall_plan(&snap, &[]).expect("plan");
        let j = serde_json::to_value(&plan).unwrap();
        assert_eq!(j["code"], "confirmation_required");
        assert_eq!(j["action"], "uninstall");
        assert_eq!(j["service"], "appid");
        assert_eq!(j["current_package_version"], "3910 (Minor)");
        let warn = j["warning"].as_str().expect("warning");
        assert!(warn.contains("3910"), "warning mentions current: {warn}");
    }

    #[test]
    fn uninstall_plan_errors_when_no_current_package() {
        let snap = fresh_snapshot("3914");
        let err = build_uninstall_plan(&snap, &[]).expect_err("must reject");
        match err {
            SrxError::SignaturePackageNoUninstallTarget { router } => {
                assert_eq!(router, "vsrx-test3");
            }
            other => panic!("expected SignaturePackageNoUninstallTarget, got {other:?}"),
        }
    }

    #[test]
    fn uninstall_plan_carries_blockers_through() {
        let snap = at_version_snapshot("3910 (Minor)", "");
        let plan = build_uninstall_plan(&snap, &["commit-confirmed window open".into()])
            .expect("plan builds");
        let j = serde_json::to_value(&plan).unwrap();
        assert_eq!(j["preflight_blockers"][0], "commit-confirmed window open");
    }
}
