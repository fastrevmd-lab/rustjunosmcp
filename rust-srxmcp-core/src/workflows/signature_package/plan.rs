//! `confirmation_required` envelopes returned by call 1 of the
//! signature-package two-call confirmation protocol, plus the
//! `already_at_target` short-circuit response.
//!
//! See the Phase 2 design doc, section "Two-call confirmation protocol",
//! for the canonical wire shapes these structs reproduce.

use schemars::JsonSchema;
use serde::Serialize;

// ── Enums shared by every plan ────────────────────────────────────────────────

#[derive(Debug, Serialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    Idp,
    Appid,
}

#[derive(Debug, Serialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Topology {
    Standalone,
    ChassisCluster,
}

#[derive(Debug, Serialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetSource {
    LatestFromCheckServer,
    Pinned,
}

/// One row of the `nodes` array on a `download_and_install` plan.
///
/// For a standalone device, `re_name` is the empty string. For a chassis
/// cluster, it's `"node0"` / `"node1"`.
#[derive(Debug, Serialize, JsonSchema, Clone, PartialEq, Eq)]
pub struct NodeVersionInfo {
    pub re_name: String,
    pub current_package_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_detector_version: Option<String>,
}

// ── Per-verb plan structs ─────────────────────────────────────────────────────

/// Plan for `download_and_install` (IDP + AppID).
///
/// `code` is hard-coded to `"confirmation_required"` via `serde(rename)`
/// so the wire shape matches the design doc's §2 examples exactly.
#[derive(Debug, Serialize, JsonSchema, Clone, PartialEq, Eq)]
pub struct DownloadAndInstallPlan {
    #[serde(rename = "code")]
    pub code: ConfirmationRequiredTag,
    pub router: String,
    pub action: DownloadAndInstallAction,
    pub service: Service,
    pub topology: Topology,
    pub nodes: Vec<NodeVersionInfo>,
    pub target_package_version: String,
    pub target_source: TargetSource,
    /// Only populated when `target_source == Pinned` (so callers can still
    /// see what `check-server` reported alongside the pinned target).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_from_check_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_package_size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_install_duration_seconds: Option<u64>,
    pub preflight_blockers: Vec<String>,
    pub warning: String,
}

#[derive(Debug, Serialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DownloadAndInstallAction {
    DownloadAndInstall,
}

/// Plan for `rollback` (IDP + AppID).
#[derive(Debug, Serialize, JsonSchema, Clone, PartialEq, Eq)]
pub struct RollbackPlan {
    #[serde(rename = "code")]
    pub code: ConfirmationRequiredTag,
    pub router: String,
    pub action: RollbackAction,
    pub service: Service,
    pub topology: Topology,
    pub current_package_version: String,
    pub rollback_target_version: String,
    pub preflight_blockers: Vec<String>,
    pub warning: String,
}

#[derive(Debug, Serialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RollbackAction {
    Rollback,
}

/// Plan for `uninstall` (AppID only).
#[derive(Debug, Serialize, JsonSchema, Clone, PartialEq, Eq)]
pub struct UninstallPlan {
    #[serde(rename = "code")]
    pub code: ConfirmationRequiredTag,
    pub router: String,
    pub action: UninstallAction,
    pub service: Service,
    pub topology: Topology,
    pub current_package_version: String,
    pub preflight_blockers: Vec<String>,
    pub warning: String,
}

#[derive(Debug, Serialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UninstallAction {
    Uninstall,
}

/// Marker type that always serializes to `"confirmation_required"` — keeps
/// the `code` field literal at the type level so callers can't accidentally
/// emit a wrong code.
#[derive(Debug, Serialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationRequiredTag {
    ConfirmationRequired,
}

/// Untagged union of the three plan shapes. `serde_json::to_value(&plan)`
/// produces exactly the JSON object the design doc shows — no enum tag,
/// no wrapper key.
#[derive(Debug, Serialize, JsonSchema, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum ConfirmationPlan {
    DownloadAndInstall(DownloadAndInstallPlan),
    Rollback(RollbackPlan),
    Uninstall(UninstallPlan),
}

// ── `already_at_target` short-circuit response ────────────────────────────────

/// Returned by `download_and_install` call 1 when every node's current
/// package version already equals the resolved target — bypasses the
/// `confirmation_required` round-trip entirely.
#[derive(Debug, Serialize, JsonSchema, Clone, PartialEq, Eq)]
pub struct AlreadyAtTargetResponse {
    pub status: AlreadyAtTargetTag,
    pub router: String,
    pub service: Service,
    pub current_package_version: String,
    pub target_package_version: String,
    pub message: String,
}

#[derive(Debug, Serialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlreadyAtTargetTag {
    AlreadyAtTarget,
}

impl AlreadyAtTargetResponse {
    /// Build a default-message variant; callers can override `message` if
    /// they want verb-specific wording.
    pub fn new(
        router: impl Into<String>,
        service: Service,
        current: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            status: AlreadyAtTargetTag::AlreadyAtTarget,
            router: router.into(),
            service,
            current_package_version: current.into(),
            target_package_version: target.into(),
            message: "device already running target version; no action taken".to_string(),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    #[test]
    fn download_and_install_plan_matches_design_shape() {
        let plan = ConfirmationPlan::DownloadAndInstall(DownloadAndInstallPlan {
            code: ConfirmationRequiredTag::ConfirmationRequired,
            router: "vsrx-test19-20".into(),
            action: DownloadAndInstallAction::DownloadAndInstall,
            service: Service::Idp,
            topology: Topology::ChassisCluster,
            nodes: vec![
                NodeVersionInfo {
                    re_name: "node0".into(),
                    current_package_version: "3712(4.1)".into(),
                    current_detector_version: Some("12.6.180200620_v6".into()),
                },
                NodeVersionInfo {
                    re_name: "node1".into(),
                    current_package_version: "3712(4.1)".into(),
                    current_detector_version: Some("12.6.180200620_v6".into()),
                },
            ],
            target_package_version: "3714".into(),
            target_source: TargetSource::LatestFromCheckServer,
            latest_from_check_server: None,
            estimated_package_size_bytes: Some(287_309_824),
            estimated_install_duration_seconds: Some(90),
            preflight_blockers: vec![],
            warning: "Will download IDP signature package 3714…".into(),
        });

        let j = serde_json::to_value(&plan).expect("serialize");
        assert_eq!(j["code"], "confirmation_required");
        assert_eq!(j["router"], "vsrx-test19-20");
        assert_eq!(j["action"], "download_and_install");
        assert_eq!(j["service"], "idp");
        assert_eq!(j["topology"], "chassis_cluster");
        assert_eq!(j["nodes"][0]["re_name"], "node0");
        assert_eq!(j["nodes"][1]["current_package_version"], "3712(4.1)");
        assert_eq!(j["target_package_version"], "3714");
        assert_eq!(j["target_source"], "latest_from_check_server");
        assert_eq!(j["estimated_package_size_bytes"], 287_309_824);
        assert_eq!(j["estimated_install_duration_seconds"], 90);
        assert_eq!(j["preflight_blockers"], json!([]));
        // Optional fields not set must be omitted, not null.
        assert!(j.get("latest_from_check_server").is_none());
    }

    #[test]
    fn pinned_target_includes_latest_from_check_server() {
        let plan = ConfirmationPlan::DownloadAndInstall(DownloadAndInstallPlan {
            code: ConfirmationRequiredTag::ConfirmationRequired,
            router: "vsrx-test10".into(),
            action: DownloadAndInstallAction::DownloadAndInstall,
            service: Service::Idp,
            topology: Topology::Standalone,
            nodes: vec![NodeVersionInfo {
                re_name: String::new(),
                current_package_version: "3712(4.1)".into(),
                current_detector_version: None,
            }],
            target_package_version: "3710".into(),
            target_source: TargetSource::Pinned,
            latest_from_check_server: Some("3714".into()),
            estimated_package_size_bytes: None,
            estimated_install_duration_seconds: None,
            preflight_blockers: vec![],
            warning: "".into(),
        });
        let j = serde_json::to_value(&plan).unwrap();
        assert_eq!(j["target_source"], "pinned");
        assert_eq!(j["latest_from_check_server"], "3714");
        assert_eq!(j["nodes"][0]["re_name"], "");
        // detector omitted on standalone when None
        assert!(j["nodes"][0].get("current_detector_version").is_none());
    }

    #[test]
    fn rollback_plan_matches_design_shape() {
        let plan = ConfirmationPlan::Rollback(RollbackPlan {
            code: ConfirmationRequiredTag::ConfirmationRequired,
            router: "vsrx-test10".into(),
            action: RollbackAction::Rollback,
            service: Service::Idp,
            topology: Topology::Standalone,
            current_package_version: "3714(4.1)".into(),
            rollback_target_version: "3712(4.1)".into(),
            preflight_blockers: vec![],
            warning: "Will revert IDP signature package…".into(),
        });
        let j = serde_json::to_value(&plan).unwrap();
        assert_eq!(j["code"], "confirmation_required");
        assert_eq!(j["action"], "rollback");
        assert_eq!(j["current_package_version"], "3714(4.1)");
        assert_eq!(j["rollback_target_version"], "3712(4.1)");
        // Rollback shape must NOT carry the download_and_install-only fields.
        assert!(j.get("nodes").is_none());
        assert!(j.get("target_source").is_none());
    }

    #[test]
    fn uninstall_plan_matches_design_shape() {
        let plan = ConfirmationPlan::Uninstall(UninstallPlan {
            code: ConfirmationRequiredTag::ConfirmationRequired,
            router: "vsrx-test10".into(),
            action: UninstallAction::Uninstall,
            service: Service::Appid,
            topology: Topology::Standalone,
            current_package_version: "3458".into(),
            preflight_blockers: vec![],
            warning: "Will uninstall the active AppID signature package…".into(),
        });
        let j = serde_json::to_value(&plan).unwrap();
        assert_eq!(j["action"], "uninstall");
        assert_eq!(j["service"], "appid");
        assert_eq!(j["current_package_version"], "3458");
        // Uninstall must NOT carry a rollback_target_version.
        assert!(j.get("rollback_target_version").is_none());
    }

    #[test]
    fn already_at_target_response_matches_design_shape() {
        let resp = AlreadyAtTargetResponse::new("vsrx-test10", Service::Idp, "3714(4.1)", "3714");
        let j = serde_json::to_value(&resp).unwrap();
        assert_eq!(j["status"], "already_at_target");
        assert_eq!(j["router"], "vsrx-test10");
        assert_eq!(j["service"], "idp");
        assert_eq!(j["current_package_version"], "3714(4.1)");
        assert_eq!(j["target_package_version"], "3714");
        assert_eq!(
            j["message"],
            "device already running target version; no action taken"
        );
    }

    #[test]
    fn confirmation_plan_fits_in_srxerror_variant() {
        // The SrxError::SignaturePackageConfirmationRequired variant embeds
        // a serde_json::Value — this test pins the round-trip so callers
        // can freely shove any of the three plans in there without losing
        // shape.
        let plan = ConfirmationPlan::Rollback(RollbackPlan {
            code: ConfirmationRequiredTag::ConfirmationRequired,
            router: "vsrx-test10".into(),
            action: RollbackAction::Rollback,
            service: Service::Idp,
            topology: Topology::Standalone,
            current_package_version: "3714".into(),
            rollback_target_version: "3712".into(),
            preflight_blockers: vec![],
            warning: "".into(),
        });
        let value: serde_json::Value = serde_json::to_value(&plan).unwrap();
        let err = crate::SrxError::SignaturePackageConfirmationRequired {
            router: "vsrx-test10".into(),
            plan: value,
        };
        let display = err.to_string();
        assert!(display.contains("[code=confirmation_required]"));
        assert!(display.contains("rollback_target_version"));
    }
}
