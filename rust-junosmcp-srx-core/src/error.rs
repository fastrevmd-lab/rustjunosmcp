//! Error taxonomy for SRX workflows.

use thiserror::Error;

/// Error taxonomy for SRX workflows.
///
/// Covers transport failures, RPC errors, parsing failures, signature package
/// lifecycle errors, cluster health checks, and support bundle collection.
#[derive(Debug, Error)]
pub enum SrxError {
    /// NETCONF transport or connection failure.
    #[error("transport: {0}")]
    Transport(#[from] rust_junosmcp_core::JmcpError),

    /// Device returned an RPC error response.
    #[error("rpc error: {tag} ({severity}) — {message}")]
    Rpc {
        /// Error tag from the device.
        tag: String,
        /// Severity level.
        severity: String,
        /// Error message text.
        message: String,
    },

    /// Failed to parse device XML response.
    #[error("xml parse: {0}")]
    Parse(String),

    /// Expected XML element missing from device response.
    #[error("schema mismatch in {rpc}: missing required element <{element}>")]
    SchemaMismatch {
        /// RPC name that returned unexpected schema.
        rpc: &'static str,
        /// Missing element name.
        element: &'static str,
    },

    /// Tool argument validation failed.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    // ---------------------------------------------------------------------
    // Signature-package variants (Phase 2 / v0.2.0, IDP + future AppID).
    //
    // Display convention: `[code=<snake>] router=<name>: <detail>`.
    // MCP callers pattern-match on the bracketed `code=...` token.
    // ---------------------------------------------------------------------
    /// Signature package operation requires explicit confirmation.
    ///
    /// Returned when a destructive operation (install, rollback, uninstall) needs
    /// user approval before proceeding.
    #[error(
        "[code=confirmation_required] router={router}: confirmation required — re-call with confirm=true and the plan's confirmation_token; plan: {plan}"
    )]
    SignaturePackageConfirmationRequired {
        /// Device name.
        router: String,
        /// Execution plan requiring confirmation.
        plan: serde_json::Value,
    },

    /// Confirmation token missing from request.
    #[error(
        "[code=confirmation_token_required] router={router}: confirm=true requires the server-issued confirmation_token from a fresh preview"
    )]
    SignaturePackageConfirmationTokenRequired {
        /// Device name.
        router: String,
    },

    /// Confirmation token is malformed or expired.
    #[error("[code=confirmation_token_invalid] router={router}: {reason}")]
    SignaturePackageConfirmationTokenInvalid {
        /// Device name.
        router: String,
        /// Reason token was rejected.
        reason: &'static str,
    },

    /// Device state changed since the plan was previewed.
    #[error(
        "[code=confirmation_plan_drift] router={router}: device state or requested plan changed; request and review a new preview"
    )]
    SignaturePackageConfirmationPlanDrift {
        /// Device name.
        router: String,
    },

    /// Too many pending confirmations; capacity limit reached.
    #[error(
        "[code=confirmation_capacity_exceeded] router={router}: too many pending confirmations; retry after existing confirmations expire"
    )]
    SignaturePackageConfirmationCapacityExceeded {
        /// Device name.
        router: String,
    },

    /// Required feature license is not active on device.
    #[error("[code=license_inactive] router={router}: feature license '{feature}' not active")]
    SignaturePackageLicenseInactive {
        /// Device name.
        router: String,
        /// License feature name (e.g., "idp-sig", "appid-sig").
        feature: String,
    },

    /// Juniper signature update server is not reachable from device.
    #[error("[code=signatures_server_unreachable] router={router}: {detail}")]
    SignaturePackageServerUnreachable {
        /// Device name.
        router: String,
        /// Error detail from device.
        detail: String,
    },

    /// No previous IDP package to roll back to.
    #[error(
        "[code=no_rollback_target] router={router}: no preserved previous IDP signature package to roll back to"
    )]
    SignaturePackageNoRollbackTarget {
        /// Device name.
        router: String,
    },

    /// No AppID package installed; nothing to uninstall.
    #[error(
        "[code=no_uninstall_target] router={router}: no AppID application package is currently installed; nothing to uninstall"
    )]
    SignaturePackageNoUninstallTarget {
        /// Device name.
        router: String,
    },

    /// Chassis cluster is not synchronized.
    #[error(
        "[code=cluster_desynced] router={router}: cluster state '{state}' (expected synchronized)"
    )]
    SignaturePackageClusterDesynced {
        /// Device name.
        router: String,
        /// Current cluster state.
        state: String,
    },

    // A5: SignaturePackageCommitConfirmedActive dropped — sig-package install
    // is op-mode, not config-mode. Pre-flight emits tracing::warn! when a
    // window is open and proceeds (see
    // signature_package/preflight.rs::detect_commit_confirmed).
    /// Package download from Juniper server failed.
    #[error("[code=download_failed] router={router}: {detail}")]
    SignaturePackageDownloadFailed {
        /// Device name.
        router: String,
        /// Error detail from device.
        detail: String,
    },

    /// Package install operation failed on device.
    #[error("[code=install_failed] router={router}: {detail}")]
    SignaturePackageInstallFailed {
        /// Device name.
        router: String,
        /// Error detail from device.
        detail: String,
    },

    /// Package version after install does not match expected version.
    #[error("[code=post_install_version_mismatch] router={router}: expected={expected}, got={got}")]
    SignaturePackageVerificationFailed {
        /// Device name.
        router: String,
        /// Expected package version.
        expected: String,
        /// Actual package version found.
        got: String,
    },

    /// Polling for package operation completion timed out.
    #[error("[code=poll_timeout] router={router} action={action}: elapsed={elapsed_secs}s")]
    SignaturePackagePollTimeout {
        /// Device name.
        router: String,
        /// Action being polled (e.g., "download", "install").
        action: String,
        /// Elapsed time in seconds.
        elapsed_secs: u64,
    },

    // Discovered during Task 1 live capture: a fresh device with no `security
    // idp` config stanza hangs ~60s and returns
    // `timeout communicating with idp-policy daemon` (rpc-error channel).
    // Pre-flight should detect this case (or auto-`restart idp-policy` once)
    // before surfacing this variant.
    /// IDP daemon not initialized; device has no `security idp` configuration.
    #[error(
        "[code=daemon_not_ready] router={router}: idp-policy daemon not initialized — restart idp-policy or add minimum 'security idp' config stanza"
    )]
    SignaturePackageDaemonNotReady {
        /// Device name.
        router: String,
    },

    // ---------------------------------------------------------------------
    // Phase 3 / v0.3.0 — cluster health + support bundle.
    // Same `[code=<snake>] router=<name>: <detail>` convention.
    // ---------------------------------------------------------------------
    /// Cluster health check exceeded time budget.
    #[error(
        "[code=cluster_health_check_timeout] router={router}: outer budget exceeded after {elapsed_secs}s"
    )]
    ClusterHealthCheckTimeout {
        /// Device name.
        router: String,
        /// Elapsed time in seconds.
        elapsed_secs: u64,
    },

    /// Support bundle staging directory full despite LRU eviction.
    #[error(
        "[code=bundle_staging_full] router={router}: staging dir over cap even after LRU eviction (bundle {bundle_bytes} bytes; cap {cap_bytes} bytes)"
    )]
    BundleStagingFull {
        /// Device name.
        router: String,
        /// Size of bundle being staged, in bytes.
        bundle_bytes: u64,
        /// Staging directory capacity, in bytes.
        cap_bytes: u64,
    },

    /// Requested bundle was evicted from staging.
    #[error(
        "[code=bundle_staging_evicted] router={router}: requested request_id={request_id} not present in staging (LRU evicted or never written)"
    )]
    BundleStagingEvicted {
        /// Device name.
        router: String,
        /// Bundle request ID that was evicted.
        request_id: String,
    },

    /// Some bundle collection RPCs failed; partial results returned.
    #[error(
        "[code=bundle_rpc_subset_failed] router={router}: {failed_count} of {total_count} bundle RPCs failed (first error: {first_error})"
    )]
    BundleRpcSubsetFailed {
        /// Device name.
        router: String,
        /// Number of failed RPCs.
        failed_count: usize,
        /// Total number of RPCs attempted.
        total_count: usize,
        /// First error encountered.
        first_error: String,
    },

    /// Another support bundle collection is in progress for this device.
    #[error(
        "[code=bundle_per_router_contention] router={router}: another collect_jtac_support_bundle is in flight; retry after it completes"
    )]
    BundlePerRouterContention {
        /// Device name.
        router: String,
    },

    /// Universal baseline configuration capture failed.
    #[error(
        "[code=bundle_config_capture_failed] router={router}: universal-baseline get-configuration RPC failed: {detail}"
    )]
    BundleConfigCaptureFailed {
        /// Device name.
        router: String,
        /// Error detail.
        detail: String,
    },
}

impl SrxError {
    /// Convenience builder used by per-tool parsers.
    pub fn schema_mismatch(rpc: &'static str, element: &'static str) -> Self {
        Self::SchemaMismatch { rpc, element }
    }

    /// Returns the stable audit `error_kind` string for this error variant.
    ///
    /// Used by `AuditScope::fail_kind` to emit structured error classes to SIEM.
    /// This match is EXHAUSTIVE (no `_` wildcard) so that any new variant added
    /// to `SrxError` triggers a compile error here, forcing a deliberate
    /// classification decision for the new variant.
    pub fn audit_kind(&self) -> &'static str {
        match self {
            Self::Transport(inner) => inner.audit_kind(),
            Self::Rpc { .. } => "rpc",
            Self::Parse(_) => "parse",
            Self::SchemaMismatch { .. } => "parse",
            Self::InvalidInput(_) => "invalid_input",
            Self::SignaturePackageConfirmationRequired { .. } => "confirmation_required",
            Self::SignaturePackageConfirmationTokenRequired { .. } => "confirmation_token",
            Self::SignaturePackageConfirmationTokenInvalid { .. } => "confirmation_token",
            Self::SignaturePackageConfirmationPlanDrift { .. } => "confirmation_token",
            Self::SignaturePackageConfirmationCapacityExceeded { .. } => "confirmation_token",
            Self::SignaturePackageLicenseInactive { .. } => "license_inactive",
            Self::SignaturePackageServerUnreachable { .. } => "unreachable",
            Self::SignaturePackageNoRollbackTarget { .. } => "precondition_failed",
            Self::SignaturePackageNoUninstallTarget { .. } => "precondition_failed",
            Self::SignaturePackageClusterDesynced { .. } => "cluster_desynced",
            Self::SignaturePackageDownloadFailed { .. } => "download_failed",
            Self::SignaturePackageInstallFailed { .. } => "install_failed",
            Self::SignaturePackageVerificationFailed { .. } => "verify_mismatch",
            Self::SignaturePackagePollTimeout { .. } => "timeout",
            Self::SignaturePackageDaemonNotReady { .. } => "daemon_not_ready",
            Self::ClusterHealthCheckTimeout { .. } => "timeout",
            Self::BundleStagingFull { .. } => "staging_full",
            Self::BundleStagingEvicted { .. } => "staging_evicted",
            Self::BundleRpcSubsetFailed { .. } => "bundle_partial",
            Self::BundlePerRouterContention { .. } => "contention",
            Self::BundleConfigCaptureFailed { .. } => "capture_failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_mismatch_displays_rpc_and_element() {
        let e = SrxError::schema_mismatch("get-chassis-cluster-status-information", "cluster-id");
        let s = e.to_string();
        assert!(s.contains("get-chassis-cluster-status-information"), "{s}");
        assert!(s.contains("cluster-id"), "{s}");
    }

    #[test]
    fn rpc_variant_includes_tag_and_message() {
        let e = SrxError::Rpc {
            tag: "data-missing".into(),
            severity: "error".into(),
            message: "configuration database empty".into(),
        };
        let s = e.to_string();
        assert!(s.contains("data-missing"));
        assert!(s.contains("configuration database empty"));
    }

    // Signature-package error variants (Phase 2 / v0.2.0).
    // Display convention: `[code=<snake>] router=<name>: <detail>` so MCP
    // callers can pattern-match on the bracketed code.

    #[test]
    fn confirmation_required_display_includes_code_and_router() {
        let payload = serde_json::json!({"router": "vsrx-test10", "service": "idp"});
        let s = SrxError::SignaturePackageConfirmationRequired {
            router: "vsrx-test10".into(),
            plan: payload,
        }
        .to_string();
        assert!(s.contains("[code=confirmation_required]"), "got {s}");
        assert!(s.contains("vsrx-test10"), "got {s}");
    }

    #[test]
    fn confirmation_token_errors_have_stable_codes() {
        let required = SrxError::SignaturePackageConfirmationTokenRequired {
            router: "vsrx-test10".into(),
        }
        .to_string();
        assert!(required.contains("[code=confirmation_token_required]"));

        let drift = SrxError::SignaturePackageConfirmationPlanDrift {
            router: "vsrx-test10".into(),
        }
        .to_string();
        assert!(drift.contains("[code=confirmation_plan_drift]"));
    }

    #[test]
    fn license_inactive_display_includes_feature() {
        let s = SrxError::SignaturePackageLicenseInactive {
            router: "vsrx-test10".into(),
            feature: "idp-sig".into(),
        }
        .to_string();
        assert!(s.contains("[code=license_inactive]"), "got {s}");
        assert!(s.contains("idp-sig"), "got {s}");
    }

    #[test]
    fn server_unreachable_display_includes_detail() {
        let s = SrxError::SignaturePackageServerUnreachable {
            router: "vsrx-ci-tester".into(),
            detail: "Fetching signed manifest.xml failed, error: Server not reachable".into(),
        }
        .to_string();
        assert!(
            s.contains("[code=signatures_server_unreachable]"),
            "got {s}"
        );
        assert!(s.contains("Server not reachable"), "got {s}");
    }

    #[test]
    fn no_rollback_target_display() {
        let s = SrxError::SignaturePackageNoRollbackTarget {
            router: "vsrx-test10".into(),
        }
        .to_string();
        assert!(s.contains("[code=no_rollback_target]"), "got {s}");
        assert!(s.contains("vsrx-test10"), "got {s}");
    }

    #[test]
    fn no_uninstall_target_display() {
        let s = SrxError::SignaturePackageNoUninstallTarget {
            router: "vsrx-test3".into(),
        }
        .to_string();
        assert!(s.contains("[code=no_uninstall_target]"), "got {s}");
        assert!(s.contains("vsrx-test3"), "got {s}");
    }

    #[test]
    fn cluster_desynced_display_includes_state() {
        let s = SrxError::SignaturePackageClusterDesynced {
            router: "vsrx-test19-20".into(),
            state: "secondary-hold".into(),
        }
        .to_string();
        assert!(s.contains("[code=cluster_desynced]"), "got {s}");
        assert!(s.contains("secondary-hold"), "got {s}");
    }

    #[test]
    fn download_failed_display_includes_detail() {
        let s = SrxError::SignaturePackageDownloadFailed {
            router: "vsrx-test10".into(),
            detail: "HTTP 503 from signatures.juniper.net".into(),
        }
        .to_string();
        assert!(s.contains("[code=download_failed]"), "got {s}");
        assert!(s.contains("HTTP 503"), "got {s}");
    }

    #[test]
    fn install_failed_display_includes_detail() {
        let s = SrxError::SignaturePackageInstallFailed {
            router: "vsrx-test10".into(),
            detail: "Attack DB update : failed - parser error at line 42".into(),
        }
        .to_string();
        assert!(s.contains("[code=install_failed]"), "got {s}");
        assert!(s.contains("parser error"), "got {s}");
    }

    #[test]
    fn verification_failed_display_includes_expected_and_got() {
        let s = SrxError::SignaturePackageVerificationFailed {
            router: "vsrx-test10".into(),
            expected: "3910".into(),
            got: "3909".into(),
        }
        .to_string();
        assert!(
            s.contains("[code=post_install_version_mismatch]"),
            "got {s}"
        );
        assert!(s.contains("3910"), "got {s}");
        assert!(s.contains("3909"), "got {s}");
    }

    #[test]
    fn poll_timeout_display_includes_action_and_elapsed() {
        let s = SrxError::SignaturePackagePollTimeout {
            router: "vsrx-test10".into(),
            action: "download".into(),
            elapsed_secs: 300,
        }
        .to_string();
        assert!(s.contains("[code=poll_timeout]"), "got {s}");
        assert!(s.contains("download"), "got {s}");
        assert!(s.contains("300"), "got {s}");
    }

    #[test]
    fn daemon_not_ready_display() {
        let s = SrxError::SignaturePackageDaemonNotReady {
            router: "vsrx-ci-tester".into(),
        }
        .to_string();
        assert!(s.contains("[code=daemon_not_ready]"), "got {s}");
        assert!(s.contains("vsrx-ci-tester"), "got {s}");
    }

    // --- audit_kind tests ---

    #[test]
    fn audit_kind_transport() {
        let jmcp_err = rust_junosmcp_core::JmcpError::Timeout(std::time::Duration::from_secs(30));
        assert_eq!(SrxError::Transport(jmcp_err).audit_kind(), "timeout");
    }

    #[test]
    fn audit_kind_timeout() {
        assert_eq!(
            SrxError::SignaturePackagePollTimeout {
                router: "r1".into(),
                action: "download".into(),
                elapsed_secs: 300,
            }
            .audit_kind(),
            "timeout"
        );
    }

    #[test]
    fn audit_kind_confirmation_required() {
        assert_eq!(
            SrxError::SignaturePackageConfirmationRequired {
                router: "r1".into(),
                plan: serde_json::json!({}),
            }
            .audit_kind(),
            "confirmation_required"
        );
    }
}
