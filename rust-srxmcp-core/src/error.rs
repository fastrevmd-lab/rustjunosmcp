//! Error taxonomy for SRX workflows.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SrxError {
    #[error("transport: {0}")]
    Transport(#[from] rust_junosmcp_core::JmcpError),

    #[error("rpc error: {tag} ({severity}) — {message}")]
    Rpc {
        tag: String,
        severity: String,
        message: String,
    },

    #[error("xml parse: {0}")]
    Parse(String),

    #[error("schema mismatch in {rpc}: missing required element <{element}>")]
    SchemaMismatch {
        rpc: &'static str,
        element: &'static str,
    },

    #[error("invalid input: {0}")]
    InvalidInput(String),

    // ---------------------------------------------------------------------
    // Signature-package variants (Phase 2 / v0.2.0, IDP + future AppID).
    //
    // Display convention: `[code=<snake>] router=<name>: <detail>`.
    // MCP callers pattern-match on the bracketed `code=...` token.
    // ---------------------------------------------------------------------
    #[error(
        "[code=confirmation_required] router={router}: confirmation required — re-call with confirm=true; plan: {plan}"
    )]
    SignaturePackageConfirmationRequired {
        router: String,
        plan: serde_json::Value,
    },

    #[error("[code=license_inactive] router={router}: feature license '{feature}' not active")]
    SignaturePackageLicenseInactive { router: String, feature: String },

    #[error("[code=signatures_server_unreachable] router={router}: {detail}")]
    SignaturePackageServerUnreachable { router: String, detail: String },

    #[error(
        "[code=no_rollback_target] router={router}: no preserved previous IDP signature package to roll back to"
    )]
    SignaturePackageNoRollbackTarget { router: String },

    #[error(
        "[code=cluster_desynced] router={router}: cluster state '{state}' (expected synchronized)"
    )]
    SignaturePackageClusterDesynced { router: String, state: String },

    // A5: SignaturePackageCommitConfirmedActive dropped — sig-package install
    // is op-mode, not config-mode. Pre-flight emits tracing::warn! when a
    // window is open and proceeds (see
    // signature_package/preflight.rs::detect_commit_confirmed).
    #[error("[code=download_failed] router={router}: {detail}")]
    SignaturePackageDownloadFailed { router: String, detail: String },

    #[error("[code=install_failed] router={router}: {detail}")]
    SignaturePackageInstallFailed { router: String, detail: String },

    #[error(
        "[code=post_install_version_mismatch] router={router}: expected={expected}, got={got}"
    )]
    SignaturePackageVerificationFailed {
        router: String,
        expected: String,
        got: String,
    },

    #[error("[code=poll_timeout] router={router} action={action}: elapsed={elapsed_secs}s")]
    SignaturePackagePollTimeout {
        router: String,
        action: String,
        elapsed_secs: u64,
    },

    // Discovered during Task 1 live capture: a fresh device with no `security
    // idp` config stanza hangs ~60s and returns
    // `timeout communicating with idp-policy daemon` (rpc-error channel).
    // Pre-flight should detect this case (or auto-`restart idp-policy` once)
    // before surfacing this variant.
    #[error(
        "[code=daemon_not_ready] router={router}: idp-policy daemon not initialized — restart idp-policy or add minimum 'security idp' config stanza"
    )]
    SignaturePackageDaemonNotReady { router: String },
}

impl SrxError {
    /// Convenience builder used by per-tool parsers.
    pub fn schema_mismatch(rpc: &'static str, element: &'static str) -> Self {
        Self::SchemaMismatch { rpc, element }
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
}
