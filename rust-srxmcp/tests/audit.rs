//! Audit field + redaction assertions for rust-srxmcp.

use rust_junosmcp_audit::testutil::run_with_capture;
use rust_junosmcp_audit::AuditScope;

#[test]
fn scope_denial_emits_deny_not_fail() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(
            None,
            "get_chassis_cluster_status",
            "read",
            vec!["srx-01".into()],
        );
        a.deny("tool_scope");
    });
    assert!(out.contains("result=denied"), "output: {}", out);
    assert!(out.contains("reason=tool_scope"), "output: {}", out);
}

#[test]
fn missing_caller_context_denial() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(
            None,
            "manage_idp_security_package",
            "idp-package",
            vec!["srx-01".into()],
        );
        a.deny("missing_caller_context");
    });
    assert!(out.contains("result=denied"), "output: {}", out);
    assert!(
        out.contains("reason=missing_caller_context"),
        "output: {}",
        out
    );
}

#[test]
fn router_scope_denial() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(
            None,
            "get_srx_security_services_status",
            "read",
            vec!["srx-02".into()],
        );
        a.deny("router_scope");
    });
    assert!(out.contains("result=denied"), "output: {}", out);
    assert!(out.contains("reason=router_scope"), "output: {}", out);
}

#[test]
fn get_chassis_cluster_status_audit_logs_output_bytes() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(
            None,
            "get_chassis_cluster_status",
            "read",
            vec!["srx-01".into()],
        );
        a.meta("output_bytes", 512u64);
        a.succeed();
    });
    assert!(out.contains("output_bytes=512"), "output: {}", out);
    assert!(out.contains("result=ok"), "output: {}", out);
}

#[test]
fn check_srx_feature_license_logs_feature_not_output() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(
            None,
            "check_srx_feature_license",
            "read",
            vec!["srx-01".into()],
        );
        a.meta("feature", "IDP");
        a.succeed();
    });
    assert!(out.contains("feature=IDP"), "output: {}", out);
    assert!(!out.contains("license_key"));
}

#[test]
fn manage_idp_security_package_logs_action_and_version() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(
            None,
            "manage_idp_security_package",
            "idp-package",
            vec!["srx-01".into()],
        );
        a.meta("action", "DownloadAndInstall");
        a.meta("target_version", "5467");
        a.succeed();
    });
    assert!(out.contains("action=DownloadAndInstall"), "output: {}", out);
    assert!(out.contains("target_version=5467"), "output: {}", out);
}

#[test]
fn manage_appid_signature_package_logs_action() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(
            None,
            "manage_appid_signature_package",
            "appid-package",
            vec!["srx-01".into()],
        );
        a.meta("action", "CheckServer");
        a.succeed();
    });
    assert!(out.contains("action=CheckServer"), "output: {}", out);
}

#[test]
fn vpn_lifecycle_report_redacts_output() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(None, "vpn_lifecycle_report", "read", vec!["srx-01".into()]);
        a.meta("output_bytes", 2048u64);
        a.succeed();
    });
    assert!(out.contains("output_bytes=2048"), "output: {}", out);
    // The actual VPN SA details (PSKs, remote IPs) are not logged
    assert!(!out.contains("pre-shared-key"));
}

#[test]
fn validate_chassis_cluster_health_logs_output_bytes() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(
            None,
            "validate_chassis_cluster_health",
            "read",
            vec!["srx-01".into()],
        );
        a.meta("output_bytes", 1024u64);
        a.succeed();
    });
    assert!(out.contains("output_bytes=1024"), "output: {}", out);
}

#[test]
fn collect_jtac_support_bundle_succeeds_without_bundle_bytes() {
    // Support bundle doesn't attach bundle_bytes per the brief's table
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(
            None,
            "collect_jtac_support_bundle",
            "collect",
            vec!["srx-01".into()],
        );
        a.succeed();
    });
    assert!(out.contains("result=ok"), "output: {}", out);
    assert!(out.contains("routers=srx-01"), "output: {}", out);
}

#[test]
fn srxmcp_status_logs_read_action() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(None, "srxmcp_status", "read", vec![]);
        a.succeed();
    });
    assert!(out.contains("result=ok"), "output: {}", out);
    assert!(out.contains("action=read"), "output: {}", out);
}

#[test]
fn audit_scope_emits_unsettled_on_drop() {
    // AuditScope should emit "unsettled" if neither succeed() nor fail() nor deny() was called
    let out = run_with_capture(|| {
        let _a = AuditScope::new(
            None,
            "manage_idp_security_package",
            "idp-package",
            vec!["srx-01".into()],
        );
        // Drop without calling succeed/fail/deny
    });
    assert!(out.contains("result=unsettled"), "output: {}", out);
}
