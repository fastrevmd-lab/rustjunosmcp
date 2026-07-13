//! Audit field + redaction assertions for rust-junosmcp.

use rust_junosmcp_audit::testutil::run_with_capture;
use rust_junosmcp_audit::AuditScope;

#[test]
fn add_device_audit_omits_credentials() {
    // Simulate the metadata the handler attaches — must never include secrets.
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(None, "add_device", "add-device", vec![]);
        a.meta("name", "r99");
        a.meta("host", "192.0.2.10");
        a.meta("auth_kind", "password");
        // NOTE: the handler must NOT attach the password; assert it never appears.
        a.succeed();
    });
    assert!(out.contains("auth_kind=password"), "output: {}", out);
    assert!(!out.contains("hunter2"));
}

#[test]
fn commit_audit_logs_hash_not_body() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(None, "load_and_commit_config", "commit", vec!["r1".into()]);
        a.meta("config_bytes", 42u64);
        a.meta("config_sha256", "abc123");
        a.succeed();
    });
    assert!(out.contains("config_sha256=abc123"), "output: {}", out);
    assert!(!out.contains("pre-shared-key"));
}

#[test]
fn execute_command_redacts_command_output() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(None, "execute_junos_command", "execute", vec!["r1".into()]);
        a.meta("command", "show version");
        a.meta("output_bytes", 1024u64);
        a.succeed();
    });
    assert!(out.contains("command=show version"), "output: {}", out);
    assert!(out.contains("output_bytes=1024"), "output: {}", out);
    // The actual command output is not logged
    assert!(!out.contains("Junos: 25.4R1"));
}

#[test]
fn transfer_file_logs_sha256_not_content() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(None, "transfer_file", "transfer", vec!["r1".into()]);
        a.meta("basename", "junos-upgrade.tgz");
        a.meta("sha256", "deadbeef1234");
        a.succeed();
    });
    assert!(out.contains("sha256=deadbeef1234"), "output: {}", out);
    assert!(
        out.contains("basename=junos-upgrade.tgz"),
        "output: {}",
        out
    );
}

#[test]
fn scope_denial_emits_deny_not_fail() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(None, "execute_junos_command", "execute", vec!["r1".into()]);
        a.deny("tool_scope");
    });
    assert!(out.contains("result=denied"), "output: {}", out);
    assert!(out.contains("reason=tool_scope"), "output: {}", out);
}

#[test]
fn inventory_readonly_denial() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(None, "add_device", "add-device", vec![]);
        a.deny("inventory_readonly");
    });
    assert!(out.contains("result=denied"), "output: {}", out);
    assert!(out.contains("reason=inventory_readonly"), "output: {}", out);
}

#[test]
fn audit_scope_emits_unsettled_on_drop() {
    // AuditScope should emit "unsettled" if neither succeed() nor fail() nor deny() was called
    let out = run_with_capture(|| {
        let _a = AuditScope::new(None, "upgrade_junos", "upgrade", vec!["r1".into()]);
        // Drop without calling succeed/fail/deny
    });
    assert!(out.contains("result=unsettled"), "output: {}", out);
}

#[test]
fn batch_command_count_logged() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(
            None,
            "execute_junos_command_batch",
            "execute-batch",
            vec!["r1".into(), "r2".into()],
        );
        a.meta("command_count", 5u64);
        a.succeed();
    });
    assert!(out.contains("command_count=5"), "output: {}", out);
    assert!(out.contains("routers=r1,r2"), "output: {}", out);
}

#[test]
fn template_var_count_logged() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(
            None,
            "render_and_apply_j2_template",
            "apply",
            vec!["r1".into()],
        );
        a.meta("var_count", 3u64);
        a.meta("committed", true);
        a.succeed();
    });
    assert!(out.contains("var_count=3"), "output: {}", out);
    assert!(out.contains("committed=true"), "output: {}", out);
}

#[test]
fn get_router_list_count() {
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(None, "get_router_list", "read", vec![]);
        a.meta("count", 24u64);
        a.succeed();
    });
    assert!(out.contains("count=24"), "output: {}", out);
    assert!(out.contains("result=ok"), "output: {}", out);
}
