//! Spawn the `rust-junosmcp` binary and exercise the `token` subcommand.

use std::process::Command;

mod common;
use common::{binary_path, ensure_built};

#[test]
fn add_then_list_reports_name_no_secret() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");

    let out = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "alice",
            "--routers",
            "*",
            "--tools",
            "get_router_list,get_junos_config",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stderr.is_empty(),
        "expected empty stderr on successful add, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let secret = String::from_utf8(out.stdout).unwrap().trim().to_string();
    assert_eq!(secret.len(), 43);

    let out = Command::new(binary_path())
        .args(["token", "list", "--tokens-file", tokens.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let body = String::from_utf8(out.stdout).unwrap();
    assert!(body.contains("alice"));
    assert!(!body.contains(&secret), "secret leaked into list output");
    assert!(!body.contains("sha256:"), "hash leaked into list output");
}

#[test]
fn revoke_then_list_omits_name() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");

    Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "bob",
            "--routers",
            "*",
            "--tools",
            "*",
        ])
        .status()
        .unwrap();
    let out = Command::new(binary_path())
        .args([
            "token",
            "revoke",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "bob",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    let out = Command::new(binary_path())
        .args(["token", "list", "--tokens-file", tokens.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let body = String::from_utf8(out.stdout).unwrap();
    assert!(!body.contains("bob"));
}

#[test]
fn rotate_changes_secret_keeps_scopes() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");

    let out1 = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "carol",
            "--routers",
            "r1,r2",
            "--tools",
            "execute_junos_command",
        ])
        .output()
        .unwrap();
    let secret1 = String::from_utf8(out1.stdout).unwrap().trim().to_string();

    let out2 = Command::new(binary_path())
        .args([
            "token",
            "rotate",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "carol",
        ])
        .output()
        .unwrap();
    assert!(out2.status.success());
    let secret2 = String::from_utf8(out2.stdout).unwrap().trim().to_string();
    assert_ne!(secret1, secret2);

    let body = std::fs::read_to_string(&tokens).unwrap();
    assert!(body.contains("\"r1\""));
    assert!(body.contains("execute_junos_command"));
}

#[test]
fn add_rejects_wildcard_mixed_with_names() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let out = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "evil",
            "--routers",
            "*,mx-01",
            "--tools",
            "*",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("'*'"),
        "expected '*'-related error, got: {stderr}"
    );
}

#[test]
fn add_rejects_unknown_tool() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let out = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "dan",
            "--routers",
            "*",
            "--tools",
            "no_such_tool",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(stderr.contains("no_such_tool"));
}

#[test]
fn add_accepts_srx_only_tool_scope() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let out = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "srx-read-only",
            "--routers",
            "srx-01",
            "--tools",
            "get_chassis_cluster_status,get_srx_security_services_status",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "token add rejected SRX scopes: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim().len(), 43);

    let body: serde_json::Value = serde_json::from_slice(&std::fs::read(&tokens).unwrap()).unwrap();
    assert_eq!(body["tokens"][0]["routers"], serde_json::json!(["srx-01"]));
    assert_eq!(
        body["tokens"][0]["tools"],
        serde_json::json!([
            "get_chassis_cluster_status",
            "get_srx_security_services_status"
        ])
    );
}
