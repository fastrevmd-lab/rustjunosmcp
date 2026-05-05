//! Spawn the `rust-junosmcp` binary and exercise the `token` subcommand.

use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("target");
    p.push(if cfg!(debug_assertions) { "debug" } else { "release" });
    p.push("rust-junosmcp");
    p
}

fn ensure_built() {
    let s = Command::new("cargo").args(["build", "-p", "rust-junosmcp"]).status().unwrap();
    assert!(s.success());
}

#[test]
fn add_then_list_reports_name_no_secret() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");

    let out = Command::new(binary_path())
        .args(["token", "add",
               "--tokens-file", tokens.to_str().unwrap(),
               "--name", "alice",
               "--routers", "*",
               "--tools", "get_router_list,get_junos_config"])
        .output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let secret = String::from_utf8(out.stdout).unwrap().trim().to_string();
    assert_eq!(secret.len(), 43);

    let out = Command::new(binary_path())
        .args(["token", "list", "--tokens-file", tokens.to_str().unwrap()])
        .output().unwrap();
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
        .args(["token", "add", "--tokens-file", tokens.to_str().unwrap(),
               "--name", "bob", "--routers", "*", "--tools", "*"])
        .status().unwrap();
    let out = Command::new(binary_path())
        .args(["token", "revoke", "--tokens-file", tokens.to_str().unwrap(), "--name", "bob"])
        .output().unwrap();
    assert!(out.status.success());

    let out = Command::new(binary_path())
        .args(["token", "list", "--tokens-file", tokens.to_str().unwrap()])
        .output().unwrap();
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
        .args(["token", "add", "--tokens-file", tokens.to_str().unwrap(),
               "--name", "carol", "--routers", "r1,r2", "--tools", "execute_junos_command"])
        .output().unwrap();
    let secret1 = String::from_utf8(out1.stdout).unwrap().trim().to_string();

    let out2 = Command::new(binary_path())
        .args(["token", "rotate", "--tokens-file", tokens.to_str().unwrap(), "--name", "carol"])
        .output().unwrap();
    assert!(out2.status.success());
    let secret2 = String::from_utf8(out2.stdout).unwrap().trim().to_string();
    assert_ne!(secret1, secret2);

    let body = std::fs::read_to_string(&tokens).unwrap();
    assert!(body.contains("\"r1\""));
    assert!(body.contains("execute_junos_command"));
}

#[test]
fn add_rejects_unknown_tool() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let out = Command::new(binary_path())
        .args(["token", "add", "--tokens-file", tokens.to_str().unwrap(),
               "--name", "dan", "--routers", "*", "--tools", "no_such_tool"])
        .output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(stderr.contains("no_such_tool"));
}
