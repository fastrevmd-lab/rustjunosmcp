#![allow(clippy::unwrap_used)]
//! End-to-end streamable-http smoke for the PFE tool.

mod common;
use common::*;
use serde_json::json;
use std::process::Command;

fn write_tmp(json: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), json).unwrap();
    f
}

fn add_token(tokens_path: &std::path::Path, name: &str, routers: &str, tools: &str) -> String {
    let out = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens_path.to_str().unwrap(),
            "--name",
            name,
            "--routers",
            routers,
            "--tools",
            tools,
        ])
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn pfe_scope_denial_returns_tool_error() {
    ensure_built();
    let inv = write_tmp(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let toks = dir.path().join("tokens.json");
    // Mint a token WITHOUT the pfe tool in scope.
    let secret = add_token(&toks, "no-pfe", "*", "execute_junos_command");

    let s = spawn(inv.path(), &toks);
    let sid = initialize(s.port, &secret);
    let r = http_post(
        s.port,
        Some(&secret),
        Some(&sid),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"execute_junos_pfe_command",
            "arguments":{"router_name":"r1","fpc_target":"fpc0","pfe_command":"show jnh 0 stats","timeout":1}
        }}),
    );
    // Scope preflight rejects tool scope violation before dispatch with 403
    assert_eq!(r.code, 403);
    assert_eq!(r.body["error"], "insufficient_scope");
}

#[test]
fn pfe_connect_failure_surfaces_through_tool_call() {
    ensure_built();
    // Unreachable IP/port so connect must fail.
    let inv = write_tmp(
        r#"{"r1":{"ip":"127.0.0.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let toks = dir.path().join("tokens.json");
    let secret = add_token(&toks, "ops", "*", "execute_junos_pfe_command");

    let s = spawn(inv.path(), &toks);
    let sid = initialize(s.port, &secret);
    let r = http_post(
        s.port,
        Some(&secret),
        Some(&sid),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"execute_junos_pfe_command",
            "arguments":{"router_name":"r1","fpc_target":"fpc0","pfe_command":"show jnh 0 stats","timeout":1}
        }}),
    );
    assert_eq!(r.code, 200);
    let result = r.body.pointer("/result").expect("result");
    assert_eq!(result.get("isError"), Some(&json!(true)));
}
