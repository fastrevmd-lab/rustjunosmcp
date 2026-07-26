#![allow(clippy::unwrap_used)]
//! End-to-end streamable-http smoke for the execute_junos_command_batch tool.

mod common;
use common::*;
use serde_json::{Value, json};
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
fn batch_router_scope_first_failure_rejects_call() {
    ensure_built();
    let inv = write_tmp(
        r#"{
            "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}},
            "r2":{"ip":"203.0.113.2","port":1,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let toks = dir.path().join("tokens.json");
    // Token sees only r1.
    let secret = add_token(&toks, "scoped", "r1", "execute_junos_command_batch");

    let s = spawn(inv.path(), &toks);
    let sid = initialize(s.port, &secret);
    let r = http_post(
        s.port,
        Some(&secret),
        Some(&sid),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"execute_junos_command_batch",
            "arguments":{
                "routers":["r1","r2"],
                "commands":["show version"],
                "command_timeout":1,
                "max_concurrent_routers":2
            }
        }}),
    );
    assert_eq!(r.code, 200);
    let result = r.body.pointer("/result").expect("result");
    assert_eq!(result.get("isError"), Some(&json!(true)));
    let text = serde_json::to_string(result).unwrap();
    assert!(text.contains("not authorized for router"), "got: {text}");
}

#[test]
fn batch_returns_per_router_error_rows_on_unreachable_ips() {
    ensure_built();
    let inv = write_tmp(
        r#"{
            "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}},
            "r2":{"ip":"203.0.113.2","port":1,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let toks = dir.path().join("tokens.json");
    let secret = add_token(&toks, "ops", "*", "execute_junos_command_batch");

    let s = spawn(inv.path(), &toks);
    let sid = initialize(s.port, &secret);
    let r = http_post(
        s.port,
        Some(&secret),
        Some(&sid),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"execute_junos_command_batch",
            "arguments":{
                "routers":["r1","r2"],
                "commands":["show version"],
                "command_timeout":1,
                "batch_timeout":3,
                "max_concurrent_routers":2
            }
        }}),
    );
    assert_eq!(r.code, 200);
    let result = r.body.pointer("/result").expect("result");
    // Tool succeeded (not isError) — failures are inside the rows.
    assert_ne!(result.get("isError"), Some(&json!(true)));
    let content = result
        .pointer("/content/0/text")
        .expect("content text")
        .as_str()
        .unwrap();
    let parsed: Value = serde_json::from_str(content).expect("content is JSON");
    let arr = parsed.as_array().expect("array of routers");
    assert_eq!(arr.len(), 2);
    for row in arr {
        let cmds = row.pointer("/commands").unwrap().as_array().unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].get("ok"), Some(&json!(false)));
        let err = cmds[0].get("error").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            err.contains("connect failed") || err == "command timeout" || err == "batch timeout",
            "unexpected error string: {err}",
        );
    }
}
