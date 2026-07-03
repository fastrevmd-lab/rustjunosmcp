//! SIGHUP hot reload smoke. Unix-only.
//!
//! Verifies that sending SIGHUP to the running server causes it to re-read
//! the tokens file and atomically swap the in-memory store, so a token that
//! was valid before the signal becomes rejected after it.
#![cfg(unix)]

mod common;
use common::*;
use serde_json::json;
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn sighup_reloads_token_store() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let inv = dir.path().join("inv.json");
    std::fs::write(
        &inv,
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    )
    .unwrap();
    let toks = dir.path().join("tokens.json");

    // Mint a wildcard token via the subcommand.
    let out = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            toks.to_str().unwrap(),
            "--name",
            "all",
            "--routers",
            "*",
            "--tools",
            "*",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "token add failed: {:?}", out);
    let secret = String::from_utf8(out.stdout).unwrap().trim().to_string();
    assert!(!secret.is_empty(), "minted secret should not be empty");

    let s = spawn(&inv, &toks);

    // Phase 1: token is valid. Auth layer must let the request through. We
    // don't care what rmcp does with a bare tools/list (it'll likely return
    // 400/406 for missing session) — only that the auth verdict is "pass",
    // i.e. status != 401.
    let r = http_post(
        s.port,
        Some(&secret),
        None,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
    );
    assert_ne!(
        r.code, 401,
        "valid token should not be rejected before SIGHUP (got {})",
        r.code
    );

    // Revoke the token on disk. The running server still has the old store.
    let revoke = Command::new(binary_path())
        .args([
            "token",
            "revoke",
            "--tokens-file",
            toks.to_str().unwrap(),
            "--name",
            "all",
        ])
        .output()
        .unwrap();
    assert!(revoke.status.success(), "token revoke failed: {:?}", revoke);

    // SIGHUP the server to trigger reload.
    let pid = s.child.id() as i32;
    let rc = unsafe { libc::kill(pid, libc::SIGHUP) };
    assert_eq!(rc, 0, "kill(SIGHUP) failed: errno");

    // Phase 2: same token, but now revoked + reloaded. Poll until we observe
    // 401 or hit the deadline. This is faster on the happy path than a fixed
    // sleep and tolerates slow CI.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_code = 0u16;
    let mut last_body = json!({});
    while Instant::now() < deadline {
        let r = http_post(
            s.port,
            Some(&secret),
            None,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        );
        last_code = r.code;
        last_body = r.body;
        if last_code == 401 {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        last_code, 401,
        "revoked token should be 401 within 5s of SIGHUP reload (body: {})",
        last_body
    );
}
