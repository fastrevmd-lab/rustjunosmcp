//! End-to-end streamable-http smoke: spawn the binary on an ephemeral port,
//! send HTTP, assert auth + scope + blocklist behavior.

mod common;
use common::*;
use rust_junosmcp_auth::{ScopeSet, TokenStoreFile};
use serde_json::json;
use std::process::Command; // still used by tests that mint tokens via `token add`

#[test]
fn missing_authorization_returns_401() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let toks = write_tokens(r#"{"version":1,"tokens":[]}"#);
    let s = spawn(inv.path(), toks.path());
    let r = http_post(
        s.port,
        None,
        None,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
    );
    assert_eq!(r.code, 401);
    // RFC 6750 §3: every 401 must carry a Bearer challenge.
    let challenge = r
        .www_authenticate
        .expect("401 must carry WWW-Authenticate per RFC 6750 §3");
    assert!(
        challenge.to_ascii_lowercase().starts_with("bearer"),
        "challenge must use Bearer scheme: {challenge:?}"
    );
    // Body must be the RFC 6749 §5.2 JSON error object so OAuth-aware MCP
    // clients (e.g. Claude Code SDK) don't choke on a plain-text reason
    // phrase.
    assert_eq!(
        r.body["error"], "invalid_request",
        "missing-auth 401 body must be {{error:\"invalid_request\",...}}: {:?}",
        r.body
    );
    assert!(
        r.body["error_description"].is_string(),
        "401 body must include error_description string: {:?}",
        r.body
    );
}

#[test]
fn wrong_bearer_returns_401() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let toks = write_tokens(r#"{"version":1,"tokens":[]}"#);
    let s = spawn(inv.path(), toks.path());
    let r = http_post(
        s.port,
        Some("not-a-real-token"),
        None,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
    );
    assert_eq!(r.code, 401);
    // RFC 6750 §3 + §3.1: 401 for a rejected token must include the Bearer
    // challenge with error="invalid_token" so clients can distinguish a
    // bearer rejection from an OAuth-discovery prompt.
    let challenge = r
        .www_authenticate
        .expect("401 must carry WWW-Authenticate per RFC 6750 §3");
    assert!(
        challenge.to_ascii_lowercase().starts_with("bearer"),
        "challenge must use Bearer scheme: {challenge:?}"
    );
    assert!(
        challenge.contains(r#"error="invalid_token""#),
        "wrong-bearer challenge must include error=\"invalid_token\" per RFC 6750 §3.1: {challenge:?}"
    );
    // Body must be the RFC 6749 §5.2 JSON error object with the matching
    // OAuth error code so SDK clients can parse the response.
    assert_eq!(
        r.body["error"], "invalid_token",
        "wrong-bearer 401 body must be {{error:\"invalid_token\",...}}: {:?}",
        r.body
    );
    assert!(
        r.body["error_description"].is_string(),
        "401 body must include error_description string: {:?}",
        r.body
    );
}

#[test]
fn router_scope_denial_returns_tool_error_with_message() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let toks = dir.path().join("tokens.json");
    let out = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            toks.to_str().unwrap(),
            "--name",
            "scoped",
            "--routers",
            "other-router",
            "--tools",
            "*",
        ])
        .output()
        .unwrap();
    let secret = String::from_utf8(out.stdout).unwrap().trim().to_string();

    let s = spawn(inv.path(), &toks);

    let sid = initialize(s.port, &secret);
    let r = http_post(
        s.port,
        Some(&secret),
        Some(&sid),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":{"router_name":"r1","command":"show version","timeout":1}
        }}),
    );
    assert_eq!(r.code, 200, "body: {}", r.body);
    let result = r.body.pointer("/result").expect("result");
    assert_eq!(result.get("isError"), Some(&json!(true)));
    let text = serde_json::to_string(result).unwrap();
    assert!(
        text.contains("not authorized for router"),
        "expected scope denial, got {text}"
    );
}

#[test]
fn router_list_returns_only_current_names_in_caller_scope() {
    ensure_built();
    let inv = write_inv(
        r#"{
            "core-01":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}},
            "edge-01":{"ip":"203.0.113.2","port":1,"username":"u","auth":{"type":"password","password":"x"}},
            "edge-02":{"ip":"203.0.113.3","port":1,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "router-list-scope",
        ScopeSet::Allowlist(vec!["edge-02".into(), "retired-99".into()]),
        ScopeSet::Allowlist(vec!["get_router_list".into()]),
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose());
    let response = http_post(
        server.port,
        Some(secret.expose()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"get_router_list",
            "arguments":{}
        }}),
    );
    assert_eq!(response.code, 200, "body: {}", response.body);
    let text = response
        .body
        .pointer("/result/content/0/text")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("missing router-list text: {}", response.body));
    let names: Vec<String> = serde_json::from_str(text).unwrap();
    assert_eq!(names, vec!["edge-02"]);
    assert!(!text.contains("core-01"));
    assert!(!text.contains("edge-01"));
    assert!(!text.contains("retired-99"));
}

#[test]
fn auth_then_scope_then_blocklist_ordering() {
    ensure_built();
    let inv = write_inv(
        r#"{
        "_blocklist_defaults":{"commands":[{"action":"deny","pattern":"request system *"}]},
        "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
    }"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let toks = dir.path().join("tokens.json");
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
    let secret = String::from_utf8(out.stdout).unwrap().trim().to_string();

    let s = spawn(inv.path(), &toks);
    let sid = initialize(s.port, &secret);
    let r = http_post(
        s.port,
        Some(&secret),
        Some(&sid),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":{"router_name":"r1","command":"request system reboot","timeout":1}
        }}),
    );
    assert_eq!(r.code, 200, "body: {}", r.body);
    let result = r.body.pointer("/result").expect("result");
    assert_eq!(result.get("isError"), Some(&json!(true)));
    let text = serde_json::to_string(result).unwrap();
    assert!(
        text.contains("denied by blocklist"),
        "expected blocklist denial, got {text}"
    );
}

/// RJMCP-SEC-001: a token scoped only to `transfer_file` must NOT be able to
/// call `upgrade_junos`. Prior to v0.5.2, `KNOWN_TOOLS` was stale and minting a
/// token scoped to `transfer_file` was outright rejected — so the only way to
/// authorize `transfer_file` at all was a wildcard token, which also opened up
/// `upgrade_junos` (destructive, reboots devices).
#[test]
fn tool_scope_transfer_only_cannot_call_upgrade_junos() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let toks = dir.path().join("tokens.json");
    let out = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            toks.to_str().unwrap(),
            "--name",
            "transfer-only",
            "--routers",
            "*",
            "--tools",
            "transfer_file",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "token add must accept transfer_file scope post-SEC-001: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let secret = String::from_utf8(out.stdout).unwrap().trim().to_string();

    let s = spawn(inv.path(), &toks);
    let sid = initialize(s.port, &secret);
    let r = http_post(
        s.port,
        Some(&secret),
        Some(&sid),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"upgrade_junos",
            "arguments":{
                "router_name":"r1",
                "source_path":"junos.tgz",
                "target_version":"25.4R1.12",
                "confirm":false
            }
        }}),
    );
    assert_eq!(r.code, 200, "body: {}", r.body);
    let result = r.body.pointer("/result").expect("result");
    assert_eq!(result.get("isError"), Some(&json!(true)));
    let text = serde_json::to_string(result).unwrap();
    assert!(
        text.contains("not authorized for tool"),
        "expected tool-scope denial for upgrade_junos, got: {text}"
    );
}

#[test]
fn disallowed_host_is_rejected_403() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    // Default loopback allowlist only; no --allowed-host.
    let s = spawn_no_auth(inv.path(), &[]);
    let code = post_init_with_host(s.port, "evil.example.com");
    assert_eq!(
        code, 403,
        "rmcp's built-in Host allowlist must reject a disallowed Host (DNS-rebinding guard)"
    );
}

#[test]
fn allowed_host_flag_permits_custom_host() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let s = spawn_no_auth(inv.path(), &["--allowed-host", "friendly.example.com"]);
    let code = post_init_with_host(s.port, "friendly.example.com");
    assert_eq!(
        code, 200,
        "an --allowed-host authority must pass rmcp's Host check and reach initialize"
    );
}

#[test]
fn disable_host_check_allows_any_host() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let s = spawn_no_auth(inv.path(), &["--disable-host-check"]);
    let code = post_init_with_host(s.port, "anything.example");
    assert_eq!(
        code, 200,
        "--disable-host-check must bypass rmcp's Host check"
    );
}
