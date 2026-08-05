#![allow(clippy::unwrap_used)]
//! End-to-end streamable-http smoke: spawn the binary on an ephemeral port,
//! send HTTP, assert auth + scope + blocklist behavior.

mod common;
use common::*;
use rust_junosmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
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
    // Scope preflight rejects before dispatch with 403
    assert_eq!(r.code, 403);
    assert_eq!(r.body["error"], "insufficient_scope");
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
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
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
fn device_list_returns_only_current_names_in_caller_scope() {
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
        "device-list-scope",
        ScopeSet::Allowlist(vec!["edge-02".into(), "retired-99".into()]),
        ScopeSet::Allowlist(vec!["get_device_list".into()]),
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"get_device_list",
            "arguments":{}
        }}),
    );
    assert_eq!(response.code, 200, "body: {}", response.body);
    let text = response
        .body
        .pointer("/result/content/0/text")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("missing device-list text: {}", response.body));
    let names: Vec<String> = serde_json::from_str(text).unwrap();
    assert_eq!(names, vec!["edge-02"]);
    assert!(!text.contains("core-01"));
    assert!(!text.contains("edge-01"));
    assert!(!text.contains("retired-99"));
}

#[test]
fn get_router_list_alias_still_works() {
    // Prove backward compat: get_router_list still registered and callable
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "router-list-compat",
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(vec!["get_router_list".into()]),
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
            "name":"get_router_list",
            "arguments":{}
        }}),
    );
    assert_eq!(
        response.code, 200,
        "get_router_list failed: {}",
        response.body
    );
    let text = response
        .body
        .pointer("/result/content/0/text")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("missing text: {}", response.body));
    let names: Vec<String> = serde_json::from_str(text).unwrap();
    assert_eq!(names, vec!["r1"]);
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
    // Scope preflight rejects tool scope violation before dispatch with 403
    assert_eq!(r.code, 403);
    assert_eq!(r.body["error"], "insufficient_scope");
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

/// The Host allowlist has no off switch. `--disable-host-check` was removed in
/// 0.15.3: DNS rebinding (RUSTSEC-2026-0189) targets loopback-bound services, so
/// disabling the gate was most dangerous exactly where it looked safest. The flag
/// must be *rejected*, not silently ignored — an operator whose unit file still
/// carries it needs to find out at startup, not by being unprotected.
#[test]
fn disable_host_check_flag_is_rejected() {
    ensure_built();
    let out = Command::new(binary_path())
        .args(["--transport", "streamable-http", "--disable-host-check"])
        .output()
        .expect("run binary");
    assert!(
        !out.status.success(),
        "--disable-host-check must be rejected, not accepted"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unexpected argument") || stderr.contains("--disable-host-check"),
        "clap should name the removed flag; got: {stderr}"
    );
}

/// The replacement path: a foreign Host is refused, and `--allowed-host` is the
/// only way to admit one.
#[test]
fn foreign_host_is_rejected_with_no_escape_hatch() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let s = spawn_no_auth(inv.path(), &[]);
    let code = post_init_with_host(s.port, "anything.example");
    assert_ne!(
        code, 200,
        "an unlisted Host must not reach initialize (DNS-rebinding guard)"
    );
}

/// #199: a wildcard tool scope excludes write tools, so tools/list must not
/// advertise them. What you can see is what you can call.
#[test]
fn tools_list_hides_write_tools_from_a_wildcard_token() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "wildcard-ops",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    );
    assert_eq!(response.code, 200, "body: {}", response.body);

    let listed: Vec<String> = response
        .body
        .pointer("/result/tools")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("missing tools array: {}", response.body))
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect();

    assert!(
        !listed.is_empty(),
        "wildcard token must still see read tools"
    );
    for write_tool in rust_junosmcp_auth::WRITE_TOOLS {
        assert!(
            !listed.contains(&(*write_tool).to_string()),
            "tools/list must not advertise write tool {write_tool} to a wildcard token: {listed:?}"
        );
    }
    assert!(
        listed.contains(&"gather_device_facts".to_string()),
        "read-only tools must still be advertised: {listed:?}"
    );
}

/// The other half of #199: an explicit allowlist naming a write tool must
/// still advertise it, so narrowing a scope does not silently remove
/// capability the operator deliberately granted.
#[test]
fn tools_list_advertises_write_tools_named_in_an_explicit_allowlist() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "explicit-ops",
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(vec![
            "gather_device_facts".into(),
            "load_and_commit_config".into(),
        ]),
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    );
    assert_eq!(response.code, 200, "body: {}", response.body);

    let mut listed: Vec<String> = response
        .body
        .pointer("/result/tools")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("missing tools array: {}", response.body))
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect();
    listed.sort();

    assert_eq!(
        listed,
        vec![
            "gather_device_facts".to_string(),
            "load_and_commit_config".to_string()
        ]
    );
}
