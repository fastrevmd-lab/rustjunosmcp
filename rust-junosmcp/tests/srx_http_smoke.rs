//! Streamable-http integration smoke for the unified server's SRX tools: auth (RFC 6750 401s),
//! rmcp 2.0 Host allowlist (#97), and the tool-surface tripwire. All tests
//! exercise the transport/auth layers only — no device is contacted.

mod common;
use common::*;
use rust_junosmcp_auth::{ScopeSet, TokenStoreFile};
use serde_json::json;
use std::collections::HashSet;

fn add_token(path: &std::path::Path, name: &str, routers: ScopeSet, tools: ScopeSet) -> String {
    TokenStoreFile::add(path, name, routers, tools)
        .unwrap()
        .expose()
        .to_string()
}

fn initialize_authenticated(server: &Server, secret: &str) -> String {
    let init = http_post(server.port, Some(secret), None, init_body());
    assert_eq!(init.code, 200, "initialize failed: {:?}", init.body);
    let sid = init
        .session_id
        .expect("server did not return Mcp-Session-Id");
    let initialized = http_post(
        server.port,
        Some(secret),
        Some(&sid),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    assert_eq!(
        initialized.code, 202,
        "initialized failed: {:?}",
        initialized.body
    );
    sid
}

fn srx_router_tool_calls() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        ("get_chassis_cluster_status", json!({"router":"r1"})),
        ("get_srx_security_services_status", json!({"router":"r1"})),
        (
            "check_srx_feature_license",
            json!({"router":"r1","feature":"idp"}),
        ),
        ("vpn_lifecycle_report", json!({"router":"r1"})),
        (
            "manage_idp_security_package",
            json!({"router":"r1","action":"check_server"}),
        ),
        (
            "manage_appid_signature_package",
            json!({"router":"r1","action":"check_server"}),
        ),
        ("validate_chassis_cluster_health", json!({"router":"r1"})),
        (
            "collect_jtac_support_bundle",
            json!({"router":"r1","problem_type":"generic"}),
        ),
    ]
}

fn placeholder_inv() -> tempfile::NamedTempFile {
    write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    )
}

#[test]
fn missing_authorization_returns_401() {
    ensure_built();
    let inv = placeholder_inv();
    let toks = write_tokens(r#"{"version":1,"tokens":[]}"#);
    let s = spawn(inv.path(), toks.path());
    let r = http_post(
        s.port,
        None,
        None,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
    );
    assert_eq!(r.code, 401);
    let challenge = r
        .www_authenticate
        .expect("401 must carry WWW-Authenticate per RFC 6750 §3");
    assert!(
        challenge.to_ascii_lowercase().starts_with("bearer"),
        "challenge must use Bearer scheme: {challenge:?}"
    );
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
    let inv = placeholder_inv();
    let toks = write_tokens(r#"{"version":1,"tokens":[]}"#);
    let s = spawn(inv.path(), toks.path());
    let r = http_post(
        s.port,
        Some("not-a-real-token"),
        None,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
    );
    assert_eq!(r.code, 401);
    let challenge = r
        .www_authenticate
        .expect("401 must carry WWW-Authenticate per RFC 6750 §3");
    assert!(
        challenge.contains(r#"error="invalid_token""#),
        "wrong-bearer challenge must include error=\"invalid_token\": {challenge:?}"
    );
    assert_eq!(
        r.body["error"], "invalid_token",
        "wrong-bearer 401 body must be {{error:\"invalid_token\",...}}: {:?}",
        r.body
    );
}

#[test]
fn disallowed_host_is_rejected_403() {
    ensure_built();
    let inv = placeholder_inv();
    let s = spawn_no_auth(inv.path(), &[]);
    let code = post_init_with_host(s.port, "evil.example.com");
    assert_eq!(
        code, 403,
        "rmcp's built-in Host allowlist must reject a disallowed Host"
    );
}

#[test]
fn allowed_host_flag_permits_custom_host() {
    ensure_built();
    let inv = placeholder_inv();
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
    let inv = placeholder_inv();
    let s = spawn_no_auth(inv.path(), &["--disable-host-check"]);
    let code = post_init_with_host(s.port, "anything.example");
    assert_eq!(
        code, 200,
        "--disable-host-check must bypass rmcp's Host check"
    );
}

#[test]
fn lists_all_known_tools() {
    ensure_built();
    let inv = placeholder_inv();
    let s = spawn_no_auth(inv.path(), &[]);
    // initialize (no auth) then tools/list.
    let init = http_post(s.port, None, None, init_body());
    assert_eq!(init.code, 200, "initialize failed: {:?}", init.body);
    let sid = init
        .session_id
        .expect("server did not return Mcp-Session-Id");
    let _ = http_post(
        s.port,
        None,
        Some(&sid),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    let r = http_post(
        s.port,
        None,
        Some(&sid),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    );
    assert_eq!(r.code, 200, "tools/list failed: {:?}", r.body);
    let tools = r
        .body
        .pointer("/result/tools")
        .and_then(|t| t.as_array())
        .expect("tools array");
    let names: HashSet<&str> = tools
        .iter()
        .filter_map(|tool| tool.get("name").and_then(serde_json::Value::as_str))
        .collect();
    let expected: HashSet<&str> = rust_junosmcp_auth::file::KNOWN_TOOLS
        .iter()
        .copied()
        .collect();
    assert_eq!(names, expected);
    assert_eq!(tools.len(), 26);
    assert_eq!(names.len(), 26);
}

#[test]
fn every_srx_tool_enforces_tool_scope_before_device_access() {
    ensure_built();
    let inv = placeholder_inv();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = add_token(
        &tokens,
        "junos-only",
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(vec!["get_router_list".into()]),
    );
    let server = spawn(inv.path(), &tokens);
    let sid = initialize_authenticated(&server, &secret);

    let mut calls = vec![("srxmcp_status", json!({}))];
    calls.extend(srx_router_tool_calls());
    for (index, (tool, arguments)) in calls.into_iter().enumerate() {
        let response = http_post(
            server.port,
            Some(&secret),
            Some(&sid),
            json!({"jsonrpc":"2.0","id":index + 1,"method":"tools/call","params":{
                "name":tool,"arguments":arguments
            }}),
        );
        assert_eq!(response.code, 200, "{tool}: {}", response.body);
        let result = response.body.pointer("/result").expect("tool result");
        assert_eq!(
            result.get("isError"),
            Some(&json!(true)),
            "{tool}: {result}"
        );
        let text = serde_json::to_string(result).unwrap();
        assert!(
            text.contains("[code=tool_scope_denied]"),
            "{tool} did not enforce tool scope: {text}"
        );
        assert!(
            !text.contains("opening device"),
            "{tool} reached DeviceManager before authorization: {text}"
        );
    }
}

#[test]
fn every_router_tool_enforces_router_scope_without_disclosing_router() {
    ensure_built();
    let inv = placeholder_inv();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = add_token(
        &tokens,
        "other-router-only",
        ScopeSet::Allowlist(vec!["other-router".into()]),
        ScopeSet::Wildcard,
    );
    let server = spawn(inv.path(), &tokens);
    let sid = initialize_authenticated(&server, &secret);

    for (index, (tool, arguments)) in srx_router_tool_calls().into_iter().enumerate() {
        let response = http_post(
            server.port,
            Some(&secret),
            Some(&sid),
            json!({"jsonrpc":"2.0","id":index + 1,"method":"tools/call","params":{
                "name":tool,"arguments":arguments
            }}),
        );
        assert_eq!(response.code, 200, "{tool}: {}", response.body);
        let result = response.body.pointer("/result").expect("tool result");
        assert_eq!(
            result.get("isError"),
            Some(&json!(true)),
            "{tool}: {result}"
        );
        let text = serde_json::to_string(result).unwrap();
        assert!(
            text.contains("[code=router_scope_denied]"),
            "{tool} did not enforce router scope: {text}"
        );
        assert!(
            !text.contains("r1") && !text.contains("opening device"),
            "{tool} disclosed the router or reached DeviceManager: {text}"
        );
    }
}
