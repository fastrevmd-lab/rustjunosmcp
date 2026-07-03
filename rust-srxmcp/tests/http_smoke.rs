//! Streamable-http integration smoke for rust-srxmcp: auth (RFC 6750 401s),
//! rmcp 2.0 Host allowlist (#97), and the tool-surface tripwire. All tests
//! exercise the transport/auth layers only — no device is contacted.

mod common;
use common::*;
use serde_json::json;

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
fn lists_nine_tools() {
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
    assert_eq!(
        tools.len(),
        9,
        "srx tool surface must be 9: {:?}",
        tools
            .iter()
            .filter_map(|t| t.get("name"))
            .collect::<Vec<_>>()
    );
}
