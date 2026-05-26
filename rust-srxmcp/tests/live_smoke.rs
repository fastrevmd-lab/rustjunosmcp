//! Live smoke against the LXC 601 deployment.
//!
//! Required env:
//!   `JMCP_SRX_LIVE_URL`   e.g. `http://192.168.1.194:30032/mcp`
//!   `JMCP_SRX_LIVE_TOKEN` bearer token
//!
//! Run: `cargo test --test live_smoke -p rust-srxmcp -- --ignored`.

#![cfg(test)]

use serde_json::{json, Value};

fn endpoint() -> (String, String) {
    let url = std::env::var("JMCP_SRX_LIVE_URL").expect("JMCP_SRX_LIVE_URL required");
    let tok = std::env::var("JMCP_SRX_LIVE_TOKEN").expect("JMCP_SRX_LIVE_TOKEN required");
    (url, tok)
}

#[test]
#[ignore]
fn cluster_status_against_test19_20() {
    let (url, token) = endpoint();
    let mut c = Client::connect(&url, &token);
    let resp = c.tool_call(
        "get_chassis_cluster_status",
        json!({"router": "vSRX-test19-20"}),
    );
    let inner = parse_tool_text(&resp);
    assert_eq!(inner["state"], "active", "resp: {inner}");
    assert_eq!(inner["data"]["cluster_id"], 1, "resp: {inner}");
}

#[test]
#[ignore]
fn license_idp_against_test10_is_not_configured_in_lab() {
    let (url, token) = endpoint();
    let mut c = Client::connect(&url, &token);
    let resp = c.tool_call(
        "check_srx_feature_license",
        json!({"router": "vSRX-test10", "feature": "idp"}),
    );
    let inner = parse_tool_text(&resp);
    assert_eq!(inner["state"], "not_configured", "resp: {inner}");
}

#[test]
#[ignore]
fn services_status_against_test10() {
    let (url, token) = endpoint();
    let mut c = Client::connect(&url, &token);
    let resp = c.tool_call(
        "get_srx_security_services_status",
        json!({"router": "vSRX-test10"}),
    );
    let inner = parse_tool_text(&resp);
    // test10 has at least IDP configured (it's the lab device).
    assert_eq!(inner["state"], "active", "resp: {inner}");
}

#[test]
#[ignore]
fn vpn_report_against_test10_after_appendix_a() {
    let (url, token) = endpoint();
    let mut c = Client::connect(&url, &token);
    let resp = c.tool_call("vpn_lifecycle_report", json!({"router": "vSRX-test10"}));
    let inner = parse_tool_text(&resp);
    assert_eq!(inner["state"], "active", "resp: {inner}");
    let nodes = inner["data"]["nodes"].as_array().expect("nodes array");
    assert!(
        nodes
            .iter()
            .any(|n| !n["ike_sas"].as_array().unwrap_or(&vec![]).is_empty()),
        "expected at least one IKE SA across nodes: {inner}"
    );
}

// ── IDP signature-package smokes (Phase 2 / v0.2.0) ────────────────────────
//
// All target `vSRX-twin` (Demolab demo, IDP-SIG + APPID Signature active
// through 2027-05-21 per LXC 601's /etc/jmcp/devices.json). Destructive
// tests modify the live device — `#[ignore]`d, run only with explicit
// operator authorization.
//
// Run order matters: `idp_download_and_install_call2_succeeds` must run
// before `idp_already_at_target_short_circuits` and
// `idp_rollback_after_install_restores_previous`. Constrain with
// `--test-threads=1 idp_`.

const IDP_PRIMARY: &str = "vSRX-test3";
/// Cluster target. No IDP-licensed clustered device exists in the current
/// lab inventory (vSRX-test19-20 is the cluster but trial-only as of
/// 2026-05-26); this test will fail until a licensed pair is provisioned.
const IDP_CLUSTER: &str = "vSRX-test19-20";

#[test]
#[ignore]
fn idp_check_server_returns_latest_version() {
    let (url, token) = endpoint();
    let mut c = Client::connect(&url, &token);
    let resp = c.tool_call(
        "manage_idp_security_package",
        json!({"router": IDP_PRIMARY, "action": "check_server"}),
    );
    let inner = parse_tool_text(&resp);
    assert_eq!(inner["router"], IDP_PRIMARY, "resp: {inner}");
    let latest = inner["latest_version"]
        .as_str()
        .unwrap_or_else(|| panic!("no latest_version str in {inner}"));
    assert!(
        latest.chars().all(|c| c.is_ascii_digit()) && !latest.is_empty(),
        "latest_version not numeric: {latest:?}"
    );
    let nodes = inner["nodes"].as_array().expect("nodes array");
    assert!(!nodes.is_empty(), "expected at least one node row: {inner}");
}

#[test]
#[ignore]
fn idp_download_and_install_call1_returns_plan() {
    let (url, token) = endpoint();
    let mut c = Client::connect(&url, &token);
    // No confirm=true → expect JSON-RPC error with the
    // [code=confirmation_required] bracketed token + embedded plan JSON.
    let err = c.tool_error_call(
        "manage_idp_security_package",
        json!({"router": IDP_PRIMARY, "action": "download_and_install"}),
    );
    let msg = err
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no /error/message in {err}"));
    assert!(
        msg.contains("[code=confirmation_required]"),
        "expected confirmation_required token, got: {msg}"
    );
    assert!(msg.contains("plan:"), "expected plan: section in {msg}");
}

#[test]
#[ignore]
fn idp_download_and_install_call2_succeeds() {
    let (url, token) = endpoint();
    let mut c = Client::connect(&url, &token);
    // Real download (~300MB pulled from signatures.juniper.net) + install.
    // Allow 20 min server-side budget; ureq has no default read timeout so
    // it'll block until rmcp responds.
    let resp = c.tool_call(
        "manage_idp_security_package",
        json!({
            "router": IDP_PRIMARY,
            "action": "download_and_install",
            "confirm": true,
            "timeout": 1200_u64,
        }),
    );
    let inner = parse_tool_text(&resp);
    // Either Completed (full install ran) or AlreadyAtTarget (idempotent rerun).
    let status = inner["status"]
        .as_str()
        .unwrap_or_else(|| panic!("no status in {inner}"));
    assert!(
        status == "completed" || status == "already_at_target",
        "unexpected status: {status} body: {inner}"
    );
}

#[test]
#[ignore]
fn idp_already_at_target_short_circuits() {
    // Assumes idp_download_and_install_call2_succeeds ran first.
    let (url, token) = endpoint();
    let mut c = Client::connect(&url, &token);
    let resp = c.tool_call(
        "manage_idp_security_package",
        json!({
            "router": IDP_PRIMARY,
            "action": "download_and_install",
            "confirm": true,
        }),
    );
    let inner = parse_tool_text(&resp);
    assert_eq!(
        inner["status"], "already_at_target",
        "expected short-circuit: {inner}"
    );
}

#[test]
#[ignore]
fn idp_version_pin_accepts_explicit() {
    // Discover the latest via check_server, then pin and reinstall.
    let (url, token) = endpoint();
    let mut c = Client::connect(&url, &token);
    let cs = c.tool_call(
        "manage_idp_security_package",
        json!({"router": IDP_PRIMARY, "action": "check_server"}),
    );
    let latest = parse_tool_text(&cs)["latest_version"]
        .as_str()
        .expect("latest_version")
        .to_string();
    let resp = c.tool_call(
        "manage_idp_security_package",
        json!({
            "router": IDP_PRIMARY,
            "action": "download_and_install",
            "version": latest,
            "confirm": true,
            "timeout": 1200_u64,
        }),
    );
    let inner = parse_tool_text(&resp);
    let status = inner["status"].as_str().expect("status");
    assert!(
        status == "completed" || status == "already_at_target",
        "unexpected status: {status} body: {inner}"
    );
}

#[test]
#[ignore]
fn idp_rollback_after_install_restores_previous() {
    // Requires a prior successful install so the device carries a
    // <security-package-rollback-version>.
    let (url, token) = endpoint();
    let mut c = Client::connect(&url, &token);
    let resp = c.tool_call(
        "manage_idp_security_package",
        json!({
            "router": IDP_PRIMARY,
            "action": "rollback",
            "confirm": true,
            "timeout": 600_u64,
        }),
    );
    let inner = parse_tool_text(&resp);
    assert_eq!(inner["status"], "completed", "rollback failed: {inner}");
}

#[test]
#[ignore]
fn idp_cluster_install_syncs_both_nodes() {
    // Cluster target; will fail until a clustered+IDP-licensed device exists.
    let (url, token) = endpoint();
    let mut c = Client::connect(&url, &token);
    let resp = c.tool_call(
        "manage_idp_security_package",
        json!({
            "router": IDP_CLUSTER,
            "action": "download_and_install",
            "confirm": true,
            "timeout": 1500_u64,
        }),
    );
    let inner = parse_tool_text(&resp);
    let status = inner["status"].as_str().expect("status");
    assert!(
        status == "completed" || status == "already_at_target",
        "unexpected status: {status} body: {inner}"
    );
}

// ── Minimal MCP streamable-HTTP client ─────────────────────────────────────

struct Client {
    url: String,
    token: String,
    session_id: String,
    next_id: i64,
}

impl Client {
    fn connect(url: &str, token: &str) -> Self {
        let mut c = Self {
            url: url.to_string(),
            token: token.to_string(),
            session_id: String::new(),
            next_id: 0,
        };
        let init = c.post_raw(
            None,
            json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
                "protocolVersion":"2025-03-26","capabilities":{},
                "clientInfo":{"name":"srx-smoke","version":"0.1"}
            }}),
        );
        c.session_id = init.session_id.expect("Mcp-Session-Id from initialize");
        assert_eq!(init.code, 200, "initialize failed: {:?}", init.body);
        let n = c.post_raw(
            Some(&c.session_id.clone()),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        );
        assert!(
            n.code == 200 || n.code == 202,
            "initialized notification rejected: {} {:?}",
            n.code,
            n.body
        );
        c
    }

    fn tool_call(&mut self, name: &str, arguments: Value) -> Value {
        self.next_id += 1;
        let body = json!({
            "jsonrpc":"2.0","id":self.next_id,"method":"tools/call","params":{
                "name": name,
                "arguments": arguments,
            }
        });
        let sid = self.session_id.clone();
        let r = self.post_raw(Some(&sid), body);
        assert_eq!(r.code, 200, "{name} failed: {} body={:?}", r.code, r.body);
        r.body
    }

    /// Like `tool_call` but expects a JSON-RPC error in the body (HTTP 200,
    /// `/error/{code,message}` populated). Used for the call-1
    /// `confirmation_required` path of the IDP signature-package tool.
    fn tool_error_call(&mut self, name: &str, arguments: Value) -> Value {
        self.next_id += 1;
        let body = json!({
            "jsonrpc":"2.0","id":self.next_id,"method":"tools/call","params":{
                "name": name,
                "arguments": arguments,
            }
        });
        let sid = self.session_id.clone();
        let r = self.post_raw(Some(&sid), body);
        assert_eq!(
            r.code, 200,
            "expected 200 with body-level error, got {}: {:?}",
            r.code, r.body
        );
        assert!(
            r.body.pointer("/error/message").is_some(),
            "expected /error/message in body, got: {}",
            r.body
        );
        r.body
    }

    fn post_raw(&self, session: Option<&str>, body: Value) -> PostResult {
        let mut req = ureq::post(&self.url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Accept", "application/json, text/event-stream")
            .set("Content-Type", "application/json");
        if let Some(sid) = session {
            req = req.set("Mcp-Session-Id", sid);
        }
        let (code, sid, ct, text) = match req.send_json(body) {
            Ok(resp) => {
                let code = resp.status();
                let s = resp.header("Mcp-Session-Id").map(str::to_string);
                let ct = resp.header("Content-Type").unwrap_or("").to_string();
                let t = resp.into_string().unwrap_or_default();
                (code, s, ct, t)
            }
            Err(ureq::Error::Status(code, resp)) => {
                let s = resp.header("Mcp-Session-Id").map(str::to_string);
                let ct = resp.header("Content-Type").unwrap_or("").to_string();
                let t = resp.into_string().unwrap_or_default();
                (code, s, ct, t)
            }
            Err(e) => panic!("transport error: {e}"),
        };
        let body_value = if ct.contains("text/event-stream") {
            parse_first_sse_data(&text).unwrap_or(json!({}))
        } else if !text.is_empty() {
            serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text}))
        } else {
            json!({})
        };
        PostResult {
            code,
            body: body_value,
            session_id: sid,
        }
    }
}

struct PostResult {
    code: u16,
    body: Value,
    session_id: Option<String>,
}

fn parse_first_sse_data(sse: &str) -> Option<Value> {
    for line in sse.lines() {
        if let Some(payload) = line.strip_prefix("data:") {
            return serde_json::from_str(payload.trim()).ok();
        }
    }
    None
}

/// Tool replies arrive as `{result: {content: [{type: "text", text: "<json>"}]}}`.
/// Pull the first text item and parse it as JSON — that's our `SrxToolResponse`.
fn parse_tool_text(resp: &Value) -> Value {
    let text = resp
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no /result/content/0/text in {resp}"));
    serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("inner JSON parse failed: {e} text={text}"))
}
