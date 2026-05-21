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
