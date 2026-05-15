//! End-to-end streamable-http smoke: spawn the binary on an ephemeral port,
//! send HTTP, assert auth + scope + blocklist behavior.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn binary_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("target");
    p.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    p.push("rust-junosmcp");
    p
}

fn ensure_built() {
    let s = Command::new("cargo")
        .args(["build", "-p", "rust-junosmcp"])
        .status()
        .unwrap();
    assert!(s.success());
}

fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// RAII child guard: kills + waits on drop so panics don't leak processes.
/// Also keeps a background drain thread on stderr so the child never blocks
/// or SIGPIPEs on log writes after the readiness line.
struct Server {
    child: Child,
    port: u16,
    _stderr_drain: std::thread::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn(inv_path: &std::path::Path, tokens_path: &std::path::Path) -> Server {
    let port = pick_port();
    let mut child = Command::new(binary_path())
        .args([
            "-f",
            inv_path.to_str().unwrap(),
            "-t",
            "streamable-http",
            "-H",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "--tokens-file",
            tokens_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let stderr = child.stderr.take().unwrap();
    let mut reader = BufReader::new(stderr);
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut ready = false;
    loop {
        if Instant::now() > deadline {
            break;
        }
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF: process died
            Ok(_) => {
                if line.contains("streamable-http listening") {
                    ready = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }
    if !ready {
        let _ = child.kill();
        panic!("server did not start within 15s");
    }
    // Spawn a drain thread so the child's stderr pipe never fills and the
    // BufReader (and underlying ChildStderr) is kept alive for the test's
    // duration.
    let drain = std::thread::spawn(move || {
        let mut sink = String::new();
        loop {
            sink.clear();
            match reader.read_line(&mut sink) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });
    Server {
        child,
        port,
        _stderr_drain: drain,
    }
}

/// Outcome of a streamable-http POST: status, body parsed as JSON-RPC payload
/// (extracted from SSE if needed), any returned `Mcp-Session-Id`, and the
/// `WWW-Authenticate` header if present (for RFC 6750 §3 assertions on 401).
struct PostResult {
    code: u16,
    body: Value,
    session_id: Option<String>,
    www_authenticate: Option<String>,
}

fn http_post(port: u16, bearer: Option<&str>, session_id: Option<&str>, body: Value) -> PostResult {
    let mut req = ureq::post(&format!("http://127.0.0.1:{port}/mcp"));
    if let Some(b) = bearer {
        req = req.set("Authorization", &format!("Bearer {b}"));
    }
    req = req.set("Accept", "application/json, text/event-stream");
    if let Some(sid) = session_id {
        req = req.set("Mcp-Session-Id", sid);
    }
    let (code, resp_session, content_type, www_auth, text) = match req.send_json(body) {
        Ok(resp) => {
            let code = resp.status();
            let sid = resp.header("Mcp-Session-Id").map(str::to_string);
            let ct = resp.header("Content-Type").unwrap_or("").to_string();
            let wa = resp.header("WWW-Authenticate").map(str::to_string);
            let text = resp.into_string().unwrap_or_default();
            (code, sid, ct, wa, text)
        }
        Err(ureq::Error::Status(code, resp)) => {
            let sid = resp.header("Mcp-Session-Id").map(str::to_string);
            let ct = resp.header("Content-Type").unwrap_or("").to_string();
            let wa = resp.header("WWW-Authenticate").map(str::to_string);
            let text = resp.into_string().unwrap_or_default();
            (code, sid, ct, wa, text)
        }
        Err(e) => panic!("transport error: {e}"),
    };
    let body_value = if content_type.contains("text/event-stream") {
        parse_first_sse_data(&text).unwrap_or(json!({}))
    } else if !text.is_empty() {
        serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }))
    } else {
        json!({})
    };
    PostResult {
        code,
        body: body_value,
        session_id: resp_session,
        www_authenticate: www_auth,
    }
}

/// Parse the first `data:` line from an SSE stream as JSON.
fn parse_first_sse_data(sse: &str) -> Option<Value> {
    for line in sse.lines() {
        if let Some(payload) = line.strip_prefix("data:") {
            return serde_json::from_str(payload.trim()).ok();
        }
    }
    None
}

/// Send an `initialize` request followed by the required
/// `notifications/initialized` notification, return the negotiated
/// `Mcp-Session-Id`.
fn initialize(port: u16, bearer: &str) -> String {
    let r = http_post(port, Some(bearer), None, init_body());
    assert_eq!(r.code, 200, "initialize failed: {:?}", r.body);
    let sid = r.session_id.expect("server did not return Mcp-Session-Id");
    // rmcp requires `notifications/initialized` before any further requests.
    let n = http_post(
        port,
        Some(bearer),
        Some(&sid),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    assert!(
        n.code == 200 || n.code == 202,
        "initialized notification rejected: {} {:?}",
        n.code,
        n.body
    );
    sid
}

fn init_body() -> Value {
    json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
        "protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}
    }})
}

fn write_inv(json: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), json).unwrap();
    f
}

fn write_tokens(json: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), json).unwrap();
    f
}

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
