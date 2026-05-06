//! End-to-end streamable-http smoke for the PFE tool.

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
    p.push(if cfg!(debug_assertions) { "debug" } else { "release" });
    p.push("rust-junosmcp");
    p
}

fn ensure_built() {
    let s = Command::new("cargo").args(["build", "-p", "rust-junosmcp"]).status().unwrap();
    assert!(s.success());
}

fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Server {
    child: Child,
    port: u16,
    _drain: std::thread::JoinHandle<()>,
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
            "-f", inv_path.to_str().unwrap(),
            "-t", "streamable-http",
            "-H", "127.0.0.1",
            "-p", &port.to_string(),
            "--tokens-file", tokens_path.to_str().unwrap(),
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
        if Instant::now() > deadline { break; }
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) if line.contains("streamable-http listening") => { ready = true; break; }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    if !ready {
        let _ = child.kill();
        panic!("server did not start within 15s");
    }
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
    Server { child, port, _drain: drain }
}

struct PostResult { code: u16, body: Value, session_id: Option<String> }

fn http_post(port: u16, bearer: Option<&str>, sid: Option<&str>, body: Value) -> PostResult {
    let mut req = ureq::post(&format!("http://127.0.0.1:{port}/mcp"))
        .set("Accept", "application/json, text/event-stream");
    if let Some(b) = bearer { req = req.set("Authorization", &format!("Bearer {b}")); }
    if let Some(s) = sid { req = req.set("Mcp-Session-Id", s); }
    let (code, sid_out, ct, text) = match req.send_json(body) {
        Ok(r) => {
            let c = r.status();
            let s = r.header("Mcp-Session-Id").map(str::to_string);
            let ct = r.header("Content-Type").unwrap_or("").to_string();
            (c, s, ct, r.into_string().unwrap_or_default())
        }
        Err(ureq::Error::Status(c, r)) => {
            let s = r.header("Mcp-Session-Id").map(str::to_string);
            let ct = r.header("Content-Type").unwrap_or("").to_string();
            (c, s, ct, r.into_string().unwrap_or_default())
        }
        Err(e) => panic!("transport error: {e}"),
    };
    let body_value = if ct.contains("text/event-stream") {
        text.lines()
            .find_map(|l| l.strip_prefix("data:").and_then(|p| serde_json::from_str(p.trim()).ok()))
            .unwrap_or(json!({}))
    } else if !text.is_empty() {
        serde_json::from_str(&text).unwrap_or(json!({"raw": text}))
    } else {
        json!({})
    };
    PostResult { code, body: body_value, session_id: sid_out }
}

fn initialize(port: u16, bearer: &str) -> String {
    let init = json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
        "protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}
    }});
    let r = http_post(port, Some(bearer), None, init);
    assert_eq!(r.code, 200, "initialize failed: {:?}", r.body);
    let sid = r.session_id.expect("Mcp-Session-Id");
    let n = http_post(port, Some(bearer), Some(&sid),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    assert!(n.code == 200 || n.code == 202, "initialized notification rejected: {} {:?}", n.code, n.body);
    sid
}

fn write_tmp(json: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), json).unwrap();
    f
}

fn add_token(tokens_path: &std::path::Path, name: &str, routers: &str, tools: &str) -> String {
    let out = Command::new(binary_path())
        .args([
            "token", "add",
            "--tokens-file", tokens_path.to_str().unwrap(),
            "--name", name,
            "--routers", routers,
            "--tools", tools,
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
    let r = http_post(s.port, Some(&secret), Some(&sid),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"execute_junos_pfe_command",
            "arguments":{"router_name":"r1","fpc_target":"fpc0","pfe_command":"show jnh 0 stats","timeout":1}
        }}));
    assert_eq!(r.code, 200);
    let result = r.body.pointer("/result").expect("result");
    assert_eq!(result.get("isError"), Some(&json!(true)));
    let text = serde_json::to_string(result).unwrap();
    assert!(text.contains("not authorized for tool"), "got: {text}");
}

#[test]
fn pfe_connect_failure_surfaces_through_tool_call() {
    ensure_built();
    // Unreachable IP/port so connect must fail.
    let inv = write_tmp(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let toks = dir.path().join("tokens.json");
    let secret = add_token(&toks, "ops", "*", "execute_junos_pfe_command");

    let s = spawn(inv.path(), &toks);
    let sid = initialize(s.port, &secret);
    let r = http_post(s.port, Some(&secret), Some(&sid),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"execute_junos_pfe_command",
            "arguments":{"router_name":"r1","fpc_target":"fpc0","pfe_command":"show jnh 0 stats","timeout":1}
        }}));
    assert_eq!(r.code, 200);
    let result = r.body.pointer("/result").expect("result");
    assert_eq!(result.get("isError"), Some(&json!(true)));
}
