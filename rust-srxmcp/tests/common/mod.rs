#![allow(dead_code)]
//! Shared streamable-http integration-test harness for rust-srxmcp.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub fn binary_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("target");
    p.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    p.push("rust-srxmcp");
    p
}

pub fn ensure_built() {
    let s = Command::new("cargo")
        .args(["build", "-p", "rust-srxmcp"])
        .status()
        .unwrap();
    assert!(s.success(), "cargo build failed");
}

pub fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub struct Server {
    pub child: Child,
    pub port: u16,
    pub _stderr_drain: std::thread::JoinHandle<()>,
    pub _device_lease_dir: tempfile::TempDir,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Wait for the readiness line and spawn a stderr-drain thread; panics if the
/// server doesn't announce within 15s.
fn finish_spawn(mut child: Child, port: u16, device_lease_dir: tempfile::TempDir) -> Server {
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
            Ok(0) => break,
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
        _device_lease_dir: device_lease_dir,
    }
}

/// Spawn with bearer auth enabled (tokens file). Requires a device-mapping file.
pub fn spawn(inv_path: &Path, tokens_path: &Path) -> Server {
    spawn_with_auth_args(inv_path, tokens_path, &[])
}

pub fn spawn_with_auth_args(inv_path: &Path, tokens_path: &Path, extra: &[&str]) -> Server {
    let port = pick_port();
    let port_s = port.to_string();
    let device_lease_dir = tempfile::tempdir().expect("create device lease directory");
    let mut argv = vec![
        "--host",
        "127.0.0.1",
        "--port",
        &port_s,
        "--device-mapping",
        inv_path.to_str().unwrap(),
        "--tokens-file",
        tokens_path.to_str().unwrap(),
        "--device-lease-dir",
        device_lease_dir.path().to_str().unwrap(),
    ];
    argv.extend_from_slice(extra);
    let child = Command::new(binary_path())
        .args(&argv)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    finish_spawn(child, port, device_lease_dir)
}

/// Spawn with `--allow-no-auth` (no auth layer) + extra args (host-allowlist flags).
pub fn spawn_no_auth(inv_path: &Path, extra: &[&str]) -> Server {
    let port = pick_port();
    let port_s = port.to_string();
    let device_lease_dir = tempfile::tempdir().expect("create device lease directory");
    let mut argv = vec![
        "--host",
        "127.0.0.1",
        "--port",
        &port_s,
        "--device-mapping",
        inv_path.to_str().unwrap(),
        "--allow-no-auth",
        "--device-lease-dir",
        device_lease_dir.path().to_str().unwrap(),
    ];
    argv.extend_from_slice(extra);
    let child = Command::new(binary_path())
        .args(&argv)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    finish_spawn(child, port, device_lease_dir)
}

pub struct PostResult {
    pub code: u16,
    pub body: Value,
    pub session_id: Option<String>,
    pub www_authenticate: Option<String>,
}

pub fn http_post(
    port: u16,
    bearer: Option<&str>,
    session_id: Option<&str>,
    body: Value,
) -> PostResult {
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

pub fn close_session(port: u16, bearer: &str, session_id: &str) -> u16 {
    let request = ureq::delete(&format!("http://127.0.0.1:{port}/mcp"))
        .set("Authorization", &format!("Bearer {bearer}"))
        .set("Mcp-Session-Id", session_id);
    match request.call() {
        Ok(response) => response.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(error) => panic!("transport error: {error}"),
    }
}

/// Parse the first non-empty `data:` line from an SSE stream as JSON (skips the
/// rmcp 2.0 priming event).
pub fn parse_first_sse_data(sse: &str) -> Option<Value> {
    for line in sse.lines() {
        if let Some(payload) = line.strip_prefix("data:") {
            let payload = payload.trim();
            if payload.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str(payload) {
                return Some(v);
            }
        }
    }
    None
}

pub fn init_body() -> Value {
    json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
        "protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}
    }})
}

/// Send an `initialize` request followed by the required
/// `notifications/initialized` notification, return the negotiated
/// `Mcp-Session-Id`.
pub fn initialize(port: u16, bearer: &str) -> String {
    let response = http_post(port, Some(bearer), None, init_body());
    assert_eq!(response.code, 200, "initialize failed: {:?}", response.body);
    let session_id = response
        .session_id
        .expect("server did not return Mcp-Session-Id");
    let initialized = http_post(
        port,
        Some(bearer),
        Some(&session_id),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    assert!(
        initialized.code == 200 || initialized.code == 202,
        "initialized notification rejected: {} {:?}",
        initialized.code,
        initialized.body
    );
    session_id
}

/// POST an `initialize` with an explicit Host header; return the HTTP status.
pub fn post_init_with_host(port: u16, host: &str) -> u16 {
    let req = ureq::post(&format!("http://127.0.0.1:{port}/mcp"))
        .set("Accept", "application/json, text/event-stream")
        .set("Host", host);
    match req.send_json(init_body()) {
        Ok(resp) => resp.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(e) => panic!("transport error: {e}"),
    }
}

pub fn write_inv(json: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), json).unwrap();
    f
}

pub fn write_tokens(json: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), json).unwrap();
    f
}

/// Spawn with `--allow-no-auth` (no auth layer) + extra CLI args, carrying a
/// stub token string for signature parity with authed harnesses (not actually used).
pub struct ServerWithToken {
    pub server: Server,
    pub token: String,
}

impl std::ops::Deref for ServerWithToken {
    type Target = Server;
    fn deref(&self) -> &Self::Target {
        &self.server
    }
}

pub fn spawn_with_args(extra: &[&str]) -> ServerWithToken {
    let inv = write_inv(
        r#"{"stub":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let port = pick_port();
    let port_s = port.to_string();
    let device_lease_dir = tempfile::tempdir().expect("create device lease directory");
    let mut argv = vec![
        "--host",
        "127.0.0.1",
        "--port",
        &port_s,
        "--device-mapping",
        inv.path().to_str().unwrap(),
        "--allow-no-auth",
        "--device-lease-dir",
        device_lease_dir.path().to_str().unwrap(),
    ];
    argv.extend_from_slice(extra);
    let child = Command::new(binary_path())
        .args(&argv)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let server = finish_spawn(child, port, device_lease_dir);
    ServerWithToken {
        server,
        token: String::new(),
    }
}

/// POST raw body bytes and return just the HTTP status code (for testing
/// body-limit rejections before the JSON-RPC layer).
pub fn http_post_raw(port: u16, _bearer: &str, _session_id: Option<&str>, body: &str) -> u16 {
    let req = ureq::post(&format!("http://127.0.0.1:{port}/mcp"))
        .set("Accept", "application/json, text/event-stream")
        .set("Content-Type", "application/json");
    match req.send_string(body) {
        Ok(resp) => resp.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(e) => panic!("transport error: {e}"),
    }
}
