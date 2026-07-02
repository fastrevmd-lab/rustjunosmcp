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
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Wait for the readiness line and spawn a stderr-drain thread; panics if the
/// server doesn't announce within 15s.
fn finish_spawn(mut child: Child, port: u16) -> Server {
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
    }
}

/// Spawn with bearer auth enabled (tokens file). Requires a device-mapping file.
pub fn spawn(inv_path: &Path, tokens_path: &Path) -> Server {
    let port = pick_port();
    let port_s = port.to_string();
    let child = Command::new(binary_path())
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            &port_s,
            "--device-mapping",
            inv_path.to_str().unwrap(),
            "--tokens-file",
            tokens_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    finish_spawn(child, port)
}

/// Spawn with `--allow-no-auth` (no auth layer) + extra args (host-allowlist flags).
pub fn spawn_no_auth(inv_path: &Path, extra: &[&str]) -> Server {
    let port = pick_port();
    let port_s = port.to_string();
    let mut argv = vec![
        "--host",
        "127.0.0.1",
        "--port",
        &port_s,
        "--device-mapping",
        inv_path.to_str().unwrap(),
        "--allow-no-auth",
    ];
    argv.extend_from_slice(extra);
    let child = Command::new(binary_path())
        .args(&argv)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    finish_spawn(child, port)
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
