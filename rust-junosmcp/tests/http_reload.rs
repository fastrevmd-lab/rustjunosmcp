//! SIGHUP hot reload smoke. Unix-only.
//!
//! Verifies that sending SIGHUP to the running server causes it to re-read
//! the tokens file and atomically swap the in-memory store, so a token that
//! was valid before the signal becomes rejected after it.
#![cfg(unix)]

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

/// RAII child guard. Kills + waits on drop, and keeps a background drain
/// thread on stderr so the child never blocks or SIGPIPEs writing logs.
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

struct PostResult {
    code: u16,
    #[allow(dead_code)]
    body: Value,
}

fn http_post(port: u16, bearer: Option<&str>, body: Value) -> PostResult {
    let mut req = ureq::post(&format!("http://127.0.0.1:{port}/mcp"));
    if let Some(b) = bearer {
        req = req.set("Authorization", &format!("Bearer {b}"));
    }
    req = req.set("Accept", "application/json, text/event-stream");
    let (code, content_type, text) = match req.send_json(body) {
        Ok(resp) => {
            let code = resp.status();
            let ct = resp.header("Content-Type").unwrap_or("").to_string();
            let text = resp.into_string().unwrap_or_default();
            (code, ct, text)
        }
        Err(ureq::Error::Status(code, resp)) => {
            let ct = resp.header("Content-Type").unwrap_or("").to_string();
            let text = resp.into_string().unwrap_or_default();
            (code, ct, text)
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
    }
}

fn parse_first_sse_data(sse: &str) -> Option<Value> {
    // rmcp 2.0.0 prepends an empty "priming" SSE event (`data: ` with no
    // payload) before the real JSON-RPC payload when `sse_retry` is set
    // (the default), so skip blank/unparseable `data:` lines instead of
    // returning on the very first one.
    for line in sse.lines() {
        if let Some(payload) = line.strip_prefix("data:") {
            let payload = payload.trim();
            if payload.is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str(payload) {
                return Some(value);
            }
        }
    }
    None
}

#[test]
fn sighup_reloads_token_store() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let inv = dir.path().join("inv.json");
    std::fs::write(
        &inv,
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    )
    .unwrap();
    let toks = dir.path().join("tokens.json");

    // Mint a wildcard token via the subcommand.
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
    assert!(out.status.success(), "token add failed: {:?}", out);
    let secret = String::from_utf8(out.stdout).unwrap().trim().to_string();
    assert!(!secret.is_empty(), "minted secret should not be empty");

    let s = spawn(&inv, &toks);

    // Phase 1: token is valid. Auth layer must let the request through. We
    // don't care what rmcp does with a bare tools/list (it'll likely return
    // 400/406 for missing session) — only that the auth verdict is "pass",
    // i.e. status != 401.
    let r = http_post(
        s.port,
        Some(&secret),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
    );
    assert_ne!(
        r.code, 401,
        "valid token should not be rejected before SIGHUP (got {})",
        r.code
    );

    // Revoke the token on disk. The running server still has the old store.
    let revoke = Command::new(binary_path())
        .args([
            "token",
            "revoke",
            "--tokens-file",
            toks.to_str().unwrap(),
            "--name",
            "all",
        ])
        .output()
        .unwrap();
    assert!(revoke.status.success(), "token revoke failed: {:?}", revoke);

    // SIGHUP the server to trigger reload.
    let pid = s.child.id() as i32;
    let rc = unsafe { libc::kill(pid, libc::SIGHUP) };
    assert_eq!(rc, 0, "kill(SIGHUP) failed: errno");

    // Phase 2: same token, but now revoked + reloaded. Poll until we observe
    // 401 or hit the deadline. This is faster on the happy path than a fixed
    // sleep and tolerates slow CI.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_code = 0u16;
    let mut last_body = json!({});
    while Instant::now() < deadline {
        let r = http_post(
            s.port,
            Some(&secret),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        );
        last_code = r.code;
        last_body = r.body;
        if last_code == 401 {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        last_code, 401,
        "revoked token should be 401 within 5s of SIGHUP reload (body: {})",
        last_body
    );
}
