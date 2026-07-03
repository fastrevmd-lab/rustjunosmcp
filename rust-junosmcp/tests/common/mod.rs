#![allow(dead_code)]
//! Shared test harness for rust-junosmcp integration tests.
//!
//! Two families of helpers live here:
//! - stdio smoke helpers: spawn the `rust-junosmcp` binary with `-t stdio`,
//!   perform the MCP handshake, and expose a small `call_tool` helper that
//!   returns the parsed JSON content of the tool's response.
//! - streamable-http helpers: spawn the binary on an ephemeral port, POST
//!   JSON-RPC, parse SSE, assert HTTP behavior (auth, sessions, etc.).

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

/// Absolute path to the freshly-built `rust-junosmcp` binary.
pub fn binary_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // workspace root
    p.push("target");
    p.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    p.push("rust-junosmcp");
    p
}

/// Build the binary if it isn't already built. Cargo no-ops when up-to-date.
pub fn ensure_built() {
    let status = Command::new("cargo")
        .args(["build", "-p", "rust-junosmcp"])
        .status()
        .expect("cargo build");
    assert!(status.success(), "cargo build failed");
}

/// Write `json` to `dir/name` and return the full path.
#[allow(dead_code)]
pub fn write_inventory_in(dir: &Path, name: &str, json: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, json).expect("write inventory");
    path
}

/// Write a minimal JSON inventory to a temp file and return the handle.
/// Each tuple: (name, ip, port, username, key_file_path).
#[allow(dead_code)]
pub fn write_inventory_temp(devices: &[(&str, &str, u16, &str, &str)]) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut f = tempfile::Builder::new()
        .prefix("jmcp-inv-")
        .suffix(".json")
        .tempfile()
        .expect("create temp inventory");
    let mut obj = serde_json::Map::new();
    for (name, ip, port, user, key) in devices {
        obj.insert(
            (*name).to_string(),
            serde_json::json!({
                "ip": ip,
                "port": port,
                "username": user,
                "auth": { "type": "ssh_key", "private_key_path": key },
            }),
        );
    }
    let payload = serde_json::Value::Object(obj);
    writeln!(f, "{}", serde_json::to_string_pretty(&payload).unwrap()).expect("write inventory");
    f
}

/// Live `rust-junosmcp` child wired up for JSON-RPC over stdio.
pub struct StdioChild {
    pub child: Child,
    pub stdin: ChildStdin,
    pub reader: BufReader<ChildStdout>,
    pub next_id: i64,
}

impl Drop for StdioChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn send(stdin: &mut ChildStdin, msg: &Value) {
    let line = serde_json::to_string(msg).expect("serialize jsonrpc msg");
    writeln!(stdin, "{line}").expect("write stdin");
    stdin.flush().expect("flush stdin");
}

fn read_response_with_id(reader: &mut BufReader<ChildStdout>, id: i64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap_or(0);
        if n == 0 {
            break;
        }
        let v: Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("id") == Some(&json!(id)) {
            return v;
        }
    }
    panic!("did not receive response with id={id} within 15s");
}

/// Spawn the server with `-t stdio` plus any extra CLI args (for example
/// `&["-f", path, "--allow-password-auth-add"]`). Performs the MCP
/// `initialize` (id=0) + `notifications/initialized` handshake before
/// returning. Subsequent `tools/call` ids start at 2.
pub fn spawn_stdio_server_with_args(extra_args: &[&str]) -> StdioChild {
    ensure_built();

    let mut cmd = Command::new(binary_path());
    cmd.arg("-t").arg("stdio");
    for a in extra_args {
        cmd.arg(a);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rust-junosmcp");

    let mut stdin = child.stdin.take().expect("take stdin");
    let stdout = child.stdout.take().expect("take stdout");
    let mut reader = BufReader::new(stdout);

    send(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": "smoke", "version": "0.1" }
            }
        }),
    );
    let _ = read_response_with_id(&mut reader, 0);

    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );

    StdioChild {
        child,
        stdin,
        reader,
        next_id: 2,
    }
}

/// Send a `tools/call` and block until the matching response arrives.
///
/// Returns:
/// - On success: the parsed JSON in `result.content[0].text` (the handlers
///   stringify their JSON Value into a single text content), falling back to
///   `result.structuredContent` if present, else the raw `result`.
/// - On tool error (`result.isError == true`): the full `result` Value, so
///   callers can call `.to_string()` and `.contains("...")` on it.
pub fn call_tool(child: &mut StdioChild, name: &str, args: Value) -> Value {
    let id = child.next_id;
    child.next_id += 1;

    send(
        &mut child.stdin,
        &json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": name, "arguments": args }
        }),
    );

    let resp = read_response_with_id(&mut child.reader, id);
    let result = resp
        .get("result")
        .cloned()
        .unwrap_or_else(|| panic!("missing /result in response: {resp}"));

    if result.get("isError") == Some(&json!(true)) {
        return result;
    }

    if let Some(text) = result.pointer("/content/0/text").and_then(Value::as_str) {
        if let Ok(parsed) = serde_json::from_str::<Value>(text) {
            return parsed;
        }
    }
    if let Some(sc) = result.get("structuredContent") {
        return sc.clone();
    }
    result
}

// ---------------------------------------------------------------------------
// streamable-http harness (shared by http_smoke.rs, http_reload.rs, and the
// non-TLS-specific bits of http_tls.rs). `binary_path`/`ensure_built` above
// are reused as-is.
// ---------------------------------------------------------------------------

pub fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// RAII child guard: kills + waits on drop so panics don't leak processes.
/// Also keeps a background drain thread on stderr so the child never blocks
/// or SIGPIPEs on log writes after the readiness line.
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

pub fn spawn(inv_path: &Path, tokens_path: &Path) -> Server {
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

/// Spawn with `--allow-no-auth` (no auth layer) plus extra CLI args (e.g.
/// `--allowed-host` / `--disable-host-check`), so rmcp's built-in Host
/// allowlist is the sole gate in front of `initialize`.
pub fn spawn_no_auth(inv_path: &Path, extra: &[&str]) -> Server {
    let port = pick_port();
    let port_s = port.to_string();
    let mut argv = vec![
        "-f",
        inv_path.to_str().unwrap(),
        "-t",
        "streamable-http",
        "-H",
        "127.0.0.1",
        "-p",
        &port_s,
        "--allow-no-auth",
    ];
    argv.extend_from_slice(extra);
    let mut child = Command::new(binary_path())
        .args(&argv)
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

/// Outcome of a streamable-http POST: status, body parsed as JSON-RPC payload
/// (extracted from SSE if needed), any returned `Mcp-Session-Id`, and the
/// `WWW-Authenticate` header if present (for RFC 6750 §3 assertions on 401).
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

/// Parse the first `data:` line from an SSE stream as JSON.
pub fn parse_first_sse_data(sse: &str) -> Option<Value> {
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

/// Send an `initialize` request followed by the required
/// `notifications/initialized` notification, return the negotiated
/// `Mcp-Session-Id`.
pub fn initialize(port: u16, bearer: &str) -> String {
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
