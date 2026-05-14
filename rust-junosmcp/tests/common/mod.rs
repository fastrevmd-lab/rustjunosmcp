//! Shared helpers for stdio smoke tests.
//!
//! Spawns the `rust-junosmcp` binary with `-t stdio`, performs the MCP
//! handshake, and exposes a small `call_tool` helper that returns the parsed
//! JSON content of the tool's response (or the full `result` Value on error
//! so callers can `.to_string()` and inspect the error message).

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
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
