//! Spawn the `rust-junosmcp` binary, send MCP `initialize` + `tools/list` over
//! stdin, parse responses on stdout, assert we advertise the 6 v0.1 tools.

use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const EXPECTED_TOOLS: &[&str] = &[
    "get_router_list",
    "gather_device_facts",
    "execute_junos_command",
    "get_junos_config",
    "junos_config_diff",
    "load_and_commit_config",
];

fn binary_path() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // workspace root
    p.push("target");
    p.push(if cfg!(debug_assertions) { "debug" } else { "release" });
    p.push("rust-junosmcp");
    p
}

#[test]
fn lists_six_tools() {
    // Build first so the binary exists.
    let status = Command::new("cargo")
        .args(["build", "-p", "rust-junosmcp"])
        .status()
        .expect("cargo build");
    assert!(status.success(), "cargo build failed");

    // Empty inventory file is enough for `tools/list`.
    let inv = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(inv.path(), "{}").unwrap();

    let mut child = Command::new(binary_path())
        .args(["-f", inv.path().to_str().unwrap(), "-t", "stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rust-junosmcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    // MCP framing is JSON-RPC delimited by newlines.
    fn send(stdin: &mut impl Write, msg: &Value) {
        let line = serde_json::to_string(msg).unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    send(&mut stdin, &json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": { "name": "smoke", "version": "0.1" }
        }
    }));
    send(&mut stdin, &json!({
        "jsonrpc": "2.0", "method": "notifications/initialized"
    }));
    send(&mut stdin, &json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
    }));

    // Read until we see the tools/list response.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut tools_response: Option<Value> = None;
    use std::io::{BufRead, BufReader};
    let mut reader = BufReader::new(&mut stdout);
    while Instant::now() < deadline && tools_response.is_none() {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 { break; }
        let v: Value = match serde_json::from_str(line.trim()) { Ok(v) => v, Err(_) => continue };
        if v.get("id") == Some(&json!(2)) {
            tools_response = Some(v);
        }
    }

    let _ = child.kill();
    let resp = tools_response.expect("did not receive tools/list response within 15s");
    let tools = resp.pointer("/result/tools").expect("missing /result/tools").as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t.get("name").and_then(Value::as_str).unwrap()).collect();
    for expected in EXPECTED_TOOLS {
        assert!(names.contains(expected),
                "missing tool {expected}; got {names:?}");
    }
    assert_eq!(names.len(), EXPECTED_TOOLS.len(),
               "extra/missing tools: got {names:?}");
}
