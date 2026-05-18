//! Stdio-transport smoke tests for `render_and_apply_j2_template`.
//!
//! Render-only paths run end-to-end (no real device I/O). Apply-path is
//! covered by integration_real_device.rs (`#[ignore]`).
//!
//! No shared `tests/common` module exists in this crate; existing smoke
//! tests inline their helpers (see `stdio_smoke.rs`). We follow the same
//! pattern here.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

fn binary_path() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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

fn ensure_built() {
    let status = Command::new("cargo")
        .args(["build", "-p", "rust-junosmcp"])
        .status()
        .expect("cargo build");
    assert!(status.success(), "cargo build failed");
}

fn write_inventory(json_text: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), json_text).unwrap();
    f
}

fn spawn_stdio_server(inv_path: &Path) -> Child {
    Command::new(binary_path())
        .args(["-f", inv_path.to_str().unwrap(), "-t", "stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rust-junosmcp")
}

fn send_line(stdin: &mut impl Write, msg: &Value) {
    let line = serde_json::to_string(msg).unwrap();
    writeln!(stdin, "{line}").unwrap();
    stdin.flush().unwrap();
}

/// Read JSON-RPC lines from stdout until we get a response with the given id.
fn read_response_with_id(reader: &mut BufReader<&mut ChildStdout>, id: i64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let value: Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if value.get("id") == Some(&json!(id)) {
            return value;
        }
    }
    panic!("did not receive response for id={id} within 15s");
}

/// Initialize the MCP session, call `tools/call` for `tool_name` with `arguments`,
/// and return the full JSON-RPC response value (caller can inspect `/result`).
fn call_tool(child: &mut Child, tool_name: &str, arguments: Value) -> Value {
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    send_line(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": "smoke", "version": "0.1" }
            }
        }),
    );
    send_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    send_line(
        &mut stdin,
        &json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name": tool_name, "arguments": arguments}
        }),
    );

    let mut reader = BufReader::new(&mut stdout);
    // Drain id=1 (initialize) first, then return id=2 (tools/call).
    let _ = read_response_with_id(&mut reader, 1);
    let resp = read_response_with_id(&mut reader, 2);

    drop(reader);
    drop(stdin);
    drop(stdout);
    let _ = child.kill();
    let _ = child.wait();
    resp
}

/// For success cases, the tool's JSON return value is serialized into
/// `result.content[0].text`. Parse it back into a `Value` for assertions.
fn extract_success_payload(resp: &Value) -> Value {
    let result = resp.pointer("/result").expect("missing /result");
    assert_ne!(
        result.get("isError"),
        Some(&json!(true)),
        "tool returned isError=true: {result}"
    );
    let text = result
        .pointer("/content/0/text")
        .and_then(Value::as_str)
        .expect("missing /result/content/0/text");
    serde_json::from_str(text).expect("content text was not JSON")
}

#[test]
fn render_only_path_returns_rendered_string_with_json_vars() {
    ensure_built();
    let inv = write_inventory(
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server(inv.path());
    let resp = call_tool(
        &mut child,
        "render_and_apply_j2_template",
        json!({
            "template_content": "set system host-name {{ name }}",
            "vars_content": r#"{"name":"r1"}"#,
            "router_name": "r1"
        }),
    );
    let payload = extract_success_payload(&resp);
    let rows = payload["results"].as_array().expect("results array");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["rendered_template"], "set system host-name r1");
    assert_eq!(rows[0]["config_format"], "set");
    assert_eq!(rows[0]["router"], "r1");
    assert_eq!(payload["applied"], false);
}

/// RJMCP-SEC-002: YAML `vars_content` is rejected at the tool boundary as of
/// v0.5.2. The previous version of this test asserted YAML rendered cleanly;
/// now it asserts the call surfaces a JSON parse error.
#[test]
fn yaml_vars_content_is_rejected_with_json_error() {
    ensure_built();
    let inv = write_inventory(
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server(inv.path());
    let resp = call_tool(
        &mut child,
        "render_and_apply_j2_template",
        json!({
            "template_content": "set system host-name {{ name }}\ndelete protocols bgp",
            "vars_content": "name: r1\n",
            "router_name": "r1"
        }),
    );
    let result = resp.pointer("/result").expect("missing /result");
    assert_eq!(
        result.get("isError"),
        Some(&json!(true)),
        "expected isError=true for YAML vars_content, got: {result}"
    );
    let text = result
        .pointer("/content/0/text")
        .and_then(Value::as_str)
        .expect("missing /result/content/0/text")
        .to_string();
    assert!(
        text.contains("JSON parse failed"),
        "error should steer caller toward JSON; got: {text}"
    );
}

#[test]
fn strict_undefined_surfaces_through_tool_call() {
    ensure_built();
    let inv = write_inventory(
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server(inv.path());
    let resp = call_tool(
        &mut child,
        "render_and_apply_j2_template",
        json!({
            "template_content": "set foo {{ missing }}",
            "vars_content": "{}",
            "router_name": "r1"
        }),
    );
    // `to_call_result` maps `JmcpError` to `CallToolResult::error` with the
    // error string in content[0].text. `JmcpError::TemplateRender` formats
    // with the `template render` Display prefix.
    let result = resp.pointer("/result").expect("missing /result");
    assert_eq!(
        result.get("isError"),
        Some(&json!(true)),
        "expected isError=true for strict-undefined render, got: {result}"
    );
    let body = serde_json::to_string(result).unwrap();
    let lower = body.to_lowercase();
    assert!(
        lower.contains("template render") || lower.contains("undefined"),
        "expected render error indication, got: {body}"
    );
}
