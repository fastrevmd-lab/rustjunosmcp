#![allow(clippy::unwrap_used)]
//! Stdio-transport smoke tests for `render_and_apply_j2_template`.
//!
//! Render-only paths run end-to-end (no real device I/O). Apply-path is
//! covered by integration_real_device.rs (`#[ignore]`).
//!
//! Uses the shared `tests/common` stdio harness (see `add_device_smoke.rs`
//! for the same idiom).

mod common;
use common::{call_tool, spawn_stdio_server_with_args, write_inventory_in};
use serde_json::json;

#[test]
fn render_only_path_returns_rendered_string_with_json_vars() {
    let dir = tempfile::tempdir().unwrap();
    let inv_path = write_inventory_in(
        dir.path(),
        "devices.json",
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server_with_args(&["-f", inv_path.to_str().unwrap()]);
    let payload = call_tool(
        &mut child,
        "render_and_apply_j2_template",
        json!({
            "template_content": "set system host-name {{ name }}",
            "vars_content": r#"{"name":"r1"}"#,
            "router_name": "r1"
        }),
    );
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
    let dir = tempfile::tempdir().unwrap();
    let inv_path = write_inventory_in(
        dir.path(),
        "devices.json",
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server_with_args(&["-f", inv_path.to_str().unwrap()]);
    let err = call_tool(
        &mut child,
        "render_and_apply_j2_template",
        json!({
            "template_content": "set system host-name {{ name }}\ndelete protocols bgp",
            "vars_content": "name: r1\n",
            "router_name": "r1"
        }),
    );
    assert_eq!(
        err.get("isError"),
        Some(&json!(true)),
        "expected isError=true for YAML vars_content, got: {err}"
    );
    let s = err.to_string();
    assert!(
        s.contains("JSON parse failed"),
        "error should steer caller toward JSON; got: {s}"
    );
}

#[test]
fn strict_undefined_surfaces_through_tool_call() {
    let dir = tempfile::tempdir().unwrap();
    let inv_path = write_inventory_in(
        dir.path(),
        "devices.json",
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server_with_args(&["-f", inv_path.to_str().unwrap()]);
    let err = call_tool(
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
    assert_eq!(
        err.get("isError"),
        Some(&json!(true)),
        "expected isError=true for strict-undefined render, got: {err}"
    );
    let lower = err.to_string().to_lowercase();
    assert!(
        lower.contains("template render") || lower.contains("undefined"),
        "expected render error indication, got: {err}"
    );
}
