//! Stdio smoke for reload_devices.

mod common;
use common::{call_tool, spawn_stdio_server_with_args, write_inventory_in};
use serde_json::json;

#[test]
fn reload_no_args_re_reads_current_path() {
    let dir = tempfile::tempdir().unwrap();
    let inv_path = write_inventory_in(
        dir.path(),
        "devices.json",
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server_with_args(&["-f", inv_path.to_str().unwrap()]);

    // Edit on disk -- add a second device.
    std::fs::write(
        &inv_path,
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}},
             "r2":{"ip":"127.0.0.2","username":"u","auth":{"type":"password","password":"x"}}}"#,
    )
    .unwrap();

    let r = call_tool(&mut child, "reload_devices", json!({}));
    assert_eq!(r["new_router_count"], 2);
    let added: Vec<String> = serde_json::from_value(r["added"].clone()).unwrap();
    assert!(added.contains(&"r2".to_string()));
}

#[test]
fn reload_with_file_name_swaps_inventory() {
    let dir = tempfile::tempdir().unwrap();
    let p1 = write_inventory_in(
        dir.path(),
        "a.json",
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let p2 = write_inventory_in(
        dir.path(),
        "b.json",
        r#"{"r9":{"ip":"127.0.0.9","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server_with_args(&["-f", p1.to_str().unwrap()]);

    let r = call_tool(
        &mut child,
        "reload_devices",
        json!({"file_name": p2.to_str().unwrap()}),
    );
    assert_eq!(r["new_router_count"], 1, "got: {r}");
    let list = call_tool(&mut child, "get_router_list", json!({}));
    let names: Vec<String> = serde_json::from_value(list.clone())
        .unwrap_or_else(|e| panic!("get_router_list shape: {e}, got: {list}"));
    assert!(names.contains(&"r9".to_string()), "names: {names:?}");
    assert!(!names.contains(&"r1".to_string()), "names: {names:?}");
}

#[test]
fn reload_inventory_readonly_returns_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let inv_path = write_inventory_in(
        dir.path(),
        "devices.json",
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child =
        spawn_stdio_server_with_args(&["-f", inv_path.to_str().unwrap(), "--inventory-readonly"]);

    let err = call_tool(&mut child, "reload_devices", json!({}));
    let s = err.to_string();
    assert!(s.contains("read-only"), "got: {s}");
}
