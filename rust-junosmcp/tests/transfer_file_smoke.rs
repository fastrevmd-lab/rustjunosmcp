mod common;

use common::{call_tool, spawn_stdio_server_with_args, write_inventory_temp, StdioChild};
use serde_json::json;
use std::path::Path;

/// Shared setup: staging dir with a placeholder file, dummy SSH key, inventory,
/// and known_hosts. Returns a running StdioChild pointed at TEST-NET-1 (192.0.2.1).
fn make_server(dir: &Path) -> StdioChild {
    let staging = dir.join("staging");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(staging.join("foo.tgz"), b"placeholder").unwrap();

    let key_file = dir.join("dummy_key");
    std::fs::write(&key_file, b"").unwrap();

    let inv = write_inventory_temp(&[(
        "vsrx-test10",
        "192.0.2.1",
        830,
        "admin",
        key_file.to_str().unwrap(),
    )]);

    let known = dir.join("known_hosts");
    std::fs::write(&known, b"").unwrap();

    spawn_stdio_server_with_args(&[
        "-f",
        inv.path().to_str().unwrap(),
        "--staging-dir",
        staging.to_str().unwrap(),
        "--known-hosts-file",
        known.to_str().unwrap(),
    ])
}

#[test]
fn transfer_file_rejects_bad_source_path() {
    let dir = tempfile::tempdir().unwrap();
    let mut server = make_server(dir.path());

    let resp = call_tool(
        &mut server,
        "transfer_file",
        json!({
            "router_name": "vsrx-test10",
            "source_path": "../etc/passwd",
        }),
    );

    let text = resp.to_string();
    assert!(
        text.contains("code=bad_source_path"),
        "expected [code=bad_source_path] in response: {}",
        text
    );
}

#[test]
fn transfer_file_rejects_unknown_router() {
    let dir = tempfile::tempdir().unwrap();
    let mut server = make_server(dir.path());

    let resp = call_tool(
        &mut server,
        "transfer_file",
        json!({
            "router_name": "does-not-exist",
            "source_path": "foo.tgz",
        }),
    );

    let text = resp.to_string();
    assert!(
        text.contains("does-not-exist"),
        "expected router name 'does-not-exist' in response: {}",
        text
    );
}

#[test]
#[ignore = "requires outbound network to TEST-NET-1; run with --ignored in CI"]
fn transfer_file_connect_timeout_against_test_net_1() {
    let dir = tempfile::tempdir().unwrap();
    let mut server = make_server(dir.path());

    let resp = call_tool(
        &mut server,
        "transfer_file",
        json!({
            "router_name": "vsrx-test10",
            "source_path": "foo.tgz",
            "timeout": 30,
        }),
    );

    let text = resp.to_string();
    assert!(
        text.contains("code=connect_timeout") || text.contains("code=outer_timeout"),
        "expected [code=connect_timeout] or [code=outer_timeout] in response: {}",
        text
    );
}
