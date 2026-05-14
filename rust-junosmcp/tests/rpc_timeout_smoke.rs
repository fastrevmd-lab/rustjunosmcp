//! Smoke test: per-call MCP timeout is the user-visible bound, NOT the
//! rustez internal 30 s cap.
//!
//! Regression for a real-world bug seen on 2026-05-14 where
//! `request system software add` ran to completion on a vSRX but the
//! MCP returned RPC timeout at 30 s, blinding the operator for the
//! remaining ~6 minutes of install + reboot.

mod common;

use common::{call_tool, spawn_stdio_server_with_args, write_inventory_temp};
use serde_json::json;
use std::time::Instant;

#[test]
fn execute_junos_command_outer_timeout_fires_before_rustez_cap() {
    // Inventory points at TEST-NET-1 (RFC 5737) — guaranteed unreachable,
    // so the connect attempt will hang until *something* times out.
    let inv_path = write_inventory_temp(&[(
        "unreachable",
        "192.0.2.1",
        22,
        "netconf",
        // Use a fake key file path — connection will fail at TCP layer
        // long before key parsing matters, but we need a valid auth field.
        "/dev/null",
    )]);

    let mut child = spawn_stdio_server_with_args(&["-f", inv_path.path().to_str().unwrap()]);

    let start = Instant::now();
    let resp = call_tool(
        &mut child,
        "execute_junos_command",
        json!({
            "router_name": "unreachable",
            "command": "show version",
            "timeout": 5,
        }),
    );
    let elapsed = start.elapsed();

    // Two observable properties of the fix:
    // 1. The error returns within ~5 s (MCP outer timeout), well before
    //    the legacy 30 s rustez cap. Allow generous slack for CI jitter
    //    and the connect-attempt tail (TCP retries).
    assert!(
        elapsed.as_secs() < 25,
        "Outer timeout should fire within MCP-side bound (~5s); got {:?}. \
         If this exceeds 25s, rustez's internal cap is likely still in play.",
        elapsed
    );

    // 2. The response is an error (it must not silently succeed against
    //    an unreachable host).
    let is_error = resp
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(is_error, "expected isError=true, got: {resp:?}");
}
