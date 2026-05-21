//! End-to-end test of the `srxmcp_status` tool body. Constructs a
//! `JmcpSrxHandler` with a known start instant, invokes the test-only
//! body, and asserts the response shape.

use rust_junosmcp_core::{DeviceManager, Inventory};
use rust_srxmcp::server::{JmcpSrxHandler, SrxmcpStatusArgs};
use std::io::Write;
use std::sync::Arc;
use tokio::time::Instant;

#[tokio::test]
async fn srxmcp_status_returns_version_endpoint_and_uptime() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(b"{}").unwrap();
    let inv = Arc::new(Inventory::load(f.path()).unwrap());
    let dev_manager = Arc::new(DeviceManager::new(inv));

    let started = Arc::new(Instant::now());
    let handler = JmcpSrxHandler::new(started.clone(), dev_manager);

    // Small delay so uptime > 0 ms (still 0 seconds, fine).
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let resp = handler.srxmcp_status_test(SrxmcpStatusArgs::default());

    assert_eq!(resp.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(resp.endpoint, "srxmcp");
    // uptime in seconds — at 10ms it's 0; just assert sane upper bound.
    assert!(resp.uptime_seconds < 60);
}
