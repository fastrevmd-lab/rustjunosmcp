//! Host validation integration tests for mecmcp-transport 0.7.0 migration.
//!
//! These tests verify critical production behaviors that MUST NOT regress:
//! - Portless `--allowed-host` entries match ANY port (LXC 609 production shape)
//! - Loopback hosts remain allowed after custom hosts are added
//! - Unlisted Host headers are rejected with 421 MISDIRECTED_REQUEST
//! - Origin validation works when enabled (pass-through to mecmcp_transport)
//!
//! These tests directly call `build_http_router` and test the Axum router with
//! tower::ServiceExt::oneshot, which exercises the middleware stack without
//! needing to bind a real TCP listener.

#![cfg_attr(test, allow(clippy::unwrap_used))]

mod common;

use mecmcp_changeset::ChangesetCoordinator;
use mecmcp_transport::LimitsConfig;
use rust_junosmcp::server::JmcpHandler;
use rust_junosmcp_core::{DeviceManager, MecmcpScpRunner, Policy, TransferConfig, UpgradeConfig};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

/// Build a minimal test handler for router tests.
/// Mirrors production initialization but with an empty inventory (no devices needed).
fn test_handler() -> JmcpHandler {
    let inventory = rust_junosmcp_core::Inventory::empty();
    let policy = Arc::new(Policy::build(&inventory).expect("test policy"));
    let dev_manager = Arc::new(DeviceManager::new(Arc::new(inventory)));

    // Minimal transfer/upgrade config for test purposes
    let transfer_cfg = TransferConfig {
        staging_dir: std::path::PathBuf::from("/tmp"),
        known_hosts_file: std::path::PathBuf::from("/dev/null"),
        scp_runner: Arc::new(MecmcpScpRunner),
        transfer_locks: Arc::new(Default::default()),
        accept_new_host_keys: false,
    };
    // Use a tempdir for leases to avoid permissions issues with /tmp
    let lease_dir = tempfile::tempdir().expect("test lease tempdir");
    let upgrade_cfg = UpgradeConfig {
        transfer_cfg: transfer_cfg.clone(),
        device_leases: Arc::new(
            rust_junosmcp_core::DeviceLeaseManager::for_directory(lease_dir.path())
                .expect("test lease manager"),
        ),
    };
    let coordinator = Arc::new(
        ChangesetCoordinator::load(
            None, // in-memory
            mecmcp_changeset::OperationLimits::default(),
            std::time::Duration::from_secs(300),
            false,
        )
        .expect("test changeset coordinator"),
    );

    JmcpHandler::new(
        dev_manager,
        policy,
        transfer_cfg,
        upgrade_cfg,
        coordinator,
        false,
        false,
    )
}

#[tokio::test]
async fn portless_allowed_host_matches_any_port() {
    // Production shape: LXC 609 binds 0.0.0.0:30031 with `--allowed-host 192.168.1.194`
    // (no port). This MUST accept Host: 192.168.1.194:30031 (with port).
    let handler = test_handler();
    let (router, _shutdown) = rust_junosmcp::http_transport::build_http_router(
        handler,
        None, // No auth
        vec!["192.168.1.194".to_string()],
        Vec::new(), // No origins
        LimitsConfig::default(),
        false, // No metrics
        CancellationToken::new(),
    )
    .expect("router build");

    // Request with explicit port in Host header
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(axum::http::header::HOST, "192.168.1.194:30031")
        .body(axum::body::Body::from("{}"))
        .expect("request");

    let response = router.oneshot(request).await.expect("response");

    // Should NOT be 421 (portless allowlist entry must match explicit port)
    // assert_eq, not assert_ne: a bare "not 421" also passes when the request
    // was rejected somewhere else entirely. 406 is rmcp's answer to a probe
    // carrying no `Accept: text/event-stream`, so it is positive evidence the
    // request reached rmcp rather than being turned away by the guard.
    assert_eq!(
        response.status(),
        axum::http::StatusCode::NOT_ACCEPTABLE,
        "portless allowlist entry MUST match explicit port (production requirement)"
    );
}

#[tokio::test]
async fn portless_allowed_host_also_matches_portless_host() {
    // A portless allowlist entry should also accept a portless Host header.
    let handler = test_handler();
    let (router, _shutdown) = rust_junosmcp::http_transport::build_http_router(
        handler,
        None,
        vec!["192.168.1.194".to_string()],
        Vec::new(),
        LimitsConfig::default(),
        false,
        CancellationToken::new(),
    )
    .expect("router build");

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(axum::http::header::HOST, "192.168.1.194")
        .body(axum::body::Body::from("{}"))
        .expect("request");

    let response = router.oneshot(request).await.expect("response");

    assert_eq!(
        response.status(),
        axum::http::StatusCode::NOT_ACCEPTABLE,
        "portless allowlist entry should match portless Host"
    );
}

#[tokio::test]
async fn loopback_still_allowed_after_adding_host() {
    // The default loopback allowlist (localhost/127.0.0.1/[::1]) must remain
    // accessible after adding a custom host with --allowed-host.
    let handler = test_handler();
    let (router, _shutdown) = rust_junosmcp::http_transport::build_http_router(
        handler,
        None,
        vec!["192.168.1.194".to_string()],
        Vec::new(),
        LimitsConfig::default(),
        false,
        CancellationToken::new(),
    )
    .expect("router build");

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(axum::http::header::HOST, "localhost")
        .body(axum::body::Body::from("{}"))
        .expect("request");

    let response = router.oneshot(request).await.expect("response");

    assert_eq!(
        response.status(),
        axum::http::StatusCode::NOT_ACCEPTABLE,
        "loopback must remain allowed after custom hosts are added"
    );
}

#[tokio::test]
async fn unlisted_host_rejected_with_421() {
    // An unlisted Host header must be rejected with 421 MISDIRECTED_REQUEST.
    let handler = test_handler();
    let (router, _shutdown) = rust_junosmcp::http_transport::build_http_router(
        handler,
        None,
        vec!["192.168.1.194".to_string()],
        Vec::new(),
        LimitsConfig::default(),
        false,
        CancellationToken::new(),
    )
    .expect("router build");

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(axum::http::header::HOST, "attacker.example")
        .body(axum::body::Body::from("{}"))
        .expect("request");

    let response = router.oneshot(request).await.expect("response");

    assert_eq!(
        response.status(),
        axum::http::StatusCode::MISDIRECTED_REQUEST,
        "unlisted Host must be rejected with 421"
    );
}

#[tokio::test]
async fn origin_allow_pass_through() {
    // When an Origin allowlist is provided, matching origins should pass.
    let handler = test_handler();
    let (router, _shutdown) = rust_junosmcp::http_transport::build_http_router(
        handler,
        None,
        Vec::new(), // No extra hosts beyond loopback
        vec!["http://localhost:8080".to_string()],
        LimitsConfig::default(),
        false,
        CancellationToken::new(),
    )
    .expect("router build");

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(axum::http::header::HOST, "localhost")
        .header(axum::http::header::ORIGIN, "http://localhost:8080")
        .body(axum::body::Body::from("{}"))
        .expect("request");

    let response = router.oneshot(request).await.expect("response");

    assert_eq!(
        response.status(),
        axum::http::StatusCode::NOT_ACCEPTABLE,
        "matching Origin should pass validation"
    );
}

#[tokio::test]
async fn origin_deny_pass_through() {
    // When an Origin allowlist is provided, non-matching origins should be rejected.
    let handler = test_handler();
    let (router, _shutdown) = rust_junosmcp::http_transport::build_http_router(
        handler,
        None,
        Vec::new(),
        vec!["http://localhost:8080".to_string()],
        LimitsConfig::default(),
        false,
        CancellationToken::new(),
    )
    .expect("router build");

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(axum::http::header::HOST, "localhost")
        .header(axum::http::header::ORIGIN, "http://attacker.example")
        .body(axum::body::Body::from("{}"))
        .expect("request");

    let response = router.oneshot(request).await.expect("response");

    assert_eq!(
        response.status(),
        axum::http::StatusCode::FORBIDDEN,
        "unlisted Origin must be rejected with 403"
    );
}
