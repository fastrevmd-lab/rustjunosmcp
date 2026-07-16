mod common;

use common::{
    close_session, http_get, http_post, http_post_raw, initialize, spawn_with_auth_args, write_inv,
    write_tokens,
};
use rust_junosmcp_auth::{ScopeSet, TokenStoreFile};
use serde_json::json;

#[test]
fn metrics_disabled_leaves_route_absent() {
    let inventory = write_inv(
        r#"{"secret-srx":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let tokens = write_tokens(r#"{"version":1,"tokens":[]}"#);
    let token = TokenStoreFile::add(
        tokens.path(),
        "secret-srx-token",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
    )
    .unwrap();
    let server = spawn_with_auth_args(inventory.path(), tokens.path(), &[]);
    let response = http_get(server.port, "/metrics", Some(token.expose()), None);
    assert_eq!(response.code, 404);
}

#[test]
fn enabled_metrics_are_unauthenticated_bounded_and_live() {
    let inventory = write_inv(
        r#"{"secret-srx":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let tokens = write_tokens(r#"{"version":1,"tokens":[]}"#);
    let token = TokenStoreFile::add(
        tokens.path(),
        "secret-srx-token",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
    )
    .unwrap();
    let server = spawn_with_auth_args(
        inventory.path(),
        tokens.path(),
        &["--enable-metrics", "--max-request-body-bytes", "512"],
    );

    let initial = http_get(server.port, "/metrics", None, Some("untrusted.example"));
    assert_eq!(initial.code, 200);
    assert_eq!(
        initial.content_type,
        "text/plain; version=0.0.4; charset=utf-8"
    );

    let session_id = initialize(server.port, token.expose());
    let tool = http_post(
        server.port,
        Some(token.expose()),
        Some(&session_id),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "srxmcp_status", "arguments": {}}
        }),
    );
    assert_eq!(tool.code, 200, "offline SRX tool failed: {:?}", tool.body);

    let big = "x".repeat(4096);
    let body = format!(r#"{{"jsonrpc":"2.0","id":3,"method":"ping","params":"{big}"}}"#);
    assert_eq!(http_post_raw(server.port, token.expose(), None, &body), 413);

    let scrape = http_get(server.port, "/metrics", None, None);
    assert!(scrape
        .body
        .contains("junosmcp_active_sessions{server=\"junos\"} 1"));
    assert!(scrape.body.lines().any(|line| {
        line.starts_with("junosmcp_tool_duration_seconds_bucket{")
            && line.contains("server=\"junos\"")
            && line.contains("tool=\"srxmcp_status\"")
            && line.contains("result=\"ok\"")
    }));
    assert!(scrape.body.lines().any(|line| {
        line.starts_with("junosmcp_limit_hits_total{")
            && line.contains("limit=\"request_body\"")
            && line.contains("event=\"request_rejected\"")
    }));
    for forbidden in [
        "secret-srx-token",
        token.expose(),
        "secret-srx",
        &session_id,
        "caller=",
        "router=",
        "session_id=",
        "correlation_id=",
        "error=",
    ] {
        assert!(
            !scrape.body.contains(forbidden),
            "metrics leaked {forbidden}: {}",
            scrape.body
        );
    }

    assert!(matches!(
        close_session(server.port, token.expose(), &session_id),
        200 | 202 | 204
    ));
    let closed = http_get(server.port, "/metrics", None, None);
    assert!(closed
        .body
        .contains("junosmcp_active_sessions{server=\"junos\"} 0"));
}
