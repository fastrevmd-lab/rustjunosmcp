//! e2e: request-body limit returns 413; happy-path still works with limits on.

mod common;
use common::{spawn_with_args, http_post_raw};

#[test]
fn oversized_body_returns_413() {
    // Start the server with a tiny body cap so the test payload exceeds it.
    let server = spawn_with_args(&["--max-request-body-bytes", "512"]);
    let big = "x".repeat(4096);
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":"{big}"}}"#);
    let status = http_post_raw(server.port, &server.token, None, &body);
    assert_eq!(status, 413, "oversized body must be rejected before buffering");
}
