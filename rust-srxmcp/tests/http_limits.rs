//! e2e: request-body limit returns 413; happy-path still works with limits on.

mod common;
use common::{
    close_session, http_post, http_post_raw, init_body, initialize, spawn_with_args,
    spawn_with_auth_args, write_inv, write_tokens,
};
use rust_junosmcp_auth::{ScopeSet, TokenStoreFile};

#[test]
fn oversized_body_returns_413() {
    // Start the server with a tiny body cap so the test payload exceeds it.
    let server = spawn_with_args(&["--max-request-body-bytes", "512"]);
    let big = "x".repeat(4096);
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":"{big}"}}"#);
    let status = http_post_raw(server.port, &server.token, None, &body);
    assert_eq!(
        status, 413,
        "oversized body must be rejected before buffering"
    );
}

#[test]
fn token_session_cap_isolated_by_token_and_released_on_close() {
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let tokens = write_tokens(r#"{"version":1,"tokens":[]}"#);
    let alice = TokenStoreFile::add(
        tokens.path(),
        "alice",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
    )
    .unwrap();
    let bob =
        TokenStoreFile::add(tokens.path(), "bob", ScopeSet::Wildcard, ScopeSet::Wildcard).unwrap();
    let server = spawn_with_auth_args(
        inv.path(),
        tokens.path(),
        &["--max-sessions-per-token", "1"],
    );

    let alice_session = initialize(server.port, alice.expose());
    let shed = http_post(server.port, Some(alice.expose()), None, init_body());
    assert_eq!(shed.code, 503);
    assert_eq!(shed.body["limit"], "token_session_cap");

    let bob_session = initialize(server.port, bob.expose());
    assert!(matches!(
        close_session(server.port, alice.expose(), &alice_session),
        200 | 202 | 204
    ));
    let alice_again = initialize(server.port, alice.expose());

    assert!(matches!(
        close_session(server.port, alice.expose(), &alice_again),
        200 | 202 | 204
    ));
    assert!(matches!(
        close_session(server.port, bob.expose(), &bob_session),
        200 | 202 | 204
    ));
}
