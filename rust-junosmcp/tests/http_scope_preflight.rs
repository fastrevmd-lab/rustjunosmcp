#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! Scope preflight tests: assert that out-of-scope requests are rejected
//! before dispatch, not merely that they fail.

mod common;
use common::*;
use rust_junosmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use serde_json::json;

#[test]
fn tool_out_of_scope_rejected_before_dispatch() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "read-only",
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(vec!["get_router_list".into()]),
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    // Attempt a write tool (load_and_commit_config) that the token doesn't allow
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"load_and_commit_config",
            "arguments":{"router":"r1","config":"set system login message test","comment":"test"}
        }}),
    );

    // Preflight should reject with 403 insufficient_scope
    assert_eq!(
        response.code, 403,
        "expected 403, got {}: {}",
        response.code, response.body
    );
    assert_eq!(
        response.body["error"], "insufficient_scope",
        "expected insufficient_scope error: {:?}",
        response.body
    );
}

#[test]
fn device_out_of_scope_rejected_before_dispatch_router() {
    ensure_built();
    let inv = write_inv(
        r#"{
            "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}},
            "r2":{"ip":"203.0.113.2","port":1,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "r1-only",
        ScopeSet::Allowlist(vec!["r1".into()]),
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    // Attempt to access r2 using the "router" argument
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":{"router":"r2","command":"show version","timeout":1}
        }}),
    );

    assert_eq!(
        response.code, 403,
        "expected 403, got {}: {}",
        response.code, response.body
    );
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn device_out_of_scope_rejected_before_dispatch_router_name() {
    ensure_built();
    let inv = write_inv(
        r#"{
            "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}},
            "r2":{"ip":"203.0.113.2","port":1,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "r1-only",
        ScopeSet::Allowlist(vec!["r1".into()]),
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    // Attempt to access r2 using the "router_name" argument
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":{"router_name":"r2","command":"show version","timeout":1}
        }}),
    );

    assert_eq!(
        response.code, 403,
        "expected 403, got {}: {}",
        response.code, response.body
    );
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn device_out_of_scope_rejected_before_dispatch_routers() {
    ensure_built();
    let inv = write_inv(
        r#"{
            "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}},
            "r2":{"ip":"203.0.113.2","port":1,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "r1-only",
        ScopeSet::Allowlist(vec!["r1".into()]),
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    // Attempt to access r2 using the "routers" argument (array form)
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command_batch",
            "arguments":{"routers":["r2"],"command":"show version","timeout":1}
        }}),
    );

    assert_eq!(
        response.code, 403,
        "expected 403, got {}: {}",
        response.code, response.body
    );
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn device_out_of_scope_rejected_before_dispatch_router_names() {
    ensure_built();
    let inv = write_inv(
        r#"{
            "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}},
            "r2":{"ip":"203.0.113.2","port":1,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "r1-only",
        ScopeSet::Allowlist(vec!["r1".into()]),
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    // Attempt to access r2 using the "router_names" argument (array form)
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command_batch",
            "arguments":{"router_names":["r2"],"command":"show version","timeout":1}
        }}),
    );

    assert_eq!(
        response.code, 403,
        "expected 403, got {}: {}",
        response.code, response.body
    );
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn in_scope_request_passes_through() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "full-access",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    // An in-scope request should succeed (though the command will fail because r1 is fake)
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"get_router_list",
            "arguments":{}
        }}),
    );

    // Should get a 200 response, not 403
    assert_eq!(
        response.code, 200,
        "expected 200, got {}: {}",
        response.code, response.body
    );
    // Result should have content, not an error
    assert!(
        response.body.get("result").is_some(),
        "expected result field: {:?}",
        response.body
    );
}

#[test]
fn batched_request_with_one_out_of_scope_is_refused() {
    ensure_built();
    let inv = write_inv(
        r#"{
            "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}},
            "r2":{"ip":"203.0.113.2","port":1,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "r1-only",
        ScopeSet::Allowlist(vec!["r1".into()]),
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    // Send a batched request where one element is out of scope
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!([
            {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_junos_command","arguments":{"router":"r1","command":"show version","timeout":1}}},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_junos_command","arguments":{"router":"r2","command":"show version","timeout":1}}}
        ]),
    );

    // The entire batch should be rejected at preflight
    assert_eq!(
        response.code, 403,
        "expected 403, got {}: {}",
        response.code, response.body
    );
    assert_eq!(response.body["error"], "insufficient_scope");
}

// Security bypass tests: ensure malformed inputs are rejected, not silently allowed

#[test]
fn malformed_router_number_is_denied() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":{"router":1,"command":"show version","timeout":1}
        }}),
    );

    assert_eq!(response.code, 403);
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn malformed_router_object_is_denied() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":{"router":{"x":1},"command":"show version","timeout":1}
        }}),
    );

    assert_eq!(response.code, 403);
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn malformed_router_null_is_denied() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":{"router":null,"command":"show version","timeout":1}
        }}),
    );

    assert_eq!(response.code, 403);
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn malformed_router_boolean_is_denied() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":{"router":true,"command":"show version","timeout":1}
        }}),
    );

    assert_eq!(response.code, 403);
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn empty_routers_array_is_denied() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command_batch",
            "arguments":{"routers":[],"command":"show version","timeout":1}
        }}),
    );

    assert_eq!(response.code, 403);
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn mixed_valid_and_malformed_array_elements_denied() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command_batch",
            "arguments":{"routers":["r1",{"x":1}],"command":"show version","timeout":1}
        }}),
    );

    assert_eq!(response.code, 403);
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn malformed_arguments_non_object_is_denied() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":"not-an-object"
        }}),
    );

    assert_eq!(response.code, 403);
    assert_eq!(response.body["error"], "insufficient_scope");
}
