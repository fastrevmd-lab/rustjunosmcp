#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]

//! `tools/list` must carry the cache descriptor a 2026-07-28 client validates.
//!
//! This server overrides `list_tools` to filter the surface by token scope, and
//! `ListToolsResult::with_all_items` leaves `ttl_ms` and `cache_scope` unset —
//! both omitted on the wire. A client on the 2026-07-28 protocol validates the
//! result and rejects it outright; Claude Code reports "tools fetch failed"
//! while the server is healthy and answering in milliseconds.
//!
//! Servers that do *not* override `list_tools` get these fields from rmcp's
//! generated handler, which is why this only bit the scope-filtering ones.
#![cfg(unix)]

mod common;
use common::*;
use serde_json::{Value, json};
use std::time::Duration;

/// 2026-07-28 is stateless — no `initialize`, no session — so the call carries
/// its own protocol context in headers and `_meta`.
fn stateless_tools_list(port: u16) -> Value {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{
    "_meta":{
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"cache-test","version":"1"},
        "io.modelcontextprotocol/clientCapabilities":{}
    }}});
    let response = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build()
        .post(&format!("http://127.0.0.1:{port}/mcp"))
        .set("Content-Type", "application/json")
        .set("Accept", "application/json, text/event-stream")
        .set("MCP-Protocol-Version", "2026-07-28")
        .set("Mcp-Method", "tools/list")
        .send_json(body)
        .expect("tools/list");
    let raw = response.into_string().expect("body");
    // The transport may frame the reply as one SSE event.
    let payload = raw
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap_or(&raw);
    serde_json::from_str(payload).expect("json reply")
}

/// The list is filtered per token, so it must be marked private rather than
/// shareable — a cache keyed only by URL would otherwise hand one caller's
/// permitted surface to another.
#[test]
fn tools_list_carries_a_private_cache_descriptor() {
    let server = spawn_with_args(&[]);
    let reply = stateless_tools_list(server.server.port);

    let result = &reply["result"];
    assert!(
        result["tools"].as_array().is_some_and(|t| !t.is_empty()),
        "no tools listed, so the assertions below would prove nothing: {reply}"
    );
    assert_eq!(
        result["ttlMs"], 0,
        "a 2026-07-28 client rejects a tools/list without ttlMs: {result}"
    );
    assert_eq!(
        result["cacheScope"], "private",
        "a scope-filtered list is per-token and must not be shared: {result}"
    );
}
