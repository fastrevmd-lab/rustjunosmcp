# Shared HTTP-test harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dedup the junos HTTP integration-test harness into a per-crate `tests/common` module (#100) and add an equivalent srx HTTP harness + tests (#101).

**Architecture:** Rust integration tests share code via a `tests/common/mod.rs` submodule. Task 1 moves the duplicated junos helpers there and refactors the 3 HTTP test files to use it. Task 2 creates the srx analog and a new `rust-srxmcp/tests/http_smoke.rs` covering auth + Host allowlist + tool-surface. Test-only; no source (non-test) changes.

**Tech Stack:** Rust integration tests, `ureq`, `tempfile`, `serde_json`.

## Global Constraints

- Per-crate `tests/common/mod.rs` (the submodule path — NOT `tests/common.rs`, which cargo compiles as a standalone test binary). First line: `#![allow(dead_code)]` (shared test module; consumers use subsets).
- Readiness substring the spawn helper waits on: `"streamable-http listening"` (a substring of both junos's and srx's `"…streamable-http listening"` log line).
- Unified `http_post` signature: `http_post(port: u16, bearer: Option<&str>, session_id: Option<&str>, body: Value) -> PostResult`.
- srx is HTTP-only (no `-t/--transport` flag); srx CLI: `--host`, `--port`, `--tokens-file`, `--device-mapping`, `--allow-no-auth`, `--allowed-host`, `--disable-host-check`. Both crates share the auth layer (`rust-junosmcp-auth`), so 401 bodies are RFC 6749 JSON `{error, error_description}` in both.
- srx tool surface count = **9**.
- `cargo test --workspace` 0 failures; `cargo fmt -- --check` + `cargo clippy --workspace --all-targets` clean. No non-test source changes.

---

### Task 1: #100 — junos `tests/common/mod.rs` + refactor 3 HTTP test files

**Files:**
- Create: `rust-junosmcp/tests/common/mod.rs`
- Modify: `rust-junosmcp/tests/http_smoke.rs`, `rust-junosmcp/tests/http_reload.rs`, `rust-junosmcp/tests/http_tls.rs`

**Interfaces:**
- Produces (in `common`): `binary_path() -> PathBuf`, `ensure_built()`, `pick_port() -> u16`, `struct Server`, `spawn(inv: &Path, tokens: &Path) -> Server`, `spawn_no_auth(inv: &Path, extra: &[&str]) -> Server`, `struct PostResult { code: u16, body: Value, session_id: Option<String>, www_authenticate: Option<String> }`, `http_post(port, bearer: Option<&str>, session_id: Option<&str>, body: Value) -> PostResult`, `parse_first_sse_data(&str) -> Option<Value>`, `init_body() -> Value`, `initialize(port, bearer: &str) -> String`, `post_init_with_host(port, host: &str) -> u16`, `write_inv(&str) -> NamedTempFile`, `write_tokens(&str) -> NamedTempFile`.

- [ ] **Step 1: Create `common/mod.rs` by moving the shared helpers**

Create `rust-junosmcp/tests/common/mod.rs`. Move these functions/types **verbatim** from the CURRENT `rust-junosmcp/tests/http_smoke.rs` (it holds the superset versions): `binary_path`, `ensure_built`, `pick_port`, `Server` (struct + `impl Drop`), `spawn`, `spawn_no_auth`, `PostResult`, `http_post`, `parse_first_sse_data`, `initialize`, `init_body`, `post_init_with_host`, `write_inv`, `write_tokens`. Prepend the module with the attribute + imports the moved code needs:

```rust
#![allow(dead_code)]
//! Shared streamable-http integration-test harness for rust-junosmcp: spawn the
//! binary on an ephemeral port, POST JSON-RPC, parse SSE, assert HTTP behavior.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// <moved fns/types here, verbatim from http_smoke.rs>
```

Make each moved item `pub` (they are called from sibling test files): `pub fn`, `pub struct Server { … }` with `pub` fields as needed by call sites (`port` is read as `s.port`), `pub struct PostResult` with `pub` fields (`code`, `body`, `session_id`, `www_authenticate` are all read by tests).

- [ ] **Step 2: Refactor `http_smoke.rs` to use `common`**

In `rust-junosmcp/tests/http_smoke.rs`: delete the now-moved function/type definitions, and replace the top-of-file `use`/helpers with:

```rust
//! End-to-end streamable-http smoke: spawn the binary on an ephemeral port,
//! send HTTP, assert auth + scope + blocklist behavior.

mod common;
use common::*;
use serde_json::{json, Value};
use std::process::Command; // still used by tests that mint tokens via `token add`
```

Keep the `#[test]` functions as-is (they call the now-`common` helpers). Retain only imports the remaining test bodies use (the compiler will flag unused ones — remove those). Note several tests use `Command` (token minting) and `json!`/`Value`.

- [ ] **Step 3: Refactor `http_reload.rs` to use `common`; fix `http_post` call sites**

In `rust-junosmcp/tests/http_reload.rs`: delete its local `binary_path`/`ensure_built`/`pick_port`/`Server`/`spawn`/`PostResult`/`http_post`/`parse_first_sse_data` copies. Add `mod common; use common::*;`. Its `http_post` was `http_post(port, bearer, body)` (no session id); update every call site to the unified signature by inserting `None`:

```rust
// before: http_post(port, Some(tok), body)
// after:
http_post(port, Some(tok), None, body)
```
Update ALL `http_post(` calls in the file the same way. Keep the `sighup_reloads_token_store` test logic otherwise unchanged.

- [ ] **Step 4: Refactor `http_tls.rs` to use `common` for the shared bits**

In `rust-junosmcp/tests/http_tls.rs`: delete its local `binary_path`/`ensure_built`/`pick_port`/`Server`(+Drop)/`parse_first_sse_data` copies and add `mod common; use common::{binary_path, ensure_built, pick_port, Server, parse_first_sse_data};`. KEEP the TLS-specific helpers in this file: `wait_for_port`, `write_self_signed`, `build_tls_agent`, `spawn_tls` (single consumer). `spawn_tls` builds its own `Server` — it now constructs `common::Server`; ensure `Server`'s fields are `pub` (done in Step 1) so `spawn_tls` can build it, OR keep `spawn_tls` using the same readiness/drain pattern returning `common::Server` (add a `pub fn` constructor `Server::from_child(child, port)` in common if direct struct construction across modules is awkward — prefer making fields `pub`).

- [ ] **Step 5: Build + run all junos HTTP tests**

Run: `cargo test -p rust-junosmcp --test http_smoke --test http_reload --test http_tls 2>&1 | tail -25`
Expected: all pass (behavior-preserving refactor — same test count as before, now green from `common`). If `http_tls` needs the TLS feature: `cargo test -p rust-junosmcp --features tls --test http_tls`.

- [ ] **Step 6: fmt + clippy + commit**

Run: `cargo fmt && cargo fmt -- --check && cargo clippy -p rust-junosmcp --tests 2>&1 | tail -5`
Expected: clean (no unused-import or dead-code warnings — `#![allow(dead_code)]` covers helpers unused by a given file).

```bash
git add rust-junosmcp/tests/common/mod.rs rust-junosmcp/tests/http_smoke.rs rust-junosmcp/tests/http_reload.rs rust-junosmcp/tests/http_tls.rs
git commit -m "test(junos): hoist shared http harness into tests/common (#100)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_019mPwHV2n6YmBTd5j8HcAAJ"
```

---

### Task 2: #101 — srx `tests/common/mod.rs` + `tests/http_smoke.rs` + live_smoke dedup

**Files:**
- Create: `rust-srxmcp/tests/common/mod.rs`, `rust-srxmcp/tests/http_smoke.rs`
- Modify: `rust-srxmcp/tests/live_smoke.rs`

**Interfaces:**
- Consumes: nothing from Task 1 (separate crate).
- Produces (in srx `common`): `binary_path`, `pick_port`, `Server`, `spawn(inv, tokens) -> Server`, `spawn_no_auth(inv, extra) -> Server`, `PostResult`, `http_post`, `parse_first_sse_data`, `init_body`, `post_init_with_host`, `write_inv`, `write_tokens`.

- [ ] **Step 1: Create srx `tests/common/mod.rs`**

Create `rust-srxmcp/tests/common/mod.rs`. This mirrors the junos common but with srx CLI args (no `-t`; `--device-mapping` + `--tokens-file`; bind via `--host/--port`). Full content:

```rust
#![allow(dead_code)]
//! Shared streamable-http integration-test harness for rust-srxmcp.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub fn binary_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("target");
    p.push(if cfg!(debug_assertions) { "debug" } else { "release" });
    p.push("rust-srxmcp");
    p
}

pub fn ensure_built() {
    let s = Command::new("cargo").args(["build", "-p", "rust-srxmcp"]).status().unwrap();
    assert!(s.success(), "cargo build failed");
}

pub fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

pub struct Server {
    pub child: Child,
    pub port: u16,
    pub _stderr_drain: std::thread::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Wait for the readiness line and spawn a stderr-drain thread; panics if the
/// server doesn't announce within 15s.
fn finish_spawn(mut child: Child, port: u16) -> Server {
    let stderr = child.stderr.take().unwrap();
    let mut reader = BufReader::new(stderr);
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut ready = false;
    loop {
        if Instant::now() > deadline { break; }
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => { if line.contains("streamable-http listening") { ready = true; break; } }
            Err(_) => break,
        }
    }
    if !ready { let _ = child.kill(); panic!("server did not start within 15s"); }
    let drain = std::thread::spawn(move || {
        let mut sink = String::new();
        loop { sink.clear(); match reader.read_line(&mut sink) { Ok(0) | Err(_) => break, Ok(_) => {} } }
    });
    Server { child, port, _stderr_drain: drain }
}

/// Spawn with bearer auth enabled (tokens file). Requires a device-mapping file.
pub fn spawn(inv_path: &Path, tokens_path: &Path) -> Server {
    let port = pick_port();
    let port_s = port.to_string();
    let child = Command::new(binary_path())
        .args([
            "--host", "127.0.0.1",
            "--port", &port_s,
            "--device-mapping", inv_path.to_str().unwrap(),
            "--tokens-file", tokens_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    finish_spawn(child, port)
}

/// Spawn with `--allow-no-auth` (no auth layer) + extra args (host-allowlist flags).
pub fn spawn_no_auth(inv_path: &Path, extra: &[&str]) -> Server {
    let port = pick_port();
    let port_s = port.to_string();
    let mut argv = vec![
        "--host", "127.0.0.1",
        "--port", &port_s,
        "--device-mapping", inv_path.to_str().unwrap(),
        "--allow-no-auth",
    ];
    argv.extend_from_slice(extra);
    let child = Command::new(binary_path())
        .args(&argv)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    finish_spawn(child, port)
}

pub struct PostResult {
    pub code: u16,
    pub body: Value,
    pub session_id: Option<String>,
    pub www_authenticate: Option<String>,
}

pub fn http_post(port: u16, bearer: Option<&str>, session_id: Option<&str>, body: Value) -> PostResult {
    let mut req = ureq::post(&format!("http://127.0.0.1:{port}/mcp"));
    if let Some(b) = bearer { req = req.set("Authorization", &format!("Bearer {b}")); }
    req = req.set("Accept", "application/json, text/event-stream");
    if let Some(sid) = session_id { req = req.set("Mcp-Session-Id", sid); }
    let (code, resp_session, content_type, www_auth, text) = match req.send_json(body) {
        Ok(resp) => {
            let code = resp.status();
            let sid = resp.header("Mcp-Session-Id").map(str::to_string);
            let ct = resp.header("Content-Type").unwrap_or("").to_string();
            let wa = resp.header("WWW-Authenticate").map(str::to_string);
            let text = resp.into_string().unwrap_or_default();
            (code, sid, ct, wa, text)
        }
        Err(ureq::Error::Status(code, resp)) => {
            let sid = resp.header("Mcp-Session-Id").map(str::to_string);
            let ct = resp.header("Content-Type").unwrap_or("").to_string();
            let wa = resp.header("WWW-Authenticate").map(str::to_string);
            let text = resp.into_string().unwrap_or_default();
            (code, sid, ct, wa, text)
        }
        Err(e) => panic!("transport error: {e}"),
    };
    let body_value = if content_type.contains("text/event-stream") {
        parse_first_sse_data(&text).unwrap_or(json!({}))
    } else if !text.is_empty() {
        serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }))
    } else {
        json!({})
    };
    PostResult { code, body: body_value, session_id: resp_session, www_authenticate: www_auth }
}

/// Parse the first non-empty `data:` line from an SSE stream as JSON (skips the
/// rmcp 2.0 priming event).
pub fn parse_first_sse_data(sse: &str) -> Option<Value> {
    for line in sse.lines() {
        if let Some(payload) = line.strip_prefix("data:") {
            let payload = payload.trim();
            if payload.is_empty() { continue; }
            if let Ok(v) = serde_json::from_str(payload) { return Some(v); }
        }
    }
    None
}

pub fn init_body() -> Value {
    json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
        "protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}
    }})
}

/// POST an `initialize` with an explicit Host header; return the HTTP status.
pub fn post_init_with_host(port: u16, host: &str) -> u16 {
    let req = ureq::post(&format!("http://127.0.0.1:{port}/mcp"))
        .set("Accept", "application/json, text/event-stream")
        .set("Host", host);
    match req.send_json(init_body()) {
        Ok(resp) => resp.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(e) => panic!("transport error: {e}"),
    }
}

pub fn write_inv(json: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), json).unwrap();
    f
}

pub fn write_tokens(json: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), json).unwrap();
    f
}
```

- [ ] **Step 2: Confirm `ureq` + `tempfile` are dev-deps of rust-srxmcp**

Run: `grep -E "ureq|tempfile" rust-srxmcp/Cargo.toml`
Expected: both present under `[dev-dependencies]` (they are — `live_smoke.rs` uses `ureq`, `status_tool.rs` uses `tempfile`). If `tempfile` is missing, add `tempfile = { workspace = true }` to `rust-srxmcp/Cargo.toml [dev-dependencies]`.

- [ ] **Step 3: Create `rust-srxmcp/tests/http_smoke.rs`**

```rust
//! Streamable-http integration smoke for rust-srxmcp: auth (RFC 6750 401s),
//! rmcp 2.0 Host allowlist (#97), and the tool-surface tripwire. All tests
//! exercise the transport/auth layers only — no device is contacted.

mod common;
use common::*;
use serde_json::json;

fn placeholder_inv() -> tempfile::NamedTempFile {
    write_inv(r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#)
}

#[test]
fn missing_authorization_returns_401() {
    ensure_built();
    let inv = placeholder_inv();
    let toks = write_tokens(r#"{"version":1,"tokens":[]}"#);
    let s = spawn(inv.path(), toks.path());
    let r = http_post(s.port, None, None, json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}));
    assert_eq!(r.code, 401);
    let challenge = r.www_authenticate.expect("401 must carry WWW-Authenticate per RFC 6750 §3");
    assert!(challenge.to_ascii_lowercase().starts_with("bearer"), "challenge must use Bearer scheme: {challenge:?}");
    assert_eq!(r.body["error"], "invalid_request", "missing-auth 401 body must be {{error:\"invalid_request\",...}}: {:?}", r.body);
    assert!(r.body["error_description"].is_string(), "401 body must include error_description string: {:?}", r.body);
}

#[test]
fn wrong_bearer_returns_401() {
    ensure_built();
    let inv = placeholder_inv();
    let toks = write_tokens(r#"{"version":1,"tokens":[]}"#);
    let s = spawn(inv.path(), toks.path());
    let r = http_post(s.port, Some("not-a-real-token"), None, json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}));
    assert_eq!(r.code, 401);
    let challenge = r.www_authenticate.expect("401 must carry WWW-Authenticate per RFC 6750 §3");
    assert!(challenge.contains(r#"error="invalid_token""#), "wrong-bearer challenge must include error=\"invalid_token\": {challenge:?}");
    assert_eq!(r.body["error"], "invalid_token", "wrong-bearer 401 body must be {{error:\"invalid_token\",...}}: {:?}", r.body);
}

#[test]
fn disallowed_host_is_rejected_403() {
    ensure_built();
    let inv = placeholder_inv();
    let s = spawn_no_auth(inv.path(), &[]);
    let code = post_init_with_host(s.port, "evil.example.com");
    assert_eq!(code, 403, "rmcp's built-in Host allowlist must reject a disallowed Host");
}

#[test]
fn allowed_host_flag_permits_custom_host() {
    ensure_built();
    let inv = placeholder_inv();
    let s = spawn_no_auth(inv.path(), &["--allowed-host", "friendly.example.com"]);
    let code = post_init_with_host(s.port, "friendly.example.com");
    assert_eq!(code, 200, "an --allowed-host authority must pass rmcp's Host check and reach initialize");
}

#[test]
fn disable_host_check_allows_any_host() {
    ensure_built();
    let inv = placeholder_inv();
    let s = spawn_no_auth(inv.path(), &["--disable-host-check"]);
    let code = post_init_with_host(s.port, "anything.example");
    assert_eq!(code, 200, "--disable-host-check must bypass rmcp's Host check");
}

#[test]
fn lists_nine_tools() {
    ensure_built();
    let inv = placeholder_inv();
    let s = spawn_no_auth(inv.path(), &[]);
    // initialize (no auth) then tools/list.
    let init = http_post(s.port, None, None, init_body());
    assert_eq!(init.code, 200, "initialize failed: {:?}", init.body);
    let sid = init.session_id.expect("server did not return Mcp-Session-Id");
    let _ = http_post(s.port, None, Some(&sid), json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let r = http_post(s.port, None, Some(&sid), json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}));
    assert_eq!(r.code, 200, "tools/list failed: {:?}", r.body);
    let tools = r.body.pointer("/result/tools").and_then(|t| t.as_array()).expect("tools array");
    assert_eq!(tools.len(), 9, "srx tool surface must be 9: {:?}", tools.iter().filter_map(|t| t.get("name")).collect::<Vec<_>>());
}
```

- [ ] **Step 4: Refactor `live_smoke.rs` to use `common::parse_first_sse_data`**

In `rust-srxmcp/tests/live_smoke.rs`: add `mod common;` near the top, delete its local `parse_first_sse_data` definition, and add `use common::parse_first_sse_data;` (only that helper — live_smoke hits a live endpoint via its own `endpoint()`, it does NOT use the spawn helpers). Leave all `#[ignore]`/env-based test logic unchanged. If live_smoke has no local `parse_first_sse_data` (verify with grep), skip this step and note it.

- [ ] **Step 5: Run the srx tests**

Run: `cargo test -p rust-srxmcp --test http_smoke 2>&1 | tail -20`
Expected: all 6 tests pass (they spawn the debug binary and exercise auth/host/surface). Then confirm live_smoke still compiles (its ignored tests aren't run): `cargo test -p rust-srxmcp --test live_smoke 2>&1 | tail -5` (expect 0 run / N ignored, compiles clean).

- [ ] **Step 6: fmt + clippy + full workspace + commit**

Run: `cargo fmt && cargo fmt -- --check && cargo clippy --workspace --all-targets 2>&1 | tail -5 && cargo test --workspace 2>&1 | grep -E "FAILED|error\[" || echo "workspace clean"`
Expected: clean; 0 workspace failures.

```bash
git add rust-srxmcp/tests/common/mod.rs rust-srxmcp/tests/http_smoke.rs rust-srxmcp/tests/live_smoke.rs
git commit -m "test(srxmcp): add http_smoke harness (auth + Host allowlist + surface) (#101)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_019mPwHV2n6YmBTd5j8HcAAJ"
```

---

## Self-Review

**Spec coverage:**
- junos `tests/common/mod.rs` with the shared helpers + `#![allow(dead_code)]` + submodule path → Task 1 Step 1. ✔
- Refactor http_smoke/http_reload/http_tls; unify `http_post` (http_reload gains `None`); TLS helpers stay local → Task 1 Steps 2-4. ✔
- srx `common` mirroring junos with srx CLI args → Task 2 Step 1. ✔
- srx `http_smoke.rs`: 401 (missing + wrong bearer, RFC 6750 + JSON body), Host allowlist 403/200/disable, 9-tool tripwire → Task 2 Step 3. ✔
- live_smoke borrows only `parse_first_sse_data` → Task 2 Step 4. ✔
- No source (non-test) changes; workspace green; fmt/clippy clean → both tasks' verify steps. ✔

**Placeholder scan:** No TBD/TODO. Task 1 uses "move verbatim" pointers to existing named functions in a named file (correct for a refactor-move — re-transcribing 300 lines would risk divergence); Task 2 provides full new code. Every step has concrete commands.

**Type consistency:** `http_post(port, Option<&str> bearer, Option<&str> session_id, Value) -> PostResult` used identically in both crates' `common` and all call sites (http_reload updated to pass `None`). `Server { child, port, _stderr_drain }` fields `pub` so `spawn_tls` (junos) can construct it. `parse_first_sse_data` identical shape in both. srx `spawn`/`spawn_no_auth` signatures match the junos ones the tests expect.

**Risk note for implementer:** (1) after moving helpers out of junos http_smoke.rs, prune leftover `use` imports there or clippy will warn. (2) In http_tls.rs, `spawn_tls` constructs a `common::Server` — rely on the `pub` fields (Step 1) rather than a private constructor. (3) If srx startup requires a readable device-mapping, the placeholder inventory file is passed to every spawn; confirm the srx binary starts with it (it should — the file is valid JSON). (4) srx `lists_nine_tools` is the surface tripwire — if it reports a different count, that's a real surface change to reconcile, not a test bug.
