# Per-Token MCP Session Caps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce a race-free, configurable per-bearer-token MCP session cap on both streamable-HTTP servers, with exact session ownership and close/reap cleanup.

**Architecture:** The existing authenticated concurrency middleware atomically reserves a token session slot before rmcp handles an initialize candidate. A successful response commits the reservation to the returned `Mcp-Session-Id`; RAII releases every uncommitted reservation. `SessionTracker` owns exact token counts and session-to-token bindings, and its existing unregister/reaper paths return committed capacity.

**Tech Stack:** Rust 2024, Axum 0.8 middleware, rmcp 2.x streamable HTTP, `std::sync::Mutex`, existing `dashmap`, Tokio, clap, ureq integration tests.

## Global Constraints

- Junos CLI/env: `--max-sessions-per-token` / `JMCP_MAX_SESSIONS_PER_TOKEN`.
- SRX CLI/env: `--max-sessions-per-token` / `JMCP_SRX_MAX_SESSIONS_PER_TOKEN`.
- Default is `16`; `0` disables admission and token-accounting map growth.
- Saturation is immediate HTTP 503 with `Retry-After: 1`, `Content-Type: application/json`, and body `{"error":"overloaded","limit":"token_session_cap"}`.
- Exact `CallerCtx.token_name` is the accounting key; do not normalize it.
- No-auth mode skips the token cap because it has no token identity; the global session cap remains active.
- Preserve stdio, MCP schemas, annotations, auth scopes, audit fields, device I/O, and all existing overload formats.
- Do not solve the separate global session overshoot tracked by #151 in this issue.
- Add no new external dependency or package version.
- Use TDD for every behavioral change and commit each task independently.
- Never run ignored/live-device tests or set `CONFIRM_LAB_INTEGRATION`.

---

### Task 1: Public Configuration and Binary Wiring

**Files:**
- Modify: `rust-junosmcp-limits/src/config.rs`
- Modify: `rust-junosmcp/src/cli.rs`
- Modify: `rust-junosmcp/src/main.rs`
- Modify: `rust-srxmcp/src/cli.rs`
- Modify: `rust-srxmcp/src/main.rs`

**Interfaces:**
- Consumes: Existing `LimitsConfig`, clap CLI parsing, and HTTP `serve` wiring.
- Produces: `LimitsConfig::max_sessions_per_token: usize`, populated identically by both binaries.

- [ ] **Step 1: Add failing shared-default and CLI parity assertions**

In `rust-junosmcp-limits/src/config.rs`'s `defaults_are_generous_and_enabled` test add:

```rust
assert_eq!(c.max_sessions_per_token, 16);
```

In the existing Junos and SRX CLI default/limit tests, add assertions equivalent to:

```rust
let default_cli = Cli::parse_from(["server"]);
assert_eq!(default_cli.max_sessions_per_token, 16);

let disabled = Cli::parse_from(["server", "--max-sessions-per-token", "0"]);
assert_eq!(disabled.max_sessions_per_token, 0);

let custom = Cli::parse_from(["server", "--max-sessions-per-token", "9"]);
assert_eq!(custom.max_sessions_per_token, 9);
```

Use the existing parser helper and required fixture arguments already present in each test module; the assertions and values must remain exact.

- [ ] **Step 2: Run the focused tests to verify RED**

```bash
cargo test -p rust-junosmcp-limits config::tests::defaults_are_generous_and_enabled --locked
cargo test -p rust-junosmcp cli::tests::defaults --locked
cargo test -p rust-srxmcp cli::tests::secure_defaults --locked
```

Expected: compilation fails because `max_sessions_per_token` does not exist.

- [ ] **Step 3: Add the shared configuration field and startup logging**

Add after `max_sessions`:

```rust
/// Max concurrent MCP sessions per bearer token. `0` disables.
pub max_sessions_per_token: usize,
```

Add to `Default` and `log_effective`:

```rust
max_sessions_per_token: 16,
```

```rust
max_sessions_per_token = self.max_sessions_per_token,
```

- [ ] **Step 4: Add the Junos and SRX clap controls**

Junos:

```rust
/// Max concurrent MCP sessions per bearer token. 0 = unlimited.
#[arg(long, env = "JMCP_MAX_SESSIONS_PER_TOKEN", default_value_t = 16)]
pub max_sessions_per_token: usize,
```

SRX:

```rust
/// Max concurrent MCP sessions per bearer token. 0 = unlimited.
#[arg(
    long,
    env = "JMCP_SRX_MAX_SESSIONS_PER_TOKEN",
    default_value_t = 16
)]
pub max_sessions_per_token: usize,
```

- [ ] **Step 5: Wire the new field into both `LimitsConfig` literals**

In both `main.rs` files add immediately after `max_sessions`:

```rust
max_sessions_per_token: args.max_sessions_per_token,
```

- [ ] **Step 6: Run GREEN tests, strict lint, and commit**

Run the three focused commands from Step 2, then:

```bash
cargo clippy -p rust-junosmcp-limits -p rust-junosmcp -p rust-srxmcp --all-targets -- -D warnings
git diff --check
```

Commit:

```bash
git add rust-junosmcp-limits/src/config.rs rust-junosmcp/src/cli.rs rust-junosmcp/src/main.rs rust-srxmcp/src/cli.rs rust-srxmcp/src/main.rs
git commit -m "feat(#148): configure per-token session caps"
```

---

### Task 2: Atomic Token Session Reservation State

**Files:**
- Modify: `rust-junosmcp-limits/src/session.rs`

**Interfaces:**
- Consumes: `LimitsConfig::max_sessions_per_token`, rmcp `SessionId`, and existing `SessionTracker::unregister`/`reap` paths.
- Produces: `TokenSessionCapacity`, `TokenSessionReservation`, `SessionTracker::try_reserve_token`, `SessionTracker::active_for_token`, and reservation commit/unregister semantics for Task 3.

- [ ] **Step 1: Write failing reservation and cleanup tests**

Add:

```rust
#[test]
fn token_reservations_enforce_isolation_and_drop_rollback() {
    let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
        max_sessions_per_token: 1,
        ..Default::default()
    }));
    let alice = tracker.try_reserve_token("alice".to_owned()).unwrap().unwrap();
    let full = tracker.try_reserve_token("alice".to_owned()).unwrap_err();
    assert_eq!(full, TokenSessionCapacity { current: 1, max: 1 });
    let bob = tracker.try_reserve_token("bob".to_owned()).unwrap().unwrap();
    assert_eq!(tracker.active_for_token("alice"), 1);
    assert_eq!(tracker.active_for_token("bob"), 1);
    drop(alice);
    drop(bob);
    assert_eq!(tracker.active_for_token("alice"), 0);
    assert_eq!(tracker.active_for_token("bob"), 0);
    assert_eq!(tracker.token_population_len(), 0);
}

#[test]
fn committed_token_reservation_releases_on_unregister_once() {
    let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
        max_sessions_per_token: 1,
        ..Default::default()
    }));
    let session = id("session-a");
    let reservation = tracker.try_reserve_token("alice".to_owned()).unwrap().unwrap();
    assert!(reservation.commit(session.clone()));
    assert_eq!(tracker.active_for_token("alice"), 1);
    tracker.unregister(&session);
    tracker.unregister(&session);
    assert_eq!(tracker.active_for_token("alice"), 0);
    assert_eq!(tracker.token_population_len(), 0);
}

#[test]
fn duplicate_session_binding_keeps_first_owner_and_rolls_back_second() {
    let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
        max_sessions_per_token: 2,
        ..Default::default()
    }));
    let session = id("duplicate");
    assert!(tracker.try_reserve_token("alice".to_owned()).unwrap().unwrap().commit(session.clone()));
    assert!(!tracker.try_reserve_token("bob".to_owned()).unwrap().unwrap().commit(session.clone()));
    assert_eq!(tracker.active_for_token("alice"), 1);
    assert_eq!(tracker.active_for_token("bob"), 0);
    tracker.unregister(&session);
    assert_eq!(tracker.active_for_token("alice"), 0);
}

#[test]
fn zero_disables_token_session_tracking() {
    let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
        max_sessions_per_token: 0,
        ..Default::default()
    }));
    assert!(tracker.try_reserve_token("alice".to_owned()).unwrap().is_none());
    assert_eq!(tracker.token_population_len(), 0);
}
```

- [ ] **Step 2: Run focused tests to verify RED**

```bash
cargo test -p rust-junosmcp-limits token_reservations_enforce_isolation_and_drop_rollback --locked
cargo test -p rust-junosmcp-limits committed_token_reservation_releases_on_unregister_once --locked
cargo test -p rust-junosmcp-limits duplicate_session_binding_keeps_first_owner_and_rolls_back_second --locked
cargo test -p rust-junosmcp-limits zero_disables_token_session_tracking --locked
```

Expected: compilation fails on missing token-session types and methods.

- [ ] **Step 3: Add the token state and capacity result**

```rust
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct TokenSessionState {
    counts: HashMap<String, usize>,
    sessions: HashMap<SessionId, String>,
    pending_reservations: usize,
    created_unbound: HashSet<SessionId>,
    closed_before_bind: HashSet<SessionId>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TokenSessionCapacity {
    pub(crate) current: usize,
    pub(crate) max: usize,
}
```

Add and initialize `SessionTracker` fields:

```rust
max_sessions_per_token: usize,
token_sessions: Mutex<TokenSessionState>,
```

```rust
max_sessions_per_token: cfg.max_sessions_per_token,
token_sessions: Mutex::new(TokenSessionState::default()),
```

Add helpers:

```rust
fn token_state(&self) -> std::sync::MutexGuard<'_, TokenSessionState> {
    self.token_sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn decrement_token(state: &mut TokenSessionState, token: &str) {
    let remove = match state.counts.get_mut(token) {
        Some(count) if *count > 1 => {
            *count -= 1;
            false
        }
        Some(_) => true,
        None => false,
    };
    if remove {
        state.counts.remove(token);
    }
}

fn complete_pending_reservation(state: &mut TokenSessionState) {
    debug_assert!(state.pending_reservations > 0);
    state.pending_reservations -= 1;
    if state.pending_reservations == 0 {
        state.created_unbound.clear();
        state.closed_before_bind.clear();
    }
}
```

- [ ] **Step 4: Implement the owned reservation**

```rust
pub(crate) struct TokenSessionReservation {
    tracker: Arc<SessionTracker>,
    token: Option<String>,
}

impl TokenSessionReservation {
    pub(crate) fn commit(mut self, id: SessionId) -> bool {
        let token = self.token.as_ref().expect("uncommitted reservation").clone();
        let mut state = self.tracker.token_state();
        if state.sessions.contains_key(&id) {
            tracing::warn!(session_id = %id, token = %token, "duplicate token session binding");
            drop(state);
            return false;
        }
        if state.closed_before_bind.remove(&id) {
            tracing::warn!(session_id = %id, token = %token, "token session closed before binding");
            drop(state);
            return false;
        }
        if !state.created_unbound.remove(&id) {
            tracing::warn!(session_id = %id, token = %token, "token session was not recorded at creation");
            drop(state);
            return false;
        }
        state.sessions.insert(id, token);
        SessionTracker::complete_pending_reservation(&mut state);
        self.token = None;
        true
    }
}

impl Drop for TokenSessionReservation {
    fn drop(&mut self) {
        let Some(token) = self.token.take() else {
            return;
        };
        let mut state = self.tracker.token_state();
        SessionTracker::decrement_token(&mut state, &token);
        SessionTracker::complete_pending_reservation(&mut state);
    }
}
```

The duplicate, closed-before-bind, and unrecorded-ID branches must drop their
mutex guards before returning so `Drop` can reacquire the token-state mutex.
Commit and unregister coordinate entirely under that mutex: commit-first
creates a binding that unregister subsequently removes, while unregister-first
moves a known-created ID to the transient closed set and makes commit roll back.
Commit intentionally does not consult global activity because #151 permits a
live inner session whose best-effort global registration was rejected.

- [ ] **Step 5: Implement reservation, query, and unregister cleanup**

```rust
pub(crate) fn try_reserve_token(
    self: &Arc<Self>,
    token: String,
) -> Result<Option<TokenSessionReservation>, TokenSessionCapacity> {
    if self.max_sessions_per_token == 0 {
        return Ok(None);
    }
    let mut state = self.token_state();
    let current = state.counts.get(&token).copied().unwrap_or(0);
    if current >= self.max_sessions_per_token {
        return Err(TokenSessionCapacity { current, max: self.max_sessions_per_token });
    }
    state.counts.insert(token.clone(), current + 1);
    state.pending_reservations += 1;
    drop(state);
    Ok(Some(TokenSessionReservation {
        tracker: self.clone(),
        token: Some(token),
    }))
}

pub(crate) fn note_session_created(&self, id: &SessionId) {
    let mut state = self.token_state();
    if state.pending_reservations > 0 {
        state.created_unbound.insert(id.clone());
    }
}

#[cfg(test)]
pub(crate) fn active_for_token(&self, token: &str) -> usize {
    self.token_state().counts.get(token).copied().unwrap_or(0)
}

#[cfg(test)]
fn token_population_len(&self) -> usize {
    self.token_state().counts.len()
}
```

Extend `unregister` independently of global activity removal:

```rust
let mut state = self.token_state();
if let Some(token) = state.sessions.remove(id) {
    Self::decrement_token(&mut state, &token);
} else if state.created_unbound.remove(id) {
    state.closed_before_bind.insert(id.clone());
}
```

Every successful nonzero-cap reservation increments the token count and pending
count atomically. `LimitedSessionManager::create_session` must call
`note_session_created` immediately after inner creation and before best-effort
global `try_register`. Successful commit and reservation `Drop` use the same
pending completion helper, which clears both transient sets when the pending
wave reaches zero. Unknown/repeated unregister IDs do not grow state, and the
combined transient cardinality is bounded by actual creation notes. With cap
zero or no pending reservation, creation noting and unregister cannot grow this
state.

- [ ] **Step 6: Add and pass reap cleanup coverage**

```rust
#[test]
fn reaped_session_unregister_releases_token_slot() {
    let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
        max_sessions: 10,
        max_sessions_per_token: 1,
        session_idle_timeout_secs: 1,
        ..Default::default()
    }));
    let base = Instant::now();
    let session = id("idle-token-session");
    assert!(tracker.try_register(session.clone(), base));
    assert!(tracker.try_reserve_token("alice".to_owned()).unwrap().unwrap().commit(session.clone()));
    for expired in tracker.reap(base + Duration::from_secs(2)) {
        tracker.unregister(&expired);
    }
    assert_eq!(tracker.active_for_token("alice"), 0);
    assert_eq!(tracker.active(), 0);
}
```

Run:

```bash
cargo test -p rust-junosmcp-limits session::tests --locked
cargo clippy -p rust-junosmcp-limits --all-targets -- -D warnings
git diff --check
```

- [ ] **Step 7: Commit tracker behavior**

```bash
git add rust-junosmcp-limits/src/session.rs
git commit -m "feat(#148): track sessions per token"
```

---

### Task 3: Middleware Admission, Response Binding, and Cancellation

**Files:**
- Modify: `rust-junosmcp-limits/src/concurrency.rs`

**Interfaces:**
- Consumes: `SessionTracker::try_reserve_token`, `TokenSessionCapacity`, `TokenSessionReservation::commit`, `CallerCtx`, and rmcp's `Mcp-Session-Id` response header.
- Produces: Race-free `token_session_cap` admission and response-to-session binding shared by both binaries.

- [ ] **Step 1: Add initialize request and state helpers**

```rust
fn initialize_request(token: &str) -> Request<Body> {
    let mut request = Request::builder()
        .method(axum::http::Method::POST)
        .uri("/mcp")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "limits-test", "version": "1"}
            }
        }).to_string()))
        .unwrap();
    request.extensions_mut().insert(ctx(token));
    request
}

fn token_session_state(max: usize) -> (ConcurrencyState, Arc<SessionTracker>) {
    let cfg = LimitsConfig {
        max_inflight_requests: 0,
        max_inflight_requests_per_token: 0,
        max_inflight_requests_per_router: 0,
        max_sessions: 0,
        max_sessions_per_token: max,
        ..Default::default()
    };
    let tracker = Arc::new(SessionTracker::new(&cfg));
    (ConcurrencyState::new(&cfg, Some(tracker.clone())), tracker)
}
```

- [ ] **Step 2: Write the failing saturation/isolation/binding test**

```rust
#[tokio::test]
async fn per_token_session_cap_binds_response_and_isolates_tokens() {
    let (state, tracker) = token_session_state(1);
    let app = Router::new()
        .route(
            "/mcp",
            post(|axum::Extension(caller): axum::Extension<CallerCtx>| async move {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("mcp-session-id", format!("{}-session", caller.token_name))
                    .body(Body::empty())
                    .unwrap()
            }),
        )
        .layer(axum::middleware::from_fn_with_state(state, concurrency_middleware));

    let first = app.clone().oneshot(initialize_request("alice")).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    drop(first);

    let shed = app.clone().oneshot(initialize_request("alice")).await.unwrap();
    assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(shed.headers().get("retry-after").unwrap(), "1");
    assert_eq!(shed.headers().get("content-type").unwrap(), "application/json");
    let body = axum::body::to_bytes(shed.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"error": "overloaded", "limit": "token_session_cap"})
    );

    let bob = app.clone().oneshot(initialize_request("bob")).await.unwrap();
    assert_eq!(bob.status(), StatusCode::OK);
    tracker.unregister(&Arc::from("alice-session"));
    let alice_again = app.oneshot(initialize_request("alice")).await.unwrap();
    assert_eq!(alice_again.status(), StatusCode::OK);
}
```

- [ ] **Step 3: Write failing rollback and cancellation tests**

Add `failed_initialize_releases_token_session_reservation`: its handler returns
500 without `Mcp-Session-Id`, then a second same-token initialize must reach the
handler, and `tracker.active_for_token("alice")` must return 0 after each failure.

Add `cancelled_initialize_releases_token_session_reservation`: its handler
signals entry and waits on `Notify`; abort the first `oneshot`, require the join
to report cancellation within `TEST_TIMEOUT`, then prove a second same-token
request enters and completes. Bound every wait and join with `TEST_TIMEOUT`.

- [ ] **Step 4: Run the tests to verify RED**

```bash
cargo test -p rust-junosmcp-limits per_token_session_cap_binds_response_and_isolates_tokens --locked -- --nocapture
cargo test -p rust-junosmcp-limits failed_initialize_releases_token_session_reservation --locked -- --nocapture
cargo test -p rust-junosmcp-limits cancelled_initialize_releases_token_session_reservation --locked -- --nocapture
```

Expected: Alice is admitted twice and rollback/cancellation accounting assertions fail.

- [ ] **Step 5: Reserve before rmcp and shed at capacity**

At middleware entry add:

```rust
let session_creating = is_session_creating(&req);
let mut token_session_reservation = None;
```

After the existing global-session early check add:

```rust
if session_creating {
    if let (Some(tracker), Some(ctx)) = (
        state.sessions.as_ref(),
        req.extensions().get::<CallerCtx>(),
    ) {
        let token = ctx.token_name.clone();
        match tracker.try_reserve_token(token.clone()) {
            Ok(reservation) => token_session_reservation = reservation,
            Err(capacity) => {
                tracing::warn!(
                    limit = "token_session_cap",
                    token = %token,
                    current = capacity.current,
                    max = capacity.max,
                    "request shed"
                );
                let mut response = overload_response("token_session_cap");
                response.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json"),
                );
                return response;
            }
        }
    }
}
```

- [ ] **Step 6: Commit successful response headers to the reservation**

Change the response local to mutable and add before `attach_permits`:

```rust
let mut resp = next.run(req).await;
if let Some(reservation) = token_session_reservation {
    if resp.status().is_success() {
        match resp.headers().get("mcp-session-id").and_then(|value| value.to_str().ok()) {
            Some(session_id) => {
                let id: rmcp::transport::common::server_side_http::SessionId = Arc::from(session_id);
                let _ = reservation.commit(id);
            }
            None => tracing::warn!(
                limit = "token_session_cap",
                "successful initialize candidate returned no valid session id"
            ),
        }
    }
}
```

The reservation drops on non-success, missing/malformed header, middleware
error, or cancellation. Keep request permits attached to the response body.

- [ ] **Step 7: Run GREEN limits verification and commit**

```bash
cargo test -p rust-junosmcp-limits concurrency::tests --locked -- --nocapture
cargo test -p rust-junosmcp-limits --locked
cargo clippy -p rust-junosmcp-limits --all-targets -- -D warnings
git diff --check
git add rust-junosmcp-limits/src/concurrency.rs
git commit -m "feat(#148): enforce token session admission"
```

---

### Task 4: Real Junos and SRX Endpoint Parity

**Files:**
- Modify: `rust-junosmcp/tests/common/mod.rs`
- Modify: `rust-junosmcp/tests/http_limits.rs`
- Modify: `rust-srxmcp/tests/common/mod.rs`
- Modify: `rust-srxmcp/tests/http_limits.rs`

**Interfaces:**
- Consumes: Both binaries' CLI wiring, real auth middleware, rmcp initialize/DELETE behavior, and shared session admission.
- Produces: Offline end-to-end proof that both endpoints bind, isolate, shed, close, and readmit token sessions.

- [ ] **Step 1: Add authenticated spawn-with-extra-args helpers**

In each common harness, make existing `spawn` delegate to:

```rust
pub fn spawn_with_auth_args(inv_path: &Path, tokens_path: &Path, extra: &[&str]) -> Server {
```

Build the existing authenticated argv as a mutable vector, append `extra`,
spawn the same binary, and call `finish_spawn`. Preserve every existing flag.
`spawn(inv_path, tokens_path)` must call
`spawn_with_auth_args(inv_path, tokens_path, &[])`.

- [ ] **Step 2: Add explicit session close helpers**

Add to each harness:

```rust
pub fn close_session(port: u16, bearer: &str, session_id: &str) -> u16 {
    let request = ureq::delete(&format!("http://127.0.0.1:{port}/mcp"))
        .set("Authorization", &format!("Bearer {bearer}"))
        .set("Mcp-Session-Id", session_id);
    match request.call() {
        Ok(response) => response.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(error) => panic!("transport error: {error}"),
    }
}
```

- [ ] **Step 3: Write failing Junos and SRX endpoint tests**

In each `tests/http_limits.rs`, use `TokenStoreFile::add` and `ScopeSet::Wildcard`
to mint exact token names `alice` and `bob`. Start the authenticated server with
`["--max-sessions-per-token", "1"]`. Use a TEST-NET placeholder inventory only.

The core test body for each binary is:

```rust
let alice_session = initialize(server.port, &alice);
let shed = http_post(server.port, Some(&alice), None, init_body());
assert_eq!(shed.code, 503);
assert_eq!(shed.body["limit"], "token_session_cap");

let bob_session = initialize(server.port, &bob);
assert!(matches!(close_session(server.port, &alice, &alice_session), 200 | 202 | 204));
let alice_again = initialize(server.port, &alice);

assert!(matches!(close_session(server.port, &alice, &alice_again), 200 | 202 | 204));
assert!(matches!(close_session(server.port, &bob, &bob_session), 200 | 202 | 204));
```

- [ ] **Step 4: Run parity and regression suites**

```bash
cargo test -p rust-junosmcp --test http_limits --locked -- --nocapture
cargo test -p rust-srxmcp --test http_limits --locked -- --nocapture
cargo test -p rust-junosmcp --test http_smoke --locked
cargo test -p rust-srxmcp --test http_smoke --locked
cargo clippy -p rust-junosmcp -p rust-srxmcp --all-targets -- -D warnings
git diff --check
```

Expected: all offline endpoint tests pass and no device is contacted.

- [ ] **Step 5: Commit endpoint parity coverage**

```bash
git add rust-junosmcp/tests/common/mod.rs rust-junosmcp/tests/http_limits.rs rust-srxmcp/tests/common/mod.rs rust-srxmcp/tests/http_limits.rs
git commit -m "test(#148): cover token session caps end to end"
```

---

### Task 5: Operator Documentation and Changelogs

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `rust-srxmcp/CHANGELOG.md`

**Interfaces:**
- Consumes: Final flag/env names, default, overload contract, auth behavior, and cleanup semantics.
- Produces: Operator-facing configuration and compatibility guidance.

- [ ] **Step 1: Run the failing documentation contract search**

```bash
rg -n "max-sessions-per-token|JMCP_MAX_SESSIONS_PER_TOKEN|JMCP_SRX_MAX_SESSIONS_PER_TOKEN|token_session_cap" README.md CHANGELOG.md rust-srxmcp/CHANGELOG.md
```

Expected: no matches before documentation changes.

- [ ] **Step 2: Extend README**

Add after global `--max-sessions`:

```markdown
| `--max-sessions-per-token` | `JMCP_MAX_SESSIONS_PER_TOKEN` / `JMCP_SRX_MAX_SESSIONS_PER_TOKEN` | 16 | Per-bearer-token session cap → **503** |
```

Add:

```markdown
Per-token session accounting uses the exact authenticated token name. Successful
initialization binds the returned `Mcp-Session-Id`; explicit close and idle/lifetime
reaping return the slot. Saturation returns
`{"error":"overloaded","limit":"token_session_cap"}`. The cap is skipped in
explicit no-auth mode because no token identity exists.
```

Remove `per-token session caps` from the deferred #131 list while retaining
metrics and RPS.

- [ ] **Step 3: Add both Unreleased changelog entries**

In the existing `### Added` section of root and SRX changelogs add:

```markdown
- **#148 - per-token MCP session caps.** Streamable HTTP now limits each exact
  bearer-token name to 16 live sessions by default (`0` disables), with atomic
  initialize admission, stable `token_session_cap` 503 responses, token isolation,
  and capacity returned on close or reap.
```

- [ ] **Step 4: Verify and commit documentation**

```bash
rg -n "max-sessions-per-token|JMCP_MAX_SESSIONS_PER_TOKEN|JMCP_SRX_MAX_SESSIONS_PER_TOKEN|token_session_cap" README.md CHANGELOG.md rust-srxmcp/CHANGELOG.md rust-junosmcp/src/cli.rs rust-srxmcp/src/cli.rs rust-junosmcp-limits/src/concurrency.rs
git diff --check
git add README.md CHANGELOG.md rust-srxmcp/CHANGELOG.md
git commit -m "docs(#148): document per-token session caps"
```

---

### Task 6: Full Offline Verification and Handoff Evidence

**Files:**
- Verify: every tracked file changed since the issue branch base.
- Modify: only a file causing a concrete verification failure, followed by a focused regression and correction commit.

**Interfaces:**
- Consumes: Complete #148 implementation and documentation.
- Produces: Merge-ready evidence covering behavior, compatibility, dependencies, security, and skipped live checks.

- [ ] **Step 1: Verify formatting and literal diffs**

```bash
cargo fmt --all --check
git diff --check
```

Expected: both exit 0. If formatting changes are required, run `cargo fmt --all`,
inspect the exact diff, rerun checks, and commit only that correction.

- [ ] **Step 2: Run strict workspace lint**

`just` is unavailable on this workstation, so run the underlying recipe:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: exit 0 with no warning.

- [ ] **Step 3: Run the complete locked workspace suite**

```bash
cargo test --workspace --locked
```

Expected: every selected test passes and all marked ignored real-device/network
tests remain ignored. Record actual passed/failed/ignored totals with a terse
aggregation if Cargo does not print a workspace total.

- [ ] **Step 4: Run both offline CLI help paths**

```bash
cargo run -p rust-junosmcp -- --help >/dev/null
cargo run -p rust-srxmcp -- --help >/dev/null
cargo run -q -p rust-junosmcp -- --help | rg -- "--max-sessions-per-token"
cargo run -q -p rust-srxmcp -- --help | rg -- "--max-sessions-per-token"
```

Expected: all exit 0 and both assertions show the new flag.

- [ ] **Step 5: Run the pinned security scan**

```bash
mise exec -- trivy fs --scanners vuln,misconfig,secret --exit-code 1 .
```

Expected repository baseline: Trivy may still report the pre-existing
`cmov 0.5.3` advisory and unchanged Dockerfile hardening findings. Compare every
finding to `origin/main`; do not claim the security/release gate is green when
the command exits 1, and do not widen #148 into unrelated remediation.

- [ ] **Step 6: Audit scope, dependencies, and compatibility**

```bash
git diff origin/main...HEAD --stat
git diff origin/main...HEAD -- Cargo.toml Cargo.lock
cargo tree -p rust-junosmcp-limits
git status --short --branch
```

Verify and record:

- no new dependency or resolved package version;
- no MCP schema, annotation, auth-scope, audit-field, device-I/O, or core workflow file changed;
- existing overload bodies/content types are unchanged;
- stdio and explicit no-auth behavior are unchanged except that no-auth skips the token-only cap by design;
- tracked state is clean.

- [ ] **Step 7: Record exclusions and risks**

The handoff must state:

```text
Skipped: just integration and all ignored real-device tests; CONFIRM_LAB_INTEGRATION was not set and no device was contacted.
Compatibility: stdio, MCP schemas, annotations, auth scopes, audit fields, existing overload formats, device I/O, and device lease semantics are unchanged.
Remaining risks: initialize candidates are POST requests without Mcp-Session-Id, so invalid requests may reserve briefly but release unless a successful response returns a valid session ID. External session-store restore remains outside current LocalSessionManager deployments. The separate global manager overshoot remains tracked by #151.
```

- [ ] **Step 8: Commit only a required verification correction**

If verification identifies a concrete defect, write a failing focused
regression, make the minimal correction, rerun focused and full checks, then:

```bash
git add -u
git commit -m "fix(#148): address final verification finding"
```

If no tracked correction is required, do not create an empty commit.
