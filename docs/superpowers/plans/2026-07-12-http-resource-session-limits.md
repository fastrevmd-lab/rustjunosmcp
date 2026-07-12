# HTTP Resource & Session Limits Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add configurable HTTP request-body, concurrency, and session limits to both `rust-junosmcp` and `rust-srxmcp` streamable-HTTP endpoints, enabled by default with generous values.

**Architecture:** A new shared crate `rust-junosmcp-limits` provides a `LimitsConfig`, a load-shedding concurrency middleware (global + per-token, permits attached to the SSE response body so they release at end-of-stream), a body-size layer helper, and a `LimitedSessionManager<S>` wrapper that adds a session count cap plus an idle/lifetime reaper over rmcp's `LocalSessionManager`. Both binaries wire the crate in identically.

**Tech Stack:** Rust 2021, axum 0.8, tower-http 0.6 (`limit` feature), rmcp 2.0, tokio, dashmap, tracing.

## Global Constraints

- **Crate versions (workspace deps, exact):** `axum = "0.8"`, `tower = "0.5"`, `tower-http = "0.6"`, `http = "1"`, `rmcp = "2"`, `tokio = "1"` (features `full`), `tokio-util = "0.7"` (feature `rt`), `tracing = "0.1"`, `thiserror = "2"`.
- **New workspace deps to add:** `dashmap = "6"`, `http-body = "1"`.
- **Parity:** every behavior must be identical on both `rust-junosmcp` and `rust-srxmcp`.
- **Defaults enabled, `0 = unlimited`** on every numeric limit.
- **Load-shed, never queue.** Over-limit → HTTP 503 + `Retry-After: 1`.
- **No new runtime deps beyond `dashmap`, `http-body`, `tokio-util`** (tracing-only observability; no Prometheus).
- **Rust/Python doc comments on public functions** (repo convention: doc comments on public items).
- **Every crate manifest field uses `*.workspace = true`** where the sibling `rust-junosmcp-auth/Cargo.toml` does.
- Commit after every task. Branch: `feat/131-http-resource-session-limits` (already checked out).

---

## File Structure

**New crate `rust-junosmcp-limits/`:**
- `Cargo.toml` — manifest, mirrors `rust-junosmcp-auth/Cargo.toml`.
- `src/lib.rs` — module wiring + re-exports.
- `src/config.rs` — `LimitsConfig` (all tunables, `Default`, startup log).
- `src/overload.rs` — `overload_response(limit_kind) -> Response` (503 + `Retry-After`).
- `src/concurrency.rs` — `ConcurrencyState`, `concurrency_middleware`, `GuardedBody`, `apply_body_limit`.
- `src/session.rs` — `SessionMeta`, `SessionTracker`, `LimitedSessionManager<S>`, reaper.

**Modified:**
- `Cargo.toml` (workspace) — add member + `dashmap`, `http-body` deps.
- `rust-junosmcp/Cargo.toml`, `rust-srxmcp/Cargo.toml` — add `rust-junosmcp-limits` dep.
- `rust-junosmcp/src/http_transport.rs`, `rust-srxmcp/src/http_transport.rs` — `serve()` gains `LimitsConfig`; wires the three layers + `LimitedSessionManager`.
- `rust-junosmcp/src/cli.rs`, `rust-srxmcp/src/cli.rs` — six clap flags + `LimitsConfig` assembly.
- `rust-junosmcp/src/main.rs`, `rust-srxmcp/src/main.rs` — pass `LimitsConfig` to `serve()`.
- `README.md` — "Resource limits" section.

**New tests:**
- `rust-junosmcp-limits/src/*` inline `#[cfg(test)]` modules (config, concurrency, session tracker).
- `rust-junosmcp/tests/http_limits.rs`, `rust-srxmcp/tests/http_limits.rs` — e2e body-limit + happy-path.

---

### Task 1: Scaffold `rust-junosmcp-limits` crate + `LimitsConfig`

**Files:**
- Create: `rust-junosmcp-limits/Cargo.toml`
- Create: `rust-junosmcp-limits/src/lib.rs`
- Create: `rust-junosmcp-limits/src/config.rs`
- Modify: `Cargo.toml` (workspace members + deps)

**Interfaces:**
- Produces: `rust_junosmcp_limits::LimitsConfig` with public fields
  `max_request_body_bytes: usize`, `max_inflight_requests: usize`,
  `max_inflight_requests_per_token: usize`, `max_sessions: usize`,
  `session_idle_timeout_secs: u64`, `session_max_lifetime_secs: u64`; `Default` impl;
  methods `pub fn idle_timeout(&self) -> Option<Duration>`,
  `pub fn max_lifetime(&self) -> Option<Duration>`, `pub fn log_effective(&self)`.

- [ ] **Step 1: Add workspace deps and member**

In `Cargo.toml` (workspace root), add to `members` and `[workspace.dependencies]`:

```toml
# members line becomes:
members          = ["rust-junosmcp", "rust-junosmcp-core", "rust-junosmcp-auth", "rust-srxmcp", "rust-srxmcp-core", "rust-junosmcp-limits"]
```

Add under `[workspace.dependencies]`:

```toml
dashmap          = "6"
http-body        = "1"
```

- [ ] **Step 2: Create the crate manifest**

`rust-junosmcp-limits/Cargo.toml`:

```toml
[package]
name        = "rust-junosmcp-limits"
version     = "0.1.0"
edition.workspace     = true
license.workspace     = true
repository.workspace  = true
authors.workspace     = true
description = "HTTP resource, concurrency, and session limits for rust-junosmcp / rust-srxmcp."

[dependencies]
axum         = { workspace = true }
tower-http   = { workspace = true, features = ["limit"] }
http         = { workspace = true }
http-body    = { workspace = true }
rmcp         = { version = "2", features = ["server", "transport-streamable-http-server"] }
rust-junosmcp-auth = { path = "../rust-junosmcp-auth" }
tokio        = { workspace = true }
tokio-util   = { workspace = true }
dashmap      = { workspace = true }
tracing      = { workspace = true }

[dev-dependencies]
tokio        = { workspace = true }
```

- [ ] **Step 3: Write the failing config test**

`rust-junosmcp-limits/src/config.rs`:

```rust
//! Tunable resource limits for the streamable-HTTP endpoints.

use std::time::Duration;

/// All HTTP resource / session limits. Every numeric field uses `0` as an
/// "unlimited / disabled" escape hatch.
#[derive(Debug, Clone)]
pub struct LimitsConfig {
    /// Max request body size in bytes before rejecting with 413. `0` disables.
    pub max_request_body_bytes: usize,
    /// Max concurrent in-flight requests across all callers. `0` disables.
    pub max_inflight_requests: usize,
    /// Max concurrent in-flight requests per bearer token. `0` disables.
    pub max_inflight_requests_per_token: usize,
    /// Max concurrent MCP sessions. `0` disables.
    pub max_sessions: usize,
    /// Idle timeout (seconds) after which a session is reaped. `0` disables.
    pub session_idle_timeout_secs: u64,
    /// Max session lifetime (seconds) after which it is reaped. `0` disables.
    pub session_max_lifetime_secs: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_request_body_bytes: 10 * 1024 * 1024,
            max_inflight_requests: 64,
            max_inflight_requests_per_token: 16,
            max_sessions: 128,
            session_idle_timeout_secs: 300,
            session_max_lifetime_secs: 3600,
        }
    }
}

impl LimitsConfig {
    /// Idle timeout as a `Duration`, or `None` when disabled (`0`).
    pub fn idle_timeout(&self) -> Option<Duration> {
        (self.session_idle_timeout_secs > 0).then(|| Duration::from_secs(self.session_idle_timeout_secs))
    }

    /// Max lifetime as a `Duration`, or `None` when disabled (`0`).
    pub fn max_lifetime(&self) -> Option<Duration> {
        (self.session_max_lifetime_secs > 0).then(|| Duration::from_secs(self.session_max_lifetime_secs))
    }

    /// Emit the effective configuration at startup.
    pub fn log_effective(&self) {
        tracing::info!(
            max_request_body_bytes = self.max_request_body_bytes,
            max_inflight_requests = self.max_inflight_requests,
            max_inflight_requests_per_token = self.max_inflight_requests_per_token,
            max_sessions = self.max_sessions,
            session_idle_timeout_secs = self.session_idle_timeout_secs,
            session_max_lifetime_secs = self.session_max_lifetime_secs,
            "http resource limits configured"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_generous_and_enabled() {
        let c = LimitsConfig::default();
        assert_eq!(c.max_request_body_bytes, 10 * 1024 * 1024);
        assert_eq!(c.max_inflight_requests, 64);
        assert_eq!(c.max_sessions, 128);
        assert_eq!(c.idle_timeout(), Some(Duration::from_secs(300)));
        assert_eq!(c.max_lifetime(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn zero_disables_timeouts() {
        let c = LimitsConfig { session_idle_timeout_secs: 0, session_max_lifetime_secs: 0, ..Default::default() };
        assert_eq!(c.idle_timeout(), None);
        assert_eq!(c.max_lifetime(), None);
    }
}
```

- [ ] **Step 4: Create `lib.rs` exposing config only (other modules added later)**

`rust-junosmcp-limits/src/lib.rs`:

```rust
//! HTTP resource, concurrency, and session limits for the streamable-HTTP
//! endpoints shared by `rust-junosmcp` and `rust-srxmcp`.

mod config;

pub use config::LimitsConfig;
```

- [ ] **Step 5: Run the config tests**

Run: `cargo test -p rust-junosmcp-limits --lib`
Expected: PASS (`defaults_are_generous_and_enabled`, `zero_disables_timeouts`).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock rust-junosmcp-limits/
git commit -m "feat(131): scaffold rust-junosmcp-limits crate with LimitsConfig"
```

---

### Task 2: Overload response + concurrency middleware + body limit

**Files:**
- Create: `rust-junosmcp-limits/src/overload.rs`
- Create: `rust-junosmcp-limits/src/concurrency.rs`
- Modify: `rust-junosmcp-limits/src/lib.rs`

**Interfaces:**
- Consumes: `LimitsConfig` (Task 1); `rust_junosmcp_auth::CallerCtx` (field `token_name: String`).
- Produces:
  - `overload_response(limit_kind: &'static str) -> axum::response::Response`
  - `ConcurrencyState` (Clone) with `pub fn new(cfg: &LimitsConfig, sessions: Option<Arc<SessionTracker>>) -> Self` — **NOTE:** `sessions` param typed `Option<Arc<crate::session::SessionTracker>>`, wired in Task 3; in this task pass a placeholder unit until Task 3 lands (see step 4).
  - `async fn concurrency_middleware(State<ConcurrencyState>, Request, Next) -> Response`
  - `fn apply_body_limit(router: axum::Router, cfg: &LimitsConfig) -> axum::Router`

- [ ] **Step 1: Write `overload.rs`**

```rust
//! Stable overload responses: HTTP 503 + `Retry-After`, load-shed semantics.

use axum::http::{header::RETRY_AFTER, StatusCode};
use axum::response::{IntoResponse, Response};

/// Seconds advertised in `Retry-After` on every shed response.
const RETRY_AFTER_SECS: u64 = 1;

/// Build a stable overload response for the given limit kind
/// (e.g. `"global_concurrency"`, `"token_concurrency"`, `"session_cap"`).
pub fn overload_response(limit_kind: &'static str) -> Response {
    let body = format!(r#"{{"error":"overloaded","limit":"{limit_kind}"}}"#);
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(RETRY_AFTER, RETRY_AFTER_SECS.to_string())],
        body,
    )
        .into_response()
}
```

- [ ] **Step 2: Write the failing concurrency test**

Create `rust-junosmcp-limits/src/concurrency.rs` with the implementation (step 3) plus this test module. First write the test so it fails to compile/pass:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use rust_junosmcp_auth::CallerCtx;
    use rust_junosmcp_auth::scope::ScopeSet; // adjust path if ScopeSet re-exported elsewhere
    use std::sync::Arc;
    use tokio::sync::Notify;
    use tower::ServiceExt; // oneshot

    fn ctx(name: &str) -> CallerCtx {
        CallerCtx { token_name: name.to_string(), routers: ScopeSet::all(), tools: ScopeSet::all() }
    }

    // A handler that blocks until `release` is notified, so we can pin permits.
    fn blocking_router(release: Arc<Notify>) -> Router {
        Router::new().route("/mcp", get(move || {
            let release = release.clone();
            async move { release.notified().await; "ok" }
        }))
    }

    #[tokio::test]
    async fn global_concurrency_sheds_over_limit() {
        let state = ConcurrencyState::new(
            &LimitsConfig { max_inflight_requests: 1, max_inflight_requests_per_token: 0, ..Default::default() },
            None,
        );
        let release = Arc::new(Notify::new());
        let app = blocking_router(release.clone())
            .layer(axum::middleware::from_fn_with_state(state, concurrency_middleware));

        // First request occupies the only permit (held on the blocked handler).
        let app2 = app.clone();
        let inflight = tokio::spawn(async move {
            app2.oneshot(Request::builder().uri("/mcp").body(Body::empty()).unwrap()).await.unwrap()
        });
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Second concurrent request must be shed with 503.
        let resp = app.clone()
            .oneshot(Request::builder().uri("/mcp").body(Body::empty()).unwrap())
            .await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers().get("retry-after").unwrap(), "1");

        // Release the first; its permit frees.
        release.notify_waiters();
        let first = inflight.await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        // A new request now succeeds (permit freed at end-of-body).
        // Drain the first response body first to release its GuardedBody permit.
        let _ = axum::body::to_bytes(first.into_body(), usize::MAX).await.unwrap();
    }

    #[tokio::test]
    async fn per_token_isolated() {
        let state = ConcurrencyState::new(
            &LimitsConfig { max_inflight_requests: 0, max_inflight_requests_per_token: 1, ..Default::default() },
            None,
        );
        let release = Arc::new(Notify::new());
        let app = blocking_router(release.clone())
            .layer(axum::middleware::from_fn_with_state(state, concurrency_middleware));

        // token "a" occupies its single per-token permit.
        let app_a = app.clone();
        let inflight = tokio::spawn(async move {
            let mut req = Request::builder().uri("/mcp").body(Body::empty()).unwrap();
            req.extensions_mut().insert(ctx("a"));
            app_a.oneshot(req).await.unwrap()
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // second "a" request is shed...
        let mut req_a2 = Request::builder().uri("/mcp").body(Body::empty()).unwrap();
        req_a2.extensions_mut().insert(ctx("a"));
        let resp_a2 = app.clone().oneshot(req_a2).await.unwrap();
        assert_eq!(resp_a2.status(), StatusCode::SERVICE_UNAVAILABLE);

        // ...but token "b" still has its own permit.
        release.notify_waiters();
        let _ = inflight.await.unwrap();
        let mut req_b = Request::builder().uri("/mcp").body(Body::empty()).unwrap();
        req_b.extensions_mut().insert(ctx("b"));
        let resp_b = app.oneshot(req_b).await.unwrap();
        assert_eq!(resp_b.status(), StatusCode::OK);
    }
}
```

> If the real `CallerCtx` construction or `ScopeSet` path differs, open
> `rust-junosmcp-auth/src/caller.rs` and `scope.rs` and match the exact
> constructor. `CallerCtx` fields are `token_name`, `routers`, `tools`.

- [ ] **Step 3: Write the concurrency implementation (top of `concurrency.rs`)**

```rust
//! Load-shedding concurrency middleware. Permits are attached to the response
//! body (`GuardedBody`) so they release at end-of-stream — rmcp runs the tool
//! lazily while the SSE body is polled, so a permit held only across the
//! response future would release too early.

use crate::config::LimitsConfig;
use crate::overload::overload_response;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use dashmap::DashMap;
use http_body::{Body as HttpBody, Frame, SizeHint};
use rust_junosmcp_auth::CallerCtx;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower_http::limit::RequestBodyLimitLayer;

/// Shared concurrency state, cheaply cloneable.
#[derive(Clone)]
pub struct ConcurrencyState {
    global: Arc<Semaphore>,
    max_global: usize,
    per_token: Arc<DashMap<String, Arc<Semaphore>>>,
    max_per_token: usize,
    sessions: Option<Arc<crate::session::SessionTracker>>,
}

impl ConcurrencyState {
    /// Build from config. `sessions` enables the `session_cap` early-shed.
    pub fn new(cfg: &LimitsConfig, sessions: Option<Arc<crate::session::SessionTracker>>) -> Self {
        let global_permits = if cfg.max_inflight_requests > 0 { cfg.max_inflight_requests } else { 1 };
        Self {
            global: Arc::new(Semaphore::new(global_permits)),
            max_global: cfg.max_inflight_requests,
            per_token: Arc::new(DashMap::new()),
            max_per_token: cfg.max_inflight_requests_per_token,
            sessions,
        }
    }

    fn token_sem(&self, token: &str) -> Arc<Semaphore> {
        self.per_token
            .entry(token.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.max_per_token.max(1))))
            .clone()
    }
}

/// Axum middleware enforcing global + per-token concurrency with load-shed.
pub async fn concurrency_middleware(
    State(state): State<ConcurrencyState>,
    req: Request,
    next: Next,
) -> Response {
    let mut permits: Vec<OwnedSemaphorePermit> = Vec::new();

    if state.max_global > 0 {
        match state.global.clone().try_acquire_owned() {
            Ok(p) => permits.push(p),
            Err(_) => {
                tracing::warn!(limit = "global_concurrency", max = state.max_global, "request shed");
                return overload_response("global_concurrency");
            }
        }
    }

    if state.max_per_token > 0 {
        if let Some(ctx) = req.extensions().get::<CallerCtx>() {
            let token = ctx.token_name.clone();
            let sem = state.token_sem(&token);
            match sem.try_acquire_owned() {
                Ok(p) => permits.push(p),
                Err(_) => {
                    tracing::warn!(limit = "token_concurrency", token = %token, max = state.max_per_token, "request shed");
                    return overload_response("token_concurrency"); // global permit drops here
                }
            }
        }
    }

    if let Some(tracker) = &state.sessions {
        if is_session_creating(&req) && tracker.at_capacity() {
            tracing::warn!(limit = "session_cap", "request shed");
            return overload_response("session_cap");
        }
    }

    let resp = next.run(req).await;
    attach_permits(resp, permits)
}

/// A session-creating request = POST without an `Mcp-Session-Id` header.
fn is_session_creating(req: &Request) -> bool {
    req.method() == axum::http::Method::POST && !req.headers().contains_key("mcp-session-id")
}

/// Apply the request-body size limit as the outermost concern. `0` disables.
pub fn apply_body_limit(router: axum::Router, cfg: &LimitsConfig) -> axum::Router {
    if cfg.max_request_body_bytes > 0 {
        router.layer(RequestBodyLimitLayer::new(cfg.max_request_body_bytes))
    } else {
        router
    }
}

/// Move the held permits into the response body so they release at end-of-stream.
fn attach_permits(resp: Response, permits: Vec<OwnedSemaphorePermit>) -> Response {
    if permits.is_empty() {
        return resp;
    }
    let (parts, body) = resp.into_parts();
    Response::from_parts(parts, Body::new(GuardedBody { inner: body, _permits: permits }))
}

/// Response body wrapper that owns concurrency permits until the body ends.
struct GuardedBody {
    inner: Body,
    _permits: Vec<OwnedSemaphorePermit>,
}

impl HttpBody for GuardedBody {
    type Data = axum::body::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // axum::body::Body is Unpin, so GuardedBody is Unpin.
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
```

- [ ] **Step 4: Temporarily stub `SessionTracker` so this task compiles standalone**

Task 3 replaces this. Add to the TOP of a new `rust-junosmcp-limits/src/session.rs`:

```rust
//! (placeholder — full implementation in Task 3)
pub struct SessionTracker;
impl SessionTracker {
    pub fn at_capacity(&self) -> bool { false }
}
```

Update `lib.rs`:

```rust
mod config;
mod concurrency;
mod overload;
mod session;

pub use config::LimitsConfig;
pub use concurrency::{apply_body_limit, concurrency_middleware, ConcurrencyState};
pub use overload::overload_response;
```

- [ ] **Step 5: Run tests to verify they fail, then pass**

Run: `cargo test -p rust-junosmcp-limits --lib concurrency`
Expected: after implementation compiles, PASS on `global_concurrency_sheds_over_limit` and `per_token_isolated`.

- [ ] **Step 6: Commit**

```bash
git add rust-junosmcp-limits/src/
git commit -m "feat(131): load-shedding concurrency middleware + body limit"
```

---

### Task 3: `SessionTracker` + `LimitedSessionManager` + reaper

**Files:**
- Modify: `rust-junosmcp-limits/src/session.rs` (replace the Task 2 stub)
- Modify: `rust-junosmcp-limits/src/lib.rs` (export session types)

**Interfaces:**
- Consumes: `LimitsConfig` (Task 1); rmcp `SessionManager` trait, `SessionId = Arc<str>`.
- Produces:
  - `SessionTracker` with `pub fn new(cfg: &LimitsConfig) -> Self`,
    `pub fn at_capacity(&self) -> bool`,
    `pub fn try_register(&self, id: SessionId, now: Instant) -> bool`,
    `pub fn touch(&self, id: &SessionId, now: Instant)`,
    `pub fn unregister(&self, id: &SessionId)`,
    `pub fn reap(&self, now: Instant) -> Vec<SessionId>`,
    `pub fn active(&self) -> usize`.
  - `LimitedSessionManager<S>` with `pub fn new(inner: S, cfg: &LimitsConfig) -> Arc<Self>`
    and `pub fn tracker(&self) -> Arc<SessionTracker>`; implements rmcp `SessionManager`.

- [ ] **Step 1: Write the failing `SessionTracker` tests**

Replace `session.rs` with the implementation (step 2) plus:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn id(s: &str) -> SessionId { Arc::from(s) }

    #[test]
    fn cap_enforced_and_gauge_accurate() {
        let t = SessionTracker::new(&LimitsConfig { max_sessions: 2, ..Default::default() });
        let now = Instant::now();
        assert!(t.try_register(id("a"), now));
        assert!(t.try_register(id("b"), now));
        assert_eq!(t.active(), 2);
        assert!(t.at_capacity());
        assert!(!t.try_register(id("c"), now)); // over cap
        assert_eq!(t.active(), 2);
        t.unregister(&id("a"));
        assert_eq!(t.active(), 1);
        assert!(!t.at_capacity());
    }

    #[test]
    fn reap_returns_idle_and_expired() {
        let t = SessionTracker::new(&LimitsConfig {
            max_sessions: 10,
            session_idle_timeout_secs: 60,
            session_max_lifetime_secs: 3600,
            ..Default::default()
        });
        let base = Instant::now();
        t.try_register(id("idle"), base);
        t.try_register(id("fresh"), base);
        // "fresh" gets touched recently; "idle" does not.
        let later = base + Duration::from_secs(120);
        t.touch(&id("fresh"), later);
        let expired = t.reap(later);
        assert!(expired.contains(&id("idle")));
        assert!(!expired.contains(&id("fresh")));
    }

    #[test]
    fn zero_disables_cap() {
        let t = SessionTracker::new(&LimitsConfig { max_sessions: 0, ..Default::default() });
        let now = Instant::now();
        for i in 0..1000 { assert!(t.try_register(id(&i.to_string()), now)); }
        assert!(!t.at_capacity());
    }
}
```

- [ ] **Step 2: Write the `SessionTracker` + `LimitedSessionManager` implementation**

```rust
//! Session count cap + idle/lifetime reaper layered over any rmcp
//! `SessionManager` (default `LocalSessionManager`).

use crate::config::LimitsConfig;
use dashmap::DashMap;
use futures::Stream;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::streamable_http_server::session::{
    RestoreOutcome, SessionManager,
};
use rmcp::transport::common::server_side_http::{ServerSseMessage, SessionId};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::task::AbortOnDropHandle;

/// Per-session activity metadata.
struct SessionMeta {
    created_at: Instant,
    last_active: Instant,
}

/// Tracks live sessions, enforces the count cap, and identifies stale sessions.
pub struct SessionTracker {
    active: AtomicUsize,
    max_sessions: usize,
    idle_timeout: Option<Duration>,
    max_lifetime: Option<Duration>,
    activity: DashMap<SessionId, SessionMeta>,
}

impl SessionTracker {
    /// Build from config.
    pub fn new(cfg: &LimitsConfig) -> Self {
        Self {
            active: AtomicUsize::new(0),
            max_sessions: cfg.max_sessions,
            idle_timeout: cfg.idle_timeout(),
            max_lifetime: cfg.max_lifetime(),
            activity: DashMap::new(),
        }
    }

    /// Current live session count.
    pub fn active(&self) -> usize { self.active.load(Ordering::Acquire) }

    /// True when at or above the configured cap (`0` = never).
    pub fn at_capacity(&self) -> bool {
        self.max_sessions > 0 && self.active() >= self.max_sessions
    }

    /// Reserve a slot and record the session. Returns false if over cap
    /// (race-free via fetch_add/rollback).
    pub fn try_register(&self, id: SessionId, now: Instant) -> bool {
        let prev = self.active.fetch_add(1, Ordering::AcqRel);
        if self.max_sessions > 0 && prev >= self.max_sessions {
            self.active.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        self.activity.insert(id, SessionMeta { created_at: now, last_active: now });
        true
    }

    /// Update last-active time for a session.
    pub fn touch(&self, id: &SessionId, now: Instant) {
        if let Some(mut m) = self.activity.get_mut(id) {
            m.last_active = now;
        }
    }

    /// Drop a session from tracking and decrement the gauge.
    pub fn unregister(&self, id: &SessionId) {
        if self.activity.remove(id).is_some() {
            self.active.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Session IDs that exceed the idle timeout or max lifetime as of `now`.
    pub fn reap(&self, now: Instant) -> Vec<SessionId> {
        let mut expired = Vec::new();
        for e in self.activity.iter() {
            let m = e.value();
            let idle = self.idle_timeout.is_some_and(|t| now.duration_since(m.last_active) >= t);
            let old = self.max_lifetime.is_some_and(|t| now.duration_since(m.created_at) >= t);
            if idle || old {
                expired.push(e.key().clone());
            }
        }
        expired
    }
}

/// Interval between reaper sweeps.
const REAP_PERIOD: Duration = Duration::from_secs(30);

/// Wraps an rmcp `SessionManager`, adding a session cap and idle/lifetime reaper.
pub struct LimitedSessionManager<S> {
    inner: Arc<S>,
    tracker: Arc<SessionTracker>,
    _reaper: AbortOnDropHandle<()>,
}

impl<S: SessionManager> LimitedSessionManager<S> {
    /// Build the wrapper and spawn the background reaper. Returns `Arc<Self>`
    /// so it can be handed directly to `StreamableHttpService::new`.
    pub fn new(inner: S, cfg: &LimitsConfig) -> Arc<Self> {
        let inner = Arc::new(inner);
        let tracker = Arc::new(SessionTracker::new(cfg));
        let reaper = {
            let inner = inner.clone();
            let tracker = tracker.clone();
            AbortOnDropHandle::new(tokio::spawn(async move {
                let mut tick = tokio::time::interval(REAP_PERIOD);
                loop {
                    tick.tick().await;
                    for id in tracker.reap(Instant::now()) {
                        let _ = inner.close_session(&id).await;
                        tracker.unregister(&id);
                        tracing::info!(session_id = %id, "session reaped");
                    }
                }
            }))
        };
        Arc::new(Self { inner, tracker, _reaper: reaper })
    }

    /// Shared tracker handle for the concurrency middleware's session-cap shed.
    pub fn tracker(&self) -> Arc<SessionTracker> { self.tracker.clone() }
}

impl<S: SessionManager> SessionManager for LimitedSessionManager<S> {
    type Error = S::Error;
    type Transport = S::Transport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        let (id, transport) = self.inner.create_session().await?;
        // Best-effort registration; the middleware early-shed is the primary cap gate.
        self.tracker.try_register(id.clone(), Instant::now());
        Ok((id, transport))
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner.initialize_session(id, message).await
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner.has_session(id).await
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        let r = self.inner.close_session(id).await;
        self.tracker.unregister(id);
        r
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner.create_stream(id, message).await
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner.accept_message(id, message).await
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner.create_standalone_stream(id).await
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner.resume(id, last_event_id).await
    }

    async fn restore_session(
        &self,
        id: SessionId,
    ) -> Result<RestoreOutcome<Self::Transport>, Self::Error> {
        let outcome = self.inner.restore_session(id.clone()).await?;
        if matches!(outcome, RestoreOutcome::Restored(_)) {
            self.tracker.try_register(id, Instant::now());
        }
        Ok(outcome)
    }
}
```

> **Add `futures` to `[dependencies]`** in `rust-junosmcp-limits/Cargo.toml`:
> `futures = "0.3"` (rmcp re-exports its `Stream` bound from `futures`; match the
> import used in rmcp's `session.rs`). If `Stream` is available via
> `rmcp::...`, prefer that path and skip the extra dep.

- [ ] **Step 3: Export session types in `lib.rs`**

```rust
pub use session::{LimitedSessionManager, SessionTracker};
```

Wire the real `SessionTracker` into `ConcurrencyState::new`'s `sessions` param (already typed `Option<Arc<SessionTracker>>` from Task 2).

- [ ] **Step 4: Run the tracker tests**

Run: `cargo test -p rust-junosmcp-limits --lib session`
Expected: PASS (`cap_enforced_and_gauge_accurate`, `reap_returns_idle_and_expired`, `zero_disables_cap`).

- [ ] **Step 5: Full crate build + clippy**

Run: `cargo clippy -p rust-junosmcp-limits --all-targets -- -D warnings`
Expected: clean. (Fixes any trait-signature mismatch against rmcp 2.0.0 — the associated `impl Stream` return types must match the trait exactly.)

- [ ] **Step 6: Commit**

```bash
git add rust-junosmcp-limits/
git commit -m "feat(131): session cap + idle/lifetime reaper (LimitedSessionManager)"
```

---

### Task 4: Wire limits into `rust-junosmcp` + e2e body-limit test

**Files:**
- Modify: `rust-junosmcp/Cargo.toml` (add dep)
- Modify: `rust-junosmcp/src/cli.rs` (six flags)
- Modify: `rust-junosmcp/src/http_transport.rs` (`serve` signature + wiring)
- Modify: `rust-junosmcp/src/main.rs` (assemble `LimitsConfig`, pass it)
- Create: `rust-junosmcp/tests/http_limits.rs`

**Interfaces:**
- Consumes: `rust_junosmcp_limits::{LimitsConfig, ConcurrencyState, concurrency_middleware, apply_body_limit, LimitedSessionManager}`.
- Produces: `serve(handler, addr, token_store, allowed_hosts, disable_host_check, limits, [tls]) -> Result<()>`.

- [ ] **Step 1: Add the dependency**

In `rust-junosmcp/Cargo.toml` `[dependencies]`:

```toml
rust-junosmcp-limits = { path = "../rust-junosmcp-limits" }
```

- [ ] **Step 2: Add CLI flags**

In `rust-junosmcp/src/cli.rs`, append to the `Cli` struct (before the closing brace):

```rust
    /// Max request body bytes before HTTP 413 (streamable-http). 0 = unlimited.
    #[arg(long, env = "JMCP_MAX_REQUEST_BODY_BYTES", default_value_t = 10 * 1024 * 1024)]
    pub max_request_body_bytes: usize,

    /// Max concurrent in-flight requests across all callers. 0 = unlimited.
    #[arg(long, env = "JMCP_MAX_INFLIGHT_REQUESTS", default_value_t = 64)]
    pub max_inflight_requests: usize,

    /// Max concurrent in-flight requests per bearer token. 0 = unlimited.
    #[arg(long, env = "JMCP_MAX_INFLIGHT_REQUESTS_PER_TOKEN", default_value_t = 16)]
    pub max_inflight_requests_per_token: usize,

    /// Max concurrent MCP sessions. 0 = unlimited.
    #[arg(long, env = "JMCP_MAX_SESSIONS", default_value_t = 128)]
    pub max_sessions: usize,

    /// Session idle timeout in seconds. 0 = disabled.
    #[arg(long, env = "JMCP_SESSION_IDLE_TIMEOUT_SECS", default_value_t = 300)]
    pub session_idle_timeout_secs: u64,

    /// Session max lifetime in seconds. 0 = disabled.
    #[arg(long, env = "JMCP_SESSION_MAX_LIFETIME_SECS", default_value_t = 3600)]
    pub session_max_lifetime_secs: u64,
```

- [ ] **Step 3: Update `serve()` signature and wiring**

In `rust-junosmcp/src/http_transport.rs`, add imports:

```rust
use rust_junosmcp_limits::{
    apply_body_limit, concurrency_middleware, ConcurrencyState, LimitedSessionManager, LimitsConfig,
};
```

Change the `serve` signature to add `limits: LimitsConfig` (before the `tls` cfg param):

```rust
pub async fn serve(
    handler: JmcpHandler,
    addr: SocketAddr,
    token_store: Option<Arc<ArcSwap<TokenStore>>>,
    allowed_hosts: Vec<String>,
    disable_host_check: bool,
    limits: LimitsConfig,
    #[cfg(feature = "tls")] tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
```

Replace the session-manager + router construction (the block from `let svc = StreamableHttpService::new(...)` through the `let app = if let Some(store) = token_store { ... }` block) with:

```rust
    limits.log_effective();

    let session_mgr = LimitedSessionManager::new(LocalSessionManager::default(), &limits);
    let conc = ConcurrencyState::new(&limits, Some(session_mgr.tracker()));

    let svc = StreamableHttpService::new(handler_factory, session_mgr, http_cfg);
    let rmcp_router = Router::new().nest_service("/mcp", svc);

    // Innermost added layer: concurrency (needs CallerCtx from auth, which runs first).
    let app = rmcp_router.layer(axum::middleware::from_fn_with_state(conc, concurrency_middleware));

    // Auth runs before concurrency so CallerCtx is present.
    let app = if let Some(store) = token_store {
        app.layer(axum::middleware::from_fn_with_state(AuthState { store }, auth_layer))
    } else {
        app
    };

    // Body limit outermost: reject oversized bodies before buffering.
    let app = apply_body_limit(app, &limits);
```

> `StreamableHttpService::new` accepts `Arc<S: SessionManager>`;
> `LimitedSessionManager::new` returns `Arc<LimitedSessionManager<LocalSessionManager>>`,
> so pass `session_mgr` directly (call `.tracker()` before the move).

- [ ] **Step 4: Pass `LimitsConfig` from `main.rs`**

In `rust-junosmcp/src/main.rs`, just before the `http_transport::serve(` call, build the config:

```rust
            let limits = rust_junosmcp_limits::LimitsConfig {
                max_request_body_bytes: args.max_request_body_bytes,
                max_inflight_requests: args.max_inflight_requests,
                max_inflight_requests_per_token: args.max_inflight_requests_per_token,
                max_sessions: args.max_sessions,
                session_idle_timeout_secs: args.session_idle_timeout_secs,
                session_max_lifetime_secs: args.session_max_lifetime_secs,
            };
```

And add `limits,` as the new argument in the `serve(...)` call, positioned before the `#[cfg(feature = "tls")] tls_cfg` argument:

```rust
            http_transport::serve(
                handler,
                addr,
                token_store,
                args.allowed_host.clone(),
                args.disable_host_check,
                limits,
                #[cfg(feature = "tls")]
                tls_cfg,
            )
            .await?;
```

- [ ] **Step 5: Write the e2e body-limit test**

Create `rust-junosmcp/tests/http_limits.rs`. Reuse the existing `common` harness (see `tests/http_smoke.rs` for the exact `spawn`/`http_post` signatures; mirror them):

```rust
//! e2e: request-body limit returns 413; happy-path still works with limits on.
mod common;
use common::{spawn_with_args, http_post_raw}; // see note below

#[test]
fn oversized_body_returns_413() {
    // Start the server with a tiny body cap so the test payload exceeds it.
    let server = spawn_with_args(&["--max-request-body-bytes", "512"]);
    let big = "x".repeat(4096);
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":"{big}"}}"#);
    let status = http_post_raw(server.port, &server.token, None, &body);
    assert_eq!(status, 413, "oversized body must be rejected before buffering");
}
```

> The existing `tests/common/mod.rs` `spawn()` may not take extra args. Add a
> `spawn_with_args(extra: &[&str])` helper (copy `spawn`, splice `extra` into the
> `Command` args) and an `http_post_raw` that returns just the HTTP status code.
> Match the existing harness's token-provisioning path exactly. If the harness
> already supports passing args, use it directly.

- [ ] **Step 6: Build, test, clippy**

Run: `cargo build -p rust-junosmcp`
Run: `cargo test -p rust-junosmcp --test http_limits`
Run: `cargo clippy -p rust-junosmcp --all-targets -- -D warnings`
Expected: PASS; 413 returned.

- [ ] **Step 7: Commit**

```bash
git add rust-junosmcp/
git commit -m "feat(131): wire HTTP limits into rust-junosmcp + e2e body-limit test"
```

---

### Task 5: Wire limits into `rust-srxmcp` + e2e test (parity)

**Files:**
- Modify: `rust-srxmcp/Cargo.toml` (add dep)
- Modify: `rust-srxmcp/src/cli.rs` (six flags — use `JMCP_SRX_*` env prefixes)
- Modify: `rust-srxmcp/src/http_transport.rs` (`serve_inner` signature + wiring)
- Modify: `rust-srxmcp/src/main.rs` (assemble `LimitsConfig`, pass it)
- Create: `rust-srxmcp/tests/http_limits.rs`

**Interfaces:**
- Consumes: same `rust_junosmcp_limits` items as Task 4.
- Produces: `serve`/`serve_inner` gain a `LimitsConfig` param, mirroring Task 4.

- [ ] **Step 1: Add the dependency**

In `rust-srxmcp/Cargo.toml` `[dependencies]`:

```toml
rust-junosmcp-limits = { path = "../rust-junosmcp-limits" }
```

- [ ] **Step 2: Add CLI flags** (mirror Task 4 step 2, with SRX env prefixes)

Append to the `rust-srxmcp/src/cli.rs` `Cli` struct:

```rust
    /// Max request body bytes before HTTP 413 (streamable-http). 0 = unlimited.
    #[arg(long, env = "JMCP_SRX_MAX_REQUEST_BODY_BYTES", default_value_t = 10 * 1024 * 1024)]
    pub max_request_body_bytes: usize,

    /// Max concurrent in-flight requests across all callers. 0 = unlimited.
    #[arg(long, env = "JMCP_SRX_MAX_INFLIGHT_REQUESTS", default_value_t = 64)]
    pub max_inflight_requests: usize,

    /// Max concurrent in-flight requests per bearer token. 0 = unlimited.
    #[arg(long, env = "JMCP_SRX_MAX_INFLIGHT_REQUESTS_PER_TOKEN", default_value_t = 16)]
    pub max_inflight_requests_per_token: usize,

    /// Max concurrent MCP sessions. 0 = unlimited.
    #[arg(long, env = "JMCP_SRX_MAX_SESSIONS", default_value_t = 128)]
    pub max_sessions: usize,

    /// Session idle timeout in seconds. 0 = disabled.
    #[arg(long, env = "JMCP_SRX_SESSION_IDLE_TIMEOUT_SECS", default_value_t = 300)]
    pub session_idle_timeout_secs: u64,

    /// Session max lifetime in seconds. 0 = disabled.
    #[arg(long, env = "JMCP_SRX_SESSION_MAX_LIFETIME_SECS", default_value_t = 3600)]
    pub session_max_lifetime_secs: u64,
```

- [ ] **Step 3: Update `serve` / `serve_inner` + wiring**

In `rust-srxmcp/src/http_transport.rs`, add the same import block as Task 4 step 3. Add `limits: LimitsConfig` to BOTH `serve`, `serve_with_tls`, and `serve_inner` signatures (thread it through the `serve`/`serve_with_tls` → `serve_inner` calls). In `serve_inner`, replace the session-manager + router block with the identical wiring from Task 4 step 3 (using `JmcpSrxHandler`).

- [ ] **Step 4: Pass `LimitsConfig` from `main.rs`** (mirror Task 4 step 4)

Build the `LimitsConfig` from `args.*` and add `limits` as the new arg to the `serve`/`serve_with_tls` call in `rust-srxmcp/src/main.rs`.

- [ ] **Step 5: Write the e2e test** (mirror Task 4 step 5)

Create `rust-srxmcp/tests/http_limits.rs` using the SRX `tests/common` harness; assert oversized body → 413.

- [ ] **Step 6: Build, test, clippy**

Run: `cargo build -p rust-srxmcp`
Run: `cargo test -p rust-srxmcp --test http_limits`
Run: `cargo clippy -p rust-srxmcp --all-targets -- -D warnings`
Expected: PASS; 413 returned.

- [ ] **Step 7: Commit**

```bash
git add rust-srxmcp/
git commit -m "feat(131): wire HTTP limits into rust-srxmcp + e2e body-limit test"
```

---

### Task 6: Documentation + follow-up tracking

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a "Resource limits" section to `README.md`**

Document, in a table: each flag, its env var (both `JMCP_*` and `JMCP_SRX_*`), default,
and that `0 = unlimited/disabled`. Document the overload contract (413 for body,
503 + `Retry-After: 1` for concurrency/session caps) and the two known limitations:
(a) session cap may briefly overshoot under concurrent `initialize` bursts (reaper
re-bounds it); (b) per-token *session* caps, per-router limits, Prometheus metrics,
and RPS limiting are deferred follow-ups on #131.

Exact content to insert (adapt heading depth to the README):

```markdown
## Resource limits (streamable-HTTP)

Both endpoints enforce configurable DoS guardrails, enabled by default with
generous values. Every numeric limit accepts `0` to disable it.

| Flag | Env (junos / srx) | Default | Effect |
|------|-------------------|---------|--------|
| `--max-request-body-bytes` | `JMCP_MAX_REQUEST_BODY_BYTES` / `JMCP_SRX_...` | 10 MiB | Reject larger bodies with **413** before buffering |
| `--max-inflight-requests` | `JMCP_MAX_INFLIGHT_REQUESTS` / `JMCP_SRX_...` | 64 | Global concurrency cap; over-limit → **503** |
| `--max-inflight-requests-per-token` | `..._PER_TOKEN` | 16 | Per-token concurrency cap → **503** |
| `--max-sessions` | `JMCP_MAX_SESSIONS` / `JMCP_SRX_...` | 128 | Session count cap → **503** |
| `--session-idle-timeout-secs` | `..._SESSION_IDLE_TIMEOUT_SECS` | 300 | Idle sessions reaped |
| `--session-max-lifetime-secs` | `..._SESSION_MAX_LIFETIME_SECS` | 3600 | Old sessions reaped |

Over-limit responses carry `Retry-After: 1`. Concurrency permits are released when
the response stream ends, so slow clients hold at most one slot each.

**Deferred (follow-ups on #131):** per-router limits composing with destructive
leases, per-token session caps, a Prometheus `/metrics` endpoint, and RPS
rate-limiting.
```

- [ ] **Step 2: Full workspace verification**

Run: `cargo test --workspace --all-targets --locked`
Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Run: `cargo audit`
Expected: all PASS / clean.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs(131): document HTTP resource & session limits"
```

- [ ] **Step 4: Post deferred-scope comment on #131**

After the PR is opened, comment on #131 listing the deferred items (per-router
limits, per-token session caps, Prometheus, RPS) so they remain tracked.

---

## Self-Review

**Spec coverage:**
- Body limit before buffering → Task 2 (`apply_body_limit`) + Task 4/5 wiring (outermost). ✅
- Global + per-token concurrency (load-shed) → Task 2 (`concurrency_middleware`). ✅
- Session cap + idle/lifetime + cleanup → Task 3 (`SessionTracker` + reaper). ✅
- Stable overload responses + retry guidance → Task 2 (`overload_response`, 503 + `Retry-After`). ✅
- Tracing observability → `tracing::warn!`/`info!` in Tasks 2–3; `log_effective` in Task 1. ✅
- Load-test items (oversized body, session flood, slow client via permit-on-body, cancellation, expensive calls) → crate-level tests (Tasks 2–3) + e2e body test (Tasks 4–5). ✅
- Document defaults/tuning → Task 6. ✅
- Deferred items explicitly recorded → Task 6 README + #131 comment. ✅

**Placeholder scan:** The Task 2 `SessionTracker` stub and Task 4/5 harness-helper
notes are intentional, bounded, and replaced/closed within the same or next task —
not open-ended TODOs. No "TBD"/"handle edge cases" placeholders remain.

**Type consistency:** `LimitsConfig` field names identical across config.rs,
`ConcurrencyState::new`, `SessionTracker::new`, and both `main.rs` builders.
`SessionId = Arc<str>` used consistently as the tracker key and reaper argument.
`ConcurrencyState::new(&LimitsConfig, Option<Arc<SessionTracker>>)` signature matches
its call site in Task 4/5 wiring. `serve()` gains `limits: LimitsConfig` in the same
parameter position (before the `tls` cfg arg) in both binaries.

**Known risk carried from spec:** `is_session_creating` uses a header heuristic
(POST without `Mcp-Session-Id`). If it proves unreliable during Task 4 e2e testing,
the session-cap early-shed can be dropped without affecting body/concurrency limits;
`SessionTracker` still bounds sessions via the reaper. Documented in Task 6.
