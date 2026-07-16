# Prometheus HTTP Metrics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in, unauthenticated Prometheus `/metrics` route to both streamable-HTTP binaries and report bounded-label resource-limit, session, reaper, and tool-duration metrics.

**Architecture:** `rust-junosmcp-limits` owns recorder installation, upkeep, rendering, and resource/session emitters; `rust-junosmcp-audit` emits tool-duration observations from `AuditScope`. Each binary adds one disabled-by-default CLI flag, installs one recorder before session state, builds the protected `/mcp` application unchanged, and only then merges the independent `/metrics` route.

**Tech Stack:** Rust 1.97.0, Axum 0.8, Tokio 1, rmcp 2, metrics 0.24.6, metrics-exporter-prometheus 0.18.3, Clap 4, ureq 2.

## Global Constraints

- Work only in `.worktrees/issue-149-prometheus-metrics` on branch `agent/issue-149-prometheus-metrics`.
- Use `metrics = "0.24.6"` and `metrics-exporter-prometheus = { version = "0.18.3", default-features = false }`.
- Do not enable the exporter HTTP-listener, push-gateway, protobuf, or crypto/TLS features; Axum remains the only listener.
- Junos uses `--enable-metrics` / `JMCP_ENABLE_METRICS`; SRX uses `--enable-metrics` / `JMCP_SRX_ENABLE_METRICS`; both default to `false`.
- Junos rejects metrics in stdio mode before inventory, file-transfer, or network initialization.
- Enabled metrics share the MCP TCP/TLS listener but bypass bearer auth, rmcp Host validation, body/concurrency/session middleware, and MCP audit handling.
- Recorder initialization is fail-fast and occurs before `SessionTracker` construction.
- Run `PrometheusHandle::run_upkeep()` every five seconds and once immediately before each render.
- Preserve these exact public names: `junosmcp_active_sessions`, `junosmcp_limit_hits_total`, `junosmcp_tool_duration_seconds`, and `junosmcp_sessions_reaped_total`.
- Preserve exact bounded labels: global `server`; `limit` plus `event`; `tool` plus `result`; and reaper `reason`.
- Never emit caller/token/router/session/correlation/error identifiers or arbitrary metadata as labels.
- Keep existing 413/503 status codes, bodies, `Retry-After`, MCP schemas, annotations, auth scopes, audit fields, timeouts, leases, TLS behavior, and default behavior unchanged.
- Do not add queue-time metrics because the current limiters load-shed and never queue.
- Do not fix the global session-cap race tracked by #151; report its failed best-effort registration as `event="session_registration_rejected"`.
- Use Cargo to update `Cargo.lock`; never hand-edit the lockfile.
- All tests remain offline. Do not run `just integration`, ignored tests, or contact a device.

## File Structure

- `Cargo.toml` — pins the two shared metrics dependencies.
- `Cargo.lock` — Cargo-generated resolution for the new dependencies.
- `rust-junosmcp-limits/src/prometheus.rs` — metric constants, recorder builder, upkeep owner, render router, fixed emit helpers, and component tests.
- `rust-junosmcp-limits/src/overload.rs` — authoritative 503 rejection emission.
- `rust-junosmcp-limits/src/concurrency.rs` — body-limit 413 response observation.
- `rust-junosmcp-limits/src/session.rs` — active gauge, manager-level cap event, expiration reason, and reaper metric.
- `rust-junosmcp-audit/src/scope.rs` — tool-duration histogram emission using the existing audit outcome.
- `rust-junosmcp/src/{cli.rs,cli_validate.rs,main.rs,http_transport.rs}` — Junos flag, refusal, propagation, recorder install, and route merge.
- `rust-srxmcp/src/{cli.rs,main.rs,http_transport.rs}` — SRX flag, propagation, recorder install, and route merge.
- `rust-junosmcp/tests/common/mod.rs` and `rust-srxmcp/tests/common/mod.rs` — reusable GET scrape helpers.
- `rust-junosmcp/tests/http_metrics.rs` and `rust-srxmcp/tests/http_metrics.rs` — subprocess endpoint, parity, privacy, and lifecycle coverage.
- `docs/METRICS.md`, `README.md`, `CHANGELOG.md`, and `rust-srxmcp/CHANGELOG.md` — operator contract and release notes.

---

### Task 1: Shared Prometheus Recorder and Render Runtime

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock` through Cargo
- Modify: `rust-junosmcp-limits/Cargo.toml`
- Modify: `rust-junosmcp-limits/src/lib.rs`
- Create: `rust-junosmcp-limits/src/prometheus.rs`

**Interfaces:**
- Consumes: Tokio runtime, Axum `Router`, and metrics-exporter-prometheus recorder APIs.
- Produces: `PrometheusRuntime::install(server: &str) -> Result<PrometheusRuntime, BuildError>` and `PrometheusRuntime::router(&self) -> Router`.
- Produces internally: `record_limit_hit`, `increment_active_sessions`, `decrement_active_sessions`, and `record_session_reaped`.

- [ ] **Step 1: Add exact dependency declarations**

Add to the root `[workspace.dependencies]`:

```toml
metrics                     = "0.24.6"
metrics-exporter-prometheus = { version = "0.18.3", default-features = false }
```

Add to `rust-junosmcp-limits/Cargo.toml`:

```toml
metrics                     = { workspace = true }
metrics-exporter-prometheus = { workspace = true }
```

Run:

```bash
cargo check -p rust-junosmcp-limits
```

Expected: PASS and Cargo updates `Cargo.lock`; `cargo tree -e features -p metrics-exporter-prometheus` contains no `http-listener` or `push-gateway` feature.

- [ ] **Step 2: Write the failing shared metric-contract test**

Add `mod prometheus;` plus the public re-export to `rust-junosmcp-limits/src/lib.rs`:

```rust
mod prometheus;

pub use prometheus::PrometheusRuntime;
```

Create `rust-junosmcp-limits/src/prometheus.rs` with this test module first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{header::CONTENT_TYPE, Request, StatusCode};
    use metrics::with_local_recorder;
    use tower::ServiceExt as _;

    fn sample_with<'a>(text: &'a str, prefix: &str, fragments: &[&str]) -> &'a str {
        text.lines()
            .find(|line| {
                line.starts_with(prefix)
                    && fragments.iter().all(|fragment| line.contains(fragment))
            })
            .unwrap_or_else(|| panic!("missing {prefix} with {fragments:?} in:\n{text}"))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn renders_exact_metric_contract_and_content_type() {
        let (recorder, handle) = test_recorder("junos");
        with_local_recorder(&recorder, || {
            describe_metrics();
            metrics::gauge!(ACTIVE_SESSIONS).set(2.0);
            record_limit_hit("global_concurrency", "request_rejected");
            record_session_reaped("idle");
            metrics::histogram!(
                TOOL_DURATION_SECONDS,
                "tool" => "get_router_list",
                "result" => "ok"
            )
            .record(0.25);
        });
        handle.run_upkeep();

        let response = metrics_router(handle)
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            PROMETHEUS_CONTENT_TYPE
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();

        sample_with(
            text,
            "junosmcp_active_sessions{",
            &["server=\"junos\"", "} 2"],
        );
        sample_with(
            text,
            "junosmcp_limit_hits_total{",
            &[
                "server=\"junos\"",
                "limit=\"global_concurrency\"",
                "event=\"request_rejected\"",
                "} 1",
            ],
        );
        sample_with(
            text,
            "junosmcp_sessions_reaped_total{",
            &["server=\"junos\"", "reason=\"idle\"", "} 1"],
        );
        sample_with(
            text,
            "junosmcp_tool_duration_seconds_bucket{",
            &[
                "server=\"junos\"",
                "tool=\"get_router_list\"",
                "result=\"ok\"",
                "le=\"0.01\"",
            ],
        );
        sample_with(
            text,
            "junosmcp_tool_duration_seconds_bucket{",
            &["le=\"1800\"", "tool=\"get_router_list\""],
        );
        assert!(!text.contains("junosmcp_limit_hits_total_total"));
    }
}
```

- [ ] **Step 3: Run the focused test and confirm red**

Run:

```bash
cargo test -p rust-junosmcp-limits prometheus::tests::renders_exact_metric_contract_and_content_type
```

Expected: FAIL to compile because `PrometheusRuntime`, the constants, builder, router, and emitter helpers are not defined.

- [ ] **Step 4: Implement the recorder, upkeep owner, render route, and fixed emitters**

Insert this production code above the test module in `rust-junosmcp-limits/src/prometheus.rs`:

```rust
use axum::extract::State;
use axum::http::{header::CONTENT_TYPE, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use metrics_exporter_prometheus::{BuildError, Matcher, PrometheusBuilder, PrometheusHandle};
use std::time::Duration;
use tokio::time::MissedTickBehavior;
use tokio_util::task::AbortOnDropHandle;

pub(crate) const ACTIVE_SESSIONS: &str = "junosmcp_active_sessions";
pub(crate) const LIMIT_HITS_TOTAL: &str = "junosmcp_limit_hits_total";
pub(crate) const TOOL_DURATION_SECONDS: &str = "junosmcp_tool_duration_seconds";
pub(crate) const SESSIONS_REAPED_TOTAL: &str = "junosmcp_sessions_reaped_total";
pub(crate) const PROMETHEUS_CONTENT_TYPE: &str =
    "text/plain; version=0.0.4; charset=utf-8";

const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);
const TOOL_DURATION_BUCKETS: &[f64] = &[
    0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0,
    300.0, 600.0, 1800.0,
];

pub struct PrometheusRuntime {
    handle: PrometheusHandle,
    _upkeep: AbortOnDropHandle<()>,
}

impl PrometheusRuntime {
    pub fn install(server: &str) -> Result<Self, BuildError> {
        let handle = prometheus_builder(server)?.install_recorder()?;
        describe_metrics();
        metrics::gauge!(ACTIVE_SESSIONS).set(0.0);

        let upkeep_handle = handle.clone();
        let upkeep = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut interval = tokio::time::interval(UPKEEP_INTERVAL);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                upkeep_handle.run_upkeep();
            }
        }));

        Ok(Self {
            handle,
            _upkeep: upkeep,
        })
    }

    pub fn router(&self) -> Router {
        metrics_router(self.handle.clone())
    }
}

fn prometheus_builder(server: &str) -> Result<PrometheusBuilder, BuildError> {
    PrometheusBuilder::new()
        .with_recommended_naming(false)
        .add_global_label("server", server)
        .set_buckets_for_metric(
            Matcher::Full(TOOL_DURATION_SECONDS.to_owned()),
            TOOL_DURATION_BUCKETS,
        )
}

fn describe_metrics() {
    metrics::describe_gauge!(
        ACTIVE_SESSIONS,
        "Current MCP sessions tracked by the HTTP session manager."
    );
    metrics::describe_counter!(
        LIMIT_HITS_TOTAL,
        "HTTP resource-limit rejections and manager-level session cap hits."
    );
    metrics::describe_histogram!(
        TOOL_DURATION_SECONDS,
        metrics::Unit::Seconds,
        "Elapsed MCP tool-handler duration by tool and terminal result."
    );
    metrics::describe_counter!(
        SESSIONS_REAPED_TOTAL,
        "MCP sessions removed by the idle/lifetime reaper."
    );
}

fn metrics_router(handle: PrometheusHandle) -> Router {
    Router::new()
        .route("/metrics", get(render_metrics))
        .with_state(handle)
}

async fn render_metrics(State(handle): State<PrometheusHandle>) -> Response {
    handle.run_upkeep();
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static(PROMETHEUS_CONTENT_TYPE),
        )],
        handle.render(),
    )
        .into_response()
}

pub(crate) fn record_limit_hit(limit: &'static str, event: &'static str) {
    metrics::counter!(
        LIMIT_HITS_TOTAL,
        "limit" => limit,
        "event" => event
    )
    .increment(1);
}

pub(crate) fn increment_active_sessions() {
    metrics::gauge!(ACTIVE_SESSIONS).increment(1.0);
}

pub(crate) fn decrement_active_sessions() {
    metrics::gauge!(ACTIVE_SESSIONS).decrement(1.0);
}

pub(crate) fn record_session_reaped(reason: &'static str) {
    metrics::counter!(SESSIONS_REAPED_TOTAL, "reason" => reason).increment(1);
}

#[cfg(test)]
pub(crate) fn test_recorder(
    server: &str,
) -> (
    metrics_exporter_prometheus::PrometheusRecorder,
    PrometheusHandle,
) {
    let recorder = prometheus_builder(server)
        .expect("fixed non-empty histogram buckets")
        .build_recorder();
    let handle = recorder.handle();
    (recorder, handle)
}
```

- [ ] **Step 5: Run focused tests and static checks**

Run:

```bash
cargo fmt --all
cargo test -p rust-junosmcp-limits prometheus::tests::renders_exact_metric_contract_and_content_type
cargo clippy -p rust-junosmcp-limits --all-targets -- -D warnings
```

Expected: PASS. The scrape contains the exact names, fixed `server` label, 10 ms and 1800 s buckets, and no doubled `_total`.

- [ ] **Step 6: Commit the shared runtime**

```bash
git add Cargo.toml Cargo.lock rust-junosmcp-limits/Cargo.toml \
  rust-junosmcp-limits/src/lib.rs rust-junosmcp-limits/src/prometheus.rs
git commit -m "feat(149): add shared Prometheus runtime"
```

---

### Task 2: Instrument Limits, Session Tracking, and Reaping

**Files:**
- Modify: `rust-junosmcp-limits/src/overload.rs`
- Modify: `rust-junosmcp-limits/src/concurrency.rs`
- Modify: `rust-junosmcp-limits/src/session.rs`

**Interfaces:**
- Consumes: Task 1 internal emitters.
- Preserves: `SessionTracker::reap(now) -> Vec<SessionId>` and every public limit/session interface.
- Produces internally: `ReapReason`, `ExpiredSession`, `reap_with_reasons`, and `finish_reap`.

- [ ] **Step 1: Write failing 503 and 413 metric tests**

Add to `rust-junosmcp-limits/src/overload.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overload_response_counts_each_fixed_limit_kind() {
        let (recorder, handle) = crate::prometheus::test_recorder("junos");
        metrics::with_local_recorder(&recorder, || {
            for limit in [
                "global_concurrency",
                "token_concurrency",
                "router_concurrency",
                "session_cap",
                "token_session_cap",
            ] {
                let _ = overload_response(limit);
            }
        });
        handle.run_upkeep();
        let text = handle.render();
        for limit in [
            "global_concurrency",
            "token_concurrency",
            "router_concurrency",
            "session_cap",
            "token_session_cap",
        ] {
            assert!(
                text.lines().any(|line| {
                    line.starts_with("junosmcp_limit_hits_total{")
                        && line.contains(&format!("limit=\"{limit}\""))
                        && line.contains("event=\"request_rejected\"")
                        && line.ends_with(" 1")
                }),
                "missing {limit} in:\n{text}"
            );
        }
    }
}
```

Change the existing `streamed_body_over_outer_limit_stays_413` test in
`rust-junosmcp-limits/src/concurrency.rs` to a current-thread test and wrap its
request in a local recorder:

```rust
#[tokio::test(flavor = "current_thread")]
async fn streamed_body_over_outer_limit_stays_413() {
    let (recorder, handle) = crate::prometheus::test_recorder("junos");
    let _guard = metrics::set_default_local_recorder(&recorder);

    let cfg = LimitsConfig {
        max_request_body_bytes: 8,
        max_inflight_requests: 0,
        max_inflight_requests_per_token: 0,
        max_inflight_requests_per_router: 1,
        max_sessions: 0,
        ..Default::default()
    };
    let app = Router::new().route("/mcp", post(|| async { "ok" })).layer(
        axum::middleware::from_fn_with_state(
            ConcurrencyState::new(&cfg, None),
            concurrency_middleware,
        ),
    );
    let app = apply_body_limit(app, &cfg);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(axum::http::Method::POST)
                .uri("/mcp")
                .body(Body::from("ok"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let stream = futures::stream::iter([Ok::<_, Infallible>(Bytes::from_static(
        b"more-than-eight-bytes",
    ))]);
    let request = Request::builder()
        .method(axum::http::Method::POST)
        .uri("/mcp")
        .body(Body::from_stream(stream))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    drop(_guard);
    handle.run_upkeep();
    let text = handle.render();
    let line = text
        .lines()
        .find(|line| line.starts_with("junosmcp_limit_hits_total{"))
        .expect("request-body counter sample");
    assert!(line.contains("limit=\"request_body\""));
    assert!(line.contains("event=\"request_rejected\""));
    assert!(line.ends_with(" 1"));
}
```

- [ ] **Step 2: Write failing session gauge, cap-race, and reason tests**

Add this test to the `session.rs` test module:

```rust
#[test]
fn session_metrics_cover_active_cap_and_reap_reasons() {
    let (recorder, handle) = crate::prometheus::test_recorder("junos");
    metrics::with_local_recorder(&recorder, || {
        let base = Instant::now();

        let capped = SessionTracker::new(&LimitsConfig {
            max_sessions: 1,
            ..Default::default()
        });
        assert!(capped.try_register(id("tracked"), base));
        assert!(!capped.try_register(id("race-loser"), base));
        capped.unregister(&id("tracked"));
        capped.unregister(&id("tracked"));

        let idle = SessionTracker::new(&LimitsConfig {
            max_sessions: 10,
            session_idle_timeout_secs: 60,
            session_max_lifetime_secs: 3600,
            ..Default::default()
        });
        assert!(idle.try_register(id("idle"), base));
        let expired = idle.reap_with_reasons(base + Duration::from_secs(120));
        assert_eq!(expired[0].reason, ReapReason::Idle);
        finish_reap(&idle, expired.into_iter().next().unwrap());

        let lifetime = SessionTracker::new(&LimitsConfig {
            max_sessions: 10,
            session_idle_timeout_secs: 60,
            session_max_lifetime_secs: 60,
            ..Default::default()
        });
        assert!(lifetime.try_register(id("both"), base));
        let expired = lifetime.reap_with_reasons(base + Duration::from_secs(120));
        assert_eq!(expired[0].reason, ReapReason::Lifetime);
        finish_reap(&lifetime, expired.into_iter().next().unwrap());
    });

    handle.run_upkeep();
    let text = handle.render();
    let active = text
        .lines()
        .find(|line| line.starts_with("junosmcp_active_sessions{"))
        .expect("active-session gauge");
    assert!(active.ends_with(" 0"));
    assert!(text.lines().any(|line| {
        line.starts_with("junosmcp_limit_hits_total{")
            && line.contains("limit=\"session_cap\"")
            && line.contains("event=\"session_registration_rejected\"")
            && line.ends_with(" 1")
    }));
    assert!(text.lines().any(|line| {
        line.starts_with("junosmcp_sessions_reaped_total{")
            && line.contains("reason=\"idle\"")
            && line.ends_with(" 1")
    }));
    assert!(text.lines().any(|line| {
        line.starts_with("junosmcp_sessions_reaped_total{")
            && line.contains("reason=\"lifetime\"")
            && line.ends_with(" 1")
    }));
}
```

- [ ] **Step 3: Run the focused tests and confirm red**

Run:

```bash
cargo test -p rust-junosmcp-limits overload_response_counts_each_fixed_limit_kind
cargo test -p rust-junosmcp-limits streamed_body_over_outer_limit_stays_413
cargo test -p rust-junosmcp-limits session_metrics_cover_active_cap_and_reap_reasons
```

Expected: the first two FAIL because rejection emitters are not called; the session test FAILS to compile because reason-aware reaping and session metric calls do not exist.

- [ ] **Step 4: Instrument the authoritative 503 and 413 points**

At the start of `overload_response` in `overload.rs`, add:

```rust
crate::prometheus::record_limit_hit(limit_kind, "request_rejected");
```

Add this private middleware immediately above `apply_body_limit` in
`concurrency.rs`:

```rust
async fn observe_body_limit_response(req: Request, next: Next) -> Response {
    let response = next.run(req).await;
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        crate::prometheus::record_limit_hit("request_body", "request_rejected");
    }
    response
}
```

Replace `apply_body_limit` with:

```rust
pub fn apply_body_limit(router: axum::Router, cfg: &LimitsConfig) -> axum::Router {
    if cfg.max_request_body_bytes > 0 {
        router
            .layer(RequestBodyLimitLayer::new(cfg.max_request_body_bytes))
            .layer(axum::middleware::from_fn(observe_body_limit_response))
    } else {
        router
    }
}
```

This orders the observer outside the body limiter while leaving the body limiter
outermost among behavioral middleware.

- [ ] **Step 5: Implement race-safe gauge deltas and reason-aware reaping**

Add these private types after `SessionMeta` in `session.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReapReason {
    Idle,
    Lifetime,
}

impl ReapReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Lifetime => "lifetime",
        }
    }
}

struct ExpiredSession {
    id: SessionId,
    reason: ReapReason,
}
```

In `try_register`, emit the manager-level event on rollback and increment the
gauge only after inserting the activity entry:

```rust
let prev = self.active.fetch_add(1, Ordering::AcqRel);
if self.max_sessions > 0 && prev >= self.max_sessions {
    self.active.fetch_sub(1, Ordering::AcqRel);
    crate::prometheus::record_limit_hit("session_cap", "session_registration_rejected");
    return false;
}
self.activity.insert(
    id,
    SessionMeta {
        created_at: now,
        last_active: now,
    },
);
crate::prometheus::increment_active_sessions();
true
```

In `unregister`, decrement the Prometheus gauge only in the branch where an
activity entry was actually removed:

```rust
if self.activity.remove(id).is_some() {
    self.active.fetch_sub(1, Ordering::AcqRel);
    crate::prometheus::decrement_active_sessions();
}
```

Preserve the public `reap` signature and add the reason-aware helper:

```rust
pub fn reap(&self, now: Instant) -> Vec<SessionId> {
    self.reap_with_reasons(now)
        .into_iter()
        .map(|expired| expired.id)
        .collect()
}

fn reap_with_reasons(&self, now: Instant) -> Vec<ExpiredSession> {
    let mut expired = Vec::new();
    for entry in self.activity.iter() {
        let meta = entry.value();
        let idle = self
            .idle_timeout
            .is_some_and(|timeout| now.duration_since(meta.last_active) >= timeout);
        let lifetime = self
            .max_lifetime
            .is_some_and(|timeout| now.duration_since(meta.created_at) >= timeout);
        let reason = if lifetime {
            Some(ReapReason::Lifetime)
        } else if idle {
            Some(ReapReason::Idle)
        } else {
            None
        };
        if let Some(reason) = reason {
            expired.push(ExpiredSession {
                id: entry.key().clone(),
                reason,
            });
        }
    }
    expired
}
```

Add the finalizer near `REAP_PERIOD`:

```rust
fn finish_reap(tracker: &SessionTracker, expired: ExpiredSession) {
    tracker.unregister(&expired.id);
    crate::prometheus::record_session_reaped(expired.reason.as_str());
    tracing::info!(session_id = %expired.id, "session reaped");
}
```

Replace the reaper loop body with:

```rust
for expired in tracker.reap_with_reasons(Instant::now()) {
    let _ = inner.close_session(&expired.id).await;
    finish_reap(&tracker, expired);
}
```

- [ ] **Step 6: Run the limits crate suite**

Run:

```bash
cargo fmt --all
cargo test -p rust-junosmcp-limits
cargo clippy -p rust-junosmcp-limits --all-targets -- -D warnings
```

Expected: PASS. Existing 413/503/session behavior tests remain unchanged; new output reports one event per rejection, idempotent gauge removal, idle reaping, and lifetime precedence.

- [ ] **Step 7: Commit limit/session instrumentation**

```bash
git add rust-junosmcp-limits/src/overload.rs \
  rust-junosmcp-limits/src/concurrency.rs \
  rust-junosmcp-limits/src/session.rs
git commit -m "feat(149): instrument HTTP limits and sessions"
```

---

### Task 3: Record Tool Duration from AuditScope

**Files:**
- Modify: `rust-junosmcp-audit/Cargo.toml`
- Modify: `rust-junosmcp-audit/src/scope.rs`

**Interfaces:**
- Consumes: the `metrics` facade and the existing `AuditOutcome`.
- Produces: `junosmcp_tool_duration_seconds{tool,result}` observations.
- Preserves: all current audit fields, redaction, correlation IDs, and terminal result strings.

- [ ] **Step 1: Add audit runtime and test-only exporter dependencies**

Add to `[dependencies]` in `rust-junosmcp-audit/Cargo.toml`:

```toml
metrics = { workspace = true }
```

Add to `[dev-dependencies]`:

```toml
metrics-exporter-prometheus = { workspace = true }
```

- [ ] **Step 2: Write the failing bounded-label outcome test**

Add to the `scope.rs` test module:

```rust
#[test]
fn tool_duration_metrics_cover_all_results_without_sensitive_labels() {
    use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};

    let recorder = PrometheusBuilder::new()
        .with_recommended_naming(false)
        .add_global_label("server", "junos")
        .set_buckets_for_metric(
            Matcher::Full("junosmcp_tool_duration_seconds".to_owned()),
            &[0.01, 1.0, 1800.0],
        )
        .unwrap()
        .build_recorder();
    let handle = recorder.handle();
    let caller = ctx("secret-token-name");

    metrics::with_local_recorder(&recorder, || {
        let mut ok = AuditScope::new(
            Some(&caller),
            "get_router_list",
            "read",
            vec!["secret-router".into()],
        );
        ok.succeed();

        let mut error = AuditScope::new(
            Some(&caller),
            "get_router_list",
            "read",
            vec!["secret-router".into()],
        );
        error.fail("secret-error-text");

        let mut denied = AuditScope::new(
            Some(&caller),
            "get_router_list",
            "read",
            vec!["secret-router".into()],
        );
        denied.deny("tool_scope");

        let _unsettled = AuditScope::new(
            Some(&caller),
            "get_router_list",
            "read",
            vec!["secret-router".into()],
        );
    });

    handle.run_upkeep();
    let text = handle.render();
    for result in ["ok", "error", "denied", "unsettled"] {
        assert!(
            text.lines().any(|line| {
                line.starts_with("junosmcp_tool_duration_seconds_bucket{")
                    && line.contains("server=\"junos\"")
                    && line.contains("tool=\"get_router_list\"")
                    && line.contains(&format!("result=\"{result}\""))
            }),
            "missing {result} in:\n{text}"
        );
    }
    for forbidden in [
        "secret-token-name",
        "secret-router",
        "secret-error-text",
        "caller=",
        "router=",
        "error=",
    ] {
        assert!(!text.contains(forbidden), "leaked {forbidden} in:\n{text}");
    }
}
```

- [ ] **Step 3: Run the focused test and confirm red**

Run:

```bash
cargo test -p rust-junosmcp-audit tool_duration_metrics_cover_all_results_without_sensitive_labels
```

Expected: FAIL because `AuditScope::drop` does not emit a histogram.

- [ ] **Step 4: Emit the histogram from the existing outcome mapping**

At the start of `AuditScope::drop`, capture elapsed once:

```rust
let elapsed = self.started.elapsed();
let duration_ms = elapsed.as_millis() as u64;
```

After the existing `result` match and before `tracing::info!`, add:

```rust
metrics::histogram!(
    "junosmcp_tool_duration_seconds",
    "tool" => self.tool,
    "result" => result
)
.record(elapsed.as_secs_f64());
```

Do not add `caller`, `routers`, `reason`, `error_kind`, `error`, `metadata`, or
`correlation_id` to this macro.

- [ ] **Step 5: Run audit and endpoint audit tests**

Run:

```bash
cargo fmt --all
cargo test -p rust-junosmcp-audit
cargo test -p rust-junosmcp --test audit
cargo test -p rust-srxmcp --test audit
cargo clippy -p rust-junosmcp-audit --all-targets -- -D warnings
```

Expected: PASS. Existing audit output assertions remain stable and all four histogram result values appear without sensitive labels.

- [ ] **Step 6: Commit audit timing**

```bash
git add rust-junosmcp-audit/Cargo.toml rust-junosmcp-audit/src/scope.rs
git commit -m "feat(149): record MCP tool duration metrics"
```

---

### Task 4: Expose and Verify the Junos Metrics Route

**Files:**
- Modify: `rust-junosmcp/src/cli.rs`
- Modify: `rust-junosmcp/src/cli_validate.rs`
- Modify: `rust-junosmcp/src/main.rs`
- Modify: `rust-junosmcp/src/http_transport.rs`
- Modify: `rust-junosmcp/tests/common/mod.rs`
- Create: `rust-junosmcp/tests/http_metrics.rs`

**Interfaces:**
- Consumes: `PrometheusRuntime` from Task 1 and instrumented metrics from Tasks 2–3.
- Changes: Junos `http_transport::serve` gains `enable_metrics: bool` immediately before `limits`.
- Produces: opt-in `/metrics` with global `server="junos"`.

- [ ] **Step 1: Write failing CLI parse and refusal tests**

Add this field after `disable_host_check` in `rust-junosmcp/src/cli.rs`:

```rust
/// Expose unauthenticated Prometheus metrics at /metrics (streamable-http only).
#[arg(long, env = "JMCP_ENABLE_METRICS")]
pub enable_metrics: bool,
```

Extend the `defaults` test:

```rust
assert!(!cli.enable_metrics);
let metrics = Cli::parse_from(["rust-junosmcp", "--enable-metrics"]);
assert!(metrics.enable_metrics);
```

Add the refusal variant in `cli_validate.rs`:

```rust
#[error("--enable-metrics requires --transport streamable-http")]
MetricsRequireHttp,
```

Add this test:

```rust
#[test]
fn metrics_refused_for_stdio_and_allowed_for_http() {
    assert_eq!(
        validate(&parse(&["--enable-metrics"])),
        Err(CliRefusal::MetricsRequireHttp)
    );
    assert!(validate(&parse(&[
        "-t",
        "streamable-http",
        "--allow-no-auth",
        "--enable-metrics",
    ]))
    .is_ok());
}
```

Run:

```bash
cargo test -p rust-junosmcp cli::tests::defaults
cargo test -p rust-junosmcp cli_validate::tests::metrics_refused_for_stdio_and_allowed_for_http
```

Expected: `defaults` PASS after the field is added; refusal test FAIL because validation still accepts stdio.

- [ ] **Step 2: Implement the early stdio refusal**

Before the existing `if cli.transport == Transport::Stdio { return Ok(()) }`
branch, add:

```rust
if cli.transport == Transport::Stdio && cli.enable_metrics {
    return Err(CliRefusal::MetricsRequireHttp);
}
```

Run:

```bash
cargo test -p rust-junosmcp cli_validate::tests
```

Expected: PASS, including all existing refusal-matrix tests.

- [ ] **Step 3: Write the Junos subprocess metrics tests and GET helper**

Add to `rust-junosmcp/tests/common/mod.rs`:

```rust
pub struct GetResult {
    pub code: u16,
    pub content_type: String,
    pub body: String,
}

pub fn http_get(
    port: u16,
    path: &str,
    bearer: Option<&str>,
    host: Option<&str>,
) -> GetResult {
    let mut request = ureq::get(&format!("http://127.0.0.1:{port}{path}"));
    if let Some(bearer) = bearer {
        request = request.set("Authorization", &format!("Bearer {bearer}"));
    }
    if let Some(host) = host {
        request = request.set("Host", host);
    }
    let response = match request.call() {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(error) => panic!("transport error: {error}"),
    };
    let code = response.status();
    let content_type = response.header("Content-Type").unwrap_or("").to_owned();
    let body = response.into_string().unwrap_or_default();
    GetResult {
        code,
        content_type,
        body,
    }
}
```

Create `rust-junosmcp/tests/http_metrics.rs`:

```rust
mod common;

use common::{
    binary_path, close_session, ensure_built, http_get, http_post, http_post_raw, initialize,
    spawn_with_auth_args, write_inv, write_tokens,
};
use rust_junosmcp_auth::{ScopeSet, TokenStoreFile};
use serde_json::json;
use std::process::Command;

fn fixture(extra: &[&str]) -> (
    tempfile::NamedTempFile,
    tempfile::NamedTempFile,
    rust_junosmcp_auth::token::Secret,
    common::Server,
) {
    let inventory = write_inv(
        r#"{"secret-router":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let tokens = write_tokens(r#"{"version":1,"tokens":[]}"#);
    let token = TokenStoreFile::add(
        tokens.path(),
        "secret-token-name",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
    )
    .unwrap();
    let server = spawn_with_auth_args(inventory.path(), tokens.path(), extra);
    (inventory, tokens, token, server)
}

#[test]
fn metrics_disabled_leaves_route_absent() {
    let (_inventory, _tokens, token, server) = fixture(&[]);
    let response = http_get(
        server.port,
        "/metrics",
        Some(token.expose()),
        None,
    );
    assert_eq!(response.code, 404);
}

#[test]
fn enabled_metrics_are_unauthenticated_bounded_and_live() {
    let (_inventory, _tokens, token, server) = fixture(&[
        "--enable-metrics",
        "--max-request-body-bytes",
        "512",
    ]);

    let initial = http_get(
        server.port,
        "/metrics",
        None,
        Some("untrusted.example"),
    );
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
            "params": {"name": "get_router_list", "arguments": {}}
        }),
    );
    assert_eq!(tool.code, 200, "offline tool failed: {:?}", tool.body);

    let big = "x".repeat(4096);
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":3,"method":"ping","params":"{big}"}}"#
    );
    assert_eq!(
        http_post_raw(server.port, token.expose(), None, &body),
        413
    );

    let scrape = http_get(server.port, "/metrics", None, None);
    assert_eq!(scrape.code, 200);
    assert!(scrape
        .body
        .contains("junosmcp_active_sessions{server=\"junos\"} 1"));
    assert!(scrape.body.lines().any(|line| {
        line.starts_with("junosmcp_tool_duration_seconds_bucket{")
            && line.contains("server=\"junos\"")
            && line.contains("tool=\"get_router_list\"")
            && line.contains("result=\"ok\"")
    }));
    assert!(scrape.body.lines().any(|line| {
        line.starts_with("junosmcp_limit_hits_total{")
            && line.contains("limit=\"request_body\"")
            && line.contains("event=\"request_rejected\"")
    }));
    for forbidden in [
        "secret-token-name",
        token.expose(),
        "secret-router",
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

#[test]
fn metrics_flag_is_rejected_before_stdio_startup() {
    ensure_built();
    let output = Command::new(binary_path())
        .arg("--enable-metrics")
        .output()
        .expect("run rust-junosmcp");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--enable-metrics requires --transport streamable-http"));
}
```

Run:

```bash
cargo test -p rust-junosmcp --test http_metrics
```

Expected: FAIL because the serve signature does not receive the flag and `/metrics` is not mounted.

- [ ] **Step 4: Thread the flag and merge the route after protected middleware**

In Junos `main.rs`, pass `args.enable_metrics` immediately before `limits`:

```rust
http_transport::serve(
    handler,
    addr,
    token_store,
    args.allowed_host.clone(),
    args.disable_host_check,
    args.enable_metrics,
    limits,
    #[cfg(feature = "tls")]
    tls_cfg,
)
.await?;
```

In `http_transport.rs`, import `PrometheusRuntime`, add `enable_metrics: bool`
immediately before `limits`, and install before session-manager construction:

```rust
let metrics_runtime = if enable_metrics {
    Some(
        PrometheusRuntime::install("junos")
            .context("initializing Prometheus metrics")?,
    )
} else {
    None
};

let session_mgr = LimitedSessionManager::new(LocalSessionManager::default(), &limits);
```

After `apply_body_limit` and before either TLS or plain serving branch, merge
only the independent metrics router:

```rust
let app = apply_body_limit(app, &limits);
let app = if let Some(runtime) = metrics_runtime.as_ref() {
    app.merge(runtime.router())
} else {
    app
};
```

The owned `metrics_runtime` remains in `serve` scope until the server future
returns, keeping upkeep alive.

- [ ] **Step 5: Run Junos tests and inspect route isolation**

Run:

```bash
cargo fmt --all
cargo test -p rust-junosmcp cli::tests
cargo test -p rust-junosmcp cli_validate::tests
cargo test -p rust-junosmcp --test http_metrics
cargo test -p rust-junosmcp --test http_limits
cargo test -p rust-junosmcp --test http_smoke
cargo clippy -p rust-junosmcp --all-targets -- -D warnings
```

Expected: PASS. `/metrics` is 200 without bearer and with a disallowed Host only when enabled; `/mcp` auth/Host tests remain green; stdio rejects the flag.

- [ ] **Step 6: Commit Junos wiring**

```bash
git add rust-junosmcp/src/cli.rs rust-junosmcp/src/cli_validate.rs \
  rust-junosmcp/src/main.rs rust-junosmcp/src/http_transport.rs \
  rust-junosmcp/tests/common/mod.rs rust-junosmcp/tests/http_metrics.rs
git commit -m "feat(149): expose Junos Prometheus metrics"
```

---

### Task 5: Expose and Verify the SRX Metrics Route

**Files:**
- Modify: `rust-srxmcp/src/cli.rs`
- Modify: `rust-srxmcp/src/main.rs`
- Modify: `rust-srxmcp/src/http_transport.rs`
- Modify: `rust-srxmcp/tests/common/mod.rs`
- Create: `rust-srxmcp/tests/http_metrics.rs`

**Interfaces:**
- Consumes: `PrometheusRuntime` and the same shared instrumentation.
- Changes: SRX `serve`, `serve_with_tls`, and `serve_inner` gain `enable_metrics: bool` immediately before `limits`.
- Produces: opt-in `/metrics` with global `server="srx"`.

- [ ] **Step 1: Write the SRX CLI flag test**

Add after `disable_host_check` in `rust-srxmcp/src/cli.rs`:

```rust
/// Expose unauthenticated Prometheus metrics at /metrics.
#[arg(long, env = "JMCP_SRX_ENABLE_METRICS")]
pub enable_metrics: bool,
```

Extend `secure_defaults`:

```rust
assert!(!cli.enable_metrics);
let metrics = Cli::parse_from(["rust-srxmcp", "--enable-metrics"]);
assert!(metrics.enable_metrics);
```

Run:

```bash
cargo test -p rust-srxmcp cli::tests::secure_defaults
```

Expected: PASS after adding the field and assertions.

- [ ] **Step 2: Add the SRX GET helper and failing subprocess tests**

Add this GET result and helper to `rust-srxmcp/tests/common/mod.rs`:

```rust
pub struct GetResult {
    pub code: u16,
    pub content_type: String,
    pub body: String,
}

pub fn http_get(
    port: u16,
    path: &str,
    bearer: Option<&str>,
    host: Option<&str>,
) -> GetResult {
    let mut request = ureq::get(&format!("http://127.0.0.1:{port}{path}"));
    if let Some(bearer) = bearer {
        request = request.set("Authorization", &format!("Bearer {bearer}"));
    }
    if let Some(host) = host {
        request = request.set("Host", host);
    }
    let response = match request.call() {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(error) => panic!("transport error: {error}"),
    };
    let code = response.status();
    let content_type = response.header("Content-Type").unwrap_or("").to_owned();
    let body = response.into_string().unwrap_or_default();
    GetResult {
        code,
        content_type,
        body,
    }
}
```

The helper accepts the path, optional bearer, and optional Host, and preserves
response bodies for success and HTTP status errors.

Create `rust-srxmcp/tests/http_metrics.rs`:

```rust
mod common;

use common::{
    close_session, http_get, http_post, http_post_raw, initialize, spawn_with_auth_args,
    write_inv, write_tokens,
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
    let response = http_get(
        server.port,
        "/metrics",
        Some(token.expose()),
        None,
    );
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

    let initial = http_get(
        server.port,
        "/metrics",
        None,
        Some("untrusted.example"),
    );
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
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":3,"method":"ping","params":"{big}"}}"#
    );
    assert_eq!(
        http_post_raw(server.port, token.expose(), None, &body),
        413
    );

    let scrape = http_get(server.port, "/metrics", None, None);
    assert!(scrape
        .body
        .contains("junosmcp_active_sessions{server=\"srx\"} 1"));
    assert!(scrape.body.lines().any(|line| {
        line.starts_with("junosmcp_tool_duration_seconds_bucket{")
            && line.contains("server=\"srx\"")
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
        .contains("junosmcp_active_sessions{server=\"srx\"} 0"));
}
```

Run:

```bash
cargo test -p rust-srxmcp --test http_metrics
```

Expected: FAIL because the SRX HTTP signatures do not receive the flag and the route is absent.

- [ ] **Step 3: Thread the flag through all SRX serving paths**

In `main.rs`, pass `args.enable_metrics` immediately before `limits` to both
`serve_with_tls` and `serve`.

Change the three signatures in `http_transport.rs` to include:

```rust
enable_metrics: bool,
limits: LimitsConfig,
```

Pass the boolean unchanged from `serve` and `serve_with_tls` into
`serve_inner`. In `serve_inner`, import `PrometheusRuntime`, then install before
session-manager construction:

```rust
let metrics_runtime = if enable_metrics {
    Some(
        PrometheusRuntime::install("srx")
            .context("initializing Prometheus metrics")?,
    )
} else {
    None
};
```

After the existing body-limit call and before TLS/plain binding, merge:

```rust
let app = if let Some(runtime) = metrics_runtime.as_ref() {
    app.merge(runtime.router())
} else {
    app
};
```

- [ ] **Step 4: Run SRX parity and regression tests**

Run:

```bash
cargo fmt --all
cargo test -p rust-srxmcp cli::tests
cargo test -p rust-srxmcp --test http_metrics
cargo test -p rust-srxmcp --test http_limits
cargo test -p rust-srxmcp --test http_smoke
cargo test -p rust-srxmcp --test http_tls
cargo clippy -p rust-srxmcp --all-targets -- -D warnings
```

Expected: PASS. SRX exposes the same contract with `server="srx"` while existing bearer, Host, limits, and TLS tests remain green.

- [ ] **Step 5: Commit SRX wiring**

```bash
git add rust-srxmcp/src/cli.rs rust-srxmcp/src/main.rs \
  rust-srxmcp/src/http_transport.rs rust-srxmcp/tests/common/mod.rs \
  rust-srxmcp/tests/http_metrics.rs
git commit -m "feat(149): expose SRX Prometheus metrics"
```

---

### Task 6: Document Scraping, Security, Names, and Queries

**Files:**
- Create: `docs/METRICS.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `rust-srxmcp/CHANGELOG.md`

**Interfaces:**
- Consumes: the exact public contract verified by Tasks 1–5.
- Produces: operator enablement, scrape, TLS, security, label, and PromQL guidance.

- [ ] **Step 1: Write `docs/METRICS.md` with the exact operator contract**

Create the file with these sections and values:

````markdown
# Prometheus metrics

Prometheus metrics are opt-in on the streamable-HTTP servers.

| Binary | Flag | Environment variable | Default target |
| --- | --- | --- | --- |
| rust-junosmcp | --enable-metrics | JMCP_ENABLE_METRICS | 127.0.0.1:30030 |
| rust-srxmcp | --enable-metrics | JMCP_SRX_ENABLE_METRICS | 127.0.0.1:30032 |

When disabled, GET /metrics is not registered. Junos refuses
--enable-metrics with --transport stdio.

## Security

GET /metrics is intentionally unauthenticated and bypasses bearer-token
authentication, rmcp Host validation, and MCP resource-limit middleware. It
shares the configured HTTP/TLS listener. Bind to loopback or restrict the
endpoint with a host firewall, reverse proxy, or equivalent network control.
Metrics contain aggregate bounded labels only; they never contain token,
caller, router, session, correlation, or error identifiers.

## Scrape configuration

```yaml
scrape_configs:
  - job_name: rust-junosmcp
    metrics_path: /metrics
    static_configs:
      - targets: ["127.0.0.1:30030"]

  - job_name: rust-srxmcp
    metrics_path: /metrics
    static_configs:
      - targets: ["127.0.0.1:30032"]
```

For a listener using the server's TLS certificate:

```yaml
scrape_configs:
  - job_name: rust-junosmcp-tls
    scheme: https
    metrics_path: /metrics
    tls_config:
      ca_file: /etc/prometheus/jmcp-ca.pem
      server_name: jmcp.example.net
    static_configs:
      - targets: ["jmcp.example.net:30030"]
```

No Authorization header is required for the metrics route.

## Metric names

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| junosmcp_active_sessions | gauge | server | Sessions currently tracked by the HTTP session manager |
| junosmcp_limit_hits_total | counter | server, limit, event | HTTP rejections and manager-level global session-cap hits |
| junosmcp_tool_duration_seconds | histogram | server, tool, result | Tool-handler elapsed seconds |
| junosmcp_sessions_reaped_total | counter | server, reason | Sessions removed by the idle/lifetime reaper |

Fixed values:

- server: junos or srx
- limit: request_body, global_concurrency, token_concurrency,
  router_concurrency, session_cap, or token_session_cap
- event: request_rejected or session_registration_rejected
- result: ok, error, denied, or unsettled
- reason: idle or lifetime

Counter and histogram label series appear after their first event. The active
session gauge is initialized to zero. The tool histogram has buckets from
0.01 seconds through 1800 seconds.

Queue time is not exported because the current concurrency gates reject
immediately instead of queueing.

## Example PromQL

Active sessions:

```promql
junosmcp_active_sessions
```

Rejection rate by server and limit:

```promql
sum by (server, limit) (
  rate(junosmcp_limit_hits_total{event="request_rejected"}[5m])
)
```

95th-percentile tool duration:

```promql
histogram_quantile(
  0.95,
  sum by (le, server, tool) (
    rate(junosmcp_tool_duration_seconds_bucket[5m])
  )
)
```

Tool error rate:

```promql
sum by (server, tool) (
  rate(junosmcp_tool_duration_seconds_count{result="error"}[5m])
)
```

Session reaper rate:

```promql
sum by (server, reason) (
  rate(junosmcp_sessions_reaped_total[5m])
)
```
````

- [ ] **Step 2: Link metrics from README and update deferred scope**

After the resource-limit behavior paragraphs in `README.md`, add:

```markdown
Prometheus export is opt-in with `--enable-metrics`
(`JMCP_ENABLE_METRICS` / `JMCP_SRX_ENABLE_METRICS`). It mounts an
unauthenticated `GET /metrics` beside `/mcp`; protect it with network controls.
See [Prometheus metrics](docs/METRICS.md) for scrape configuration, metric
names, labels, and PromQL examples.
```

Replace the deferred sentence with:

```markdown
**Deferred (follow-up on #131):** per-token RPS rate-limiting (#150).
```

- [ ] **Step 3: Add both Unreleased changelog entries**

Under `### Added` in root `CHANGELOG.md` and `rust-srxmcp/CHANGELOG.md`, add:

```markdown
- **#149 - Prometheus HTTP metrics.** Streamable HTTP can now expose an
  opt-in, unauthenticated `/metrics` route with bounded-label active-session,
  resource-limit, tool-duration, and reaper metrics. The route shares the
  configured listener/TLS but bypasses MCP auth and limits, so deployments must
  protect it with network controls.
```

- [ ] **Step 4: Verify documentation and CLI help**

Run:

```bash
rg -n "enable-metrics|JMCP_ENABLE_METRICS|JMCP_SRX_ENABLE_METRICS|junosmcp_" \
  README.md docs/METRICS.md CHANGELOG.md rust-srxmcp/CHANGELOG.md
cargo run -p rust-junosmcp -- --help | rg "enable-metrics"
cargo run -p rust-srxmcp -- --help | rg "enable-metrics"
```

Expected: both help commands show the flag; docs contain every public metric and both environment variables; README no longer defers Prometheus.

- [ ] **Step 5: Commit operator documentation**

```bash
git add docs/METRICS.md README.md CHANGELOG.md rust-srxmcp/CHANGELOG.md
git commit -m "docs(149): document Prometheus metrics"
```

---

### Task 7: Full Offline Verification and Dependency Review

**Files:**
- Verify only; repair any failure in the task that owns the affected file, then rerun this task from the beginning.

**Interfaces:**
- Consumes: all six implementation commits.
- Produces: handoff evidence for compatibility, dependency scope, tests, security scanning, and skipped live-device checks.

- [ ] **Step 1: Verify dependency versions, features, licenses, and attack surface**

Run:

```bash
cargo tree -i metrics
cargo tree -i metrics-exporter-prometheus
cargo tree -e features -p metrics-exporter-prometheus
```

Expected:

- `metrics` resolves to 0.24.6;
- `metrics-exporter-prometheus` resolves to 0.18.3;
- reverse dependencies are limited to the intended audit/limits path;
- exporter features do not include `http-listener`, `push-gateway`, protobuf,
  hyper, rustls, or a TLS crypto provider.

Record for the PR:

- `metrics` license: MIT;
- `metrics-exporter-prometheus` license: MIT AND Apache-2.0; both licenses are
  compatible with distribution by this MIT-licensed application when their
  terms and dependency notices are retained;
- both declare Rust 1.71.1 minimum, below the pinned Rust 1.97.0;
- exporter-owned network and crypto features are disabled;
- new transitive crates are the recorder/distribution support shown by
  `cargo tree`, not a second network stack.

- [ ] **Step 2: Run focused feature tests**

Run:

```bash
cargo test -p rust-junosmcp-limits
cargo test -p rust-junosmcp-audit
cargo test -p rust-junosmcp --test http_metrics
cargo test -p rust-srxmcp --test http_metrics
cargo test -p rust-junosmcp --test http_limits
cargo test -p rust-srxmcp --test http_limits
```

Expected: PASS with no device access.

- [ ] **Step 3: Run every required offline repository target**

Run each target independently so its result is recorded:

```bash
just fmt
just lint
just test
just guard
just e2e
just security
just release-check
```

Expected:

- formatting, lint, tests, guard, and e2e pass;
- workspace tests have zero failures and retain 29 ignored tests;
- `just security` and the security phase of `just release-check` may exit 1
  only for the already-known baseline `cmov 0.5.3` CVE and unchanged Dockerfile
  findings; any finding introduced through the metrics dependency subtree
  blocks handoff.

- [ ] **Step 4: Compare Trivy findings with clean main if security is nonzero**

Run from the issue worktree:

```bash
mise exec -- trivy fs --scanners vuln,misconfig,secret --format json \
  --output /tmp/issue149-trivy.json .
mise exec -- trivy fs --scanners vuln,misconfig,secret --format json \
  --output /tmp/main-trivy.json /home/mharman/Projects/RustJunosMCP
diff -u \
  <(jq -r '.Results[]?.Vulnerabilities[]? | [.VulnerabilityID,.PkgName,.InstalledVersion] | @tsv' \
      /tmp/main-trivy.json | sort -u) \
  <(jq -r '.Results[]?.Vulnerabilities[]? | [.VulnerabilityID,.PkgName,.InstalledVersion] | @tsv' \
      /tmp/issue149-trivy.json | sort -u)
```

Expected: no new vulnerability tuple. Also inspect misconfiguration and secret
sections; the metrics change must add zero secret findings and zero new
misconfigurations.

- [ ] **Step 5: Verify compatibility and clean branch state**

Run:

```bash
git diff --check origin/main...HEAD
git diff --stat origin/main...HEAD
git status --short --branch
git log --oneline --decorate origin/main..HEAD
```

Expected:

- no whitespace errors;
- only the design, plan, intended manifests/lockfile, metrics implementation,
  endpoint wiring/tests, docs, and changelogs differ;
- worktree is clean;
- no MCP schema/generated/package/archive files changed;
- no device inventory, token, key, fetched data, configuration, certificate,
  support bundle, or other secret-bearing artifact is present.

- [ ] **Step 6: Record skipped checks and remaining risk**

The handoff and PR body must explicitly state:

```text
Real-device/ignored tests were not run; CONFIRM_LAB_INTEGRATION was not set and
no device was contacted. MCP schemas, annotations, auth scopes, audit fields,
timeouts, overload contracts, inventory, leases, and TLS behavior are
compatible. /metrics is opt-in and unauthenticated; network restriction remains
an operator responsibility. The global recorder is process-singleton and
startup fails if another recorder is already installed.
```
