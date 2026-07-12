# HTTP Resource & Session Limits — Design

- **Issue:** [#131](https://github.com/fastrevmd-lab/rustjunosmcp/issues/131) — [Medium] Add HTTP resource and session limits
- **Date:** 2026-07-12
- **Status:** Approved (first pass)
- **Scope note:** This spec covers the **first pass** — core DoS guardrails. Several
  acceptance-criteria items from #131 are explicitly deferred to follow-up work
  (see [Out of Scope](#out-of-scope)).

## Problem

Both HTTP endpoints (`rust-junosmcp` and `rust-srxmcp`) mount the rmcp
streamable-HTTP service with a default `LocalSessionManager` and no explicit
request-body, concurrency, session-count, or session-lifetime controls
(`rust-junosmcp/src/http_transport.rs:55`, `rust-srxmcp/src/http_transport.rs:85`).
Existing output caps are tool-level and apply *after* upstream NETCONF output is
buffered (`rust-junosmcp-core/src/output.rs`), so they do not protect the process
from oversized requests, client loops, slow clients, or expensive concurrent calls.
Authentication alone does not protect availability: an authorized-but-buggy or
abusive client can exhaust memory, file descriptors, SSH sessions, and device
capacity.

## Goals (this pass)

Ship core availability guardrails on **both** endpoints, with **parity** (identical
behavior), **enabled by default** with generous values so the live lab deployment is
protected without disruption:

1. Configurable request-body size limit enforced **before** JSON/MCP buffering.
2. Global and per-token in-flight **concurrency** limits with **load-shed**
   (immediate rejection, no queue).
3. Session **count cap** plus **idle timeout** and **max lifetime** with automatic
   cleanup.
4. Stable **overload responses** with retry guidance (`Retry-After`).
5. Lightweight observability via the existing `tracing` stack (no new metrics deps).

## Non-Goals / Out of Scope

Deferred to follow-up work, tracked as comments on #131:

- **Per-router in-flight limits** composing with destructive leases.
- **Per-token session caps** (per-token *concurrency* limiting is in scope; per-token
  *session-count* caps are not — they require session↔token correlation that is more
  invasive).
- **Prometheus `/metrics` endpoint** and histogram/counter export
  (`metrics` + `metrics-exporter-prometheus`).
- **RPS token-bucket** rate limiting (concurrency limiting is sufficient here because
  the real bottleneck is concurrent expensive NETCONF/SSH calls, not request rate).

These are intentionally excluded to keep this pass a single reviewable PR. The design
below leaves clean extension points for each.

## Design Decisions (locked during brainstorming)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Throttle type | **Concurrency only** (global + per-token) | Directly bounds concurrent SSH sessions / device load; no token-bucket state to tune. |
| Overload behavior | **Load-shed → immediate 503 + `Retry-After`** | Predictable, no memory growth, no slow-client amplification. |
| Defaults | **Enabled, generous** | Protects the running lab deployment without disrupting it; every knob is tunable and `0` disables. |
| Observability | **`tracing` counters/logs** | No new deps; Prometheus is a later pass. |
| Code home | **New shared crate `rust-junosmcp-limits`** | Guarantees endpoint parity; keeps rmcp/session coupling out of the auth crate. |

## Architecture

### New crate: `rust-junosmcp-limits`

A new workspace member both binaries depend on, so the two endpoints stay identical.

**Dependencies:** `axum`, `tower`, `tower-http` (workspace), `rmcp` (for the session
wrapper), `rust-junosmcp-auth` (for `CallerCtx`), `tokio`, `tracing`, `dashmap`.

The crate exposes four pieces:

#### 1. `LimitsConfig`

One struct holding all tunables. Every field uses `0 = unlimited` as an escape hatch.
Defaults are sized well above expected lab traffic (24 vSRX devices, a handful of
clients):

| Field | CLI flag | Env var | Default | `0` means |
|-------|----------|---------|---------|-----------|
| `max_request_body_bytes` | `--max-request-body-bytes` | `JMCP_MAX_REQUEST_BODY_BYTES` | `10 * 1024 * 1024` (10 MiB) | unlimited |
| `max_inflight_requests` | `--max-inflight-requests` | `JMCP_MAX_INFLIGHT_REQUESTS` | `64` | unlimited |
| `max_inflight_requests_per_token` | `--max-inflight-requests-per-token` | `JMCP_MAX_INFLIGHT_REQUESTS_PER_TOKEN` | `16` | unlimited |
| `max_sessions` | `--max-sessions` | `JMCP_MAX_SESSIONS` | `128` | unlimited |
| `session_idle_timeout_secs` | `--session-idle-timeout-secs` | `JMCP_SESSION_IDLE_TIMEOUT_SECS` | `300` | no idle timeout |
| `session_max_lifetime_secs` | `--session-max-lifetime-secs` | `JMCP_SESSION_MAX_LIFETIME_SECS` | `3600` | no lifetime cap |

`LimitsConfig` provides a `Default` impl (the values above) and a validation method
that logs (via `tracing`) the effective configuration at startup.

#### 2. Request-body size limit

`tower_http::limit::RequestBodyLimitLayer::new(max_request_body_bytes)`, applied as the
**outermost** layer. It rejects requests whose declared or streamed body exceeds the
limit with **HTTP 413** *before* rmcp buffers the body. When `max_request_body_bytes == 0`
the layer is omitted entirely.

#### 3. Concurrency middleware: `limits_layer`

A custom `axum::middleware::from_fn_with_state` layer placed **inside** the auth layer,
so `CallerCtx` (carrying `token_name`) is already in request extensions.

State (`ConcurrencyState`, cheaply cloneable via `Arc`):

- `global: Arc<Semaphore>` — sized to `max_inflight_requests`.
- `per_token: Arc<DashMap<String, Arc<Semaphore>>>` — a `Semaphore`
  (`max_inflight_requests_per_token`) created lazily per `token_name` on first use.
- A shared **session gauge** handle (from the session wrapper, see below) used to
  early-shed `initialize` requests when the session cap is reached.

Behavior per request:

1. If `max_inflight_requests > 0`: `global.try_acquire()`. On failure → shed.
2. If `CallerCtx` present and `max_inflight_requests_per_token > 0`:
   `per_token[token].try_acquire()`. On failure → shed (and release the global permit).
3. If the request is an `initialize` (session-creating) request and the session gauge
   is at `max_sessions` → shed with a session-cap reason.
4. Otherwise call the inner service, holding the acquired permit guard(s) until the
   response future completes (RAII drop releases them, including on cancellation).

**Shed** = build a stable overload response: **HTTP 503**, `Retry-After: <secs>` header,
a small JSON body describing the limit, and a `tracing::warn!` event with fields
`limit`, `token`, `remote_addr`, and the relevant gauge. A single helper
(`overload_response(reason, retry_after)`) produces this so all shed paths are identical.

> Note: distinguishing an `initialize` request is done by inspecting the absence of the
> `Mcp-Session-Id` header combined with the JSON-RPC method. The middleware peeks headers
> only; it does not consume the body (rmcp still owns body parsing). If reliable
> body-free detection proves brittle during implementation, the session-cap early-shed
> is dropped from the middleware and the `LimitedSessionManager` hard cap (below) becomes
> the sole enforcement point — the middleware concurrency limits are unaffected either way.

#### 4. `LimitedSessionManager<S>`

A wrapper implementing rmcp's `SessionManager` trait (rmcp 2.0.0, 10 methods) by
delegating to an inner `S` (default `LocalSessionManager`). `LocalSessionManager` has
no session idle-TTL or max-count of its own, so this wrapper supplies them.

Added state:

- `active: Arc<AtomicUsize>` — current session count (the shared gauge handle exposed to
  `limits_layer`).
- `activity: Arc<DashMap<SessionId, SessionMeta>>` where `SessionMeta { created_at,
  last_active }` (both `Instant`).
- `config: LimitsConfig`.

Method behavior:

- `create_session`: if `max_sessions > 0` and `active >= max_sessions`, return an
  `Err` (backstop for the middleware early-shed race). Otherwise delegate, then
  increment `active` and insert `SessionMeta`.
- `has_session`, `initialize_session`, `create_stream`, `accept_message`, `resume`,
  `create_standalone_stream`, `restore_session`: delegate, then bump `last_active` for
  the session.
- `close_session`: delegate, then decrement `active` and remove from `activity`.

**Reaper:** a background `tokio` task (spawned when the manager is constructed) that
ticks (e.g. every 30 s) and, for each tracked session, calls inner `close_session` when
`last_active` exceeds `session_idle_timeout_secs` **or** `created_at` exceeds
`session_max_lifetime_secs` (each check skipped when its value is `0`). Closing through
the same path keeps `active`/`activity` consistent. The reaper handle is stored so it is
aborted on drop.

### Layer order (request flow, outermost first)

```
RequestBodyLimitLayer      (413 on oversized body, before buffering)
  -> auth_layer            (existing: 401, sets CallerCtx)
    -> limits_layer        (503 + Retry-After on concurrency / session-cap)
      -> StreamableHttpService  (rmcp, backed by LimitedSessionManager)
```

In axum, the **last** `.layer()` applied is the outermost, so the wiring builds the
chain in reverse of the above.

### Wiring changes

- `rust-junosmcp/src/http_transport.rs` and `rust-srxmcp/src/http_transport.rs`:
  `serve()` gains a `LimitsConfig` parameter; builds the `LimitedSessionManager`,
  the `ConcurrencyState`, and applies the three layers around the existing router.
- `rust-junosmcp/src/cli.rs` and `rust-srxmcp/src/cli.rs`: add the six clap fields
  (with env vars), assemble a `LimitsConfig`, thread it through `main.rs` to `serve()`.
- `rust-srxmcp/Cargo.toml`: add `tower-http` (workspace) — `rust-junosmcp` already has it.
- Workspace `Cargo.toml`: add the `rust-junosmcp-limits` member and `dashmap` to
  workspace deps.
- No changes to tool handlers or the existing output caps.

## Error / Overload Contract

| Condition | Status | Headers | Body |
|-----------|--------|---------|------|
| Body exceeds `max_request_body_bytes` | 413 | — (tower-http default) | tower-http default |
| Global concurrency exceeded | 503 | `Retry-After: <secs>` | `{"error":"overloaded","limit":"global_concurrency"}` |
| Per-token concurrency exceeded | 503 | `Retry-After: <secs>` | `{"error":"overloaded","limit":"token_concurrency"}` |
| Session cap reached | 503 | `Retry-After: <secs>` | `{"error":"overloaded","limit":"session_cap"}` |

`Retry-After` is a small fixed value (e.g. `1` second) — enough to signal backoff
without prescribing a schedule.

## Observability

Structured `tracing` events (no new deps):

- On every shed: `tracing::warn!(limit, token, remote_addr, current, max, "request shed")`.
- On session create/close: `tracing::debug!(active, max_sessions, ...)`.
- On reaper eviction: `tracing::info!(session_id, reason = "idle"|"lifetime", ...)`.
- Effective `LimitsConfig` logged once at startup.

## Testing Strategy

**Crate-level tests in `rust-junosmcp-limits`** (deterministic, no live devices — the
authoritative coverage for the "load-test" acceptance items):

- A synthetic slow axum handler (sleeps on a barrier) proves:
  - Global concurrency: `N` in-flight + 1 more → the extra gets 503.
  - Per-token concurrency: two tokens are isolated; exceeding one token's cap sheds only
    that token; a second token still succeeds.
  - Cancellation: dropping an in-flight request frees its permit (a subsequent request
    succeeds).
- Body limit: a request over the cap → 413; under → passes.
- `LimitedSessionManager` (with a mock inner `SessionManager`):
  - `create_session` at cap → `Err`; `active` gauge accurate across create/close.
  - Reaper evicts an idle session (short idle timeout) and an over-lifetime session;
    leaves a fresh, active one.
- `LimitsConfig`: `0` disables each corresponding limit.

**End-to-end tests** (existing `tests/common` harness: spawn binary, `ureq`):

- Oversized body → 413 on both binaries.
- A smoke assertion that a normal request still succeeds with limits enabled (parity
  check that wiring didn't break the happy path) on both binaries.

**Docs:** add a "Resource limits" section to the README documenting every knob, its
default, the `0 = unlimited` convention, and the overload contract.

## Acceptance Criteria Mapping (from #131)

| #131 criterion | This pass |
|----------------|-----------|
| Configurable body limit before buffering | ✅ `RequestBodyLimitLayer`, outermost |
| Global + per-token request/concurrency limits with bounded queues | ✅ concurrency (load-shed, **no** queue — deliberate, documented) |
| Per-router limits composing with destructive leases | ⛔ deferred |
| Cap sessions; idle timeout, lifetime, cleanup | ✅ `LimitedSessionManager` + reaper |
| Stable overload responses with retry guidance | ✅ 503 + `Retry-After` |
| Metrics (sessions, rejections, queue time, tool duration, limit hits) | ◑ tracing events for rejections/sessions; Prometheus deferred |
| Load-test oversized bodies, session floods, slow clients, cancellation, expensive calls | ✅ crate-level deterministic tests + e2e body test |
| Document defaults and tuning | ✅ README section |

## Risks / Open Questions (resolve during implementation)

- **`initialize` detection in middleware** without consuming the body — if brittle, fall
  back to the `LimitedSessionManager` hard cap only (see note in §3). Concurrency limits
  are unaffected.
- **`SessionManager` trait surface** (rmcp 2.0.0) has 10 methods including `resume` and
  `restore_session`; the wrapper must delegate all faithfully. Verified feasible; volume
  is mechanical.
- **rmcp `create_session` error → HTTP status** is controlled by rmcp; the middleware
  early-shed is what produces the clean 503, with the wrapper `Err` as the race backstop.
