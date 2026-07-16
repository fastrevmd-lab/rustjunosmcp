# Prometheus HTTP Metrics Design

**Issue:** #149

**Date:** 2026-07-15

**Status:** Design approved; pending written-spec review

## Context

The streamable-HTTP resource-limit subsystem already enforces request-body,
global, per-token, per-router, global-session, and per-token-session limits for
both `rust-junosmcp` and `rust-srxmcp`. It emits structured `tracing` events but
does not expose machine-scrapable operational metrics. Tool handlers already
use `rust-junosmcp-audit::AuditScope`, which owns the authoritative tool name,
result, and elapsed time for every audited tool call.

Issue #149 adds an opt-in Prometheus endpoint and instruments the authoritative
state transitions without changing MCP behavior.

## Goals

- Expose Prometheus text-format metrics at `GET /metrics` for both HTTP
  binaries.
- Report active sessions, resource-limit events, tool durations, and reaper
  activity.
- Keep labels bounded and free of caller, device, session, and error data.
- Preserve all existing MCP schemas, auth scopes, audit fields, limits,
  timeouts, and overload responses.
- Document configuration, scrape setup, metric names, label meanings, and
  example queries.

## Non-goals

- A dedicated metrics listener or port.
- Bearer authentication or rmcp Host validation for `/metrics`.
- Per-token, per-router, per-session, correlation, or error-detail labels.
- Request queueing or queue-time metrics. Current gates load-shed immediately
  with `try_acquire`; there is no queue to measure.
- Fixing the best-effort global session-registration race tracked by #151.
- Per-token request-rate limiting, which remains #150.
- Real-device or ignored integration testing.

## Decisions

| Concern | Decision | Rationale |
| --- | --- | --- |
| Listener | Existing HTTP listener | Avoids another bind address, port, TLS surface, and deployment change. |
| Route | Independent `GET /metrics`, merged beside `/mcp` | Keeps metrics outside MCP authentication and resource-limit middleware. |
| Enablement | Opt-in, disabled by default | The endpoint is intentionally unauthenticated and exposes operational metadata. |
| Initialization failure | Fail startup | An explicit monitoring request must not silently degrade. |
| Emission model | Direct `metrics` calls at authoritative state transitions | Avoids parsing tracing fields and avoids an injected observer abstraction. |
| Export ownership | Shared helper in `rust-junosmcp-limits`; binaries decide whether to install it | Reuses one implementation while keeping process startup policy in each binary. |
| Labels | Fixed, bounded values only | Prevents secret exposure and unbounded Prometheus cardinality. |
| Queue time | Omitted | No current subsystem waits in a queue. |

## Configuration

Both flags are booleans and default to `false`.

| Binary | Flag | Environment variable |
| --- | --- | --- |
| `rust-junosmcp` | `--enable-metrics` | `JMCP_ENABLE_METRICS` |
| `rust-srxmcp` | `--enable-metrics` | `JMCP_SRX_ENABLE_METRICS` |

`rust-junosmcp` rejects `--enable-metrics` when `--transport stdio` is
selected. `rust-srxmcp` is already HTTP-only. When metrics are disabled, no
recorder is installed and `/metrics` is absent, producing the normal 404.

## Component Ownership

### `rust-junosmcp-limits`

This shared crate gains the Prometheus setup and rendering helper because it
already owns the shared HTTP resource-limit layer and depends on Axum. It also
owns fixed helper functions/constants for:

- resource-limit event counters;
- the active-session gauge;
- session-reaper counters; and
- the body-limit response observer.

The helper installs one `metrics-exporter-prometheus` recorder, configures a
fixed global `server` label, configures the tool-duration histogram buckets,
and returns a runtime owner containing a cloneable render handle and an
abort-on-drop upkeep task. The task calls `PrometheusHandle::run_upkeep()`
every five seconds so histogram samples are drained into distributions even
when Prometheus is not scraping. Dropping the HTTP server aborts the upkeep
task. A small Axum handler renders the handle with this response content type:

```text
text/plain; version=0.0.4; charset=utf-8
```

Only recorder and render-handle support is needed. Exporter-owned HTTP listener
and push-gateway features are disabled so the existing Axum server remains the
only network listener. Recommended-name rewriting and unit suffixing remain
disabled so the explicit public metric names below are rendered exactly.

### `rust-junosmcp-audit`

`AuditScope::drop` emits the tool-duration histogram using the same elapsed
time and `AuditOutcome` classification that already produce the audit event.
This crate depends only on the lightweight `metrics` emission API, not on the
exporter or the limits crate.

### HTTP binaries

Each binary owns its CLI flag, environment variable, startup validation, and
fixed global server label:

- `server="junos"` for `rust-junosmcp`;
- `server="srx"` for `rust-srxmcp`.

When enabled, recorder installation happens before `SessionTracker`
construction so the initial zero gauge is observable. Installation errors are
returned with context before the listener binds.

## Router Composition

The `/mcp` application retains its existing order and behavior:

```text
request-body limit
  -> bearer auth (when configured)
    -> concurrency/session middleware
      -> rmcp StreamableHttpService at /mcp
```

Only after this protected application has all of its layers does the binary
merge the metrics route:

```text
shared TCP/TLS listener
  +-- protected /mcp application
  `-- unauthenticated GET /metrics
```

Consequently, `/metrics` intentionally bypasses bearer authentication, rmcp
Host validation, body/concurrency/session limits, and MCP audit handling. It
still uses the listener's TLS configuration. Operators must restrict access
with the bind address, host firewall, reverse proxy, or equivalent network
control. The default loopback bind remains the safest default.

The metrics handler renders an in-memory snapshot only. It performs no token
lookup, inventory access, device I/O, file access, or other asynchronous work.

## Public Metric Contract

All series have the fixed global `server` label (`junos` or `srx`). No series
contains token names, caller names, router names, session IDs, correlation IDs,
error kinds, error text, or arbitrary metadata.

### `junosmcp_active_sessions`

Type: gauge.

The value mirrors `SessionTracker::active()`. It is set to zero when the
tracker is created, then set after every successful registration or removal.
Repeated removal of an unknown session does not change the gauge.

This metric intentionally reflects the current tracker semantics. Until #151
is implemented, a session whose best-effort registration loses the global cap
race is reported through the limit-event counter but is not included in the
active gauge.

### `junosmcp_limit_hits_total`

Type: counter.

Labels:

- `limit`: one of `request_body`, `global_concurrency`,
  `token_concurrency`, `router_concurrency`, `session_cap`, or
  `token_session_cap`;
- `event`: `request_rejected` or `session_registration_rejected`.

`request_rejected` increments exactly once for an HTTP request rejected with
the existing 413 or 503 limit behavior. Filtering on that event produces
rejection totals grouped by limit kind without a redundant second metric.

`session_registration_rejected` records the known best-effort registration
failure in `LimitedSessionManager::create_session`. It exposes the #151 race
without changing its current behavior. When #151 later turns that condition
into a stable HTTP rejection, the distinct event value remains useful for
identifying the manager-level race path.

The existing `overload_response()` helper is the authoritative emission point
for 503 sheds. A response observer applied only to the protected `/mcp`
application counts body-limit 413 responses.

### `junosmcp_tool_duration_seconds`

Type: histogram.

Labels:

- `tool`: the compile-time MCP tool name already held by `AuditScope`;
- `result`: `ok`, `error`, `denied`, or `unsettled`.

`AuditScope::drop` captures elapsed time once, records it as seconds, and uses
the same elapsed value for the existing millisecond audit field. The audit
event schema and values remain unchanged. Histogram `_count` and `_sum` output
also provide tool-call counts and aggregate duration without another counter.

The histogram uses buckets suitable for fast local operations and long device
workflows:

```text
0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5,
5, 10, 30, 60, 120, 300, 600, 1800 seconds
```

### `junosmcp_sessions_reaped_total`

Type: counter.

Label:

- `reason`: `idle` or `lifetime`.

One reaper sweep identifies the expiration reason while collecting stale
sessions. If both thresholds expire on the same sweep, `lifetime` wins. The
counter increments after the existing close/unregister cleanup sequence, so it
counts sessions removed from tracking by the reaper.

## Instrumentation Flow

### Concurrency and overloads

Each existing middleware rejection continues to log the same tracing event and
return the same response. Calling `overload_response(limit)` increments
`junosmcp_limit_hits_total{event="request_rejected"}` before constructing the
response. Successful limit acquisitions do not increment a counter.

The body-limit observer sees the final response from `/mcp` and increments
`limit="request_body", event="request_rejected"` for status 413. It is not
merged into the independent metrics router, preventing scrapes from observing
or affecting resource-limit metrics.

### Session tracking

`SessionTracker::try_register` updates the gauge after the atomic count and
activity map are committed. If its cap check rolls back the count, it emits
`limit="session_cap", event="session_registration_rejected"` and leaves the
gauge unchanged.

`SessionTracker::unregister` updates the gauge only when it actually removes an
activity entry. Explicit close, reaper close, and duplicate close retain their
current idempotence.

### Reaper

The stale-session query returns each session with its fixed expiration reason.
The background task retains the current close-then-unregister sequence. After
unregister updates the active gauge, the task increments the reaper counter and
emits the existing tracing event.

### Tool duration

`AuditScope::drop` maps its existing outcome to the fixed `result` label,
records the duration histogram, and emits the existing redacted audit event.
Metrics never receive caller, router, metadata, reason, or error fields. An
unsettled scope still produces both the existing audit event and a histogram
sample with `result="unsettled"`.

When no recorder is installed, `metrics` emission uses its normal no-op path;
callers do not need feature checks or optional observer state.

## Error Handling

- An invalid Junos stdio/metrics combination is rejected by CLI validation
  before inventory or network initialization.
- Recorder construction or global installation failure aborts HTTP startup
  before binding the listener.
- The returned runtime owner keeps the five-second upkeep task alive for the
  lifetime of the HTTP server and aborts it during shutdown.
- The render handle produces the response body from memory. No fallible device
  or storage operation exists on the scrape path.
- Metric emission never replaces or masks the existing HTTP response, session
  cleanup, tool result, or audit emission.
- The feature adds no recovery path that silently disables requested metrics.

## Testing Strategy

### Unit and component tests

- Use a locally scoped recorder for emission tests so the test suite does not
  contend for the process-global recorder.
- Verify the exporter helper renders the documented content type, metric names,
  fixed global server label, and configured histogram buckets. Tests call
  upkeep before rendering histogram assertions.
- Exercise each overload kind and assert its exact `limit` and `event` labels.
- Verify the body-limit observer counts a 413 exactly once and ignores other
  statuses.
- Verify successful registration, failed registration, removal, and duplicate
  removal update the gauge/counter correctly.
- Extract one reaper sweep into a testable unit and verify idle, lifetime, and
  simultaneous expiration using synthetic `Instant` values.
- Verify `AuditScope` records `ok`, `error`, `denied`, and `unsettled` histogram
  series while preserving current audit output.

### Binary HTTP tests

Add parity coverage for Junos and SRX subprocesses:

- without the flag, `GET /metrics` returns 404;
- with the flag, an unauthenticated scrape returns 200 and the Prometheus
  content type;
- the metrics route remains reachable when `/mcp` bearer auth is enabled;
- offline MCP initialization and tool calls produce active-session and
  tool-duration samples;
- closing a session updates the active gauge;
- scrape output contains no test token, router, session, or correlation value;
- Junos stdio plus `--enable-metrics` fails with a clear message.

No test contacts a device. Ignored real-device tests remain skipped.

## Documentation

Create `docs/METRICS.md` containing:

- both binaries' flag and environment-variable names;
- enablement and 404 behavior;
- Prometheus scrape examples for plain HTTP and TLS;
- the unauthenticated-endpoint network-control warning;
- every metric, type, label, and fixed label value;
- example PromQL for active sessions, rejection rate by limit, tool p95, tool
  error counts from histogram `_count`, and reaper rate;
- the absence of queue time and identifier-bearing labels.

Link the guide from the README resource-limit section, remove Prometheus from
the deferred follow-up sentence, and update both Unreleased changelogs.

## Dependency and Security Review

- Add `metrics` and `metrics-exporter-prometheus` through workspace dependency
  declarations and update `Cargo.lock` mechanically with Cargo.
- Disable exporter HTTP-listener and push-gateway features; the existing Axum
  listener is the only network surface.
- Review the resolved dependency tree, licenses, maintenance status, audit
  results, and added attack surface before handoff.
- The endpoint is opt-in and contains aggregate operational data only, but it
  is still unauthenticated. Documentation must treat network restriction as an
  operator requirement.

## Compatibility and Risk

Default behavior is unchanged because metrics are disabled. Enabling metrics
adds only `GET /metrics` on the existing listener. MCP tool schemas,
annotations, auth scopes, overload bodies/statuses/headers, audit fields,
session timeouts, device leases, inventory behavior, and TLS behavior remain
compatible.

The main residual risks are exporter dependency growth, accidentally placing
the metrics route inside protected middleware, duplicate metric emission, and
future introduction of unbounded labels. Dependency review, router-level
tests, exact counter tests, and explicit label-contract documentation address
those risks.
