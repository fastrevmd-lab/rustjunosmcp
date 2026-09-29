# Per-Token RPS Token-Bucket Rate Limiting — Design

- **Issue:** [#150](https://github.com/mechubsec/rustjunosmcp/issues/150) — [Low] Optional per-token RPS (token-bucket) rate limiting
- **Date:** 2026-07-16
- **Status:** Approved design; written specification awaiting final review

## Problem

The streamable-HTTP endpoints already cap request bodies, global and per-token
concurrency, per-router concurrency, and global/per-token MCP sessions. Those
controls bound simultaneous expensive work, but they do not constrain a burst
of many short authenticated requests that complete quickly enough to release
their concurrency permits between calls.

Issue #150 closes that deliberate follow-up from #131/#146 by adding an
optional requests-per-second token bucket for each authenticated token. It must
remain distinct from concurrency shedding: request-rate exhaustion is a client
throttling condition (`429`), while exhausted concurrency or session capacity
continues to be an availability condition (`503`).

## Goals

1. Add a configurable token bucket for each exact authenticated token name.
2. Support independent whole-number requests-per-second and burst-capacity
   settings, with `0/0` disabling the feature.
3. Reject an exhausted bucket immediately with stable HTTP `429` JSON and a
   standards-compatible `Retry-After` delay.
4. Compose deterministically with the existing body, authentication,
   concurrency, router, and session limits on both binaries.
5. Prove burst, refill, isolation, concurrency, response, and endpoint behavior
   without sleeping in unit tests or contacting a device.
6. Document when request-rate limiting is useful and how it differs from
   concurrency limiting.

## Non-Goals

- Global, per-router, per-tool, per-method, or per-IP request-rate limits.
- Different rate/burst values for individual token records.
- Charging separately for each JSON-RPC item in a batched HTTP request.
- Queuing or delaying requests until quota becomes available.
- Refunding quota when downstream work fails, is shed by another limit, or is
  cancelled.
- Rate limiting unauthenticated loopback mode, `/metrics`, or stdio transport.
- Changing any MCP schema, tool annotation, auth scope, audit event, device
  timeout, concurrency default, or session default.
- Adding a third-party rate-limiting dependency.

## Locked Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Default | Disabled (`rate = 0`, `burst = 0`) | Preserves existing deployment behavior and makes this optional as requested. |
| Partial configuration | Reject startup when exactly one knob is zero | Avoids silently ignoring an operator's intended limit. |
| Algorithm | In-house continuously refilled token bucket | Small, auditable, deterministic, and requires no new dependency. |
| Rate precision | Positive whole requests per second | Matches the issue's RPS model and gives simple, safe CLI/config semantics. |
| Initial state | Full burst | Allows the configured burst immediately, which is conventional token-bucket behavior. |
| Charge unit | One authenticated `/mcp` HTTP request | The requested control is HTTP RPS, not JSON-RPC operation or tool-call rate. |
| Identity | Exact `CallerCtx.token_name` | Matches existing per-token concurrency/session isolation and survives secret rotation under the same logical name. |
| No-auth mode | Skip per-token rate limiting | There is no authenticated token identity; matches existing per-token limits. |
| Rejection | Immediate `429` + computed `Retry-After` | Distinct from existing `503` load shedding and does not create a queue. |
| Precedence | Rate check before concurrency/session checks | Over-rate traffic consumes no scarce concurrency permit and receives the most actionable response. |
| Downstream failure | Do not refund | Every authenticated attempt contributes to request frequency; refunds enable retry amplification. |
| Observability | `token_rate` limit label, no token-name metric label | Extends the bounded metrics contract without cardinality or secret risk. |

## Configuration Contract

`LimitsConfig` gains two `u64` fields:

| Field | Junos flag/env | SRX flag/env | Default |
|---|---|---|---:|
| `max_requests_per_second_per_token` | `--max-requests-per-second-per-token` / `JMCP_MAX_REQUESTS_PER_SECOND_PER_TOKEN` | same flag / `JMCP_SRX_MAX_REQUESTS_PER_SECOND_PER_TOKEN` | `0` |
| `max_request_burst_per_token` | `--max-request-burst-per-token` / `JMCP_MAX_REQUEST_BURST_PER_TOKEN` | same flag / `JMCP_SRX_MAX_REQUEST_BURST_PER_TOKEN` | `0` |

The valid combinations are:

- `rate == 0 && burst == 0`: disabled;
- `rate > 0 && burst > 0`: enabled;
- exactly one value is zero: invalid configuration and startup fails before
  binding the HTTP listener.

The shared crate exposes validation so both binaries enforce identical rules.
Validation returns a small typed error implemented with the standard library;
no dependency is added. `LimitsConfig::log_effective` includes both values so
operators can confirm the active settings without exposing token identities.

The two CLI structs expose the flags and environment variables above. Their
default/parse tests cover disabled and custom configurations. The two existing
main-to-`LimitsConfig` construction sites forward both fields explicitly.

## Architecture

### Shared rate-limit module

Add `rust-junosmcp-limits/src/rate_limit.rs`. Its only public API is
`apply_token_rate_limit(router, config) -> router`, matching the existing
`apply_body_limit` pattern. The helper returns the router unchanged when the
feature is disabled; when enabled, it builds shared state and installs the
private Axum middleware. The bucket/state types and middleware function remain
crate-private implementation details.

The state owns:

```text
Arc<DashMap<String, Bucket>>
rate_per_second: u64
burst: u64
```

Each `Bucket` contains the currently available fixed-point token units and its
last monotonic refill instant. A `DashMap` entry operation serializes the short
refill/consume calculation for one token without holding a lock across an
`await`. Different tokens can proceed independently except for the map's brief
internal shard locking.

Token names originate only from the administrator-controlled token store, not
untrusted header text. The state map therefore has the same operational
cardinality model as the existing per-token semaphore map: stable deployments
are bounded by their configured token names; historical names may remain until
process restart after high-churn administrative provisioning. No token secret
is stored as a key.

### Exact token arithmetic

Use fixed-point integer arithmetic with one token represented by
`1_000_000_000` units. For an elapsed monotonic duration measured in
nanoseconds:

```text
refilled_units = elapsed_nanoseconds * rate_per_second
available      = min(burst * 1_000_000_000,
                     available + refilled_units)
request_cost   = 1_000_000_000
```

All intermediate arithmetic uses saturating `u128` operations. This avoids
floating-point drift and overflow even for extreme CLI values or a long-idle
bucket. Production uses `std::time::Instant`; the core check accepts an explicit
instant internally so tests advance time deterministically without sleeps.

On the first request for a token, its bucket starts at full burst and the
request consumes one token. Subsequent checks:

1. Refill from elapsed monotonic time, capped at burst.
2. If at least one token is available, subtract one and admit.
3. Otherwise leave the bucket exhausted and return the delay until one whole
   token is available.

If a test supplies an earlier instant, elapsed time saturates at zero and the
stored refill instant does not move backward; the production monotonic clock
does not move backward.

### Retry calculation

For an exhausted bucket:

```text
deficit_units = 1_000_000_000 - available
wait_ns       = ceil(deficit_units / rate_per_second)
retry_secs    = max(1, ceil(wait_ns / 1_000_000_000))
```

The value is safely clamped to `u64`. With the current positive whole-number
RPS configuration, the rounded HTTP delay is always one second; it is still
derived from the exact bucket deficit so the response and algorithm remain
coupled and testable.

### Request flow and layer order

The streamable-HTTP request path becomes:

```text
RequestBodyLimitLayer
  -> auth_layer
    -> token_rate_limit_middleware
      -> concurrency_middleware
        -> StreamableHttpService / LimitedSessionManager
```

Consequences:

- oversized bodies are rejected before authentication or quota charging;
- missing/invalid bearer credentials receive the existing `401` without quota
  charging;
- authenticated `/mcp` requests consume one token before later validation or
  capacity checks;
- rate exhaustion returns `429` even if a later concurrency/session gate would
  also be full;
- an admitted request that later receives `400`, `404`, `500`, or `503`, or is
  cancelled, is not refunded;
- existing concurrency permits and session reservations are untouched;
- `/metrics` remains outside the protected MCP router and unauthenticated;
- no-auth mode has no `CallerCtx`, so the middleware passes through without a
  bucket lookup.

The rate middleware is separate from `concurrency_middleware`. This keeps the
existing permit lifetime/body wrapper unchanged and makes `429` behavior
independently testable. Both HTTP transports construct and layer the same
shared state in the same order.

## Stable Rejection Contract

Add `rate_limited_response` beside `overload_response` in `overload.rs` rather
than changing the latter's HTTP `503` contract:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: <whole seconds>
Content-Type: application/json

{"error":"rate_limited","limit":"token_rate"}
```

The helper records:

```text
junosmcp_limit_hits_total{limit="token_rate",event="request_rejected",server="..."}
```

The rate middleware emits a structured warning with `limit`, logical token
name, configured rate/burst, and retry delay. Token names are already treated
as non-secret operational identities in existing concurrency logs. They are
never metric labels, preventing unbounded Prometheus cardinality. Bearer
secrets are never logged or stored.

All existing `503` status codes, bodies, headers, and metric labels remain
unchanged:

- `global_concurrency`;
- `token_concurrency`;
- `router_concurrency`;
- `session_cap`;
- `token_session_cap`.

## Test Strategy

Implementation follows test-driven development: each behavior is introduced by
a focused failing test before production code.

### Configuration tests

- defaults are `0/0` and disabled;
- positive rate and burst validate;
- `rate > 0, burst == 0` fails;
- `rate == 0, burst > 0` fails;
- both CLI parsers retain disabled defaults and parse custom values;
- effective construction forwards both fields in each binary.

### Deterministic bucket tests

- a fresh bucket admits exactly `burst` immediate requests;
- the next request is rejected;
- a fractional interval refills the exact expected fraction;
- a full-token boundary admits without an extra delay;
- a long idle interval caps available quota at `burst`;
- a rejected request does not subtract another token;
- distinct token names have independent buckets;
- concurrent same-token checks admit exactly the available count;
- large values/elapsed durations saturate safely;
- the retry delay is rounded up and never zero.

### Middleware and response tests

- the first `burst` authenticated requests pass and the next returns the exact
  `429` status, JSON content type/body, and `Retry-After` header;
- requests without `CallerCtx` pass through and create no bucket;
- different token names are isolated;
- rate exhaustion takes precedence over a saturated concurrency gate;
- when rate quota is available, existing concurrency exhaustion still returns
  its exact `503` contract;
- cancellation/downstream errors do not refund consumed quota;
- the `token_rate` metric increments once per rejection and has no token label;
- all pre-existing overload-response metric tests continue to pass unchanged.

### Binary HTTP contract tests

Add matching tests to `rust-junosmcp/tests/http_limits.rs` and
`rust-srxmcp/tests/http_limits.rs`:

1. Start the real binary with bearer authentication, `rate = 1`, and
   `burst = 1`.
2. Send one initialize request and verify it is admitted.
3. Immediately send a second request using the same token.
4. Assert exact `429`, `Retry-After: 1`, JSON body, and absence of an MCP
   session ID.

The process guard handles cleanup. No request opens a NETCONF/SSH connection and
no device inventory entry is contacted.

## Documentation

Update:

- the root README resource-limit table with both flags/env vars/defaults;
- the README behavior section with `429`, the stable body, and configuration
  validation;
- the README guidance to use RPS limiting for bursts of short calls and
  concurrency limits for simultaneous expensive NETCONF/SSH work;
- `docs/METRICS.md` to include `token_rate` in the bounded `limit` label set;
- root `CHANGELOG.md` and `rust-srxmcp/CHANGELOG.md` with endpoint-parity notes;
- remove the README line that still calls #150 deferred.

## Compatibility and Security

- Defaults keep the limiter disabled, so existing deployments behave exactly
  as before until both knobs are set.
- The MCP wire schema and tool behavior are unchanged for admitted traffic.
- Existing auth scopes and token-file schema are unchanged; rate values are
  process-wide operator settings, not token-file properties.
- Existing `503` overload semantics remain stable. The only new response is a
  `429` for configurations that explicitly enable this feature.
- No new dependency or lockfile update is expected.
- Fixed-point saturating arithmetic prevents overflow/panic from large CLI
  values.
- Authentication precedes token-name lookup, so arbitrary unauthenticated
  input cannot create map entries.
- Metric labels remain a fixed allowlist and never contain caller identities.

## Verification and Handoff

Run the repository-required offline gates using the exact recipes because
`just` is unavailable in the environment:

1. `cargo fmt --all --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace --locked`
4. both binary `--help` checks corresponding to `just e2e`
5. Trivy filesystem scan corresponding to `just security`
6. repeat the fmt/lint/test/security combination corresponding to
   `just release-check`

Ignored real-device/network tests are not run because
`CONFIRM_LAB_INTEGRATION=yes` is not authorized. Handoff reports all changed
files, command results, compatibility, skipped checks, and remaining risk.

## Acceptance-Criteria Traceability

| Issue #150 criterion | Design evidence |
|---|---|
| Per-token token-bucket, configurable rate + burst, `0 = disabled` | Shared exact bucket keyed by `CallerCtx.token_name`; two validated `u64` knobs; `0/0` disable contract |
| Over-rate → `429` + `Retry-After`, distinct from `503` | Dedicated stable response helper and rate-before-concurrency layer order |
| Composes with concurrency + session caps | Separate ordered middleware; precedence and unchanged-503 tests |
| Tests for refill/burst behavior | Deterministic fixed-point clock-driven bucket suite plus middleware and both-binary tests |
| Document knob and rate-vs-concurrency usage | README table/behavior/guidance, metrics docs, and both changelogs |

## Remaining Risk

The per-token bucket map retains historical logical token names until process
restart. Those names are administrator-provisioned and the existing per-token
concurrency map has the same lifecycle, so remote callers cannot drive
unbounded cardinality. If high-churn automated token-name provisioning becomes
a supported deployment model, both maps should gain coordinated retirement or
reload-aware pruning in a separate change.
