# Per-Router In-Flight Limits — Design

- **Issue:** [#147](https://github.com/fastrevmd-lab/rustjunosmcp/issues/147)
- **Date:** 2026-07-14
- **Status:** Approved

## Problem

The streamable-HTTP endpoints currently bound total in-flight requests globally
and per bearer token, but they do not bound work directed at one router. A single
device can therefore receive many concurrent NETCONF or SSH operations whenever
the global and per-token limits still have capacity. This can exhaust device-side
sessions or make one unhealthy device consume disproportionate server capacity.

Destructive workflows already use `DeviceLeaseManager` to serialize writes to a
router across the Junos and SRX processes. That lease does not protect read calls,
and requests waiting for a destructive lease are not currently bounded per router.

## Goals

1. Add an enabled-by-default, configurable per-router in-flight cap to both HTTP
   endpoints, with `0` retaining the established unlimited convention.
2. Preserve the existing overload contract: immediate HTTP 503, no queue, and
   `Retry-After: 1`.
3. Count single-router and multi-router calls accurately, including the accepted
   router-parameter aliases.
4. Compose predictably with cross-process destructive-operation leases without
   double-counting or circular waits.
5. Keep the Junos and SRX endpoints behaviorally identical through the shared
   `rust-junosmcp-limits` crate.

## Non-Goals

- No per-token session cap, Prometheus endpoint, or RPS token bucket; those remain
  separate follow-up issues.
- No change to `DeviceLeaseManager`, lease wait time, or destructive workflow
  serialization.
- No tool-schema, annotation, auth-scope, audit-field, or device-I/O behavior
  changes.
- No router-name normalization. Inventory lookup and lease hashing are exact and
  case-sensitive, so limiter keys remain exact as well.

## Decision Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Enforcement point | Existing shared HTTP concurrency middleware | Produces the required HTTP 503 before `rmcp` dispatch and guarantees endpoint parity. |
| Default | `4` concurrent requests per router | Enabled protection while allowing modest parallel reads; `0` disables it. |
| Overload behavior | Non-blocking load shed | Matches the existing global and per-token contract and prevents waiter growth. |
| Batch accounting | One permit per unique router | A multi-router call consumes capacity on every device it can load; duplicates do not double-count. |
| Permit lifetime | Through response end-of-stream | Matches existing request permits and covers lazy `rmcp` execution plus slow response consumers. |
| Registry lifetime | Weak semaphore references with opportunistic cleanup | Invalid caller-supplied router names cannot permanently grow process state. |

## Configuration

Add `max_inflight_requests_per_router: usize` to `LimitsConfig`.

| Endpoint | CLI flag | Environment variable | Default | `0` means |
|----------|----------|----------------------|---------|-----------|
| Junos | `--max-inflight-requests-per-router` | `JMCP_MAX_INFLIGHT_REQUESTS_PER_ROUTER` | `4` | unlimited |
| SRX | `--max-inflight-requests-per-router` | `JMCP_SRX_MAX_INFLIGHT_REQUESTS_PER_ROUTER` | `4` | unlimited |

Both binaries construct the same shared config field, and `LimitsConfig::log_effective`
includes the effective value at startup.

## Architecture

### Request flow

Layer order remains:

```text
RequestBodyLimitLayer
  -> authentication (sets CallerCtx)
    -> shared concurrency middleware
      -> StreamableHttpService
        -> tool handler
```

The concurrency middleware continues to acquire global and per-token permits
first. When the router cap is enabled, it then inspects a POST body only far
enough to identify router targets, acquires all required router permits with
`try_acquire_owned`, and passes a rebuilt request to `rmcp`. All acquired permits
are moved into the existing `GuardedBody`, so cancellation or end-of-stream drops
them through RAII.

Acquiring global and token permits before buffering bounds the number of bodies
being inspected concurrently. `RequestBodyLimitLayer` remains outermost, so the
configured request cap still rejects oversized bodies before the middleware
buffers them. If the operator explicitly sets the body limit to `0`, buffering is
unbounded just as it already is inside `rmcp`; global and per-token caps still
bound the number of simultaneous bodies.

### Router extraction

The middleware parses the buffered body as `serde_json::Value`. For each top-level
JSON-RPC request whose method is `tools/call`, it examines only
`params.arguments`. It recognizes these top-level argument keys:

- `router`
- `router_name`
- `routers`
- `router_names`

Each recognized value may be a string or an array of strings for limiter
extraction. Supporting both shapes makes the limiter conservative across the
existing single-router aliases, `execute_junos_command_batch`, and template
multi-router calls. It does not recursively scan nested objects, which avoids
mistaking unrelated configuration data for a target router.

The extractor collects targets from a single JSON-RPC object or every object in
a JSON-RPC array, deduplicates exact strings, and sorts them before acquisition.
Malformed JSON, non-`tools/call` methods, missing arguments, or unsupported field
types yield no router targets; the original bytes are replayed unchanged so
`rmcp` remains authoritative for protocol and tool-schema errors.

### Router semaphore registry

`ConcurrencyState` gains a router registry and `max_per_router`. The registry is
a mutex-protected map from router name to `Weak<Semaphore>`:

1. Lock the map and discard entries whose semaphore has no strong owners.
2. Upgrade an existing weak reference or create a `Semaphore(max_per_router)`.
3. Return a strong reference and store only a weak reference in the map.
4. `OwnedSemaphorePermit` holds the strong semaphore reference until the response
   stream finishes.

The registry lock is held only while looking up semaphores, never while acquiring
a permit or invoking downstream code. Active requests targeting the same router
therefore share one semaphore, while inactive and invalid names disappear during
subsequent lookups.

Router names are deduplicated and sorted before lookup and acquisition. Although
all acquisitions are non-blocking, consistent ordering prevents avoidable
cross-batch contention patterns. If any acquisition fails, the middleware drops
all permits already obtained for that request and immediately returns overload.

## Lease Composition

A destructive request follows this order:

```text
HTTP router permit (non-blocking)
  -> rmcp dispatch
    -> DeviceLeaseManager lease (bounded wait)
      -> destructive operation
```

The HTTP middleware acquires exactly one permit for the target router. Core and
SRX workflow code does not reacquire that permit. The separate file lease retains
its existing cross-process serialization role.

There is no circular wait: router permit acquisition never waits, and no code
holding a device lease calls back into the HTTP limiter. A destructive request
counts against the router cap while it waits for or holds the file lease. This
bounds destructive waiters together with read traffic instead of creating a
second unbounded queue.

For a multi-router request, one permit is held for every unique target throughout
the response. Partial acquisition is rolled back immediately on failure. The
existing tool-level batch concurrency setting continues to control how many of
those routers are actively contacted at once; the HTTP cap independently protects
each router from concurrent requests across callers and batches.

## Error Contract and Observability

A router-cap rejection uses the existing overload helper:

```http
HTTP/1.1 503 Service Unavailable
Retry-After: 1
Content-Type: application/json

{"error":"overloaded","limit":"router_concurrency"}
```

The response does not expose the saturated router name. A structured warning
records `limit = "router_concurrency"`, the router name, and configured maximum
for operator diagnosis. Existing global, token, session, and body-size responses
do not change.

Body-read failures caused by `RequestBodyLimitLayer` preserve HTTP 413. Other
unparseable bodies are replayed for `rmcp` rather than being translated into a
limiter error.

## Testing

All new behavior is developed test-first.

### Shared crate tests

Synthetic Axum handlers prove:

- a second call to the same capped router receives 503 plus `Retry-After`;
- a different router remains independent;
- `router` and `router_name` identify the same limiter key;
- `routers` and `router_names` accept string and array shapes;
- duplicate names consume one permit;
- a batch acquires every unique router and rolls back partial acquisition;
- `max_inflight_requests_per_router = 0` disables router limiting;
- non-tool and malformed requests reach the inner service unchanged;
- draining or dropping a response releases router permits;
- weak registry entries are reclaimable.

A lease-composition test uses the real `DeviceLeaseManager` through a test-only
dependency on `rust-junosmcp-core`. It holds a device lease, starts a capped HTTP
request that waits for the same lease, verifies a second same-router request is
shed instead of entering the lease wait, releases the lease, and verifies the
first request completes and its router permit becomes reusable.

### Binary and documentation tests

- Junos and SRX CLI tests verify the default of `4` and explicit `0`/custom values.
- Existing endpoint HTTP-limit tests continue to prove the 413 and happy paths.
- Focused endpoint parity tests are added where they exercise behavior not already
  authoritative in the shared crate.
- README and both changelogs document the knob, environment variables, default,
  batch accounting, overload response, and lease interaction.

## Compatibility

This is an additive HTTP availability control. It changes only concurrent
streamable-HTTP calls that exceed the new default per-router threshold. Stdio is
unaffected. Tool inputs, outputs, schemas, annotations, authorization order,
audit fields, and stable device errors remain unchanged.

The implementation adds `serde_json` to `rust-junosmcp-limits` from the existing
workspace dependency set. `rust-junosmcp-core` and `tempfile` are test-only
dependencies for lease-composition coverage. No new external runtime crate or
package version is introduced. Any `Cargo.lock` change is generated by Cargo and
limited to recording the workspace crate's new direct dependencies.

## Verification and Handoff

Run the repository's required offline checks:

- `just fmt`
- `just lint`
- `just test`
- `just guard`
- `just e2e`
- `just security`
- `just release-check`

If `just` remains unavailable, run each recipe's underlying command and report
the missing runner. Do not run `just integration` or any live-device test without
`CONFIRM_LAB_INTEGRATION=yes` and explicit target review. Handoff reports changed
files, command results, compatibility, skipped live checks, and remaining risk.
