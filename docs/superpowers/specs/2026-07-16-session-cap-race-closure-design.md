# Close the Global Session-Cap Race — Design

**Issue:** #151
**Date:** 2026-07-16
**Status:** Approved

## Summary

Both streamable-HTTP binaries use the shared
`rust-junosmcp-limits::LimitedSessionManager` to enforce the configured global
MCP session cap. The concurrency middleware rejects an obvious initialize
request when the tracker is already full, but that check is only an optimization:
concurrent initialize requests can all observe spare capacity before any of them
registers a session.

`SessionTracker::try_register` already resolves that race atomically. The defect
is that `LimitedSessionManager::create_session` discards its `false` result and
returns the just-created inner session anyway. The tracker stays bounded, but the
inner manager temporarily owns an untracked live session until another path
eventually closes it.

This change makes the manager a hard backstop. A race loser closes the inner
session, returns a typed capacity error, and causes the shared HTTP middleware to
replace rmcp's generic internal-error response with the same stable session-cap
503 used by the early-shed path.

## Goals

- Make `max_sessions` a strict cap for the reachable concurrent-initialize path.
- Close every just-created inner session whose atomic registration is rejected.
- Ensure cleanup continues even if the client disconnects or the request future
  is cancelled while cleanup is in progress.
- Return the existing client contract for both binaries:
  - HTTP `503 Service Unavailable`;
  - `Retry-After: 1`;
  - `{"error":"overloaded","limit":"session_cap"}`.
- Preserve global and per-token accounting without untracked or leaked sessions.
- Preserve all existing inner-manager errors and non-cap request behavior.
- Add deterministic concurrency, cleanup, response-isolation, and endpoint tests.

## Non-Goals

- Changing the configured cap, defaults, flags, or environment variables.
- Changing per-token session-cap admission or ownership semantics from #148.
- Adding queues or retries for initialize requests.
- Forking or patching rmcp.
- Changing rmcp's generic handling of non-cap `SessionManager` errors.
- Hardening external session-store restore. Neither binary configures an external
  `SessionStore`; `restore_session` therefore remains outside the reachable path
  addressed by this issue.
- Changing stdio transport, MCP schemas, tool annotations, auth scopes, audit
  events, device I/O, or packaged service defaults.

## Current Behavior and Root Cause

The request path is:

1. `concurrency_middleware` classifies a POST without `Mcp-Session-Id` as a
   session-creating candidate.
2. If `SessionTracker::at_capacity()` is already true, middleware returns the
   stable session-cap 503 without invoking rmcp.
3. Otherwise rmcp calls `LimitedSessionManager::create_session`.
4. The inner `LocalSessionManager` creates and stores a live session.
5. `SessionTracker::try_register` uses `fetch_add` plus rollback to admit at most
   `max_sessions` IDs atomically.

The current wrapper ignores the boolean from step 5. If two requests pass step 2
concurrently at a cap of one, both inner sessions can be created, one tracker
registration succeeds, the other registration fails, and both sessions are
returned to rmcp. The existing unit test
`globally_untracked_live_session_still_binds_token_reservation` documents that
best-effort behavior.

The pinned rmcp 2.0.0 `StreamableHttpService` maps every `create_session` error
through `internal_error_response`, producing HTTP 500. Current upstream rmcp
2.2.0 retains the same trait and mapping, so a custom error alone cannot satisfy
the stable 503 acceptance criterion.

## Chosen Architecture

### Typed wrapper error

Add a public generic error type:

```rust
pub enum LimitedSessionManagerError<E> {
    Inner(E),
    SessionCapExceeded,
}
```

`Inner(E)` transparently wraps all existing `S::Error` values. The wrapper's
`SessionManager::Error` becomes `LimitedSessionManagerError<S::Error>`, and every
delegated method maps inner failures to `Inner` without changing their text or
control flow.

`SessionCapExceeded` has a fixed, non-sensitive display string. It is returned
only after an inner session was created and its global registration lost the
atomic cap race.

### Race-loser cleanup

`create_session` performs these steps after the inner create succeeds:

1. Record the new ID with `note_session_created` so any pending per-token
   reservation can coordinate with close/reap exactly as it does today.
2. Call `try_register` with the ID.
3. On success, return the ID and transport unchanged.
4. On rejection:
   - explicitly drop the unused transport;
   - call `tracker.unregister(&id)` so created-but-unbound token coordination is
     moved to its closed state without decrementing the already-rolled-back
     global counter;
   - clone the inner manager and ID into a spawned Tokio cleanup task;
   - run `inner.close_session(&id)` in that task;
   - normally await the task before returning;
   - log an inner close error or task panic with the rejected session ID;
   - mark the current request as a session-cap rejection;
   - return `SessionCapExceeded` regardless of cleanup's result.

Spawning before awaiting is intentional. If the outer `create_session` future is
dropped while cleanup is waiting on an inner lock or close operation, dropping
the `JoinHandle` does not abort the cleanup task. The inner session is still
closed. In the normal path, awaiting preserves the intuitive contract that the
manager has attempted and completed cleanup before it returns the error.

The capacity response wins over a cleanup error. For the deployed
`LocalSessionManager`, the session is removed from its map before its close
future can report a worker-close error. Logging the cleanup result retains
diagnostic evidence without changing the stable overload response.

### Request-local rejection bridge

Add a Tokio task-local boolean in the shared limits crate. Two crate-private
helpers provide the only access:

- scope an async request future with a fresh `false` marker and return both the
  future's output and the final marker value;
- set the current marker to `true`, doing nothing when called outside a scoped
  HTTP request.

For a session-creating candidate, `concurrency_middleware` runs
`next.run(request)` inside a fresh marker scope. A race-losing manager sets that
scope immediately before returning `SessionCapExceeded`. rmcp converts the typed
error to its normal 500 response, but control then returns to the same scoped
middleware future. If the marker is true, middleware discards that rmcp response
and returns `overload_response("session_cap")` instead.

This bridge is selected because it is:

- request-local under concurrent traffic;
- independent of rmcp response-body wording;
- contained in the already-shared limits crate;
- free of dependency forks or patches;
- inactive for non-initialize requests and non-cap errors.

Ordinary downstream 500 responses remain untouched. The bridge does not parse,
buffer, or match their response bodies.

rmcp logs the typed manager error as an internal error before middleware replaces
the response. That upstream log level cannot be changed without patching rmcp;
the wrapper also emits a structured capacity warning so operators can classify
the expected overload accurately.

## Detailed Request Flow

### Fast-path rejection

When the tracker is already full at middleware admission:

1. `at_capacity()` is true.
2. Middleware returns `overload_response("session_cap")` immediately.
3. rmcp and the inner manager are not invoked.

This behavior is unchanged.

### Successful concurrent winner

1. Middleware observes available capacity and enters a fresh task-local scope.
2. The inner manager creates a session.
3. `try_register` atomically reserves the final global slot.
4. The manager returns the session to rmcp.
5. Initialization succeeds and middleware receives a success response with
   `Mcp-Session-Id`.
6. Any per-token reservation commits to that exact ID.
7. Normal close or reaping later unregisters both global and token ownership.

### Concurrent race loser

1. Middleware also observed available capacity before the winner registered.
2. The inner manager creates a second session.
3. `try_register` rejects it and rolls the global counter back atomically.
4. The wrapper records closed-before-bind token coordination, drops the unused
   transport, and runs cancellation-safe inner cleanup.
5. The wrapper marks the request-local scope and returns
   `SessionCapExceeded`.
6. rmcp builds its generic internal-error response.
7. Middleware sees the marker and replaces that response with the stable
   session-cap 503.
8. Because the final response is not successful and has no session ID, any
   per-token reservation drops and releases exactly once.

### Cancelled race loser

If the request is cancelled after the cleanup task is spawned, the middleware
future and token reservation drop, but the spawned cleanup task continues to
close the inner session. No response is sent to the disconnected client, and no
inner or tracker population remains.

## Error Semantics

- `LimitedSessionManagerError::Inner(error)` preserves the prior error's display
  and source chain and remains an rmcp-generated HTTP 500.
- `SessionCapExceeded` is the only error that sets the request-local marker.
- A missing task-local scope does not panic. Direct library callers receive the
  typed error and can handle it themselves.
- Inner cleanup errors and join failures are logged, but the manager still
  returns `SessionCapExceeded`.
- Existing close, reaper, touch, resume, and disabled-cap behavior is unchanged.
- `max_sessions = 0` always admits and never creates a capacity error.

## Accounting and Metrics

`try_register` continues to record:

```text
limit="session_cap", event="session_registration_rejected"
```

for the atomic race loser. Translating the response through
`overload_response("session_cap")` also records:

```text
limit="session_cap", event="request_rejected"
```

These are intentionally separate observations: one records the manager-level
race backstop, and the other records the client-facing HTTP shed. The active
session gauge never exceeds the configured cap.

No new metric name, label, or unbounded value is introduced.

## Testing Strategy

### Manager concurrency and cleanup tests

Implement a deterministic test-only `SessionManager` and transport. Its
`create_session` calls insert unique live IDs and wait on a barrier before
returning, ensuring all concurrent inner sessions exist before wrapper
registration begins.

With `max_sessions = 1` and multiple concurrent creates, assert:

- exactly one call returns `Ok`;
- every other call returns `SessionCapExceeded`;
- every rejected ID is passed to inner `close_session` exactly once;
- the inner live-session set and tracker each contain only the winner;
- closing the winner returns both populations to zero;
- the active-session gauge never reports an overshoot.

Add focused variants proving:

- a cleanup error still returns `SessionCapExceeded` and leaves no live inner
  ID when the inner manager removes before reporting the error;
- aborting a rejected outer create while inner cleanup is blocked does not
  abort cleanup; after releasing the close barrier, all loser state is gone;
- ordinary inner create and delegated-method failures remain `Inner` errors.

### Middleware response-isolation tests

Use concurrent Axum requests to prove:

- a downstream response whose scope is marked becomes the exact existing
  session-cap 503 with `Retry-After: 1` and stable body;
- a simultaneous unmarked HTTP 500 remains 500;
- the marker does not leak across requests or later calls on the same task;
- the client-facing overload metric is incremented only for the marked request;
- any pending token reservation rolls back and leaves no token ownership.

### Binary HTTP tests

Extend both `rust-junosmcp/tests/http_limits.rs` and
`rust-srxmcp/tests/http_limits.rs` with the same behavior:

1. Start the binary with `--max-sessions 1`.
2. Initialize one session successfully.
3. Send a second initialize and assert 503, `Retry-After: 1`, no session ID, and
   `limit = "session_cap"`.
4. Close the first session.
5. Initialize and close a replacement successfully.

The deterministic shared-crate test proves the race backstop itself. The two
binary tests prove the stable public contract and shared wiring on both
endpoints.

### Repository verification

Run the required offline commands:

- `cargo fmt --all --check`;
- `cargo clippy --workspace --all-targets -- -D warnings`;
- `cargo test --workspace --locked`;
- both binary `--help` e2e checks;
- Trivy vulnerability, misconfiguration, and secret scanning;
- repository guard and release-check equivalents when `just` is unavailable.

Do not run ignored or real-device integration tests without
`CONFIRM_LAB_INTEGRATION=yes`; this issue requires no device interaction.

## Documentation and Release Notes

Update current operator-facing material only:

- README resource-limit behavior for a strict, race-safe global session cap;
- `docs/METRICS.md` to explain that a race backstop produces both manager-level
  and client-facing session-cap events;
- root and SRX changelogs under `Unreleased / Fixed`;
- any current source comments that still describe global registration as
  best-effort.

Previously committed design and implementation-plan documents remain historical
records and are not rewritten.

## Compatibility

- No configuration, default, CLI, environment, MCP schema, annotation, auth,
  audit, timeout, device, package, or dependency change.
- Existing successful HTTP sessions and early session-cap rejections retain the
  same wire behavior.
- Race losers change intentionally from a temporary live/untracked session and
  successful initialize to a stable 503.
- `LimitedSessionManager`'s associated `SessionManager::Error` changes from
  `S::Error` to `LimitedSessionManagerError<S::Error>`. Direct Rust consumers
  that explicitly name or pattern-match the old associated type must adapt.
  Workspace binary call sites use inference and require no behavior change.

## Alternatives Considered

### Parse an rmcp 500 response body

The manager could return a sentinel string and middleware could parse rmcp's 500
body. This uses less request-local machinery but couples correctness to upstream
error wording, requires buffering/matching response bodies, and risks rewriting
an unrelated 500. Rejected.

### Patch or fork rmcp

rmcp could expose typed error-to-response mapping. That is the cleanest upstream
API, but neither pinned 2.0.0 nor current 2.2.0 provides it. A fork or patch adds
dependency and maintenance risk disproportionate to this focused fix. Rejected.

### Move global reservation entirely into middleware

Middleware could reserve anonymous global capacity before rmcp runs, similar to
the per-token reservation. It would avoid creating a race-loser session, but it
would require new cross-layer reservation ownership and cancellation semantics,
and would not directly satisfy the issue's required `create_session` fail-closed
backstop. Rejected for this issue.

## Acceptance Criteria Mapping

| Issue #151 criterion | Design evidence |
|---|---|
| `create_session` closes the inner session and returns an error at cap | Atomic registration rejection triggers spawned-and-awaited inner close, tracker/token cleanup, and `SessionCapExceeded` |
| Client sees stable 503 + `Retry-After`; no untracked/leaked session | Task-local middleware bridge returns existing overload response; cleanup survives cancellation; response has no session ID |
| Concurrent-initialize test proves no overshoot or leak | Barrier-synchronized fake manager forces concurrent inner creation; exact winner/loser and zero-leak assertions |
| Applies to both endpoints | Behavior lives in shared limits crate; identical Junos and SRX HTTP tests verify the public contract |

## Remaining Risks

- rmcp logs the expected typed capacity error at error level before middleware
  translates the response. The shared wrapper warning and metric labels provide
  accurate classification, but changing rmcp's log level remains upstream work.
- A generic inner manager could fail before removing a session during cleanup.
  The deployed `LocalSessionManager` removes its map entry before reporting a
  worker-close failure; tests model and verify that deployed contract. Cleanup
  failures remain visible in logs.
- External session-store restore retains its previous best-effort registration
  behavior. It is not configured by either binary and is explicitly outside this
  issue's reachable concurrent-initialize scope.
