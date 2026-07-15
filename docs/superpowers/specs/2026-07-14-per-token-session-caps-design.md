# Per-Token MCP Session Caps Design

**Issue:** #148
**Date:** 2026-07-14
**Status:** Approved for implementation planning

## Summary

The streamable-HTTP endpoints already enforce global session count, session
idle/lifetime reaping, per-token request concurrency, and per-router request
concurrency. They do not limit how many long-lived MCP sessions one bearer
token can create. A single credential can therefore consume the global session
budget and deny session creation to otherwise independent callers.

Both HTTP servers will add a per-token MCP session cap of `16` by default. The
cap is keyed by the exact authenticated `CallerCtx.token_name`; `0` disables
the cap. Admission is an atomic reservation in the existing concurrency
middleware. A successful initialize response commits the reservation to the
returned `Mcp-Session-Id`; failed, invalid, or cancelled initialization releases
the reservation through RAII. Session close and reaping remove the binding and
return the token slot.

## Goals

- Enforce an exact, race-free session cap per bearer-token name.
- Keep token populations isolated: saturation for one token must not affect
  another token except through the existing global cap.
- Correlate successful session initialization with the token that created it.
- Release accounting on explicit close and idle/lifetime reap.
- Return an immediate, stable HTTP overload response without queueing.
- Apply identical behavior to `rust-junosmcp` and `rust-srxmcp` through the
  shared limits crate.
- Preserve stdio, MCP schemas, tool outputs, auth scopes, audit fields, device
  I/O, and existing global/session/concurrency semantics.

## Non-Goals

- Per-token request-rate limiting; that remains issue #150.
- Prometheus metrics; that remains issue #149.
- Closing the global `LimitedSessionManager::create_session` overshoot race;
  that remains issue #151.
- Persisting token ownership across process restart or an external rmcp session
  store. Both current endpoints use `LocalSessionManager` without an external
  session store.
- Applying token accounting in explicit no-auth mode, where no token identity
  exists. The existing global cap still applies there.

## Public Configuration

Add one field to `LimitsConfig`:

```text
max_sessions_per_token: usize
```

The default is `16`; `0` means unlimited/disabled.

| Binary | CLI | Environment |
|---|---|---|
| Junos | `--max-sessions-per-token` | `JMCP_MAX_SESSIONS_PER_TOKEN` |
| SRX | `--max-sessions-per-token` | `JMCP_SRX_MAX_SESSIONS_PER_TOKEN` |

The effective value is logged at startup with the other HTTP limits. Existing
flags and environment variables retain their meanings and defaults.

## Considered Approaches

### 1. Middleware reservation and response binding (selected)

The auth middleware already establishes `CallerCtx` before the concurrency
middleware. The concurrency middleware can atomically reserve a token session
slot before calling rmcp and can inspect the returned response header to learn
the new session ID. This gives the overload path full HTTP control and cleanly
maps saturation to 503.

This approach uses only public Axum/rmcp behavior, requires no task-local state,
and keeps admission close to the existing global-session early shed.

### 2. Tokio task-local caller context

The auth layer could scope `next.run` with a task-local token value and
`LimitedSessionManager::create_session` could read it. That would associate the
token at session creation, but it creates implicit coupling between two crates
and depends on task-local propagation through rmcp internals. Tests and future
rmcp upgrades would be more fragile.

### 3. Custom or forked rmcp streamable-HTTP service

Changing the service-to-session-manager interface to pass request context would
be explicit, but it would duplicate or fork substantial rmcp protocol code and
create an unnecessary upgrade burden.

## State Model

`SessionTracker` keeps its existing global activity map and gains a small,
mutex-protected token-accounting state:

```text
TokenSessionState {
    counts: HashMap<String, usize>,
    sessions: HashMap<SessionId, String>,
    pending_reservations: usize,
    created_unbound: HashSet<SessionId>,
    closed_before_bind: HashSet<SessionId>,
}
```

The mutex makes count reservation, pending-wave coordination, binding, and
release atomic across all token state. These operations contain no await points
and are short relative to HTTP or device work.

### Reservation

`SessionTracker::try_reserve_token`, called on an `Arc<SessionTracker>`, returns
an owned `TokenSessionReservation` when the token is below its cap. The method
increments the token count and `pending_reservations` together while holding the
state mutex. At capacity it makes no state change and returns the current count
to support structured logging.

The reservation owns the tracker and token name. Until committed, dropping it
decrements the token count and pending count with one shared completion helper,
and removes a zero-valued token entry. When the last pending reservation
completes, the helper clears every transient `created_unbound` and
`closed_before_bind` ID. Coordination lifetime is therefore bounded by the
current pending-reservation wave. This covers:

- malformed or non-initialize POST requests without a session header;
- rmcp/service errors;
- initialization responses without a session ID;
- request cancellation or middleware future drop.

After the inner session manager returns a newly created session ID,
`LimitedSessionManager::create_session` immediately records that ID in
`created_unbound` before attempting best-effort global registration. The hook
records only while at least one token reservation is pending. This makes actual
rmcp creation—not arbitrary close traffic—the authority for unbound IDs while
retaining a single token-state mutex.

### Commit

After `next.run(req).await`, middleware recognizes successful initialization by
a successful HTTP status plus an `Mcp-Session-Id` response header. It parses the
header using the same exact string representation as rmcp and commits the
reservation to that session ID under the token-state mutex. A malformed header
is treated as an internal anomaly: warn and release the uncommitted reservation.

Commit first preserves any existing `sessions` binding as the authoritative
owner. It then checks and removes its session ID from `closed_before_bind`. A
match means close or reap won before response binding: commit warns, explicitly
releases the mutex guard, returns false, and reservation drop rolls back both
the token and pending counts. Otherwise commit requires and removes the ID from
`created_unbound`. A response ID that was not recorded at creation is warned
and rolled back. A known-created ID is bound without changing the
already-reserved token count, completes the pending reservation, and transfers
token ownership to the session.

Commit does not consult global `activity`. The separate global cap remains
best-effort under #151: `LimitedSessionManager::create_session` records creation
before global `try_register`, so a live inner session can still bind to its
reserved token slot even when global tracking rejects it.

All close-before-bind coordination uses only the token-state mutex. If commit
binds first, a later unregister removes and decrements that binding. If
unregister wins first, it records the session ID and commit rolls back. Both
orders reclaim ownership exactly once without a second lock or lock-order
dependency.

### Release

`SessionTracker::unregister` performs both existing global cleanup and token
cleanup. If `sessions.remove(id)` yields a token name, it decrements that
token's count exactly once and removes the count entry at zero. If no committed
binding exists, unregister moves the ID from `created_unbound` to
`closed_before_bind`. Unknown IDs and repeated unregister calls make no state
change. The combined coordination cardinality is therefore bounded by actual
session IDs recorded at creation during a pending wave, not by arbitrary close
traffic. With no pending reservation—including cap-zero and no-auth
operation—the creation hook and unregister do not grow token state.

The existing reaper calls `inner.close_session` and then `unregister`, so idle
and lifetime eviction release token capacity without another code path.

## Request Flow

The layer order remains:

```text
RequestBodyLimitLayer
  -> auth_layer (sets CallerCtx)
    -> concurrency_middleware
      -> StreamableHttpService / LimitedSessionManager
```

Within `concurrency_middleware`:

1. Acquire the existing global request permit when enabled.
2. Acquire the existing per-token request permit when enabled.
3. For a POST without `Mcp-Session-Id`, perform the existing global-session
   early-cap check.
4. If the request has `CallerCtx` and the new cap is enabled, atomically reserve
   one session slot for `CallerCtx.token_name`.
5. Continue existing per-router admission. Initialization normally carries no
   router target; any early body/read failure drops the reservation.
6. Run rmcp. If rmcp creates a session, the limited manager records the
   returned ID as created-but-unbound before best-effort global registration.
7. If the response is successful and contains a valid `Mcp-Session-Id`, commit
   the token reservation only when that exact created ID remains open. A
   close/reap marker or unrecorded response ID rolls back. Otherwise let the
   reservation drop and release.
8. Attach request-concurrency permits to the response body as today. Session
   accounting is not tied to response-body lifetime; it persists until close or
   reap.

This reserves before rmcp creates a session, so concurrent initialize bursts
cannot overshoot the per-token cap. It intentionally does not change the
separate global-manager overshoot tracked by #151.

## Overload Contract

At per-token session capacity, initialization is rejected immediately:

```http
HTTP/1.1 503 Service Unavailable
Retry-After: 1
Content-Type: application/json

{"error":"overloaded","limit":"token_session_cap"}
```

The rejection is not queued and does not invoke rmcp. A structured warning is
emitted with `limit = "token_session_cap"`, exact token name, current count, and
configured maximum. Existing overload bodies and content types are unchanged.

## Edge Cases and Invariants

- Exact token names are used without case folding or whitespace normalization.
- Token rotation that retains a token name shares the existing population;
  revoking a credential does not silently orphan or reclassify live sessions.
- A new credential reusing an existing token name shares that name's cap until
  older sessions close or reap.
- No-auth requests have no `CallerCtx` and skip this cap.
- Invalid POST requests may reserve briefly but must release before returning.
- Cancellation before response binding must release exactly once.
- Close or reap before response binding makes commit fail and roll back; close
  after binding removes the committed token ownership.
- A live session rejected only by best-effort global tracking still binds its
  token reservation; hardening that global cap remains #151.
- Explicit close, reaper close, and repeated unregister are idempotent.
- Unknown unregister IDs never create pending coordination state.
- The combined created/closed coordination cardinality is bounded by actual
  session creation notes in the current pending wave.
- The last pending completion clears all transient created and closed IDs.
- Zero disables reservation work; creation noting and unregister cannot grow
  token state.
- The token map contains only names with a positive reserved/live count.

## Testing Strategy

### Shared limits crate

- Default/config tests verify `16` and `0` behavior.
- Tracker tests prove same-token saturation, different-token isolation,
  reservation-drop rollback, commit, explicit unregister, idempotency, and map
  reclamation, including barrier-synchronized contention at the configured cap.
- Close- and reaper-oriented tests prove expiration releases a committed token
  slot and that close/reap before response binding rejects a late commit.
- A saturated-global-tracker test proves the still-live inner session binds and
  later unregister releases its token ownership even without global activity.
- Pending-coordination tests prove the known-created transition, close/reap
  rollback, last-commit/drop cleanup, rejection of unrecorded response IDs,
  no growth across 10,000 arbitrary unregister IDs, and no state growth when
  the cap is zero or no reservation is pending.
- Middleware tests prove:
  - one live session for token A sheds A's second initialize at cap 1;
  - token B still initializes;
  - overload is 503 + `Retry-After: 1` + JSON content type and stable body;
  - a handler error or response without `Mcp-Session-Id` releases the slot;
  - request cancellation releases the reservation;
  - successful response-header binding persists beyond response-body drop.

### Binary parity

- Junos and SRX CLI tests verify default `16`, explicit `0`, and custom values.
- Offline HTTP coverage verifies both binaries expose the flag; authoritative
  state-machine behavior remains in the shared crate.

### Full verification

Run the repository-required offline checks: formatting, strict Clippy, locked
workspace tests, guards, offline CLI help, Trivy, and release-check equivalents.
Do not run ignored real-device tests or contact a device.

## Documentation and Compatibility

Update the README resource-limit table and both Unreleased changelogs. Remove
per-token session caps from the deferred #131 list. Document that the cap
applies only when bearer auth supplies a token identity.

This is an additive, enabled-by-default HTTP availability control. Existing
sessions and protocol payloads are unchanged. Stdio, MCP schemas, annotations,
auth scopes, audit fields, overload formats for existing limits, device lease
semantics, and device I/O remain unchanged. No new external dependency is
required.

## Handoff Risks

- The middleware identifies a session-creating candidate as POST without an
  `Mcp-Session-Id`; invalid requests can reserve temporarily but are released
  unless rmcp returns a session ID.
- Current local sessions are not restored across process restart. If an
  external rmcp session store is enabled later, restored-session token
  ownership needs a separate authenticated rebind design.
- Issue #151 remains responsible for making the global manager registration a
  hard backstop rather than best-effort.
