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
}
```

The mutex makes count reservation, binding, and release atomic across both
maps. These operations contain no await points and are short relative to HTTP
or device work.

### Reservation

`SessionTracker::try_reserve_token`, called on an `Arc<SessionTracker>`, returns
an owned `TokenSessionReservation` when the token is below its cap. The method
increments the token count while holding the state mutex. At capacity it makes
no state change and returns the current count to support structured logging.

The reservation owns the tracker and token name. Until committed, dropping it
decrements the count and removes a zero-valued token entry. This covers:

- malformed or non-initialize POST requests without a session header;
- rmcp/service errors;
- initialization responses without a session ID;
- request cancellation or middleware future drop.

### Commit

After `next.run(req).await`, middleware recognizes successful initialization by
a successful HTTP status plus an `Mcp-Session-Id` response header. It parses the
header using the same exact string representation as rmcp and commits the
reservation to that session ID under the token-state mutex. A malformed header
is treated as an internal anomaly: warn and release the uncommitted reservation.

Commit moves the reservation into the `sessions` map without changing the
already-reserved count, but only while that session ID is still present in the
authoritative global `activity` map. The token-state mutex remains held across
the liveness check and binding insert. If close or reap already removed global
activity, commit warns, explicitly releases the mutex guard, returns false, and
reservation drop rolls back the token count. Session IDs are expected to be
unique. A defensive duplicate binding, whether for the same or a different
token, leaves the first binding authoritative, rolls back the new reservation
count, and emits a warning rather than incrementing or reassigning.

This ordering does not invert `unregister`: activity removal completes before
`unregister` takes the token-state mutex. If commit observes a live session and
inserts first, a concurrent unregister subsequently removes that binding. If
unregister removes activity first, commit observes the session is absent and
rolls back instead. Both orders reclaim the count and both token maps exactly
once.

### Release

`SessionTracker::unregister` performs both existing global cleanup and token
cleanup. If `sessions.remove(id)` yields a token name, it decrements that
token's count exactly once and removes the count entry at zero. Repeated close
or reap attempts are idempotent.

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
6. Run rmcp.
7. If the response is successful and contains a valid `Mcp-Session-Id`, commit
   the token reservation to that ID only if the global tracker still reports
   it live. Otherwise let the reservation drop and release.
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
- Explicit close, reaper close, and repeated unregister are idempotent.
- Zero disables both reservation work and token-accounting map growth.
- The token map contains only names with a positive reserved/live count.

## Testing Strategy

### Shared limits crate

- Default/config tests verify `16` and `0` behavior.
- Tracker tests prove same-token saturation, different-token isolation,
  reservation-drop rollback, commit, explicit unregister, idempotency, and map
  reclamation, including barrier-synchronized contention at the configured cap.
- Close- and reaper-oriented tests prove expiration releases a committed token
  slot and that close/reap before response binding rejects a late commit.
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
