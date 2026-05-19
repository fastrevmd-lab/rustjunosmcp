# rmcp 0.8.5 streamable-HTTP client-disconnect cancellation (issue #44, Half B)

**Date:** 2026-05-19
**Status:** design draft — pre-filing
**rmcp version observed:** 0.8.5
**Companion work:** PR #54 (Half A — `notifications/cancelled` + server timeout)

## Problem statement

When a JSON-RPC client connected to RustJunosMCP over rmcp's streamable-HTTP
transport closes the underlying TCP connection mid-request, the in-flight
tool future on the server is **not cancelled**. It detaches from the HTTP
response lifecycle and runs to natural completion as a zombie task.

For destructive tools (`upgrade_junos`, large-image `transfer_file`) this
means an operator who Ctrl-Cs their MCP client — or whose client hits its
own read timeout — still triggers the full server-side effect, with no
way to abort.

Half A (PR #54) closes the two cancellation paths rmcp 0.8.5 *does*
honor today:

1. explicit JSON-RPC `notifications/cancelled` from the client
2. server-side per-request timeout

Half B is the remaining gap: **raw TCP disconnect → request cancellation**.
This gap lives in the rmcp transport layer, not in RustJunosMCP. We can
only mitigate it locally (audit/diagnostic instrumentation); the actual
fix has to ship in rmcp.

## Evidence

Conclusive live test on vSRX-test16, 2026-05-19, against v0.5.8 in LXC
601 with the PR #50 diagnostic instrumentation (`entry_diag`, `phase_diag`,
`step_diag`, `scp_diag`, `drop_diag`):

| Time     | Event                                                         |
|----------|---------------------------------------------------------------|
| 15:22:15 | client invoked `upgrade_junos` (curl `--max-time 30`)         |
| 15:22:15 | server: Phase 2 entered, `transfer_file::scp_diag phase=run`  |
| 15:22:45 | **client TCP disconnect** (curl 30s deadline)                 |
| 15:23:21 | server: SCP completed (+36 s post-disconnect) — zombie still running |
| 15:23:47 | server: `transfer_done` reached                               |
| 15:23:49 | server: opened a fresh NETCONF session post-reboot            |
| 15:27:42 | server: `audit outcome="error"` + `drop_diag consumed=true` (post-reboot NETCONF reopen naturally failed) |

Two unambiguous conclusions:

1. The Tokio future was **never dropped** between 15:22:45 and 15:27:42 —
   `drop_diag` only fired at the very end, after natural completion.
2. The device was actually upgraded to 25.4R1.12 by the zombie call.

This invalidates the earlier assumption (in #43 / v0.5.4) that rmcp 0.8.5
drops the request future on TCP close. It does not. The `UpgradeAuditGuard`
RAII pattern shipped in v0.5.4 therefore cannot detect this case on its own.

A separate 2026-05-18 trace under v0.5.3 (before PR #50 instrumentation
landed) appeared to show the future *was* dropped — no audit line ever
fired. We now read that as: the audit line *did* fire, but ~6–8 minutes
after the HTTP disconnect, well past when the operator stopped watching
the journal. v0.5.3 had no `drop_diag` to distinguish "future dropped"
from "future ran to completion silently".

## Scope: what Half B is and is not

Half B is **a rmcp transport-layer change**. RustJunosMCP cannot detect
TCP disconnect on its own — by the time control returns to a `#[tool]`
handler, the body+parts split has already happened and the original
`http::Request` is gone. The signal must come from the streamable-HTTP
transport layer itself, propagated into the `RequestContext::ct` token
(or an equivalent surface).

Half B is **not** any of:

- progress notifications (separate work, tracked in #42 mitigation notes)
- a workaround for clients with short read timeouts (use pre-staging + a
  long enough server-side timeout instead)
- detecting "the client process died" — only what its TCP stack told ours

## What an upstream fix likely looks like

Investigation needed in `rmcp::transport::streamable_http_server` (the
`tower.rs` and `session/local.rs` modules in particular). The streamable-
HTTP server today spawns the tool future via the session manager and
returns the response as an SSE stream (or a single JSON body in stateless
mode). When the client TCP-closes, axum/hyper see the disconnect and
drop their write half of the response body, but the spawn handle for the
tool future is not joined — it runs to completion.

Two candidate shapes for the fix:

### Option A — bind the request token to the response body lifecycle

In the transport, before spawning the tool future, take a clone of the
`CancellationToken` that already feeds `RequestContext::ct`. Wrap the
SSE response body in a guard whose `Drop` impl calls `token.cancel()`.
axum will drop the response body when it observes the client gone; the
token fires; every `#[tool]` handler that already uses
`select_cancel{,_raw}` (post-Half-A) wakes up and exits.

Pros:

- Reuses the existing `RequestContext::ct` surface — no new public API.
- Half A's cooperative-cancellation work in RustJunosMCP needs zero changes.
- Implementation is local to one or two files in the streamable-HTTP server.

Cons:

- SSE keep-alive (`sse_keep_alive=15s`) needs to be the disconnect detector;
  there's no hyper API to learn about a closed connection asynchronously
  outside of attempting a write. The keep-alive write is the natural probe,
  so disconnect detection latency is bounded by `sse_keep_alive`.
- Stateless mode (no SSE — single JSON response) is trickier; the writer
  task may not learn about disconnect until it tries to flush the final
  body. Mitigation: emit a zero-byte chunk periodically while the tool
  future runs, so the writer task gets a `BrokenPipe` and can fire the token.

### Option B — explicit session-manager hook

Extend `LocalSessionManager` with a `cancel_in_flight(session_id)` method
that fires the per-request token. The streamable-HTTP server's existing
session-close path (DELETE `/mcp`, idle-session reaper) already knows when
a session is gone; call `cancel_in_flight` from there.

Pros:

- More explicit; easier to reason about.
- Doesn't require touching SSE writer internals.

Cons:

- Detecting TCP-disconnect-but-no-DELETE still requires Option A's
  write-probe mechanism — sessions don't autoclose on TCP close today.
- New public surface on `SessionManager` that downstream implementors
  have to provide.

Most likely outcome: ship A (write-probe + token-fire-on-body-drop) and
optionally add B as an explicit operator escape hatch.

## Investigation tasks before filing

- [ ] Reproduce the 2026-05-19 trace with a minimal rmcp example (no
      RustJunosMCP code) — confirms the bug is rmcp-side, not anything we
      did. Use `examples/servers/src/counter_streamhttp.rs` from rmcp +
      a long-sleep tool.
- [ ] Read `rmcp/crates/rmcp/src/transport/streamable_http_server/` end
      to end; identify the precise spawn site and the lifetime of
      `RequestContext::ct`. Find the place where Option A's Drop guard
      would attach.
- [ ] Check rmcp 0.9 / main branch — the fix may already be in flight.
- [ ] Survey other rmcp transports (`stdio`, `child-process`,
      `streamable-http-client`) for how they handle peer disconnect.
      The fix should be consistent with their behavior.

## Workarounds available today

Without an upstream rmcp fix, operators have:

- **`notifications/cancelled`** — works today (Half A). The client must
  still be connected to send it.
- **Per-request timeout** — works today (Half A). Set a reasonable upper
  bound on tool duration; if it elapses the token fires.
- **Pre-stage large transfers**. `transfer_file` standalone with a long
  timeout (e.g. 1200s) avoids the zombie risk for `upgrade_junos` Phase 2,
  which then idempotent-skips in <60s. See
  `memory/upgrade_junos_client_disconnect.md`.
- **Audit correlation by request ID**. PR #50's `entry_diag` /
  `phase_diag` lines + the post-completion `audit` line let an operator
  reconstruct what happened to a zombie call, even though they couldn't
  abort it.

## Local mitigations carried in v0.5.9

PR #54 ships a defensive `UpgradeOutcome::Unsettled` audit state in
`UpgradeAuditGuard`. Given the 2026-05-19 finding (futures run to
completion, the Drop guard *will* see them consumed), `Unsettled` is
not expected to fire under the rmcp 0.8.5 transport — the normal Ok/Err
arms will set `Settled` first. We keep the state anyway:

- It costs nothing.
- If upstream lands Option A (or an equivalent) and starts dropping
  futures on disconnect, our audit immediately distinguishes Cancelled
  (token fired) from Unsettled (future dropped) without further changes.
- Test coverage is already in `server::upgrade_audit_guard_tests`.

## Open questions

1. Does the upstream fix need to be opt-in (config flag) for backward
   compat? Existing rmcp consumers may rely on zombie completion.
2. Does the SSE keep-alive interval (default 15s) need to be tunable
   per-request, or is 15s acceptable as the cancellation latency floor?
3. For stateless / single-JSON-response mode: is a write-probe acceptable,
   or do we need a separate connection-watch task?

## Action items

- [ ] Land PR #54 (Half A) — this PR.
- [ ] Cut v0.5.9 bundling PR #50 (diagnostics) + PR #54 (Half A).
- [ ] Reproduce the bug with a minimal rmcp-only example.
- [ ] Draft and file the upstream rmcp issue (link this doc).
- [ ] Track upstream fix; remove the defensive `Unsettled` state if and
      when no longer needed (or, more likely, keep it as the canonical
      "future dropped" audit surface).
