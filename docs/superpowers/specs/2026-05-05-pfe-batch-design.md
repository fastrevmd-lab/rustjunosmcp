# PFE + batch execution — design

**Date:** 2026-05-05
**Sub-project of:** v0.2 (sub-project #3 of 4)
**Companion plan:** `docs/superpowers/plans/2026-05-05-pfe-batch.md` (written next)

## Goal

Two new MCP tools for the v0.2 line:

- `execute_junos_pfe_command` — one PFE-shell command on one router, against an explicit FPC target.
- `execute_junos_command_batch` — `N` routers × `M` operational CLI commands, parallel across routers, sequential per router, with per-command and optional whole-batch timeouts and a configurable concurrency cap.

Both plug into the existing scope + blocklist gating chain (sub-projects #1 and #2). PFE gets a separate blocklist rule list (`pfe_commands`) and a separate token scope, so a "CLI-only" token cannot reach PFE.

## Context

`v0.1` shipped six stdio-only tools. `v0.2`'s sub-project #1 (blocklist guardrails) and sub-project #2 (remote-transport-auth) shipped on 2026-05-05 (PRs #3 and #4). v0.2's sub-project #4 (templates + inventory mutation: `render_and_apply_j2_template`, `add_device`, `reload_devices`) is a separate effort.

This sub-project closes the "fleet operations" gap: today, asking the LLM to run the same diagnostic across 50 routers requires 50 round-trips through the model. With batch, the LLM issues one tool call and receives one structured response.

PFE is included here (rather than #4) because it is conceptually a "command flavor" alongside operational CLI: same connect path, same blocklist mechanism (just a separate rule list), same scope-check shape.

## Non-goals (deferred)

- **PFE batch.** PFE is single-call by design. A token scoped to the CLI batch tool can never reach PFE; that boundary is worth more than API symmetry.
- **CLI batch entries that mix CLI and PFE.** Same reasoning.
- **Multi-device config push.** v0.2's `load_and_commit_config` stays single-device. A multi-device config tool is a v0.3+ topic.
- **Streaming results.** Batch returns a single `tools/call` response when the whole call finishes. No incremental streaming via SSE chunks.
- **Cross-router transactions / rollback semantics.** Each router is independent; the tool is for read/diagnostic work.
- **Connection pooling beyond per-call session reuse.** When rustEZ's planned `DevicePool` lands, batch can adopt it without API change.
- **Glob / regex in `routers`.** Caller provides explicit names. (Glob expansion would conflict with token scope checks against literal router names.)

## Architecture

Tool logic lives in `rust-junosmcp-core/src/tools/`:

- New module `pfe.rs` parallel to `execute_command.rs`.
- New module `batch.rs` for the fan-out runner.

Policy and inventory grow in place:

- `policy.rs` gains `check_pfe_command(router, cmd) -> Decision` and parses a parallel `pfe_commands` rule list from `_blocklist_defaults` and per-device `pfe_blocklist`.
- `inventory.rs` gains an optional `pfe_blocklist` field per device, mirroring the existing `blocklist`.

`DeviceManager` grows a session-reuse path:

- The existing `open(name) -> Device` already returns a guard; we will keep the v0.1 contract (drop-cleanup) and just exercise multiple `cli(&str)` calls on the same handle inside `batch.rs`.
- If today's `Device` does not support multiple sequential `cli` calls, the plan spike resolves how to extend it (likely a thin wrapper that holds the open netconf/SSH session for the lifetime of the batch). The tests below assert the contract regardless of implementation.

Transport adapters in `rust-junosmcp/src/server.rs` add two `#[tool]` methods. Both use the existing `check_tool_scope` and `check_router_scope` helpers; batch loops `check_router_scope` over every router in the args before invoking the core handler.

`rust-junosmcp-auth/src/file.rs` extends `KNOWN_TOOLS` with `"execute_junos_pfe_command"` and `"execute_junos_command_batch"`. Token files that reference these names load only on a #3-or-newer binary; older binaries reject the file at parse time because `KNOWN_TOOLS` is enforced when loading. Tokens minted under v0.2.0 keep working unchanged on a #3 binary; their existing scopes simply don't grant the new tools.

## Tool surface

### `execute_junos_pfe_command`

```text
Args:
  router_name: string
  fpc_target: string          # required, no default; e.g. "fpc0"
  pfe_command: string
  timeout: u32                # seconds, per-command

Returns:
  { fpc_target: string, output: string }
```

Server runs the equivalent of `request pfe execute target <fpc_target> command "<pfe_command>"` via the existing CLI channel. Output is the captured response text. Blocklist: `policy.check_pfe_command(router, pfe_command)`. Scope: `execute_junos_pfe_command` must be in the token's tool allowlist (or `*`).

### `execute_junos_command_batch`

```text
Args:
  routers: [string]                       # non-empty
  commands: [string]                      # non-empty
  command_timeout: u32                    # seconds, per-command
  batch_timeout: u32?                     # seconds, optional whole-batch wall-clock ceiling
  max_concurrent_routers: u32?            # default 16

Returns:
  [
    {
      router: string,
      commands: [
        { command: string, ok: bool, value?: string, error?: string }
      ]
    }
  ]
```

- Returned `routers` array preserves input order. Per-router `commands` array preserves input order.
- A device-open failure for a router yields one `{ok: false, error: "<connect error>"}` entry per command in `args.commands` (so the per-router `commands` array length always equals `args.commands.len()`).
- A `command_timeout` expiry on a single command records `{ok: false, error: "command timeout"}` and the next command on that router still runs.
- A `batch_timeout` expiry cancels in-flight and pending work; not-yet-run commands get `{ok: false, error: "batch timeout"}`. Already-completed entries keep their values.

### Refusal semantics

Pre-flight is exhaustive. Before any SSH connect, the handler:

1. Resolves every router in `args.routers` against the inventory. Unknown router → `JmcpError::UnknownRouter` for the whole call.
2. Checks every (router, command) pair against `policy.check_command`. First deny → `JmcpError::Denied { tool: "execute_junos_command_batch", router, pattern, ... }` for the whole call.

If pre-flight passes, no further blocklist checks occur during execution. This matches the spirit of "blocklist is a gate, not a runtime concern" from sub-project #1.

## Concurrency mechanics

Pre-flight runs synchronously (no I/O).

Fan-out uses `tokio::sync::Semaphore` with `max_concurrent_routers` permits and a single `tokio::task::JoinSet`. Per-router tasks acquire a permit, open the device, loop the commands sequentially with `tokio::time::timeout(command_timeout, dev.cli(cmd))`, then close. `Drop` on the permit guard releases it.

`batch_timeout` wraps the JoinSet with `tokio::time::timeout`. On expiry, `abort_all()` cancels in-flight tasks. The aggregator collects whatever results landed and synthesizes `{ok: false, error: "batch timeout"}` rows for routers that did not report. Aborting at an await point relies on rustEZ's drop-cleanup semantics for the SSH session — same behavior as v0.1.

Each per-router task returns `(input_index, RouterResult)` so the aggregator can sort back into input order before serializing.

Error semantics summary:

| Failure mode                        | Effect                                                          |
| ----------------------------------- | --------------------------------------------------------------- |
| Unknown router (pre-flight)         | Whole batch rejected with `JmcpError::UnknownRouter`.           |
| Blocklist deny (pre-flight)         | Whole batch rejected with `JmcpError::Denied`.                  |
| Device-open failure                 | One row of `ok: false` for each command on that router.         |
| Per-command transport error         | That entry `ok: false`; remaining commands on the router run.   |
| `command_timeout` expiry            | That entry `ok: false, error: "command timeout"`; loop continues.|
| `batch_timeout` expiry              | Aborted entries get `ok: false, error: "batch timeout"`.        |

## Scope + blocklist integration

- `KNOWN_TOOLS` gains `"execute_junos_pfe_command"` and `"execute_junos_command_batch"`. Tokens scoped via `*` automatically receive both.
- The `#[tool]` adapter for batch calls `check_tool_scope("execute_junos_command_batch")` once, then `check_router_scope("execute_junos_command_batch", router)` for **each** router in `args.routers`. First scope failure short-circuits the whole call with the existing `ScopeError`.
- The `#[tool]` adapter for PFE calls `check_tool_scope("execute_junos_pfe_command")` and `check_router_scope("execute_junos_pfe_command", router_name)` once each.
- Stdio path remains unchanged: `caller_ctx()` returns `None`, scope checks no-op, and the blocklist gate behaves exactly as on v0.1/v0.2. Operators whose token store predates #3 cannot mint a token scoped to the new tool names without bumping the binary first.

`pfe_commands` blocklist defaults are recommended but not auto-installed. The shipped `devices-template.json` will gain a commented-out example like `_blocklist_defaults.pfe_commands = [{action: "deny", pattern: "set *"}]`.

## DeviceManager extension

If `Device::cli` already supports being called multiple times on a single open handle, no API change is needed; `batch.rs` just calls it in a loop. If the current rustEZ contract opens-then-closes per `cli`, the plan spike resolves the smallest extension to support session reuse — likely a `Device::cli_many(&[&str]) -> Vec<Result<String>>` or simply documenting that `cli` is repeatable.

The design assumes the latter is achievable in this branch. If it turns out to require an upstream rustEZ change, scope #3 narrows to single-session batch (still better than M handshakes per router) and we file an upstream issue rather than working around it.

## Inventory + policy schema changes

`devices.json` gains:

- `_blocklist_defaults.pfe_commands` — array of rule objects, same shape as `commands`.
- Per-device `pfe_blocklist` — optional, parallel to `blocklist`. Same most-specific-match-wins semantics.

Files without these fields remain backward-compatible with v0.2 and v0.1 inventories. Same compat note as the existing blocklist applies: files using these fields are not cross-compatible with Juniper/junos-mcp-server.

## Testing strategy

**Unit tests (no network):**

- `policy.rs` — `pfe_commands` parses; defaults merge; per-device override semantics; pattern globs work; `check_pfe_command` and `check_command` are independent (a deny in one does not affect the other). ~6 tests parallel to existing blocklist tests.
- `pfe.rs` — `unknown_router_propagates_error`, `denied_pfe_command_short_circuits_before_connect` (using an unreachable IP to prove pre-connect short-circuit, mirroring `execute_command.rs::tests::denied_command_short_circuits_before_connect`).
- `batch.rs` — six tests:
  - `unknown_router_in_list_aborts_preflight`
  - `denied_command_anywhere_aborts_preflight`
  - `result_ordering_matches_input` (inputs `routers=[r2,r1]`, `commands=[c2,c1]`; via stub device)
  - `concurrency_cap_is_respected` (stub device tracks peak in-flight; assert ≤ `max_concurrent_routers`)
  - `batch_timeout_marks_remaining_as_timeout`
  - `command_timeout_records_inline_and_continues`

The stub device requires a small testing seam in `DeviceManager`. The plan resolves the exact mechanism (a `cfg(test)` injectable trait, or a `DeviceFactory` indirection). A real network is not required to validate any of the above behaviors.

**Integration tests (binary-spawn, network-loopback):**

- `tests/batch_smoke.rs` — spawns the binary on streamable-http, mints a token scoped to the batch tool + 2 routers, calls the batch tool against unreachable IPs, asserts the per-router error rows; second test mints a token without the batch scope and asserts the scope-deny verdict.
- `tests/pfe_smoke.rs` — same skeleton for PFE.

**Real-device tests (ignored by default):**

One per new tool, behind `JMCP_TEST_HOST` env vars matching the v0.1 pattern. Benign payloads: `show version` for batch (one command on one router), `show jnh 0 stats packet` or similar non-mutating PFE command.

## Sub-project boundaries

This is sub-project #3 of v0.2. Sub-project #4 (templates + inventory mutation) builds on the same scope + blocklist chain and SIGHUP reload pattern but adds no shared code beyond `KNOWN_TOOLS` extension. Specifically:

- `add_device` (sub-project #4) must add new router names that any existing token's allowlist either does not cover or covers via `*`. The token store does not change.
- `reload_devices` (sub-project #4) reuses the SIGHUP-style hot-reload pattern but reloads `devices.json` / blocklist, not the token store. Whether it shares `SIGHUP` or uses `SIGUSR1` is a #4 decision.
- Jinja2 templates (sub-project #4) build on top of `load_and_commit_config`, not on PFE or batch.

## Open issues for the plan spike

1. Confirm rustEZ's current `Device::cli` supports being called repeatedly on a single open handle. If not, propose the minimal extension (workaround in this repo or upstream PR).
2. Confirm `request pfe execute target <fpc> command "<cmd>"` is the canonical wrapper, and that output capture is well-behaved (no pager prompts, no special framing).
3. Decide the testing seam for `DeviceManager` (trait + injectable factory vs. `cfg(test)` switch) before writing the batch tests.
4. Pick concrete error messages for `error` strings in the result rows; should they reuse `JmcpError`'s `Display` directly, or be flattened (no chained sources) so the LLM sees stable strings? Lean toward stable, short strings: `"command timeout"`, `"batch timeout"`, `"connect failed: <root cause>"`, `"transport error: <root cause>"`.
