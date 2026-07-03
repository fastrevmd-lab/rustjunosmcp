# Config-channel recovery: discard_candidate + config_diff hint

**Issues:** #107 (failed load leaves candidate dirty; no MCP rollback), #108 (junos_config_diff raw parse error when on-box config invalid for mode)
**Date:** 2026-07-03
**Status:** Approved design

## Problem

Two config-channel rough edges surfaced during a live chassis-cluster→standalone conversion:

- **#107:** A failed `set`-format `load_and_commit_config` used to leave the shared candidate dirty, wedging every subsequent load with `configuration database modified`, with no MCP-native recovery. **#98 (merged) already fixes the auto-discard** — a failed load/commit now runs `rollback(0)`. What remains is the reporter's second ask: an **explicit** recovery verb for a candidate left dirty by some other cause (an out-of-band session, a prior crash), so recovery never requires bypassing the MCP.
- **#108:** `junos_config_diff` returns a raw NETCONF parse error when the committed on-box config won't parse in the current mode (e.g. cluster-only `ge-7/0/x` stanzas after disabling chassis-cluster), leaving the operator blind with no hint.

## Part 1 — `discard_candidate` tool (#107 remainder)

New MCP tool: discard any uncommitted candidate changes, returning the candidate to the running config. Never touches the running config, so no confirmation gate.

**Handler** `rust-junosmcp-core/src/tools/discard_candidate.rs`:
```rust
pub async fn handle(args: DiscardCandidateArgs, dm: Arc<DeviceManager>) -> Result<Value, JmcpError>
```
Flow (inside a `tokio::time::timeout`): `dm.open` → `dev.config()` → `cfg.lock()` → `cfg.rollback(0)` (discard candidate) → `cfg.unlock()`. Returns `{ "success": true, "message": "candidate configuration discarded (rolled back to running)" }`. On any step error, best-effort `unlock()` then return the error (mirrors the cleanup discipline in `commit_check`/`load_commit`).

**Args** `DiscardCandidateArgs { router_name: String, timeout: u64 (#[serde(default="default_timeout")]) }` in `tools/mod.rs`, with the `router`/`router_name` alias added in #104 applied (`#[serde(alias = "router")]`).

**Wiring:** new `#[tool(name = "discard_candidate")]` adapter in `server.rs` with `check_tool_scope` + `check_router_scope`. Tool surface **16 → 17**: add `"discard_candidate"` to `SERVER_TOOLS` (server.rs) **and** `KNOWN_TOOLS` (`rust-junosmcp-auth/src/file.rs`), and bump the tripwire `server_tools_len_is_16` → `server_tools_len_is_17` (assert 17). (RJMCP-SEC-001: the two lists must stay set-equal.)

## Part 2 — `junos_config_diff` parse-error hint (#108)

In `rust-junosmcp-core/src/tools/config_diff.rs`, when `dev.cli()` for the compare errors, inspect the error text. If it matches a **config-parse-failure signature** — the error string contains `juniper.conf` (an on-box config-file line reference like `/config/juniper.conf:256:(12) …`) or `parse error` (case-insensitive) — return an enriched error whose message appends an actionable hint:

> `… (the on-box configuration failed to parse for the current mode — common right after a chassis-cluster enable/disable. Fix or load a valid config on the device, then retry junos_config_diff.)`

Non-matching errors (timeout, connect, auth) propagate unchanged. The success path is unchanged (`Ok(json!(diff_string))`).

Implementation: catch the inner `Err(e)`, format the enriched message into a `JmcpError` variant that carries a string (e.g. reuse the existing generic error path — return `Err(JmcpError::…)` with the combined text; if no suitable string-carrying variant exists, add a small `JmcpError::ConfigParseHint(String)` or wrap via the existing rustez-error display). Keep it an **error** (the diff genuinely failed) — do not fabricate a fake diff.

## Testing

- `discard_candidate`: short-circuit unit test `unknown_router_propagates_error` (mirrors `commit_check`/`load_commit`); the actual rollback path needs a live device (same limitation as those handlers — not unit-tested). Arg-default test (`timeout` defaults; `router` alias resolves).
- Scope wiring: the existing tripwire tests (`server_tools_len_is_17`, `server_tools_matches_known_tools_as_set`) enforce the 17-count + KNOWN_TOOLS parity.
- `config_diff`: a pure unit test on the signature-matching + hint enrichment — feed a synthetic error string containing `juniper.conf:256 … fpc value outside range` → assert the returned error message contains the hint; feed a `connection refused`/timeout-style string → assert it is passed through unchanged (no hint). Factor the enrichment into a small pure helper `parse_error_hint(err_text: &str) -> Option<String>` so it's testable without a device.
- Gates: `cargo test --workspace` 0 failures; `cargo fmt -- --check` + `cargo clippy` clean.

## Deploy

Rebuild + deploy the junos binary to ct601 (pve2), live-smoke: `tools/list` → 17 tools; `discard_candidate` against an up vSRX (e.g. vSRX-test10) → `success:true` (a no-op discard on a clean candidate is safe and confirms the path). Update the operator token scopes if a scoped token needs `discard_candidate`.

## Out of scope

- No `load override`/`load replace` mode (#107 option 3) — YAGNI for now; the auto-discard (#98) + explicit `discard_candidate` cover the reported recovery need.
- No best-effort partial-config return for #108 (the RPC fails wholesale); the actionable hint is the deliverable.
- No change to `load_and_commit_config` (its cleanup is fixed by #98).

## Risks

1. `discard_candidate` discards a legitimately in-progress candidate if one exists — that is the intended recovery semantic; documented in the tool description ("discards ANY uncommitted candidate changes").
2. #108 signature matching is string-based; `juniper.conf` / `parse error` are specific enough to config-parse failures. A false positive would only append a hint to an unrelated error (mildly misleading, not harmful); a false negative just leaves the raw error (status quo). Guarded by the pure-helper unit tests.
3. Tool-count tripwire must be bumped in lockstep (SERVER_TOOLS + KNOWN_TOOLS + the `_17` assertion), or the build fails — intentional tripwire.
