# Finish HTTP-harness dedup (#112)

**Issue:** #112 — finish HTTP-harness dedup (collapse junos spawn readiness loop + extend common to remaining smoke tests)
**Date:** 2026-07-03
**Status:** Approved design

## Problem

Follow-up to #100/#101. Two dedup gaps remain in `rust-junosmcp/tests/`:

1. `common::spawn` and `common::spawn_no_auth` each carry a verbatim ~30-line readiness-wait + stderr-drain loop; srx's `common` already factors this into `finish_spawn`.
2. Three smoke test files still carry private copies of harness helpers instead of using `common`: `batch_smoke.rs`, `pfe_smoke.rs` (HTTP), and `template_smoke.rs` (stdio). (The other non-HTTP files — add_device/transfer_file/list_staged/reload_devices/rpc_timeout — already migrated in #100.)

Test-only, behavior-preserving.

## Part 1 — `finish_spawn` in junos `common`

In `rust-junosmcp/tests/common/mod.rs`, extract the readiness-wait + stderr-drain loop (currently duplicated inside `spawn` at ~lines 235-299 and `spawn_no_auth` at ~301-360) into:

```rust
/// Wait for the "streamable-http listening" readiness line, then spawn a
/// stderr-drain thread. Panics if the server doesn't announce within 15s.
fn finish_spawn(mut child: Child, port: u16) -> Server
```

`spawn` and `spawn_no_auth` keep building their own `Command`/`argv` (they differ: auth vs `--allow-no-auth`+extra) and both end with `finish_spawn(child, port)`. Mirrors `rust-srxmcp/tests/common/mod.rs`. Behavior-preserving — the same tests pass.

## Part 2 — migrate `batch_smoke` + `pfe_smoke` (HTTP)

Both are streamable-http tests whose private helpers already match `common`'s signatures (notably `http_post(port, bearer, sid, body)` — the 4-arg unified form). For each: add `mod common;` + `use common::*;` and delete the private `binary_path`, `ensure_built`, `pick_port`, `Server` (+`Drop`), `spawn`, `PostResult`, `http_post`, `initialize` copies. Keep any test-file-specific helper local. Mechanical; no signature reconciliation.

## Part 3 — migrate `template_smoke` (stdio)

`template_smoke.rs` uses the stdio transport with private helpers that overlap `common`'s stdio helpers but with drift (raw `Child` vs `common::StdioChild`). Migrate to `common`'s canonical stdio pattern (identical to the already-migrated `add_device_smoke.rs`):

- `spawn_stdio_server(inv) -> Child` → `common::spawn_stdio_server_with_args(&["-f", inv_path])` (which adds `-t stdio` internally) returning a `StdioChild`.
- `call_tool(&mut child: Child, name, args)` → `common::call_tool(&mut child: &mut StdioChild, name, args)` (same shape; the child type changes to `StdioChild`).
- Delete the private `binary_path`, `ensure_built`, `send_line`, `read_response_with_id`, `spawn_stdio_server`, `call_tool`.
- Inventory: `template_smoke`'s local `write_inventory(json_text) -> NamedTempFile` writes arbitrary inventory JSON. `common` has `write_inventory_in(dir, name, json) -> PathBuf` (raw JSON) and `write_inventory_temp(devices)` (structured). Use `common::write_inventory_in` with a `tempfile::tempdir()` **or** keep a tiny local `write_inventory` if that reads cleaner — the plan picks one; do NOT add a redundant new `common` helper if an existing one fits.
- Keep the template-specific `extract_success_payload` local (it parses the template tool's response shape — not a shared concern).

## Testing / acceptance

- Behavior-preserving: every migrated test still passes with the same assertions and the same test count. `cargo test --workspace` 0 failures.
- After migration, **no** `rust-junosmcp/tests/*.rs` file outside `common/mod.rs` defines its own `binary_path` / `ensure_built` / `pick_port` / `Server` / `spawn` / `http_post` / `call_tool` (verified by grep in the plan's final step). `common::spawn`/`spawn_no_auth` share `finish_spawn`.
- `cargo fmt -- --check` + `cargo clippy --workspace --all-targets` clean. No non-test source changes.

## Out of scope

- srx tests (deduped in #101).
- The already-migrated non-HTTP files.
- No change to `common`'s public API beyond the private `finish_spawn` helper (and only if genuinely needed, a stdio convenience for template — preferred to reuse existing helpers).

## Risks

1. `finish_spawn` extraction must preserve the exact readiness string (`"streamable-http listening"`) and the drain-thread lifetime (the `_stderr_drain` handle kept alive in `Server`) — a behavior change would flake the HTTP tests. Guarded by the existing HTTP tests passing.
2. `template_smoke`'s stdio migration changes the child type (`Child` → `StdioChild`); each call site must switch to `common::call_tool`. The compiler catches mismatches; the existing template assertions are the behavior guard.
