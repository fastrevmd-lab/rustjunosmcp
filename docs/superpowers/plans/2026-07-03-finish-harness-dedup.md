# Finish HTTP-harness dedup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the junos test-harness dedup (#112): collapse `common`'s duplicated spawn readiness loop into `finish_spawn`, and migrate the last three private-helper files (`batch_smoke`, `pfe_smoke` — HTTP; `template_smoke` — stdio) onto `common`.

**Architecture:** Test-only, behavior-preserving. `common::spawn`/`spawn_no_auth` share one `finish_spawn` helper (mirrors srx). The three remaining smoke files drop their private harness copies and `use common::*`.

**Tech Stack:** Rust integration tests, `ureq`, stdio JSON-RPC.

## Global Constraints

- Behavior-preserving: same tests, same count, still passing. NO non-test source changes.
- `common::spawn`/`spawn_no_auth` must keep the readiness substring `"streamable-http listening"` and the `_stderr_drain` thread kept alive in `Server`.
- After migration, NO `rust-junosmcp/tests/*.rs` outside `common/mod.rs` defines its own `binary_path`/`ensure_built`/`pick_port`/`Server`/`spawn`/`http_post`/`call_tool`.
- Canonical stdio pattern (from `add_device_smoke.rs`): `common::spawn_stdio_server_with_args(&["-f", inv])` (adds `-t stdio` internally) → `StdioChild`; `common::call_tool(&mut child, name, args)`.
- `cargo test --workspace` 0 failures; `cargo fmt -- --check` + `cargo clippy --workspace --all-targets` clean.

---

### Task 1: `finish_spawn` extraction + `batch_smoke`/`pfe_smoke` migration (HTTP)

**Files:**
- Modify: `rust-junosmcp/tests/common/mod.rs` (extract `finish_spawn`)
- Modify: `rust-junosmcp/tests/batch_smoke.rs`, `rust-junosmcp/tests/pfe_smoke.rs`

**Interfaces:**
- Produces (in common): `fn finish_spawn(child: Child, port: u16) -> Server` (private).

- [ ] **Step 1: Extract `finish_spawn` in `common`**

In `rust-junosmcp/tests/common/mod.rs`, `spawn` (~lines 235-299) and `spawn_no_auth` (~301-360) each contain an identical readiness-wait + stderr-drain loop after building/`spawn()`-ing their `Command`. Extract that shared tail into a private helper (model it EXACTLY on `rust-srxmcp/tests/common/mod.rs`'s `finish_spawn` — read that file for the reference shape):

```rust
/// Wait for the "streamable-http listening" readiness line on the child's
/// stderr, then spawn a drain thread and return the guarded Server. Panics if
/// the server doesn't announce within 15s.
fn finish_spawn(mut child: Child, port: u16) -> Server {
    let stderr = child.stderr.take().unwrap();
    let mut reader = BufReader::new(stderr);
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut ready = false;
    loop {
        if Instant::now() > deadline { break; }
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => { if line.contains("streamable-http listening") { ready = true; break; } }
            Err(_) => break,
        }
    }
    if !ready { let _ = child.kill(); panic!("server did not start within 15s"); }
    let drain = std::thread::spawn(move || {
        let mut sink = String::new();
        loop { sink.clear(); match reader.read_line(&mut sink) { Ok(0) | Err(_) => break, Ok(_) => {} } }
    });
    Server { child, port, _stderr_drain: drain }
}
```

Then rewrite `spawn` and `spawn_no_auth` to build their `Command` (unchanged: `spawn` uses `--tokens-file`, `spawn_no_auth` uses `--allow-no-auth` + `extra`), `.spawn()` it, and `return finish_spawn(child, port);` — deleting the now-duplicated readiness/drain tail from each. Keep their signatures identical.

- [ ] **Step 2: Verify the HTTP tests still pass**

Run: `cargo test -p rust-junosmcp --test http_smoke --test http_reload 2>&1 | tail -12` (and `--features tls --test http_tls` if quick).
Expected: all pass — behavior-preserving.

- [ ] **Step 3: Migrate `batch_smoke.rs` to `common`**

In `rust-junosmcp/tests/batch_smoke.rs`: delete its private `binary_path`, `ensure_built`, `pick_port`, `Server` (+`impl Drop`), `spawn`, `PostResult`, `http_post`, `initialize`. Add at the top (after the `//!` doc + `use serde_json::…`):
```rust
mod common;
use common::*;
```
Its `http_post(port, bearer, sid, body)` calls already match `common::http_post`'s 4-arg signature, so call sites are unchanged. Remove any now-unused `use` imports the compiler flags. Keep any test-body-only local helper.

- [ ] **Step 4: Migrate `pfe_smoke.rs` to `common`** (identical to Step 3 for that file)

Delete the same private helpers from `rust-junosmcp/tests/pfe_smoke.rs`; add `mod common; use common::*;`; prune unused imports.

- [ ] **Step 5: Run both migrated tests + fmt/clippy**

Run: `cargo test -p rust-junosmcp --test batch_smoke --test pfe_smoke 2>&1 | tail -15`
Expected: all pass, same count as before.
Run: `cargo fmt && cargo fmt -- --check && cargo clippy -p rust-junosmcp --tests 2>&1 | tail -3`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add rust-junosmcp/tests/common/mod.rs rust-junosmcp/tests/batch_smoke.rs rust-junosmcp/tests/pfe_smoke.rs
git commit -m "test(junos): finish_spawn dedup; batch/pfe smoke use common harness (#112)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_019mPwHV2n6YmBTd5j8HcAAJ"
```

---

### Task 2: migrate `template_smoke.rs` (stdio) to `common`

**Files:**
- Modify: `rust-junosmcp/tests/template_smoke.rs`

**Interfaces:**
- Consumes (from common): `spawn_stdio_server_with_args(&[&str]) -> StdioChild`, `call_tool(&mut StdioChild, &str, Value) -> Value`, `write_inventory_in(&Path, &str, &str) -> PathBuf`, `binary_path`, `ensure_built`.

- [ ] **Step 1: Add `mod common;` and switch to common's stdio helpers**

In `rust-junosmcp/tests/template_smoke.rs`, add near the top:
```rust
mod common;
use common::{call_tool, spawn_stdio_server_with_args, write_inventory_in};
```
Delete the private helpers: `binary_path`, `ensure_built`, `spawn_stdio_server`, `send_line`, `read_response_with_id`, `call_tool`. **Keep** the template-specific `extract_success_payload` local (it parses the template tool's response and is not a shared concern).

- [ ] **Step 2: Convert the call sites**

For each test, convert the raw-`Child` pattern to `common`'s `StdioChild` pattern (matching `add_device_smoke.rs`):

- Replace `let mut child = spawn_stdio_server(inv.path());` with
  `let mut child = spawn_stdio_server_with_args(&["-f", inv.path().to_str().unwrap()]);`
  (`spawn_stdio_server_with_args` adds `-t stdio` itself; `child` is now a `StdioChild`.)
- `call_tool(&mut child, tool_name, arguments)` — the call shape is unchanged; it now resolves to `common::call_tool(&mut StdioChild, …)`. No change to the call text beyond `child` being a `StdioChild`.
- Inventory: replace the local `write_inventory(json)` usage. Where a test does `let inv = write_inventory(JSON);` then `inv.path()`, switch to a tempdir + `write_inventory_in`:
  ```rust
  let dir = tempfile::tempdir().unwrap();
  let inv_path = write_inventory_in(dir.path(), "devices.json", JSON);
  // then use `&inv_path` (a PathBuf) where `inv.path()` was used
  ```
  (Keep `dir` in scope for the test's duration so the tempdir isn't dropped early.) Delete the local `write_inventory` fn.

- [ ] **Step 3: Build + run template tests**

Run: `cargo test -p rust-junosmcp --test template_smoke 2>&1 | tail -15`
Expected: all template tests pass, same count and assertions as before (the migration is behavior-preserving — same handshake, same `call_tool`, same inventory content).

- [ ] **Step 4: Full dedup verification + workspace**

Run this grep — it MUST return nothing (no private harness helper defs remain outside `common`):
```bash
grep -rnE "^fn (binary_path|ensure_built|pick_port|spawn|http_post|call_tool|spawn_stdio_server)\b|^struct Server\b" rust-junosmcp/tests/*.rs
```
Expected: empty output.
Run: `cargo test --workspace 2>&1 | grep -E "FAILED|error\[" || echo "workspace clean"` and `cargo fmt -- --check && cargo clippy --workspace --all-targets 2>&1 | tail -3`.
Expected: 0 failures; clean.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp/tests/template_smoke.rs
git commit -m "test(junos): template_smoke uses common stdio harness (#112)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_019mPwHV2n6YmBTd5j8HcAAJ"
```

---

## Self-Review

**Spec coverage:**
- `finish_spawn` extraction (Part 1) → Task 1 Step 1. ✔
- batch/pfe HTTP migration (Part 2) → Task 1 Steps 3-4. ✔
- template stdio migration (Part 3), canonical pattern, keep `extract_success_payload`, inventory via `write_inventory_in` → Task 2 Steps 1-2. ✔
- Behavior-preserving, no-private-helpers grep verification, workspace green → Task 1 Step 2/5, Task 2 Step 3/4. ✔
- No non-test source changes → both tasks touch only `tests/`. ✔

**Placeholder scan:** No TBD/TODO. `finish_spawn` shown in full; migrations give exact call-site transforms. The one open pick (write_inventory_in vs local writer) is resolved to `write_inventory_in` with concrete code.

**Type consistency:** `finish_spawn(Child, u16) -> Server` used by both `spawn`/`spawn_no_auth` (Task 1). template call sites use `common::{spawn_stdio_server_with_args -> StdioChild, call_tool(&mut StdioChild,…), write_inventory_in -> PathBuf}` (Task 2) — matching common's actual signatures confirmed in the source.

**Risk note for implementer:** (1) `finish_spawn` must consume `child.stderr` exactly as the originals did — the `Server` still owns `child` + the drain `JoinHandle`; don't drop the reader early. (2) In template, `spawn_stdio_server_with_args` already appends `-t stdio`, so pass ONLY `["-f", inv]` (adding `-t stdio` yourself would duplicate the flag). (3) Keep the tempdir (`dir`) binding alive for the whole test or the inventory file vanishes mid-test.
