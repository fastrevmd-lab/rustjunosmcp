# RustEZ RPC Timeout Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the hidden 30 s `rustez` RPC timeout from killing long-running MCP commands (uncovered while running a real Junos upgrade through `execute_junos_command` with `command_timeout=1500`).

**Architecture:** `rustez::Device` already exposes a `.rpc_timeout(Duration)` builder (defaults to 30 s in `rustez-0.10.1/src/device.rs:15`). `rust-junosmcp-core::device_manager` doesn't call it, so every NETCONF RPC inside `dev.cli(...)` is wrapped in `tokio::time::timeout(30s, ...)`, which fires before the MCP-side outer timeout. Fix is one constant + one builder method call. The MCP's per-call `tokio::time::timeout(args.timeout, ...)` continues to be the user-visible bound; the `rustez` cap just gets raised above any reasonable per-call value.

**Tech Stack:** Rust 1.75+, `rustez = "0.10.1"`, `tokio`, existing CI gates (`cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, `cargo audit`).

**Reference:** Live upgrade run on 2026-05-14 (vSRX-test18, 24.4R1.9 → 25.4R1.12) — install command was issued, ran to completion on the device, but MCP RPC errored at 30 s with `RustEzError::Timeout`, leaving the operator without visibility for the remaining ~6 minutes.

---

## File Map

**Modified:**
- `rust-junosmcp-core/src/device_manager.rs` — add `POOL_RPC_TIMEOUT` constant and `.rpc_timeout(POOL_RPC_TIMEOUT)` builder call
- `rust-junosmcp-core/src/device_manager.rs` (tests module at the bottom) — add unit test asserting the constant value

**Created:**
- `rust-junosmcp/tests/rpc_timeout_smoke.rs` — smoke test that proves the per-Device timeout is raised: uses an unreachable IP and a small `command_timeout`, asserts the MCP-side outer timeout fires (not the rustez 30 s cap)

**Touched (docs):**
- `README.md` — short note in the existing operational notes section about the long-RPC behavior (one paragraph)

---

## Task 1: Lock in the constant

**Files:**
- Modify: `rust-junosmcp-core/src/device_manager.rs:19-23` (pool constants block)

- [ ] **Step 1: Open the file and confirm the existing constants block**

Read `rust-junosmcp-core/src/device_manager.rs` lines 19-23. Expected current contents:

```rust
// ── Pool constants ──────────────────────────────────────────────────────

const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const POOL_REAPER_INTERVAL: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
```

- [ ] **Step 2: Add the new constant immediately below `KEEPALIVE_INTERVAL`**

Replace the block with:

```rust
// ── Pool constants ──────────────────────────────────────────────────────

const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const POOL_REAPER_INTERVAL: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// Per-RPC timeout pushed into `rustez::Device` at connect time. Set high so
/// the MCP per-call `tokio::time::timeout(args.timeout, ...)` is the
/// user-visible bound. Without this, `rustez` defaults to 30 s and silently
/// truncates any long-running operational command (e.g. `request system
/// software add ...`) regardless of the MCP-side timeout.
const POOL_RPC_TIMEOUT: Duration = Duration::from_secs(3600);
```

- [ ] **Step 3: Build to confirm no syntax errors**

Run: `cargo build -p rust-junosmcp-core`
Expected: build succeeds with no warnings about unused constant (it's referenced in Task 2).

If you see `unused const POOL_RPC_TIMEOUT`, that's fine for this commit — it'll be wired up in Task 2. Add `#[allow(dead_code)]` only if `RUSTFLAGS=-D warnings` causes the build to fail; CI uses that flag.

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp-core/src/device_manager.rs
git commit -m "device_manager: add POOL_RPC_TIMEOUT constant (1h)

The hidden 30s default in rustez::Device::rpc_timeout silently
truncates long-running operational commands (request system
software add, request support information, etc.) regardless of
the MCP per-call timeout. Wire-up in next commit."
```

---

## Task 2: Wire the constant into the connection builder

**Files:**
- Modify: `rust-junosmcp-core/src/device_manager.rs:273-276` (the `Device::connect(...)` builder chain)

- [ ] **Step 1: Write the failing unit test first**

In `rust-junosmcp-core/src/device_manager.rs`, find the `#[cfg(test)] mod tests { ... }` block at the bottom (starts around line 316). Add this test inside the module:

```rust
#[test]
fn pool_rpc_timeout_is_at_least_one_hour() {
    // POOL_RPC_TIMEOUT must comfortably exceed any plausible per-call
    // MCP timeout so that the MCP-side `tokio::time::timeout` is the
    // user-visible bound, not rustez's internal cap.
    assert!(
        POOL_RPC_TIMEOUT >= Duration::from_secs(3600),
        "POOL_RPC_TIMEOUT must be >= 1h to cover long-running ops; got {:?}",
        POOL_RPC_TIMEOUT
    );
}
```

- [ ] **Step 2: Run the test — it should pass already (constant from Task 1)**

Run: `cargo test -p rust-junosmcp-core --lib device_manager::tests::pool_rpc_timeout_is_at_least_one_hour`
Expected: `test result: ok. 1 passed`

(This is the rare TDD case where the unit test exists to lock in the constraint, not to drive new code. Task 3 below has the real failing test for the wiring.)

- [ ] **Step 3: Locate the builder chain in the same file**

Find lines 273-276:

```rust
        // No pooled session — open fresh.
        let mut builder = Device::connect(&entry.ip)
            .port(entry.port)
            .username(&entry.username)
            .keepalive_interval(KEEPALIVE_INTERVAL);
```

- [ ] **Step 4: Add `.rpc_timeout(POOL_RPC_TIMEOUT)` to the chain**

Replace the block with:

```rust
        // No pooled session — open fresh.
        let mut builder = Device::connect(&entry.ip)
            .port(entry.port)
            .username(&entry.username)
            .keepalive_interval(KEEPALIVE_INTERVAL)
            .rpc_timeout(POOL_RPC_TIMEOUT);
```

- [ ] **Step 5: Build + clippy + fmt**

Run each in turn (CI runs all three):

```bash
cargo fmt -p rust-junosmcp-core -p rust-junosmcp -- --check
cargo clippy -p rust-junosmcp-core -p rust-junosmcp --all-targets -- -D warnings
cargo build --workspace
```

Expected: all three succeed.

If `cargo fmt --check` fails, run `cargo fmt -p rust-junosmcp-core -p rust-junosmcp` to fix.

- [ ] **Step 6: Run the existing core tests to confirm no regression**

Run: `cargo test -p rust-junosmcp-core`
Expected: all existing tests pass plus the new `pool_rpc_timeout_is_at_least_one_hour`.

- [ ] **Step 7: Commit**

```bash
git add rust-junosmcp-core/src/device_manager.rs
git commit -m "device_manager: pass POOL_RPC_TIMEOUT to rustez builder

Without this, every dev.cli(...) call inside rust-junosmcp-core
is wrapped in rustez's internal tokio::time::timeout(30s, ...),
which fires before the MCP-side per-call timeout — silently
killing long-running operational commands (observed during a
real Junos upgrade where 'request system software add' kept
running on the device but the MCP returned RPC timeout at 30s).

The MCP per-call timeout in execute_command.rs:44-51 is now the
sole user-visible bound."
```

---

## Task 3: End-to-end smoke test — outer timeout wins, not the rustez cap

**Files:**
- Create: `rust-junosmcp/tests/rpc_timeout_smoke.rs`
- Reference (do not modify): `rust-junosmcp/tests/common/mod.rs` for `spawn_stdio_server_with_args` + `call_tool` helpers, `rust-junosmcp/tests/batch_smoke.rs` for the prevailing test pattern

**Note:** We can't directly test "long RPC succeeds" without a real Junos device (no NETCONF mock in the suite). What we *can* test is the timeout *behavior*: with the fix, a small per-call `command_timeout` (e.g. 5 s) should produce a timeout error sourced from the MCP outer wrapper, *not* a `RustEzError::Timeout` at the 30 s mark. We use an unreachable IP so the test never depends on a real device.

- [ ] **Step 1: Read the existing test scaffolding**

Read `rust-junosmcp/tests/batch_smoke.rs` lines 1-120 to absorb the spawn pattern. Read `rust-junosmcp/tests/common/mod.rs` in full to see `spawn_stdio_server_with_args`, `call_tool`, and how inventory temp files are written.

- [ ] **Step 2: Create the test file with a failing test**

Create `rust-junosmcp/tests/rpc_timeout_smoke.rs` with the following contents:

```rust
//! Smoke test: per-call MCP timeout is the user-visible bound, NOT the
//! rustez internal 30 s cap.
//!
//! Regression for a real-world bug seen on 2026-05-14 where
//! `request system software add` ran to completion on a vSRX but the
//! MCP returned RPC timeout at 30 s, blinding the operator for the
//! remaining ~6 minutes of install + reboot.

mod common;

use common::{call_tool, spawn_stdio_server_with_args, write_inventory_temp};
use serde_json::json;
use std::time::Instant;

#[test]
fn execute_junos_command_outer_timeout_fires_before_rustez_cap() {
    // Inventory points at TEST-NET-1 (RFC 5737) — guaranteed unreachable,
    // so the connect attempt will hang until *something* times out.
    let inv_path = write_inventory_temp(&[(
        "unreachable",
        "192.0.2.1",
        22,
        "netconf",
        // Use a fake key file path — connection will fail at TCP layer
        // long before key parsing matters, but we need a valid auth field.
        "/dev/null",
    )]);

    let mut child = spawn_stdio_server_with_args(&["-f", inv_path.path().to_str().unwrap()]);

    let start = Instant::now();
    let resp = call_tool(
        &mut child,
        "execute_junos_command",
        json!({
            "router_name": "unreachable",
            "command": "show version",
            "timeout": 5,
        }),
    );
    let elapsed = start.elapsed();

    // Two observable properties of the fix:
    // 1. The error returns within ~5 s (MCP outer timeout), well before
    //    the legacy 30 s rustez cap. Allow generous slack for CI jitter
    //    and the connect-attempt tail (TCP retries).
    assert!(
        elapsed.as_secs() < 25,
        "Outer timeout should fire within MCP-side bound (~5s); got {:?}. \
         If this exceeds 25s, rustez's internal cap is likely still in play.",
        elapsed
    );

    // 2. The response is an error (it must not silently succeed against
    //    an unreachable host).
    let is_error = resp
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(is_error, "expected isError=true, got: {resp:?}");
}
```

- [ ] **Step 3: Add the `write_inventory_temp` helper to `tests/common/mod.rs` if missing**

Open `rust-junosmcp/tests/common/mod.rs` and check for an existing `write_inventory_temp` function. If missing, add this near the existing helpers:

```rust
/// Write a minimal JSON inventory to a temp file and return the handle.
/// Each tuple: (name, ip, port, username, key_file_path).
pub fn write_inventory_temp(devices: &[(&str, &str, u16, &str, &str)]) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut f = tempfile::Builder::new()
        .prefix("jmcp-inv-")
        .suffix(".json")
        .tempfile()
        .expect("create temp inventory");
    let mut obj = serde_json::Map::new();
    for (name, ip, port, user, key) in devices {
        obj.insert(
            (*name).to_string(),
            serde_json::json!({
                "ip": ip,
                "port": port,
                "username": user,
                "auth": { "type": "ssh_key", "private_key_path": key },
            }),
        );
    }
    let payload = serde_json::Value::Object(obj);
    writeln!(f, "{}", serde_json::to_string_pretty(&payload).unwrap())
        .expect("write inventory");
    f
}
```

- [ ] **Step 4: Verify the test fails on `main` (without the Task 2 fix)**

This is a regression check. Stash Task 2's change temporarily:

```bash
git stash push -m "task-2-fix" -- rust-junosmcp-core/src/device_manager.rs
cargo test --test rpc_timeout_smoke -- --nocapture
```

Expected: test FAILS — elapsed time will be ~30 s (the rustez cap), well over the 25 s assertion bound.

Then restore the fix:

```bash
git stash pop
```

- [ ] **Step 5: Run the test with the fix applied**

Run: `cargo test --test rpc_timeout_smoke -- --nocapture`
Expected: test PASSES — elapsed should be ~5-10 s (MCP outer timeout + small connect-attempt slack).

- [ ] **Step 6: Run the full test suite to confirm no regression elsewhere**

Run: `cargo test --workspace`
Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add rust-junosmcp/tests/rpc_timeout_smoke.rs rust-junosmcp/tests/common/mod.rs
git commit -m "test: smoke test — MCP outer timeout wins over rustez 30s cap

Regression test for the real-world bug seen on 2026-05-14 where
'request system software add' on a vSRX ran for 4+ minutes but
the MCP returned timeout at 30s. Without the device_manager fix
(POOL_RPC_TIMEOUT wiring), this test fails with elapsed ~30s
against an unreachable IP. With the fix, MCP-side
command_timeout=5 fires within ~5-10s as expected."
```

---

## Task 4: Document the behavior in README

**Files:**
- Modify: `README.md` — find the section about operational tools / timeouts and add a paragraph

- [ ] **Step 1: Locate the right section in README.md**

Open `README.md` and search for an existing section about timeouts, long-running commands, or operational tools. If there's a "Notes" / "Behaviour" / "Limitations" / "Operational Notes" section, that's the home. If none exists, add a new section titled `## Long-running operational commands` immediately after the existing tools description.

- [ ] **Step 2: Add the documentation paragraph**

Insert the following content (adjust heading depth to match the surrounding section):

```markdown
### Long-running operational commands

Each MCP tool exposes a per-call `timeout` parameter (default 360 s). This is
the **sole user-visible bound** on operation duration; the underlying
`rustez::Device` is configured with a 1-hour internal RPC timeout at
connection time, so commands that legitimately take many minutes
(`request system software add`, `request support information`,
`request system snapshot`, etc.) will not be silently truncated.

If you need to run an operation that exceeds 1 hour, split it into
phases or invoke the work fire-and-forget on the device and poll for
completion separately.

**Caveat:** when a long-running RPC is followed by a device reboot, the
NETCONF session will of course die. The session pool reconnects cleanly
on the next call.
```

- [ ] **Step 3: Verify markdown still renders**

Visually skim the README diff. No specific tooling check — keep it readable.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: explain long-running command timeout semantics"
```

---

## Task 5: Smoke-verify against a real device (manual, optional)

**Why:** automated tests can prove the timeout cap is raised, but only a real device can confirm a long-running RPC actually completes through the MCP. This task is for the human; not part of CI.

- [ ] **Step 1: Pick a long-but-safe Junos command**

Good candidates that take >30 s on a vSRX:
- `request system snapshot` (vSRX: ~1-2 min)
- `request support information | save /var/tmp/rsi.txt` (~1-3 min)

Avoid `request system software add` for this verification — that's the destructive case the fix was *for*. Use it once during the upgrade-tool plan, not now.

- [ ] **Step 2: Run via the MCP with explicit timeout**

Use `execute_junos_command` against a lab vSRX (e.g. `vSRX-test10` — leave `vSRX-test18` alone, it's been freshly upgraded):

```
execute_junos_command(
    router_name="vSRX-test10",
    command="request support information | save /var/tmp/rsi.txt",
    timeout=600
)
```

Expected: returns successfully after 1-3 min with the command output. **Without the fix**, would return `RustEzError::Timeout` at 30 s.

- [ ] **Step 3: Confirm the file landed on the device**

```
execute_junos_command(
    router_name="vSRX-test10",
    command="file list /var/tmp/rsi.txt detail",
    timeout=10
)
```

Expected: file present, sized > 100 KB.

- [ ] **Step 4: Clean up the file on the device**

```
execute_junos_command(
    router_name="vSRX-test10",
    command="file delete /var/tmp/rsi.txt",
    timeout=10
)
```

- [ ] **Step 5: Note the result in the PR description**

When opening the PR for this plan, paste the actual elapsed time from Step 2 into the PR description as evidence the fix lands as designed.

---

## Self-Review Checklist

- [x] **Spec coverage:** Every aspect of the user's "fix this 1st" requirement is addressed: constant added (T1), wired in (T2), regression test (T3), docs (T4), real-device verify (T5).
- [x] **No placeholders:** Every step has exact paths, exact code, exact commands, expected outputs.
- [x] **Type consistency:** `POOL_RPC_TIMEOUT` is referenced consistently across T1, T2, T3 (test name), and T4 (docs explanation).
- [x] **Reference accuracy:** `rustez-0.10.1/src/device.rs:15` (default 30 s) and `:388` (`.rpc_timeout` builder) verified by reading the local cargo registry copy. `device_manager.rs:19-23` and `:273-276` verified by reading the file in this working tree.

---

## What's NOT in this plan (intentional)

The Junos-upgrade work that surfaced this bug is much bigger than the timeout fix. It will land as separate plan files, each producing an independently shippable PR:

| # | Plan file (future) | Scope | Depends on |
|---|---|---|---|
| 1 | `2026-05-14-rustez-rpc-timeout-fix.md` (this) | Fix the 30 s cap | — |
| 2 | `2026-05-??-transfer-file-tool.md` | New `transfer_file` MCP tool: SCP-only (`-O` flag baked in), uses per-router key from `inventory.rs` `AuthConfig::SshKey` | this plan |
| 3 | `2026-05-??-wait-for-device-tool.md` | New `wait_for_device` MCP tool: ping-lost → ping-back → NETCONF responds → optional version match | this plan |
| 4 | `2026-05-??-snapshot-device-tool.md` | New `snapshot_device` + `diff_snapshots` MCP tools: structured pre/post capture (version, interfaces, routes, sessions, alarms, BGP/OSPF if present) | this plan |
| 5 | `2026-05-??-upgrade-junos-tool.md` | New `upgrade_junos` orchestrator: snapshot → transfer → checksum → install (`request system software add ... no-copy reboot`) → wait → snapshot → diff → report. **Auto-rollback on verify failure** (per user spec). No `vmhost` detection (Junos rejects wrong package itself). | plans 1-4 |

Each will have its own brainstorming → spec → plan → execution cycle. This document covers only #1 because the user explicitly chose "fix this 1st" and a tightly-scoped plan ships faster than one bundled mega-plan.
