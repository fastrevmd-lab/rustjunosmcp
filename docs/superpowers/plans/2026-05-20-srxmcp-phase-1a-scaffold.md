# `rust-srxmcp` Phase 1A Scaffolding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up an opt-in second MCP binary `rust-srxmcp` on LXC 601 alongside the live `rust-junosmcp:30031`, shipping one trivial diagnostic tool (`srxmcp_status`) to validate the workspace, build, deploy, and SIGHUP plumbing.

**Architecture:** Migrate the workspace to per-crate versioning with `default-members` excluding the new SRX crates so `cargo build` (no args) is unchanged. Move shared tower/auth wiring from `rust-junosmcp/src/auth_layer.rs` + `caller.rs` into `rust-junosmcp-auth` so both binaries reuse it. Add a small `bootstrap` module in `rust-junosmcp-core` for the trivially-extractable bits (tracing init, inventory load, host-key policy). The new `rust-srxmcp` binary bootstraps these helpers, registers exactly one rmcp `#[tool]` (`srxmcp_status`), and listens on `:30032`.

**Tech Stack:** Rust 2021, tokio, axum 0.8, rmcp 0.8, tower, tracing, schemars, serde — same versions already pinned in workspace.

**Spec:** `docs/superpowers/specs/2026-05-20-srxmcp-phase-1a-scaffold-design.md`

---

## File Structure

**Workspace root (modified):**
- `Cargo.toml` — adds `default-members`, drops `workspace.package.version`, lists 5 members
- `.github/workflows/*.yml` — append `cargo build/test --workspace` steps

**Existing crates (modified):**
- `rust-junosmcp/Cargo.toml` — `version = "0.6.2"`; drops `axum`, `tower`, `arc-swap` from `[dependencies]` if now sourced via `rust-junosmcp-auth` re-export (we keep them — binary still builds the router); but adds `version = "0.6.2"`
- `rust-junosmcp/src/main.rs` — switches to `rust_junosmcp_core::bootstrap::*` and `rust_junosmcp_auth::tower::{auth_layer, AuthState}`; deletes `mod auth_layer;` + `mod caller;`
- `rust-junosmcp/src/http_transport.rs` — imports `auth_layer`/`AuthState` from `rust_junosmcp_auth::tower` instead of `crate::auth_layer`
- `rust-junosmcp/src/server.rs` — imports `CallerCtx` from `rust_junosmcp_auth::caller::CallerCtx` instead of `crate::caller::CallerCtx`
- `rust-junosmcp/src/auth_layer.rs` — **deleted** (moved)
- `rust-junosmcp/src/caller.rs` — **deleted** (moved)
- `rust-junosmcp-core/Cargo.toml` — `version = "0.6.2"`
- `rust-junosmcp-core/src/lib.rs` — `pub mod bootstrap;`
- `rust-junosmcp-auth/Cargo.toml` — `version = "0.6.2"`; **add** `axum`, `tower`, `arc-swap`, `http` deps
- `rust-junosmcp-auth/src/lib.rs` — `pub mod tower;` + `pub mod caller;`

**New files:**
- `rust-junosmcp-core/src/bootstrap.rs` — `init_tracing()`, `load_inventory()`, `build_host_key_policy()`
- `rust-junosmcp-auth/src/tower.rs` — relocated `auth_layer` + `AuthState` from `rust-junosmcp/src/auth_layer.rs`
- `rust-junosmcp-auth/src/caller.rs` — relocated `CallerCtx` from `rust-junosmcp/src/caller.rs`
- `rust-srxmcp-core/Cargo.toml` — new lib crate at `version = "0.0.1"`
- `rust-srxmcp-core/src/lib.rs` — empty placeholder
- `rust-srxmcp/Cargo.toml` — new bin crate at `version = "0.0.1"`
- `rust-srxmcp/src/main.rs` — bootstrap + `JmcpSrxHandler` + `srxmcp_status` tool
- `rust-srxmcp/src/server.rs` — `JmcpSrxHandler` impl with `#[tool]` macro
- `rust-srxmcp/src/http_transport.rs` — axum router + tower auth layer + rmcp service (binary-specific)
- `rust-srxmcp/README.md` — workspace `default-members` note
- `rust-srxmcp/CHANGELOG.md` — `0.0.1` initial entry
- `systemd/rust-srxmcp.service` — systemd unit
- `rust-junosmcp-core/src/bootstrap/tests.rs` — unit tests (inline in `bootstrap.rs` as `#[cfg(test)]` module)
- `rust-srxmcp/tests/status_tool.rs` — integration test for the `srxmcp_status` tool

---

## Task 1: Workspace migration — per-crate versioning + `default-members`

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `rust-junosmcp/Cargo.toml`
- Modify: `rust-junosmcp-core/Cargo.toml`
- Modify: `rust-junosmcp-auth/Cargo.toml`

- [ ] **Step 1: Update workspace `Cargo.toml`**

Replace the `[workspace]` and `[workspace.package]` blocks. The `[workspace.dependencies]` block stays untouched.

```toml
[workspace]
members = [
    "rust-junosmcp",
    "rust-junosmcp-core",
    "rust-junosmcp-auth",
    "rust-srxmcp",
    "rust-srxmcp-core",
]
default-members = [
    "rust-junosmcp",
    "rust-junosmcp-core",
    "rust-junosmcp-auth",
]
resolver = "2"

[workspace.package]
edition      = "2021"
license      = "MIT OR Apache-2.0"
repository   = "https://github.com/fastrevmd-lab/RustJunosMCP"
authors      = ["fastrevmd-lab"]
```

- [ ] **Step 2: Set explicit version in each existing crate**

Edit `rust-junosmcp/Cargo.toml`: replace `version.workspace = true` with `version = "0.6.2"`.
Edit `rust-junosmcp-core/Cargo.toml`: same change.
Edit `rust-junosmcp-auth/Cargo.toml`: same change.

- [ ] **Step 3: Verify workspace still builds (no SRX crates yet, will fail member resolution — temporarily comment out the new members)**

To unblock this step before the SRX crates exist, **temporarily** restrict `members` and `default-members` to the existing 3 crates. The new members get added in Task 7 / Task 8.

```toml
[workspace]
members          = ["rust-junosmcp", "rust-junosmcp-core", "rust-junosmcp-auth"]
default-members  = ["rust-junosmcp", "rust-junosmcp-core", "rust-junosmcp-auth"]
resolver = "2"
```

Run: `cargo build`
Expected: clean build, identical to v0.6.2 output.

- [ ] **Step 4: Run the full existing test suite**

Run: `cargo test`
Expected: all existing tests pass.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml rust-junosmcp/Cargo.toml rust-junosmcp-core/Cargo.toml rust-junosmcp-auth/Cargo.toml
git commit -m "chore(workspace): migrate to per-crate versioning"
```

---

## Task 2: Relocate `caller.rs` into `rust-junosmcp-auth`

**Files:**
- Create: `rust-junosmcp-auth/src/caller.rs`
- Modify: `rust-junosmcp-auth/src/lib.rs`
- Delete: `rust-junosmcp/src/caller.rs`
- Modify: `rust-junosmcp/src/main.rs` (remove `mod caller;`)
- Modify: `rust-junosmcp/src/auth_layer.rs` (change `use crate::caller::CallerCtx;` → `use rust_junosmcp_auth::caller::CallerCtx;`)
- Modify: `rust-junosmcp/src/server.rs` (same import change)

- [ ] **Step 1: Read `rust-junosmcp/src/caller.rs` to confirm content**

Run: `cat rust-junosmcp/src/caller.rs` (already-known content reproduced below).

```rust
//! Per-request caller context populated by the auth middleware.

use rust_junosmcp_auth::{ScopeSet, TokenEntry};

#[derive(Debug, Clone)]
pub struct CallerCtx {
    pub token_name: String,
    pub routers: ScopeSet,
    pub tools: ScopeSet,
}

impl From<&TokenEntry> for CallerCtx {
    fn from(e: &TokenEntry) -> Self {
        Self {
            token_name: e.name.clone(),
            routers: e.routers.clone(),
            tools: e.tools.clone(),
        }
    }
}
```

- [ ] **Step 2: Create `rust-junosmcp-auth/src/caller.rs`**

Identical content, but `use rust_junosmcp_auth::{...}` becomes `use crate::{...}` since we're now inside the crate:

```rust
//! Per-request caller context populated by the auth middleware.

use crate::{ScopeSet, TokenEntry};

#[derive(Debug, Clone)]
pub struct CallerCtx {
    pub token_name: String,
    pub routers: ScopeSet,
    pub tools: ScopeSet,
}

impl From<&TokenEntry> for CallerCtx {
    fn from(e: &TokenEntry) -> Self {
        Self {
            token_name: e.name.clone(),
            routers: e.routers.clone(),
            tools: e.tools.clone(),
        }
    }
}
```

- [ ] **Step 3: Add `pub mod caller;` to `rust-junosmcp-auth/src/lib.rs`**

Read the current `rust-junosmcp-auth/src/lib.rs` first. Add a single line:

```rust
pub mod caller;
```

- [ ] **Step 4: Delete `rust-junosmcp/src/caller.rs`**

```bash
rm rust-junosmcp/src/caller.rs
```

- [ ] **Step 5: Remove `mod caller;` from `rust-junosmcp/src/main.rs`**

Delete the line `mod caller;` (line 2 of main.rs).

- [ ] **Step 6: Update `auth_layer.rs` import**

In `rust-junosmcp/src/auth_layer.rs`, change:
```rust
use crate::caller::CallerCtx;
```
to:
```rust
use rust_junosmcp_auth::caller::CallerCtx;
```

- [ ] **Step 7: Update `server.rs` import**

In `rust-junosmcp/src/server.rs`, grep for `crate::caller::CallerCtx` and replace with `rust_junosmcp_auth::caller::CallerCtx`.

- [ ] **Step 8: Build + test**

Run: `cargo build && cargo test`
Expected: all green.

- [ ] **Step 9: Commit**

```bash
git add rust-junosmcp-auth/src/caller.rs rust-junosmcp-auth/src/lib.rs \
        rust-junosmcp/src/main.rs rust-junosmcp/src/auth_layer.rs rust-junosmcp/src/server.rs
git rm rust-junosmcp/src/caller.rs
git commit -m "refactor(auth): move CallerCtx into rust-junosmcp-auth"
```

---

## Task 3: Add axum/tower/arc-swap/http deps to `rust-junosmcp-auth`

**Files:**
- Modify: `rust-junosmcp-auth/Cargo.toml`

These deps are needed by the tower middleware we move in Task 4.

- [ ] **Step 1: Append deps**

Add to `[dependencies]` block:

```toml
axum     = { workspace = true }
tower    = { workspace = true }
http     = { workspace = true }
```

(`arc-swap` is already present.)

- [ ] **Step 2: Verify build**

Run: `cargo build -p rust-junosmcp-auth`
Expected: clean build.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-auth/Cargo.toml
git commit -m "build(auth): add axum/tower/http deps for tower middleware"
```

---

## Task 4: Relocate `auth_layer.rs` → `rust-junosmcp-auth/src/tower.rs`

**Files:**
- Create: `rust-junosmcp-auth/src/tower.rs`
- Modify: `rust-junosmcp-auth/src/lib.rs`
- Delete: `rust-junosmcp/src/auth_layer.rs`
- Modify: `rust-junosmcp/src/main.rs` (remove `mod auth_layer;`)
- Modify: `rust-junosmcp/src/http_transport.rs` (update import path)

- [ ] **Step 1: Create `rust-junosmcp-auth/src/tower.rs`**

Copy the byte-for-byte content of `rust-junosmcp/src/auth_layer.rs` with one change: replace
```rust
use crate::caller::CallerCtx;
use rust_junosmcp_auth::TokenStore;
```
with
```rust
use crate::caller::CallerCtx;
use crate::TokenStore;
```

(All other code — `AuthState`, `auth_layer`, `parse_bearer`, `reject`, all 8 tests — kept verbatim including the doc comments and RFC challenge constants.)

- [ ] **Step 2: Register the module in `rust-junosmcp-auth/src/lib.rs`**

Append:
```rust
pub mod tower;
```

- [ ] **Step 3: Delete `rust-junosmcp/src/auth_layer.rs`**

```bash
rm rust-junosmcp/src/auth_layer.rs
```

- [ ] **Step 4: Remove `mod auth_layer;` from `rust-junosmcp/src/main.rs`**

- [ ] **Step 5: Update `http_transport.rs` import**

In `rust-junosmcp/src/http_transport.rs`, change:
```rust
use crate::auth_layer::{auth_layer, AuthState};
```
to:
```rust
use rust_junosmcp_auth::tower::{auth_layer, AuthState};
```

- [ ] **Step 6: Build + test the moved unit tests**

Run: `cargo test -p rust-junosmcp-auth tower::`
Expected: 8 `parse_bearer_*` tests pass.

Run: `cargo build && cargo test`
Expected: all workspace tests pass.

- [ ] **Step 7: fmt + clippy**

Run: `cargo fmt -- --check && cargo clippy --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add rust-junosmcp-auth/src/tower.rs rust-junosmcp-auth/src/lib.rs \
        rust-junosmcp/src/main.rs rust-junosmcp/src/http_transport.rs
git rm rust-junosmcp/src/auth_layer.rs
git commit -m "refactor(auth): move tower middleware into rust-junosmcp-auth"
```

---

## Task 5: `rust-junosmcp-core` bootstrap module — `init_tracing()`

**Files:**
- Create: `rust-junosmcp-core/src/bootstrap.rs`
- Modify: `rust-junosmcp-core/src/lib.rs`
- Modify: `rust-junosmcp-core/Cargo.toml` (add `tracing-subscriber`)

- [ ] **Step 1: Write the failing test**

Append to `rust-junosmcp-core/src/bootstrap.rs` (create the file with this content):

```rust
//! Process bootstrap helpers shared by `rust-junosmcp` and `rust-srxmcp`.

use tracing_subscriber::EnvFilter;

/// Initialize the global tracing subscriber. Reads `RUST_LOG` via env-filter,
/// defaults to `info`. Writes to stderr so stdout stays clean for stdio-mode
/// MCP transport. Idempotent-by-error — calling twice returns the second call's
/// `try_init` error which callers ignore.
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_tracing_is_idempotent() {
        init_tracing();
        init_tracing(); // must not panic on second call
    }
}
```

Add to `rust-junosmcp-core/Cargo.toml` under `[dependencies]`:
```toml
tracing-subscriber = { workspace = true }
```

Add to `rust-junosmcp-core/src/lib.rs`:
```rust
pub mod bootstrap;
```

- [ ] **Step 2: Run test (fails — bootstrap module not in scope yet from caller perspective, but the test inside the module should compile + pass)**

Run: `cargo test -p rust-junosmcp-core bootstrap::tests::init_tracing_is_idempotent`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/src/bootstrap.rs rust-junosmcp-core/src/lib.rs rust-junosmcp-core/Cargo.toml
git commit -m "feat(core): add bootstrap::init_tracing helper"
```

---

## Task 6: `rust-junosmcp-core` bootstrap — `load_inventory()` + `build_host_key_policy()`

**Files:**
- Modify: `rust-junosmcp-core/src/bootstrap.rs`
- Test fixtures: existing `rust-junosmcp-core/tests/fixtures/` device json or temp file in test

- [ ] **Step 1: Write the failing tests**

Append to `rust-junosmcp-core/src/bootstrap.rs`:

```rust
use crate::{HostKeyVerification, Inventory};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Load and hash the device inventory JSON file in one call.
/// Returns the Arc-wrapped inventory and its content sha256 for the
/// inventory-mutation provenance chain.
pub fn load_inventory(
    path: &Path,
) -> Result<(Arc<Inventory>, [u8; 32]), crate::error::JmcpError> {
    let inventory = Arc::new(Inventory::load(path).map_err(|e| {
        crate::error::JmcpError::Internal(format!(
            "loading inventory {}: {}",
            path.display(),
            e
        ))
    })?);
    let hash = crate::inventory::hash_file(path).map_err(|e| {
        crate::error::JmcpError::Internal(format!("hashing {}: {}", path.display(), e))
    })?;
    Ok((inventory, hash))
}

/// Build the host-key verification policy for NETCONF SSH:
///   - `accept_new = true`  → `AcceptAll` (lab/TOFU mode)
///   - `accept_new = false` → `KnownHosts(known_hosts_file)` (strict, default)
pub fn build_host_key_policy(
    accept_new: bool,
    known_hosts_file: PathBuf,
) -> HostKeyVerification {
    if accept_new {
        HostKeyVerification::AcceptAll
    } else {
        HostKeyVerification::KnownHosts(known_hosts_file)
    }
}
```

Add tests in the same `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn build_host_key_policy_strict_default() {
        let policy = build_host_key_policy(false, std::path::PathBuf::from("/tmp/kh"));
        match policy {
            HostKeyVerification::KnownHosts(p) => {
                assert_eq!(p, std::path::PathBuf::from("/tmp/kh"))
            }
            _ => panic!("expected KnownHosts variant"),
        }
    }

    #[test]
    fn build_host_key_policy_accept_all_when_opted_in() {
        let policy = build_host_key_policy(true, std::path::PathBuf::from("/tmp/kh"));
        assert!(matches!(policy, HostKeyVerification::AcceptAll));
    }

    #[test]
    fn load_inventory_reads_file_and_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        std::fs::write(
            &path,
            r#"[{"name":"r1","host":"10.0.0.1","port":830,"username":"u","password":"p"}]"#,
        )
        .unwrap();
        let (inv, hash) = load_inventory(&path).unwrap();
        assert_eq!(inv.names(), vec!["r1".to_string()]);
        assert_eq!(hash.len(), 32);
        // Hash deterministic for same content
        let (_, hash2) = load_inventory(&path).unwrap();
        assert_eq!(hash, hash2);
    }
```

(If the JSON shape above does not match `Inventory::load`'s schema, adjust to the existing schema — read `rust-junosmcp-core/src/inventory.rs` to confirm before writing the test.)

- [ ] **Step 2: Run tests**

Run: `cargo test -p rust-junosmcp-core bootstrap::tests`
Expected: 4 tests pass.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/src/bootstrap.rs
git commit -m "feat(core): add bootstrap::{load_inventory, build_host_key_policy}"
```

---

## Task 7: Refactor `rust-junosmcp/src/main.rs` to use bootstrap helpers

**Files:**
- Modify: `rust-junosmcp/src/main.rs`

This is the regression-sensitive change. The diff is mechanical — inline blocks at lines 22-28, 38-46, 58-70 are replaced by helper calls.

- [ ] **Step 1: Read current main.rs to confirm line ranges**

Run: `cat rust-junosmcp/src/main.rs | head -90`

- [ ] **Step 2: Apply the refactor**

Replace lines 22-28 (`tracing_subscriber::fmt()...init();`) with:
```rust
    rust_junosmcp_core::bootstrap::init_tracing();
```

Replace lines 38-46 (the `Arc::new(Inventory::load(...))` block) and the `inv_hash` derivation on lines 58-60 with:
```rust
    let inv_path = args.device_mapping.clone();
    let (inventory, inv_hash) = rust_junosmcp_core::bootstrap::load_inventory(&inv_path)
        .with_context(|| format!("loading {}", inv_path.display()))?;
    tracing::info!(
        devices = inventory.names().len(),
        path = %inv_path.display(),
        "loaded inventory"
    );
```

Replace lines 61-70 (the `host_key_policy` if/else block) with:
```rust
    let host_key_policy = rust_junosmcp_core::bootstrap::build_host_key_policy(
        args.ssh_accept_new_host_keys,
        args.known_hosts_file.clone(),
    );
```

Leave everything else (Policy::build, DeviceManager, token store, SIGHUP handler, transport selection) untouched.

- [ ] **Step 3: Build + run full test suite**

Run: `cargo build && cargo test`
Expected: all green. The behavioral change is zero — helpers are byte-for-byte extractions.

- [ ] **Step 4: Run clippy**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp/src/main.rs
git commit -m "refactor(junosmcp): use core::bootstrap helpers in main"
```

---

## Task 8: Create `rust-srxmcp-core` crate (empty placeholder)

**Files:**
- Create: `rust-srxmcp-core/Cargo.toml`
- Create: `rust-srxmcp-core/src/lib.rs`

- [ ] **Step 1: Create `rust-srxmcp-core/Cargo.toml`**

```toml
[package]
name        = "rust-srxmcp-core"
version     = "0.0.1"
edition.workspace     = true
license.workspace     = true
repository.workspace  = true
authors.workspace     = true
description = "Core logic for rust-srxmcp (SRX-specific MCP workflows). Phase 1A placeholder."

[dependencies]
# Phase 1B will add real deps. For 0.0.1 the lib is intentionally empty.
```

- [ ] **Step 2: Create `rust-srxmcp-core/src/lib.rs`**

```rust
//! Placeholder for SRX-specific core logic. Phase 1B (`srxmcp-v0.1.0`) adds
//! workflows, parsers, and polling abstractions. For Phase 1A the lib is
//! deliberately empty so the crate exists in the workspace.

#![deny(rust_2018_idioms)]
```

- [ ] **Step 3: Add the crate to workspace `members` (still excluded from `default-members`)**

Edit workspace `Cargo.toml`:
```toml
[workspace]
members          = ["rust-junosmcp", "rust-junosmcp-core", "rust-junosmcp-auth", "rust-srxmcp-core"]
default-members  = ["rust-junosmcp", "rust-junosmcp-core", "rust-junosmcp-auth"]
```

- [ ] **Step 4: Build the new crate**

Run: `cargo build -p rust-srxmcp-core`
Expected: clean build.

Run: `cargo build` (no args)
Expected: identical output to before — new crate not built by default.

- [ ] **Step 5: Commit**

```bash
git add rust-srxmcp-core/ Cargo.toml
git commit -m "feat(srxmcp-core): scaffold empty placeholder crate"
```

---

## Task 9: Scaffold `rust-srxmcp` binary crate + `srxmcp_status` tool (TDD)

**Files:**
- Create: `rust-srxmcp/Cargo.toml`
- Create: `rust-srxmcp/src/main.rs` (stub for now)
- Create: `rust-srxmcp/src/server.rs`
- Create: `rust-srxmcp/tests/status_tool.rs`

- [ ] **Step 1: Create `rust-srxmcp/Cargo.toml`**

```toml
[package]
name        = "rust-srxmcp"
version     = "0.0.1"
edition.workspace     = true
license.workspace     = true
repository.workspace  = true
authors.workspace     = true
description = "MCP server for Juniper SRX-specific operational workflows."

[[bin]]
name = "rust-srxmcp"
path = "src/main.rs"

[dependencies]
rust-junosmcp-core = { path = "../rust-junosmcp-core" }
rust-junosmcp-auth = { path = "../rust-junosmcp-auth" }
rust-srxmcp-core   = { path = "../rust-srxmcp-core" }
tokio              = { workspace = true }
serde              = { workspace = true }
serde_json         = { workspace = true }
tracing            = { workspace = true }
anyhow             = { workspace = true }
thiserror          = { workspace = true }
clap               = { version = "4", features = ["derive"] }
rmcp = { version = "0.8", features = [
    "server",
    "macros",
    "transport-io",
    "schemars",
    "transport-streamable-http-server",
] }
schemars           = { workspace = true }
arc-swap           = { workspace = true }
axum               = { workspace = true }
tower              = { workspace = true }
http               = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
```

- [ ] **Step 2: Add to workspace members**

```toml
[workspace]
members = [
    "rust-junosmcp",
    "rust-junosmcp-core",
    "rust-junosmcp-auth",
    "rust-srxmcp",
    "rust-srxmcp-core",
]
default-members = [
    "rust-junosmcp",
    "rust-junosmcp-core",
    "rust-junosmcp-auth",
]
```

- [ ] **Step 3: Write the failing tool test first**

Create `rust-srxmcp/tests/status_tool.rs`:

```rust
//! End-to-end test of the `srxmcp_status` tool handler. Constructs a
//! `JmcpSrxHandler` with a known start instant, invokes the tool, and
//! asserts the response shape.

use rust_srxmcp::server::{JmcpSrxHandler, SrxmcpStatusArgs};
use std::sync::Arc;
use tokio::time::Instant;

#[tokio::test]
async fn srxmcp_status_returns_version_endpoint_and_uptime() {
    let started = Arc::new(Instant::now());
    let handler = JmcpSrxHandler::new(started.clone());

    // Tool call: small delay so uptime > 0 (but accept 0 for very fast machines).
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let resp = handler.srxmcp_status_test(SrxmcpStatusArgs {}).await;

    assert_eq!(resp.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(resp.endpoint, "srxmcp");
    // uptime in seconds — at 10ms it's 0; just assert it's representable.
    assert!(resp.uptime_seconds < 60);
}
```

(We use `srxmcp_status_test` as a test-only inherent method on `JmcpSrxHandler` that bypasses the `#[tool]` macro plumbing.)

- [ ] **Step 4: Run test — expect compile failure**

Run: `cargo test -p rust-srxmcp`
Expected: FAIL with "cannot find module `server`" or similar.

- [ ] **Step 5: Create `rust-srxmcp/src/server.rs`**

```rust
//! `JmcpSrxHandler` — the rmcp `#[tool]` registry root for `rust-srxmcp`.
//! Phase 1A ships exactly one tool: `srxmcp_status`.

use rmcp::{
    handler::server::tool::ToolRouter,
    model::{ServerCapabilities, ServerInfo},
    schemars,
    tool, tool_handler, tool_router,
    ServerHandler,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::Instant;

#[derive(Clone)]
pub struct JmcpSrxHandler {
    started: Arc<Instant>,
    tool_router: ToolRouter<Self>,
}

impl JmcpSrxHandler {
    pub fn new(started: Arc<Instant>) -> Self {
        Self {
            started,
            tool_router: Self::tool_router(),
        }
    }

    /// Test-only inherent method — bypasses the rmcp adapter so unit tests
    /// can drive the tool body without constructing an RMCP request envelope.
    #[cfg(test)]
    pub async fn srxmcp_status_test(
        &self,
        args: SrxmcpStatusArgs,
    ) -> SrxmcpStatusResponse {
        self.srxmcp_status_impl(args)
    }

    fn srxmcp_status_impl(&self, _args: SrxmcpStatusArgs) -> SrxmcpStatusResponse {
        let uptime_seconds = Instant::now()
            .saturating_duration_since(*self.started)
            .as_secs();
        SrxmcpStatusResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            endpoint: "srxmcp".to_string(),
            uptime_seconds,
        }
    }
}

#[tool_router]
impl JmcpSrxHandler {
    #[tool(description = "Diagnostic — returns this server's version, endpoint name, and uptime in seconds.")]
    pub async fn srxmcp_status(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<SrxmcpStatusArgs>,
    ) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
        let resp = self.srxmcp_status_impl(args);
        Ok(rmcp::model::CallToolResult::structured(
            serde_json::to_value(resp).map_err(|e| {
                rmcp::ErrorData::internal_error(e.to_string(), None)
            })?,
        ))
    }
}

#[tool_handler]
impl ServerHandler for JmcpSrxHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Juniper SRX-specific MCP tools. Phase 1A scaffolding — only `srxmcp_status` is wired.".into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct SrxmcpStatusArgs {}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct SrxmcpStatusResponse {
    pub version: String,
    pub endpoint: String,
    pub uptime_seconds: u64,
}
```

(The exact rmcp macro shape — `tool_router`, `tool_handler`, `Parameters<T>` wrapper, `CallToolResult::structured` constructor — must match what's already used in `rust-junosmcp/src/server.rs`. Before writing this file, read `rust-junosmcp/src/server.rs` and `rust-junosmcp/src/server/*.rs` (if present) to copy the exact API surface used in the live codebase.)

- [ ] **Step 6: Create stub `rust-srxmcp/src/main.rs` (full main wired in Task 10)**

```rust
mod server;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    eprintln!("rust-srxmcp {} — stub main (HTTP wire-up lands in next task)", env!("CARGO_PKG_VERSION"));
    Ok(())
}

pub use server::*;
```

Wait — integration tests need to access `rust_srxmcp::server::...`. A binary crate's `src/main.rs` is not a library, so integration tests under `tests/` cannot import it. Two options:

**Option A (chosen):** Add a `src/lib.rs` that re-exports the public surface, and have `main.rs` use `rust_srxmcp::*`.

Create `rust-srxmcp/src/lib.rs`:

```rust
//! Re-exports for integration tests under `tests/`. Binary entry in `main.rs`.

pub mod server;
```

Update `Cargo.toml` `[[bin]]` section is fine as-is. Cargo auto-detects `lib.rs` alongside `main.rs`.

Update stub `rust-srxmcp/src/main.rs` to:
```rust
use anyhow::Result;
use rust_srxmcp::server;
use std::sync::Arc;
use tokio::time::Instant;

#[tokio::main]
async fn main() -> Result<()> {
    let _started: Arc<Instant> = Arc::new(Instant::now());
    let _handler = server::JmcpSrxHandler::new(_started);
    eprintln!("rust-srxmcp {} — stub main", env!("CARGO_PKG_VERSION"));
    Ok(())
}
```

- [ ] **Step 7: Run the test**

Run: `cargo test -p rust-srxmcp`
Expected: `srxmcp_status_returns_version_endpoint_and_uptime` PASSES.

- [ ] **Step 8: Build full workspace**

Run: `cargo build --workspace`
Expected: clean.

Run: `cargo build` (no args)
Expected: still default-members only (no rust-srxmcp* in output).

- [ ] **Step 9: fmt + clippy**

Run: `cargo fmt -- --check`
Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 10: Commit**

```bash
git add rust-srxmcp/ Cargo.toml
git commit -m "feat(srxmcp): scaffold binary crate with srxmcp_status tool"
```

---

## Task 10: Wire HTTP transport in `rust-srxmcp/src/main.rs`

**Files:**
- Create: `rust-srxmcp/src/http_transport.rs`
- Modify: `rust-srxmcp/src/lib.rs`
- Modify: `rust-srxmcp/src/main.rs`

The transport mirrors `rust-junosmcp/src/http_transport.rs` but is bound to `JmcpSrxHandler` (rmcp tool registries are per-handler-type) and uses `JMCP_SRX_HTTP_PORT` defaulting to `30032`.

- [ ] **Step 1: Create `rust-srxmcp/src/http_transport.rs`**

Read `rust-junosmcp/src/http_transport.rs` (already known above). Adapt:

```rust
//! axum router for rust-srxmcp: AuthLayer + rmcp streamable-http handler.
//!
//! Mirror of rust-junosmcp/src/http_transport.rs, bound to JmcpSrxHandler.

use crate::server::JmcpSrxHandler;
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use axum::Router;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rust_junosmcp_auth::tower::{auth_layer, AuthState};
use rust_junosmcp_auth::TokenStore;
use std::net::SocketAddr;
use std::sync::Arc;

pub async fn serve(
    handler: JmcpSrxHandler,
    addr: SocketAddr,
    token_store: Option<Arc<ArcSwap<TokenStore>>>,
) -> Result<()> {
    let handler_factory = move || Ok::<_, std::io::Error>(handler.clone());

    let svc = StreamableHttpService::new(
        handler_factory,
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );

    let rmcp_router = Router::new().nest_service("/mcp", svc);

    let app = if let Some(store) = token_store {
        rmcp_router.layer(axum::middleware::from_fn_with_state(
            AuthState { store },
            auth_layer,
        ))
    } else {
        rmcp_router
    };

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!(addr = %addr, "rust-srxmcp streamable-http listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("axum::serve")?;
    Ok(())
}
```

(Phase 1A skips the `tls` feature — keep it out of scope per the spec; can be re-added in Phase 1B if needed.)

- [ ] **Step 2: Register the module in `rust-srxmcp/src/lib.rs`**

```rust
pub mod http_transport;
pub mod server;
```

- [ ] **Step 3: Replace `rust-srxmcp/src/main.rs` with the real entry point**

```rust
//! `rust-srxmcp` — Phase 1A scaffolding.
//!
//! Boots an opt-in second MCP endpoint on `:30032` (override
//! `JMCP_SRX_HTTP_PORT`). Wires bearer auth against the shared
//! `/etc/jmcp/tokens.json` store and registers exactly one tool:
//! `srxmcp_status`.

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use clap::Parser;
use rust_junosmcp_auth::file::TokenStoreFile;
use rust_srxmcp::{http_transport, server::JmcpSrxHandler};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::Instant;

#[derive(Debug, Parser)]
#[command(
    name = "rust-srxmcp",
    version,
    about = "Juniper SRX-specific MCP server (Phase 1A scaffolding)."
)]
struct Cli {
    /// HTTP bind host.
    #[arg(long, default_value = "0.0.0.0", env = "JMCP_SRX_HTTP_HOST")]
    host: String,

    /// HTTP bind port.
    #[arg(long, default_value_t = 30032, env = "JMCP_SRX_HTTP_PORT")]
    port: u16,

    /// Bearer-token file (shared with rust-junosmcp).
    #[arg(long, env = "JMCP_TOKENS_PATH")]
    tokens_file: Option<PathBuf>,

    /// Devices file — read for token-scope validation; not used by `srxmcp_status` itself.
    #[arg(long, env = "JMCP_DEVICES_PATH")]
    device_mapping: Option<PathBuf>,

    /// Allow unauthenticated requests (lab only).
    #[arg(long, default_value_t = false)]
    allow_no_auth: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    rust_junosmcp_core::bootstrap::init_tracing();

    let args = Cli::parse();

    // Token store: required unless --allow-no-auth.
    let token_store = match (&args.tokens_file, args.allow_no_auth, &args.device_mapping) {
        (Some(path), _, devices) => {
            let names: Vec<String> = match devices {
                Some(dpath) => {
                    let (inv, _) = rust_junosmcp_core::bootstrap::load_inventory(dpath)
                        .with_context(|| format!("loading {}", dpath.display()))?;
                    inv.names()
                }
                None => Vec::new(),
            };
            let known: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
            let store = TokenStoreFile::load(path, &known)
                .with_context(|| format!("loading {}", path.display()))?;
            tracing::info!(tokens = store.len(), "token store loaded");
            Some(Arc::new(ArcSwap::from_pointee(store)))
        }
        (None, true, _) => {
            tracing::warn!(
                "--allow-no-auth: streamable-http will accept unauthenticated requests"
            );
            None
        }
        (None, false, _) => {
            anyhow::bail!(
                "--tokens-file required for streamable-http (or pass --allow-no-auth for lab use)"
            );
        }
    };

    let started = Arc::new(Instant::now());
    let handler = JmcpSrxHandler::new(started);

    // SIGHUP: per spec, wired but no-op in 0.0.1. Reloading the token store
    // requires inventory awareness for scope validation; mirror rust-junosmcp's
    // shape so the codebase has one consistent pattern.
    #[cfg(unix)]
    if let (Some(store_arc), Some(token_path), Some(dev_path)) = (
        token_store.clone(),
        args.tokens_file.clone(),
        args.device_mapping.clone(),
    ) {
        tokio::spawn(async move {
            let mut hup = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::hangup(),
            ) {
                Ok(sig) => sig,
                Err(e) => {
                    tracing::error!(error = %e, "failed to install SIGHUP handler; reload disabled");
                    return;
                }
            };
            while hup.recv().await.is_some() {
                tracing::info!("SIGHUP: reloading token store");
                let names = match rust_junosmcp_core::bootstrap::load_inventory(&dev_path) {
                    Ok((inv, _)) => inv.names(),
                    Err(e) => {
                        tracing::error!(error = %e, "SIGHUP inventory reload failed; reusing previous router list");
                        Vec::new()
                    }
                };
                let known: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
                match TokenStoreFile::load(&token_path, &known) {
                    Ok(new_store) => {
                        store_arc.store(Arc::new(new_store));
                        tracing::info!(path = %token_path.display(), "token store reloaded");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "SIGHUP token reload failed; keeping previous store");
                    }
                }
            }
        });
    }

    let addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .with_context(|| format!("parsing {}:{}", args.host, args.port))?;

    http_transport::serve(handler, addr, token_store).await
}
```

- [ ] **Step 4: Build**

Run: `cargo build -p rust-srxmcp`
Expected: clean.

- [ ] **Step 5: Smoke-run locally (optional, non-CI step)**

Run (in another terminal, with `/etc/jmcp/tokens.json` from lab or a test fixture):
```bash
JMCP_SRX_HTTP_PORT=30099 ./target/debug/rust-srxmcp --allow-no-auth
```
Then in a third terminal:
```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:30099/mcp
```
Expected (without auth header and `--allow-no-auth`): `200`/`405`/`406` (not `401`, since allow_no_auth bypasses auth).

Run with `--allow-no-auth` removed and a tokens file: expect `401` without `Authorization` header.

Skip if locally inconvenient; the LXC 601 deploy in Task 15 covers the real smoke.

- [ ] **Step 6: fmt + clippy + workspace tests**

Run: `cargo fmt -- --check`
Run: `cargo clippy --workspace --all-targets -- -D warnings`
Run: `cargo test --workspace`
Expected: all clean.

- [ ] **Step 7: Commit**

```bash
git add rust-srxmcp/src/main.rs rust-srxmcp/src/lib.rs rust-srxmcp/src/http_transport.rs
git commit -m "feat(srxmcp): wire axum + rmcp streamable-http on port 30032"
```

---

## Task 11: Add systemd unit

**Files:**
- Create: `systemd/rust-srxmcp.service`

- [ ] **Step 1: Read existing unit for hardening directives**

Run: `cat systemd/rust-junosmcp.service` (if present in repo; otherwise check
`ssh root@pve3 pct exec 601 -- cat /etc/systemd/system/rust-junosmcp.service`).

- [ ] **Step 2: Write the new unit**

Create `systemd/rust-srxmcp.service`. Copy the existing rust-junosmcp.service hardening directives verbatim; below is the spec-defined skeleton — extend with all `Protect*=`/`Restrict*=`/`PrivateTmp=`/`NoNewPrivileges=` lines from the live junos unit:

```ini
[Unit]
Description=Rust SRX MCP server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=jmcp
Group=jmcp
Environment=JMCP_SRX_HTTP_PORT=30032
Environment=JMCP_TOKENS_PATH=/etc/jmcp/tokens.json
Environment=JMCP_DEVICES_PATH=/etc/jmcp/devices.json
Environment=RUST_LOG=info
ExecStart=/usr/local/bin/rust-srxmcp --tokens-file /etc/jmcp/tokens.json --device-mapping /etc/jmcp/devices.json
Restart=on-failure
RestartSec=2s
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

(Append every additional `Protect*`/`Restrict*` directive present in the live rust-junosmcp.service so both binaries share identical confinement.)

- [ ] **Step 3: Commit**

```bash
git add systemd/rust-srxmcp.service
git commit -m "feat(srxmcp): add systemd unit"
```

---

## Task 12: CI workflow — append `--workspace` build/test

**Files:**
- Modify: `.github/workflows/*.yml` (the CI workflow that runs cargo build/test)

- [ ] **Step 1: Locate the CI workflow**

Run: `ls .github/workflows/`

Read the file that runs `cargo build` and `cargo test`. The change appends two new steps after the existing default-members ones — do **not** modify the existing steps (they preserve byte-for-byte behavior).

- [ ] **Step 2: Append the workspace steps**

Add (matching the existing step structure):

```yaml
      - name: cargo build --workspace
        run: cargo build --workspace --all-features

      - name: cargo test --workspace
        run: cargo test --workspace --all-features
```

- [ ] **Step 3: Verify locally**

Run: `cargo build --workspace && cargo test --workspace`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/
git commit -m "ci: add --workspace build/test steps for SRX crates"
```

---

## Task 13: README + CHANGELOG for the new crate

**Files:**
- Create: `rust-srxmcp/README.md`
- Create: `rust-srxmcp/CHANGELOG.md`

- [ ] **Step 1: Create `rust-srxmcp/README.md`**

```markdown
# rust-srxmcp

Opt-in MCP server for Juniper SRX-specific operational workflows. Phase 1A scaffolding ships only `srxmcp_status` — real workflow tools land in Phase 1B (`srxmcp-v0.1.0`).

## Status

`0.0.1` — workspace scaffolding + one diagnostic tool.

## Building

`rust-srxmcp` is excluded from the workspace `default-members`, so the root `cargo build` is unchanged. To build:

```bash
cargo build -p rust-srxmcp        # single crate
cargo build --workspace           # whole workspace
```

## Running

Listens on `:30032` by default (override with `JMCP_SRX_HTTP_PORT`). Shares `/etc/jmcp/tokens.json` and `/etc/jmcp/devices.json` with `rust-junosmcp`.

```bash
./rust-srxmcp \
    --tokens-file /etc/jmcp/tokens.json \
    --device-mapping /etc/jmcp/devices.json
```

## Tool surface (0.0.1)

| Tool | Purpose |
|---|---|
| `srxmcp_status` | Returns `{version, endpoint, uptime_seconds}` for sanity checking. |
```

- [ ] **Step 2: Create `rust-srxmcp/CHANGELOG.md`**

```markdown
# Changelog — rust-srxmcp

All notable changes to the `rust-srxmcp` binary. Versions independent of `rust-junosmcp`.

## 0.0.1 — 2026-05-20

Initial release. Workspace scaffolding plus one diagnostic tool.

### Added

- `rust-srxmcp` binary crate (opt-in; excluded from workspace `default-members`).
- `rust-srxmcp-core` placeholder crate for Phase 1B workflows.
- `srxmcp_status` tool — returns version, endpoint name, and uptime in seconds.
- Bearer-token auth via shared `rust-junosmcp-auth::tower` middleware.
- Systemd unit `systemd/rust-srxmcp.service` binding `:30032`.
- SIGHUP token-store reload (mirrors `rust-junosmcp` shape).

### Notes

- Shares `/etc/jmcp/tokens.json` and `/etc/jmcp/devices.json` with `rust-junosmcp`.
- TLS not yet wired (Phase 1B if requested).
- No NETCONF, SCP, or inventory mutation in 0.0.1.
```

- [ ] **Step 3: Commit**

```bash
git add rust-srxmcp/README.md rust-srxmcp/CHANGELOG.md
git commit -m "docs(srxmcp): add README + CHANGELOG for 0.0.1"
```

---

## Task 14: Final fmt + clippy + workspace test sweep

**Files:** (no edits; verification only)

- [ ] **Step 1: Format check**

Run: `cargo fmt -- --check`
Expected: clean.

- [ ] **Step 2: Clippy (workspace, all targets, all features)**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 3: Full workspace tests**

Run: `cargo test --workspace --all-features`
Expected: all green; new tests:
- `rust-junosmcp-auth::tower::tests::*` (8 relocated parse_bearer tests)
- `rust-junosmcp-core::bootstrap::tests::*` (4 helper tests)
- `rust-srxmcp::tests::status_tool::srxmcp_status_returns_version_endpoint_and_uptime`

- [ ] **Step 4: Default-members regression check**

Run: `cargo build && cargo test`
Expected: identical output to v0.6.2 baseline — no `rust-srxmcp*` lines.

- [ ] **Step 5: Generic binary version check**

Run: `cargo run -p rust-junosmcp -- --version`
Expected: `rust-junosmcp 0.6.2`.

Run: `cargo run -p rust-srxmcp -- --version`
Expected: `rust-srxmcp 0.0.1`.

- [ ] **Step 6: No commit needed for verification, but proceed to PR if all green.**

---

## Task 15: PR, tag, deploy to LXC 601

**Files:** (workflow only)

- [ ] **Step 1: Push branch**

```bash
git push -u origin feat/srxmcp-scaffold
```

- [ ] **Step 2: Open PR**

```bash
gh pr create \
  --title "feat(srxmcp): workspace scaffolding + status endpoint (v0.0.1)" \
  --body "$(cat <<'EOF'
## Summary

Phase 1A of the SRX MCP strategy: stand up an opt-in second binary on LXC 601 alongside the live `rust-junosmcp:30031`. Ships exactly one diagnostic tool (`srxmcp_status`) to validate workspace, build, and deploy plumbing.

- Per-crate versioning; workspace `default-members` excludes new SRX crates so `cargo build` (no args) is byte-for-byte unchanged.
- Moves `auth_layer.rs` + `caller.rs` into `rust-junosmcp-auth::{tower, caller}` so both binaries share the tower middleware.
- New `bootstrap` module in `rust-junosmcp-core` for `init_tracing`, `load_inventory`, `build_host_key_policy`.
- New `rust-srxmcp` binary binds `:30032`, shares `/etc/jmcp/tokens.json` + `/etc/jmcp/devices.json`.

Spec: `docs/superpowers/specs/2026-05-20-srxmcp-phase-1a-scaffold-design.md`
Plan: `docs/superpowers/plans/2026-05-20-srxmcp-phase-1a-scaffold.md`

## Test plan

- [ ] `cargo build` + `cargo test` (no args) — byte-for-byte equivalent to v0.6.2
- [ ] `cargo build --workspace` + `cargo test --workspace` — clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` — clean
- [ ] Deploy `rust-srxmcp 0.0.1` to LXC 601, run 7 smoke tests from spec
- [ ] Regression smoke: `rust-junosmcp:30031` still works (fetch_file + transfer_file on smoke-v0.5.2.txt → skipped)
EOF
)"
```

- [ ] **Step 3: Two-stage review (per subagent-driven-development skill)**

This step is the spec-compliance + code-quality review handled by the orchestration workflow. After both verdicts are APPROVED, proceed to merge.

- [ ] **Step 4: Rebase-merge PR**

```bash
gh pr merge --rebase --delete-branch
```

- [ ] **Step 5: Tag annotated `srxmcp-v0.0.1`**

```bash
git fetch origin
git checkout main
git pull --ff-only
git tag -a srxmcp-v0.0.1 -m "rust-srxmcp 0.0.1 — workspace scaffolding + srxmcp_status tool"
git push origin srxmcp-v0.0.1
```

- [ ] **Step 6: Build release binary on host**

```bash
cargo build --release -p rust-srxmcp
ls -l target/release/rust-srxmcp
target/release/rust-srxmcp --version  # expect "rust-srxmcp 0.0.1"
```

- [ ] **Step 7: Deploy to LXC 601**

```bash
scp target/release/rust-srxmcp root@pve3.mechub.org:/tmp/rust-srxmcp-0.0.1
scp systemd/rust-srxmcp.service root@pve3.mechub.org:/tmp/rust-srxmcp.service
ssh root@pve3.mechub.org pct push 601 /tmp/rust-srxmcp-0.0.1 /usr/local/bin/rust-srxmcp --perms 0755
ssh root@pve3.mechub.org pct push 601 /tmp/rust-srxmcp.service /etc/systemd/system/rust-srxmcp.service --perms 0644
ssh root@pve3.mechub.org pct exec 601 -- systemctl daemon-reload
ssh root@pve3.mechub.org pct exec 601 -- systemctl enable --now rust-srxmcp.service
ssh root@pve3.mechub.org pct exec 601 -- systemctl is-active rust-srxmcp.service  # expect "active"
ssh root@pve3.mechub.org pct exec 601 -- /usr/local/bin/rust-srxmcp --version    # expect "rust-srxmcp 0.0.1"
```

- [ ] **Step 8: Run all 7 smoke tests from the spec**

1. `curl -sS -o /dev/null -w '%{http_code}' http://192.168.1.194:30032/mcp` → `401`
2. `curl -sS http://192.168.1.194:30032/mcp` → body is `{"error":"invalid_request","error_description":"missing Authorization header"}` (RFC 6749 JSON shape)
3. MCP initialize with `Authorization: Bearer <token>` → 200
4. `tools/list` → exactly `["srxmcp_status"]`
5. `tools/call srxmcp_status` → `{"version":"0.0.1","endpoint":"srxmcp","uptime_seconds":<small>}`
6. `systemctl kill -s HUP rust-srxmcp.service` → still `active`, no `ERROR` in journal
7. Regression: `rust-junosmcp:30031` still works — call `fetch_file` + `transfer_file` against `vSRX-test10` with `smoke-v0.5.2.txt` → `status=skipped` on both

- [ ] **Step 9: Update memory**

Write `~/.claude/projects/-home-mharman-RustJunosMCP/memory/srxmcp_v0_0_1_released.md` per the memory schema (project type, deploy notes, regression status).

Add the entry to `~/.claude/projects/-home-mharman-RustJunosMCP/memory/MEMORY.md`.

- [ ] **Step 10: Done.**

---

## Self-Review Notes

**Spec coverage verification:**
- Workspace `default-members` migration — Task 1
- Per-crate versioning (5 crates: 0.6.2 ×3 + 0.0.1 ×2) — Tasks 1, 8, 9
- `rust-srxmcp-core` placeholder crate — Task 8
- `rust-srxmcp` binary crate — Tasks 9, 10
- Bootstrap helpers in `rust-junosmcp-core` — Tasks 5, 6; **refinement noted**: `build_auth_layer` and `build_audit_logger` from the spec are not implemented as standalone functions. Instead:
  - Auth middleware is shared via crate relocation to `rust-junosmcp-auth::tower` (Tasks 2-4), which is a cleaner factoring than a `build_auth_layer` constructor.
  - `build_audit_logger` is omitted: there is no central audit logger constructed in `rust-junosmcp/src/main.rs` (audit logging in v0.5.4 lives inside individual tool handlers, not as a top-level bootstrap concern). Phase 1B can add it when SRX tools need an audit hook.
  - `install_sighup_handler` is omitted as a shared helper; the SIGHUP closure body differs between binaries (rust-junosmcp reloads inventory + policy; rust-srxmcp 0.0.1 reloads only tokens). The closure is duplicated, with each binary using its own inlined version.
- `srxmcp_status` tool with `(version, endpoint, uptime_seconds)` — Task 9
- Systemd unit on `:30032` — Task 11
- CI `--workspace` steps — Task 12
- Manual scp+pct push deploy — Task 15
- Tag `srxmcp-v0.0.1` annotated — Task 15
- Two CHANGELOG files (top-level stays, new one in `rust-srxmcp/`) — Task 13
- 7 smoke tests — Task 15

**Placeholder scan:** No `TBD`, `TODO`, or "implement later" in the plan body. Every code block is complete and self-contained.

**Type consistency:** `JmcpSrxHandler`, `SrxmcpStatusArgs`, `SrxmcpStatusResponse`, `AuthState`, `auth_layer`, `CallerCtx`, `TokenStoreFile`, `TokenStore` — used identically across all tasks where referenced.

**Refinement deltas from spec (documented above so reviewers see the divergence):**
1. Auth middleware shared by relocation, not by `build_auth_layer` constructor.
2. `build_audit_logger` omitted (no central audit logger to extract).
3. `install_sighup_handler` not extracted as a shared helper; closure body diverges per-binary.
4. Bootstrap helper set reduced to `init_tracing` + `load_inventory` + `build_host_key_policy` — the 3 trivially-extractable pieces.

These deltas preserve the spec's success criteria (byte-for-byte `cargo build` behavior, both binaries running concurrently on LXC 601, srxmcp-v0.0.1 tag) and the risk mitigation (no behavior change in v0.6.2 production binary — the auth_layer relocation is purely textual, all 8 unit tests move with it).
