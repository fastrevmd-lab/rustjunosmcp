# Inventory Mutation Implementation Plan (PR #7)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `add_device` (with rmcp elicitation + args fallback, atomic `devices.json` write, password-auth opt-in) and `reload_devices` (optional `file_name` for path-swap), bringing tool surface to full upstream parity (11 tools).

**Architecture:** `DeviceManager` swaps from `Arc<Inventory>` to `Arc<ArcSwap<Inventory>>` plus an `inventory_path: Arc<ArcSwap<PathBuf>>`, an `inventory_hash: Arc<ArcSwap<[u8;32]>>` for TOCTOU defence, and an `inventory_write_lock: Arc<tokio::sync::Mutex<()>>` that serializes all on-disk and in-memory inventory mutations. Reads call `.load()` once at handler entry → snapshot semantics. Writes round-trip through `serde_json::Value` to preserve `_blocklist_defaults`, per-device `blocklist`, and any unknown top-level fields. Atomic file write via `tempfile::NamedTempFile::persist`. Two new CLI flags (`--inventory-readonly`, `--allow-password-auth-add`) gate the mutating tools. Existing SIGHUP handler is extended to also re-read the inventory.

**Tech Stack:** Rust 2021, `arc-swap` (already in workspace), `tempfile` (promote from dev-dep), `tokio::sync::Mutex`, `sha2` (already in workspace via auth), `rmcp` 0.8.5 elicitation API.

**Spec:** `docs/superpowers/specs/2026-05-05-templates-inventory-design.md` §4.2, §4.3, §5, §6, §7, §8, §9.

**Prerequisites:** PR #6 (templates) merged. This plan starts from a fresh worktree off `main`.

---

## File map

| Path | Action | Purpose |
|---|---|---|
| `Cargo.toml` (workspace) | Modify | Promote `tempfile` from dev to runtime; ensure `arc-swap` and `sha2` are workspace deps |
| `rust-junosmcp-core/Cargo.toml` | Modify | Pull `arc-swap`, `tempfile`, `sha2` into runtime deps |
| `rust-junosmcp-core/src/error.rs` | Modify | Add 8 inventory-mutation variants |
| `rust-junosmcp-core/src/inventory.rs` | Modify | Add `write_atomic`, `add_device_in_memory`, `IndexMap`-aware Value round-trip helpers |
| `rust-junosmcp-core/src/device_manager.rs` | Modify | Refactor to `Arc<ArcSwap<Inventory>>`; add `inventory_path`, `inventory_hash`, `inventory_write_lock`, `update_*` methods |
| `rust-junosmcp-core/src/tools/mod.rs` | Modify | Register `pub mod add_device; pub mod reload_devices;` and add `AddDeviceArgs`, `ReloadDevicesArgs` |
| `rust-junosmcp-core/src/tools/add_device.rs` | Create | Validation gates, write path, elicitation-fallback logic |
| `rust-junosmcp-core/src/tools/reload_devices.rs` | Create | Path-swap semantics, diff computation |
| `rust-junosmcp-auth/src/file.rs` | Modify | Extend `KNOWN_TOOLS` with `add_device` + `reload_devices` |
| `rust-junosmcp/src/cli.rs` | Modify | Add `--inventory-readonly` and `--allow-password-auth-add` flags; mutual-exclusion validation |
| `rust-junosmcp/src/server.rs` | Modify | `#[tool]` adapters for both new tools; elicitation peer dispatch |
| `rust-junosmcp/src/main.rs` | Modify | Pass new flags into `DeviceManager`; extend SIGHUP handler to re-read inventory |
| `rust-junosmcp/tests/stdio_smoke.rs` | Modify | Rename `lists_nine_tools` → `lists_eleven_tools`; extend `EXPECTED_TOOLS` |
| `rust-junosmcp/tests/add_device_smoke.rs` | Create | Full add → reload → verify cycle in `tempfile::TempDir` |
| `rust-junosmcp/tests/reload_devices_smoke.rs` | Create | No-args re-read; with-path swap; empty inventory rejected; readonly rejected |
| `rust-junosmcp-core/tests/integration_real_device.rs` | Modify | Append `#[ignore]` `live_add_device_persists_then_reload` |
| `README.md` | Modify | New "Inventory mutation (released)" subsection; update CLI table; SIGHUP note |

---

## Task 1: Refactor DeviceManager to Arc<ArcSwap<Inventory>>

This is a structural refactor with no new behavior. Existing read sites stay correct; tests must continue to pass.

**Files:**
- Modify: `rust-junosmcp-core/Cargo.toml`
- Modify: `rust-junosmcp-core/src/device_manager.rs`

- [ ] **Step 1: Confirm arc-swap is a workspace dep**

Run: `grep -n "arc-swap" Cargo.toml rust-junosmcp-core/Cargo.toml rust-junosmcp-auth/Cargo.toml`
Expected: present in workspace deps and in `rust-junosmcp-auth/Cargo.toml`.

- [ ] **Step 2: Add arc-swap to rust-junosmcp-core**

In `rust-junosmcp-core/Cargo.toml` `[dependencies]`:

```toml
arc-swap   = { workspace = true }
```

- [ ] **Step 3: Update DeviceManager**

Read `rust-junosmcp-core/src/device_manager.rs`. Replace the `inventory: Arc<Inventory>` field and accessor with:

```rust
use arc_swap::ArcSwap;

pub struct DeviceManager {
    inventory: Arc<ArcSwap<Inventory>>,
    // ... existing fields unchanged
}

impl DeviceManager {
    pub fn new(inventory: Arc<Inventory>) -> Self {
        Self {
            inventory: Arc::new(ArcSwap::from(inventory)),
            // ... existing fields
        }
    }

    /// Borrow a snapshot of the current inventory. Cheap; readers never block writers.
    pub fn inventory(&self) -> Arc<Inventory> {
        self.inventory.load_full()
    }
}
```

- [ ] **Step 4: Audit all callers of `.inventory()`**

Run: `grep -rn "\\.inventory()" rust-junosmcp-core/src rust-junosmcp/src rust-junosmcp-auth/src`
Expected: every caller currently treats the return as `&Inventory`-shaped (e.g., `dm.inventory().get(name)`). With the new `Arc<Inventory>` return, calls like `dm.inventory().get(...)` still work because `Arc<Inventory>` derefs to `&Inventory`.

If any caller binds `let inv = dm.inventory();` then *moves* the `Arc<Inventory>` somewhere expecting `&Inventory`, those need the explicit `&*inv` or an `as_ref()`. Most don't.

- [ ] **Step 5: Run the core lib tests**

Run: `cargo test -p rust-junosmcp-core --lib`
Expected: all PASS. If any fail, the cause is almost always a `&Inventory` vs `Arc<Inventory>` mismatch — fix at the call site.

- [ ] **Step 6: Run the workspace test suite**

Run: `cargo test --workspace --no-run`
Expected: clean compile.

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock rust-junosmcp-core/Cargo.toml rust-junosmcp-core/src/device_manager.rs
git commit -m "refactor(device_manager): inventory is Arc<ArcSwap<Inventory>>

No behavior change. Prepares for hot-swap by add_device / reload_devices
without giving up the existing read-path simplicity."
```

---

## Task 2: Add inventory path, hash, write lock to DeviceManager

**Files:**
- Modify: `rust-junosmcp-core/Cargo.toml`
- Modify: `rust-junosmcp-core/src/device_manager.rs`

- [ ] **Step 1: Pull tempfile + sha2 into runtime deps**

In `rust-junosmcp-core/Cargo.toml`:

```toml
tempfile   = { workspace = true }
sha2       = { workspace = true }
```

- [ ] **Step 2: Add the new fields**

In `device_manager.rs`:

```rust
use std::path::PathBuf;
use tokio::sync::Mutex;

pub struct DeviceManager {
    inventory: Arc<ArcSwap<Inventory>>,
    inventory_path: Arc<ArcSwap<PathBuf>>,
    inventory_hash: Arc<ArcSwap<[u8; 32]>>,
    inventory_write_lock: Arc<Mutex<()>>,
    inventory_readonly: bool,
    allow_password_auth_add: bool,
    // ... existing fields unchanged
}
```

- [ ] **Step 3: Update the constructor**

Replace `pub fn new(...)` with:

```rust
pub fn new(inventory: Arc<Inventory>) -> Self {
    Self::with_path(inventory, PathBuf::new(), [0u8; 32], false, false)
}

pub fn with_path(
    inventory: Arc<Inventory>,
    path: PathBuf,
    hash: [u8; 32],
    inventory_readonly: bool,
    allow_password_auth_add: bool,
) -> Self {
    Self {
        inventory: Arc::new(ArcSwap::from(inventory)),
        inventory_path: Arc::new(ArcSwap::from_pointee(path)),
        inventory_hash: Arc::new(ArcSwap::from_pointee(hash)),
        inventory_write_lock: Arc::new(Mutex::new(())),
        inventory_readonly,
        allow_password_auth_add,
        // ... existing fields default
    }
}
```

The bare `new()` keeps the existing test ergonomics (no need to thread a path through every test).

- [ ] **Step 4: Add accessors**

```rust
impl DeviceManager {
    pub fn inventory_path(&self) -> PathBuf {
        (**self.inventory_path.load()).clone()
    }
    pub fn inventory_hash(&self) -> [u8; 32] {
        **self.inventory_hash.load()
    }
    pub fn inventory_readonly(&self) -> bool {
        self.inventory_readonly
    }
    pub fn allow_password_auth_add(&self) -> bool {
        self.allow_password_auth_add
    }
    pub fn write_lock(&self) -> Arc<Mutex<()>> {
        self.inventory_write_lock.clone()
    }
    /// Atomically swap inventory + path + hash. Caller must hold `write_lock`.
    pub fn store_inventory(&self, inv: Arc<Inventory>, path: PathBuf, hash: [u8; 32]) {
        self.inventory.store(inv);
        self.inventory_path.store(Arc::new(path));
        self.inventory_hash.store(Arc::new(hash));
    }
}
```

- [ ] **Step 5: Tests pass**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add rust-junosmcp-core/Cargo.toml rust-junosmcp-core/src/device_manager.rs
git commit -m "feat(device_manager): add inventory path/hash/write_lock plumbing"
```

---

## Task 3: Implement atomic-write helper

**Files:**
- Modify: `rust-junosmcp-core/src/inventory.rs`

- [ ] **Step 1: Write the failing tests**

Append to the existing `#[cfg(test)] mod` block (or a new submodule `mod write_tests`):

```rust
#[cfg(test)]
mod write_tests {
    use super::*;
    use std::io::Write as _;

    fn fixture(json: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn atomic_write_replaces_file_in_place() {
        let f = fixture(r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#);
        let new_content = serde_json::json!({
            "r2": {"ip":"10.0.0.2","username":"u","auth":{"type":"password","password":"x"}}
        });
        write_atomic(f.path(), &new_content).unwrap();
        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(f.path()).unwrap()).unwrap();
        assert!(on_disk.get("r2").is_some());
        assert!(on_disk.get("r1").is_none());
    }

    #[test]
    fn atomic_write_preserves_blocklist_defaults() {
        let original = serde_json::json!({
            "_blocklist_defaults": {"commands":[{"action":"deny","pattern":"request system reboot"}]},
            "r1": {"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        });
        let f = fixture(&serde_json::to_string(&original).unwrap());

        let mut updated = original.clone();
        updated["r2"] = serde_json::json!({
            "ip":"10.0.0.2","username":"u","auth":{"type":"password","password":"x"}
        });

        write_atomic(f.path(), &updated).unwrap();

        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(f.path()).unwrap()).unwrap();
        assert!(on_disk.get("_blocklist_defaults").is_some());
        assert!(on_disk.get("r1").is_some());
        assert!(on_disk.get("r2").is_some());
    }

    #[test]
    fn atomic_write_preserves_key_order() {
        // Requires serde_json's `preserve_order` feature; verify by building
        // the input map in insertion order and checking on-disk byte order.
        let mut map = serde_json::Map::new();
        map.insert("first".into(), serde_json::json!({"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}));
        map.insert("second".into(), serde_json::json!({"ip":"127.0.0.2","username":"u","auth":{"type":"password","password":"x"}}));
        let val = serde_json::Value::Object(map);
        let f = tempfile::NamedTempFile::new().unwrap();
        write_atomic(f.path(), &val).unwrap();
        let bytes = std::fs::read(f.path()).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.find("\"first\"").unwrap() < s.find("\"second\"").unwrap());
    }
}
```

- [ ] **Step 2: Confirm `write_atomic` is undefined**

Run: `cargo test -p rust-junosmcp-core --lib inventory::write_tests`
Expected: compilation error.

- [ ] **Step 3: Enable `serde_json/preserve_order`**

In `rust-junosmcp-core/Cargo.toml`, change:

```toml
serde_json = { workspace = true, features = ["preserve_order"] }
```

(If `serde_json` is currently brought in by `workspace = true` only, add the features line.)

- [ ] **Step 4: Implement write_atomic**

Add to `inventory.rs`:

```rust
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

/// SHA-256 of the file at `path`. Returns zeros if the file doesn't exist
/// (callers treat zeros as "no last-known content").
pub fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let digest = Sha256::digest(&bytes);
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            Ok(out)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok([0u8; 32]),
        Err(e) => Err(e),
    }
}

/// Atomically replace `path` with the JSON serialization of `value`.
/// Same-filesystem rename via tempfile. Preserves existing file mode bits.
pub fn write_atomic(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "inventory path has no parent directory",
    ))?;
    if !parent.as_os_str().is_empty() && !parent.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("parent directory does not exist: {}", parent.display()),
        ));
    }
    let resolved_parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };

    let mut tmp = tempfile::NamedTempFile::new_in(resolved_parent)?;
    let pretty = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    tmp.write_all(pretty.as_bytes())?;
    tmp.write_all(b"\n")?;
    tmp.as_file().sync_all()?;

    // Preserve mode bits if the target already exists.
    #[cfg(unix)]
    if let Ok(meta) = std::fs::metadata(path) {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode))?;
    }

    tmp.persist(path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    Ok(())
}
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p rust-junosmcp-core --lib inventory::write_tests`
Expected: 3 PASS.

- [ ] **Step 6: Commit**

```bash
git add rust-junosmcp-core/src/inventory.rs rust-junosmcp-core/Cargo.toml
git commit -m "feat(inventory): atomic write_atomic + hash_file helpers

Tempfile + same-FS rename, fsync before persist. Preserves file mode
bits and any unknown top-level keys (round-trip is on serde_json::Value)."
```

---

## Task 4: Add JmcpError variants for inventory mutation

**Files:**
- Modify: `rust-junosmcp-core/src/error.rs`

- [ ] **Step 1: Append the 8 new variants**

```rust
    #[error("inventory is read-only (--inventory-readonly set)")]
    InventoryReadonly,

    #[error("device `{0}` already exists in the inventory")]
    DeviceExists(String),

    #[error("password authentication is not allowed for add_device; use --allow-password-auth-add to enable")]
    PasswordAuthDisabled,

    #[error("invalid device name `{0}`: must match ^[A-Za-z0-9_.-]+$")]
    InvalidDeviceName(String),

    #[error("invalid device IP/hostname `{0}`")]
    InvalidDeviceIp(String),

    #[error("invalid device port `{0}`: must be in 1..=65535")]
    InvalidDevicePort(u32),

    #[error("missing required arguments: {0:?}")]
    MissingArguments(Vec<String>),

    #[error("inventory file changed on disk between read and write; call reload_devices and retry")]
    InventoryDriftedOnDisk,

    #[error("inventory is empty (no devices)")]
    EmptyInventory,

    #[error("inventory file read error: {0}")]
    InventoryRead(String),

    #[error("inventory parse error: {0}")]
    InventoryParse(String),

    #[error("inventory file write error: {0}")]
    InventoryWrite(String),
```

(Convert `io::Error` and `serde_json::Error` to `String` at the call site to keep the variant `Send + Sync` and easy to format. The actual error chain is logged via `tracing` separately.)

- [ ] **Step 2: Run lib tests**

Run: `cargo test -p rust-junosmcp-core --lib error`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/src/error.rs
git commit -m "feat(error): inventory-mutation JmcpError variants"
```

---

## Task 5: Add CLI flags

**Files:**
- Modify: `rust-junosmcp/src/cli.rs`
- Modify: `rust-junosmcp/src/cli_validate.rs` (or wherever flag interactions are validated)

- [ ] **Step 1: Add the flags to the `Args` (or equivalent) struct**

```rust
    /// Reject add_device and reload_devices unconditionally.
    /// Independent of token scopes.
    #[arg(long)]
    pub inventory_readonly: bool,

    /// Permit add_device to accept auth.type="password".
    /// Off by default. Mutually exclusive with --inventory-readonly.
    #[arg(long)]
    pub allow_password_auth_add: bool,
```

- [ ] **Step 2: Add the mutual-exclusion check**

In the existing CLI validation (`cli_validate.rs` or a `validate()` method), append:

```rust
    if args.inventory_readonly && args.allow_password_auth_add {
        return Err(CliError::Conflict(
            "--inventory-readonly and --allow-password-auth-add are mutually exclusive".into(),
        ));
    }
```

- [ ] **Step 3: Add a unit test**

```rust
    #[test]
    fn inventory_readonly_and_allow_password_auth_add_are_mutually_exclusive() {
        let args = parse_argv(&[
            "rust-junosmcp",
            "--device-mapping", "x.json",
            "--inventory-readonly",
            "--allow-password-auth-add",
        ]);
        let r = validate(&args);
        assert!(matches!(r, Err(CliError::Conflict(_))));
    }

    #[test]
    fn inventory_readonly_off_by_default() {
        let args = parse_argv(&["rust-junosmcp", "--device-mapping", "x.json"]);
        assert!(!args.inventory_readonly);
        assert!(!args.allow_password_auth_add);
    }
```

(`parse_argv` and `CliError` are existing helpers — adapt to the actual code; if the CLI uses `clap::Parser::parse_from`, use that.)

- [ ] **Step 4: Run the CLI tests**

Run: `cargo test -p rust-junosmcp --lib cli`
Expected: 2 new PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp/src/cli.rs rust-junosmcp/src/cli_validate.rs
git commit -m "feat(cli): --inventory-readonly and --allow-password-auth-add"
```

---

## Task 6: Add tool argument structs

**Files:**
- Modify: `rust-junosmcp-core/src/tools/mod.rs`

- [ ] **Step 1: Append the new args structs**

```rust
#[derive(Debug, Deserialize, JsonSchema, Default)]
pub struct AddDeviceArgs {
    /// Device name/identifier in the inventory map.
    #[serde(default)]
    pub device_name: Option<String>,
    /// Device IP address or hostname.
    #[serde(default)]
    pub device_ip: Option<String>,
    /// SSH port. Default 22.
    #[serde(default)]
    pub device_port: Option<u32>,
    /// Username.
    #[serde(default)]
    pub username: Option<String>,
    /// Auth config (tagged enum: ssh_key | password).
    #[serde(default)]
    pub auth: Option<crate::inventory::AuthConfig>,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
pub struct ReloadDevicesArgs {
    /// Optional path to a different inventory file. If omitted, re-reads
    /// the current --device-mapping.
    #[serde(default)]
    pub file_name: Option<String>,
}
```

- [ ] **Step 2: Register the new modules**

```rust
pub mod add_device;
pub mod reload_devices;
```

Create stub files immediately so the module declaration compiles:

`rust-junosmcp-core/src/tools/add_device.rs`:
```rust
//! Stub — Tasks 7 + 8 implement the handler.
```

`rust-junosmcp-core/src/tools/reload_devices.rs`:
```rust
//! Stub — Task 9 implements the handler.
```

- [ ] **Step 3: Make `AuthConfig` derive `JsonSchema`**

In `rust-junosmcp-core/src/inventory.rs`, on the `AuthConfig` enum:

```rust
#[derive(Clone, Deserialize, JsonSchema, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    Password { password: String },
    SshKey { private_key_path: PathBuf },
}
```

(Add `Serialize` + `JsonSchema` derives. The `Serialize` is needed for the round-trip in `add_device`'s write path. Keep the manual `Debug` impl — never derive Debug because that would unredact the password.)

You may need to add `serde::Serialize` to imports.

- [ ] **Step 4: Add basic deserialization tests**

In the `tools/mod.rs` test block:

```rust
    #[test]
    fn add_device_args_all_optional() {
        let v = serde_json::json!({});
        let a: AddDeviceArgs = serde_json::from_value(v).unwrap();
        assert!(a.device_name.is_none());
        assert!(a.auth.is_none());
    }

    #[test]
    fn add_device_args_accepts_full_payload() {
        let v = serde_json::json!({
            "device_name": "core-3",
            "device_ip": "10.0.0.3",
            "device_port": 22,
            "username": "automation",
            "auth": {"type":"ssh_key","private_key_path":"/etc/jmcp/keys/id"}
        });
        let a: AddDeviceArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.device_name.as_deref(), Some("core-3"));
        assert_eq!(a.device_port, Some(22));
        assert!(matches!(a.auth, Some(crate::inventory::AuthConfig::SshKey { .. })));
    }

    #[test]
    fn reload_devices_args_file_name_optional() {
        let v = serde_json::json!({});
        let a: ReloadDevicesArgs = serde_json::from_value(v).unwrap();
        assert!(a.file_name.is_none());
    }
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p rust-junosmcp-core --lib tools::tests`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add rust-junosmcp-core/src/tools/mod.rs rust-junosmcp-core/src/tools/add_device.rs rust-junosmcp-core/src/tools/reload_devices.rs rust-junosmcp-core/src/inventory.rs
git commit -m "feat(tools): AddDeviceArgs + ReloadDevicesArgs structs"
```

---

## Task 7: add_device validation gates

Implements all pre-flight validation. Write path lands in Task 8.

**Files:**
- Modify: `rust-junosmcp-core/src/tools/add_device.rs`

- [ ] **Step 1: Write the failing tests**

Replace the stub:

```rust
//! `add_device` — validate, persist atomically, swap inventory.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::inventory::AuthConfig;
use crate::tools::AddDeviceArgs;
use std::sync::Arc;

/// Resolved + validated argument bundle. Produced by `validate()`.
#[derive(Debug)]
pub struct ResolvedAdd {
    pub device_name: String,
    pub device_ip: String,
    pub device_port: u32,
    pub username: String,
    pub auth: AuthConfig,
}

/// Pure validation: returns the resolved bundle or the most specific error.
/// Does NOT touch disk or the device manager's locks.
pub fn validate(
    args: &AddDeviceArgs,
    dm: &DeviceManager,
) -> Result<ResolvedAdd, JmcpError> {
    if dm.inventory_readonly() {
        return Err(JmcpError::InventoryReadonly);
    }

    let mut missing: Vec<String> = Vec::new();
    if args.device_name.is_none() { missing.push("device_name".into()); }
    if args.device_ip.is_none()   { missing.push("device_ip".into());   }
    if args.username.is_none()    { missing.push("username".into());    }
    if args.auth.is_none()        { missing.push("auth".into());        }
    if !missing.is_empty() {
        return Err(JmcpError::MissingArguments(missing));
    }

    let device_name = args.device_name.clone().unwrap();
    if !is_valid_device_name(&device_name) {
        return Err(JmcpError::InvalidDeviceName(device_name));
    }
    let inv = dm.inventory();
    if inv.get(&device_name).is_ok() {
        return Err(JmcpError::DeviceExists(device_name));
    }

    let device_ip = args.device_ip.clone().unwrap();
    if !is_valid_ip_or_hostname(&device_ip) {
        return Err(JmcpError::InvalidDeviceIp(device_ip));
    }

    let device_port = args.device_port.unwrap_or(22);
    if !(1..=65535).contains(&device_port) {
        return Err(JmcpError::InvalidDevicePort(device_port));
    }

    let auth = args.auth.clone().unwrap();
    if matches!(auth, AuthConfig::Password { .. }) && !dm.allow_password_auth_add() {
        return Err(JmcpError::PasswordAuthDisabled);
    }

    let username = args.username.clone().unwrap();

    Ok(ResolvedAdd {
        device_name,
        device_ip,
        device_port,
        username,
        auth,
    })
}

fn is_valid_device_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn is_valid_ip_or_hostname(s: &str) -> bool {
    if s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    // RFC 1123 hostname: 1..=253 chars, labels split on '.', each label
    // 1..=63 chars matching [A-Za-z0-9-] without leading/trailing hyphen.
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    fn dm_with(json: &str, readonly: bool, allow_pw: bool) -> Arc<DeviceManager> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        Arc::new(DeviceManager::with_path(
            inv,
            f.path().to_path_buf(),
            crate::inventory::hash_file(f.path()).unwrap(),
            readonly,
            allow_pw,
        ))
    }

    fn args_full() -> AddDeviceArgs {
        AddDeviceArgs {
            device_name: Some("core-3".into()),
            device_ip: Some("10.0.0.3".into()),
            device_port: Some(22),
            username: Some("automation".into()),
            auth: Some(AuthConfig::SshKey {
                private_key_path: "/etc/jmcp/keys/id".into(),
            }),
        }
    }

    #[test]
    fn rejects_when_inventory_readonly() {
        let dm = dm_with(r#"{}"#, true, false);
        let r = validate(&args_full(), &dm);
        assert!(matches!(r, Err(JmcpError::InventoryReadonly)));
    }

    #[test]
    fn rejects_existing_device_name() {
        let dm = dm_with(
            r#"{"core-3":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
            false, true,
        );
        let r = validate(&args_full(), &dm);
        assert!(matches!(r, Err(JmcpError::DeviceExists(ref n)) if n == "core-3"));
    }

    #[test]
    fn rejects_missing_required_fields_with_list() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.device_name = None;
        a.username = None;
        let r = validate(&a, &dm);
        match r {
            Err(JmcpError::MissingArguments(v)) => {
                assert!(v.contains(&"device_name".to_string()));
                assert!(v.contains(&"username".to_string()));
            }
            other => panic!("expected MissingArguments, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_name_with_shell_meta() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.device_name = Some("evil; rm -rf /".into());
        let r = validate(&a, &dm);
        assert!(matches!(r, Err(JmcpError::InvalidDeviceName(_))));
    }

    #[test]
    fn rejects_invalid_ip_garbage() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.device_ip = Some("not an ip or host".into());
        let r = validate(&a, &dm);
        assert!(matches!(r, Err(JmcpError::InvalidDeviceIp(_))));
    }

    #[test]
    fn accepts_hostname_form() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.device_ip = Some("router-3.example.net".into());
        let r = validate(&a, &dm).unwrap();
        assert_eq!(r.device_ip, "router-3.example.net");
    }

    #[test]
    fn rejects_out_of_range_port() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.device_port = Some(70_000);
        let r = validate(&a, &dm);
        assert!(matches!(r, Err(JmcpError::InvalidDevicePort(70_000))));
    }

    #[test]
    fn rejects_password_auth_when_flag_disabled() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.auth = Some(AuthConfig::Password { password: "x".into() });
        let r = validate(&a, &dm);
        assert!(matches!(r, Err(JmcpError::PasswordAuthDisabled)));
    }

    #[test]
    fn accepts_password_auth_when_flag_enabled() {
        let dm = dm_with(r#"{}"#, false, true);
        let mut a = args_full();
        a.auth = Some(AuthConfig::Password { password: "x".into() });
        validate(&a, &dm).unwrap();
    }
}
```

- [ ] **Step 2: Run the tests**

Run: `cargo test -p rust-junosmcp-core --lib tools::add_device`
Expected: 9 PASS.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/src/tools/add_device.rs
git commit -m "feat(add_device): validation gates (readonly/exists/name/ip/port/auth)"
```

---

## Task 8: add_device write path

**Files:**
- Modify: `rust-junosmcp-core/src/tools/add_device.rs`
- Modify: `rust-junosmcp-core/src/inventory.rs` (helper)

- [ ] **Step 1: Add the value-mutation helper to inventory.rs**

```rust
/// Insert a new device into a `serde_json::Value`-shaped inventory.
/// Preserves all existing top-level keys and key order. Returns the updated
/// value. Errors if `name` already exists at top-level OR inside a nested
/// `devices` map (matches both layouts upstream supports).
pub fn insert_device(
    inv: &serde_json::Value,
    name: &str,
    ip: &str,
    port: u32,
    username: &str,
    auth: &crate::inventory::AuthConfig,
) -> Result<serde_json::Value, crate::error::JmcpError> {
    use crate::error::JmcpError;
    use serde_json::{json, Value};

    let mut out = inv.clone();
    let entry = json!({
        "ip": ip,
        "port": port,
        "username": username,
        "auth": auth,
    });

    let inserted = if let Some(obj) = out.as_object_mut() {
        if obj.contains_key(name) {
            return Err(JmcpError::DeviceExists(name.to_string()));
        }
        obj.insert(name.to_string(), entry);
        true
    } else {
        false
    };

    if !inserted {
        return Err(JmcpError::InventoryParse(
            "top-level inventory is not a JSON object".into(),
        ));
    }
    Ok(out)
}
```

(Note: requires `AuthConfig: Serialize`, added in Task 6 Step 3.)

If your inventory uses a nested `{"devices": {...}}` shape, adjust the helper to insert into `out["devices"]` instead. Inspect `devices-template.json` and `inventory.rs::Inventory` to see which layout this codebase uses, and follow that.

- [ ] **Step 2: Add the handler**

Append to `add_device.rs`:

```rust
use serde_json::json;

pub async fn handle(
    args: AddDeviceArgs,
    dm: Arc<DeviceManager>,
) -> Result<serde_json::Value, JmcpError> {
    let resolved = validate(&args, &dm)?;

    let lock = dm.write_lock();
    let _guard = lock.lock().await;

    let path = dm.inventory_path();
    if path.as_os_str().is_empty() {
        return Err(JmcpError::InventoryWrite(
            "inventory has no on-disk path; add_device requires --device-mapping to point at a writable file".into(),
        ));
    }

    // TOCTOU guard: re-read disk and verify hash.
    let on_disk_hash = crate::inventory::hash_file(&path)
        .map_err(|e| JmcpError::InventoryRead(e.to_string()))?;
    if on_disk_hash != dm.inventory_hash() {
        return Err(JmcpError::InventoryDriftedOnDisk);
    }

    let raw = std::fs::read(&path)
        .map_err(|e| JmcpError::InventoryRead(e.to_string()))?;
    let value: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|e| JmcpError::InventoryParse(e.to_string()))?;

    let updated = crate::inventory::insert_device(
        &value,
        &resolved.device_name,
        &resolved.device_ip,
        resolved.device_port,
        &resolved.username,
        &resolved.auth,
    )?;

    crate::inventory::write_atomic(&path, &updated)
        .map_err(|e| JmcpError::InventoryWrite(e.to_string()))?;

    let new_hash = crate::inventory::hash_file(&path)
        .map_err(|e| JmcpError::InventoryRead(e.to_string()))?;
    let new_inv = Arc::new(crate::inventory::Inventory::load(&path)
        .map_err(|e| JmcpError::InventoryParse(e.to_string()))?);
    dm.store_inventory(new_inv, path.clone(), new_hash);

    Ok(json!({
        "added": resolved.device_name,
        "inventory_path": path,
        "router_count": dm.inventory().len(),
    }))
}
```

(`Inventory::len()` may need to be added — small accessor that returns the device-count.)

- [ ] **Step 3: Add a write-path test**

In `add_device.rs` test module:

```rust
    #[tokio::test]
    async fn add_device_persists_to_disk_and_swaps_in_memory() {
        let dm = dm_with(
            r#"{"core-1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
            false, true,
        );
        let r = handle(args_full(), dm.clone()).await.unwrap();
        assert_eq!(r["added"], "core-3");
        assert_eq!(r["router_count"], 2);

        let path = dm.inventory_path();
        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(on_disk.get("core-3").is_some());
        assert!(on_disk.get("core-1").is_some());

        // In-memory snapshot should also see it.
        assert!(dm.inventory().get("core-3").is_ok());
    }

    #[tokio::test]
    async fn add_device_drift_check_rejects_external_edit() {
        let dm = dm_with(r#"{}"#, false, true);
        // Mutate the file from underneath us, but leave the in-memory hash stale.
        std::fs::write(
            dm.inventory_path(),
            r#"{"sneaky":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        ).unwrap();
        let r = handle(args_full(), dm).await;
        assert!(matches!(r, Err(JmcpError::InventoryDriftedOnDisk)));
    }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p rust-junosmcp-core --lib tools::add_device`
Expected: 11 PASS (9 from Task 7 + 2 here).

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/add_device.rs rust-junosmcp-core/src/inventory.rs
git commit -m "feat(add_device): write path with TOCTOU drift check + ArcSwap swap"
```

---

## Task 9: reload_devices semantics

**Files:**
- Modify: `rust-junosmcp-core/src/tools/reload_devices.rs`

- [ ] **Step 1: Replace the stub**

```rust
//! `reload_devices` — re-read the current inventory or swap to a new path.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::inventory::{hash_file, Inventory};
use crate::tools::ReloadDevicesArgs;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

pub async fn handle(
    args: ReloadDevicesArgs,
    dm: Arc<DeviceManager>,
) -> Result<serde_json::Value, JmcpError> {
    if dm.inventory_readonly() {
        return Err(JmcpError::InventoryReadonly);
    }

    let lock = dm.write_lock();
    let _guard = lock.lock().await;

    let path: PathBuf = match args.file_name.as_deref() {
        None | Some("") => dm.inventory_path(),
        Some(p) => PathBuf::from(p),
    };

    if !path.is_file() {
        return Err(JmcpError::InventoryRead(format!(
            "not a regular file: {}",
            path.display(),
        )));
    }

    let new_inv = Inventory::load(&path)
        .map_err(|e| JmcpError::InventoryParse(e.to_string()))?;
    if new_inv.is_empty() {
        return Err(JmcpError::EmptyInventory);
    }

    let prev = dm.inventory();
    let prev_count = prev.len();
    let new_count = new_inv.len();

    let prev_names: std::collections::BTreeSet<&String> = prev.names().collect();
    let new_names: std::collections::BTreeSet<&String> = new_inv.names().collect();
    let added: Vec<String> = new_names.difference(&prev_names).map(|s| s.to_string()).collect();
    let removed: Vec<String> = prev_names.difference(&new_names).map(|s| s.to_string()).collect();
    let mut changed: Vec<String> = Vec::new();
    for name in prev_names.intersection(&new_names) {
        if let (Ok(p), Ok(n)) = (prev.get(name), new_inv.get(name)) {
            if !inventory_entry_equal(p, n) {
                changed.push((*name).clone());
            }
        }
    }

    let new_hash = hash_file(&path).map_err(|e| JmcpError::InventoryRead(e.to_string()))?;
    dm.store_inventory(Arc::new(new_inv), path.clone(), new_hash);

    Ok(json!({
        "previous_router_count": prev_count,
        "new_router_count": new_count,
        "added": added,
        "removed": removed,
        "changed": changed,
        "inventory_path": path,
    }))
}

fn inventory_entry_equal(
    a: &crate::inventory::DeviceEntry,
    b: &crate::inventory::DeviceEntry,
) -> bool {
    // Compare ip, port, username, auth. Adapt to the actual DeviceEntry shape.
    a.ip == b.ip
        && a.port == b.port
        && a.username == b.username
        && format!("{:?}", a.auth) == format!("{:?}", b.auth)
}
```

If `Inventory::names()` / `Inventory::is_empty()` / `DeviceEntry` field names are different, look at `inventory.rs` and adapt. Add minimal accessors if missing — no behavior change.

- [ ] **Step 2: Tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn dm_at(path: &std::path::Path, readonly: bool) -> Arc<DeviceManager> {
        let inv = Arc::new(Inventory::load(path).unwrap());
        let hash = crate::inventory::hash_file(path).unwrap();
        Arc::new(DeviceManager::with_path(
            inv, path.to_path_buf(), hash, readonly, false,
        ))
    }

    fn write_file(json: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[tokio::test]
    async fn reload_no_args_re_reads_current_path() {
        let f = write_file(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = dm_at(f.path(), false);

        // Edit the file externally.
        std::fs::write(
            f.path(),
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}},
                 "r2":{"ip":"127.0.0.2","username":"u","auth":{"type":"password","password":"x"}}}"#,
        ).unwrap();

        let r = handle(ReloadDevicesArgs::default(), dm.clone()).await.unwrap();
        assert_eq!(r["previous_router_count"], 1);
        assert_eq!(r["new_router_count"], 2);
        assert!(r["added"].as_array().unwrap().iter().any(|v| v == "r2"));
        assert!(dm.inventory().get("r2").is_ok());
    }

    #[tokio::test]
    async fn reload_with_file_name_swaps_inventory() {
        let f1 = write_file(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let f2 = write_file(
            r#"{"r9":{"ip":"127.0.0.9","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = dm_at(f1.path(), false);

        let r = handle(
            ReloadDevicesArgs { file_name: Some(f2.path().to_string_lossy().to_string()) },
            dm.clone(),
        ).await.unwrap();

        assert_eq!(r["new_router_count"], 1);
        assert_eq!(r["inventory_path"], f2.path().to_string_lossy().as_ref());
        assert!(dm.inventory().get("r9").is_ok());
        assert!(dm.inventory().get("r1").is_err());
    }

    #[tokio::test]
    async fn reload_empty_inventory_rejected() {
        let f = write_file(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = dm_at(f.path(), false);
        let f_empty = write_file(r#"{}"#);
        let r = handle(
            ReloadDevicesArgs { file_name: Some(f_empty.path().to_string_lossy().to_string()) },
            dm,
        ).await;
        assert!(matches!(r, Err(JmcpError::EmptyInventory)));
    }

    #[tokio::test]
    async fn reload_inventory_readonly_rejected() {
        let f = write_file(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = dm_at(f.path(), true);
        let r = handle(ReloadDevicesArgs::default(), dm).await;
        assert!(matches!(r, Err(JmcpError::InventoryReadonly)));
    }

    #[tokio::test]
    async fn reload_reports_added_removed_changed_diff() {
        let f1 = write_file(
            r#"{
                "keep":{"ip":"10.0.0.1","username":"u","auth":{"type":"password","password":"x"}},
                "gone":{"ip":"10.0.0.2","username":"u","auth":{"type":"password","password":"x"}},
                "mut":{"ip":"10.0.0.3","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let f2 = write_file(
            r#"{
                "keep":{"ip":"10.0.0.1","username":"u","auth":{"type":"password","password":"x"}},
                "mut":{"ip":"10.0.0.3","username":"v","auth":{"type":"password","password":"x"}},
                "new":{"ip":"10.0.0.4","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = dm_at(f1.path(), false);
        let r = handle(
            ReloadDevicesArgs { file_name: Some(f2.path().to_string_lossy().to_string()) },
            dm,
        ).await.unwrap();
        let added: Vec<String> = serde_json::from_value(r["added"].clone()).unwrap();
        let removed: Vec<String> = serde_json::from_value(r["removed"].clone()).unwrap();
        let changed: Vec<String> = serde_json::from_value(r["changed"].clone()).unwrap();
        assert_eq!(added, vec!["new"]);
        assert_eq!(removed, vec!["gone"]);
        assert_eq!(changed, vec!["mut"]);
    }
}
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p rust-junosmcp-core --lib tools::reload_devices`
Expected: 5 PASS.

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp-core/src/tools/reload_devices.rs
git commit -m "feat(reload_devices): optional file_name swap with added/removed/changed diff"
```

---

## Task 10: Wire elicitation + adapters in server.rs

**Files:**
- Modify: `rust-junosmcp-auth/src/file.rs`
- Modify: `rust-junosmcp/src/server.rs`

- [ ] **Step 1: Extend KNOWN_TOOLS**

In `rust-junosmcp-auth/src/file.rs`:

```rust
const KNOWN_TOOLS: &[&str] = &[
    "get_router_list",
    "gather_device_facts",
    "execute_junos_command",
    "get_junos_config",
    "junos_config_diff",
    "load_and_commit_config",
    "execute_junos_pfe_command",
    "execute_junos_command_batch",
    "render_and_apply_j2_template",
    "add_device",                   // NEW
    "reload_devices",               // NEW
];
```

Bump any associated count assertions (search for `KNOWN_TOOLS.len()` or `9` literals tied to the count).

- [ ] **Step 2: Add the imports in server.rs**

```rust
use rust_junosmcp_core::tools::{add_device, reload_devices, AddDeviceArgs, ReloadDevicesArgs};
```

- [ ] **Step 3: Add the add_device adapter**

```rust
    #[tool(
        name = "add_device",
        description = "Add a Junos device to the in-memory inventory and persist to devices.json. Required fields: device_name, device_ip, username, auth (ssh_key or password). port defaults to 22. With clients that advertise elicitation, missing fields are prompted; otherwise the call returns MissingArguments."
    )]
    async fn add_device(
        &self,
        Parameters(args): Parameters<AddDeviceArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "add_device") {
            return Self::scope_to_call_result(e);
        }

        // Elicitation attempt: only if the client advertises capability.
        let args = match self.try_elicit_add_device(&extensions, args).await {
            Ok(a) => a,
            Err(e) => return Self::to_call_result(Err::<serde_json::Value, _>(e)),
        };

        Self::to_call_result(add_device::handle(args, self.dm.clone()).await)
    }
```

The `try_elicit_add_device` helper inspects the rmcp peer for elicitation support and prompts for missing required fields. If the peer doesn't support elicitation, returns the args unchanged — the handler will return `MissingArguments` itself. **Implementation detail:** rmcp 0.8.5's elicitation API is `peer.elicit(ElicitRequest { ... }).await`. Check `rmcp::handler::server::tool` and `rmcp::model::ElicitRequest` for the exact shape; if the client capability check is awkward, fall back to "always pass through" — the handler's `MissingArguments` error gives a clean enough UX.

Add the helper inline:

```rust
    async fn try_elicit_add_device(
        &self,
        _extensions: &Extensions,
        args: AddDeviceArgs,
    ) -> Result<AddDeviceArgs, rmcp::ErrorData> {
        // Pass-through implementation. If rmcp 0.8.5's elicitation API is
        // straightforward to wire here, replace this with an actual peer.elicit
        // call. The handler validates and returns MissingArguments when fields
        // are missing — that is the documented contract for non-elicitation
        // transports per the design spec.
        Ok(args)
    }
```

If the rmcp 0.8.5 elicitation API is straightforward to invoke, expand `try_elicit_add_device` to actually issue a `peer.elicit()` request. If it's invasive, ship the pass-through version — the spec explicitly accepts this as the streamable-http default behavior.

- [ ] **Step 4: Add the reload_devices adapter**

```rust
    #[tool(
        name = "reload_devices",
        description = "Reload the inventory. With no args, re-reads the current --device-mapping. With file_name, swaps to a new inventory file. Reports added/removed/changed device names."
    )]
    async fn reload_devices(
        &self,
        Parameters(args): Parameters<ReloadDevicesArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "reload_devices") {
            return Self::scope_to_call_result(e);
        }
        Self::to_call_result(reload_devices::handle(args, self.dm.clone()).await)
    }
```

- [ ] **Step 5: Build and run unit tests**

Run: `cargo build -p rust-junosmcp`
Expected: clean.

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add rust-junosmcp-auth/src/file.rs rust-junosmcp/src/server.rs
git commit -m "feat(server): add_device + reload_devices tool adapters"
```

---

## Task 11: Wire CLI flags into DeviceManager + extend SIGHUP

**Files:**
- Modify: `rust-junosmcp/src/main.rs`

- [ ] **Step 1: Use `DeviceManager::with_path` at startup**

Find the existing `DeviceManager::new(inv)` call. Replace with:

```rust
let inv_path = args.device_mapping.clone();
let inv_hash = rust_junosmcp_core::inventory::hash_file(&inv_path)
    .map_err(|e| anyhow::anyhow!("inventory hash failed: {e}"))?;
let dm = Arc::new(DeviceManager::with_path(
    inv,
    inv_path,
    inv_hash,
    args.inventory_readonly,
    args.allow_password_auth_add,
));
```

- [ ] **Step 2: Extend the SIGHUP handler**

Find the existing SIGHUP loop (it currently reloads the token store). Add an inventory reload alongside it:

```rust
loop {
    match sighup.recv().await {
        Some(()) => {
            tracing::info!("SIGHUP received; reloading token store and inventory");
            if let Err(e) = token_store.reload() {
                tracing::error!(error = %e, "token store reload failed");
            }
            // Inventory reload via the same code path as the tool, file_name=None.
            let args = rust_junosmcp_core::tools::ReloadDevicesArgs::default();
            match rust_junosmcp_core::tools::reload_devices::handle(args, dm.clone()).await {
                Ok(diff) => tracing::info!(diff = %diff, "inventory reloaded"),
                Err(e) => tracing::error!(error = %e, "inventory reload failed"),
            }
        }
        None => break,
    }
}
```

(Adapt to the actual structure — the existing handler may use `tokio::signal::unix::signal(SignalKind::hangup())` directly.)

- [ ] **Step 3: Build and run a smoke test of SIGHUP**

Run: `cargo build -p rust-junosmcp --release`
Expected: clean.

Manually verify in a smoke run:
```
./target/release/rust-junosmcp -f devices.json --transport streamable-http \
    -H 127.0.0.1 -p 8765 --tokens-file tokens.json &
sleep 1
echo '{"new":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}' >> /dev/null  # simulate edit
kill -HUP $!
sleep 1
kill $!
```

(Optional; not required for passing CI. Functional smoke is in Task 12.)

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp/src/main.rs
git commit -m "feat(main): wire inventory flags + SIGHUP also reloads inventory"
```

---

## Task 12: Update stdio_smoke tool count

**Files:**
- Modify: `rust-junosmcp/tests/stdio_smoke.rs`

- [ ] **Step 1: Rename + extend**

```diff
-fn lists_nine_tools() {
+fn lists_eleven_tools() {
```

Extend `EXPECTED_TOOLS` array with `"add_device"` and `"reload_devices"` (in any deterministic order — match the order in `KNOWN_TOOLS` and the `#[tool]` adapter declaration order).

Update count assertions to `11`.

- [ ] **Step 2: Run the test**

Run: `cargo test -p rust-junosmcp --test stdio_smoke -- --nocapture`
Expected: PASS, 11 tools advertised.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp/tests/stdio_smoke.rs
git commit -m "test(stdio_smoke): expect 11 tools after inventory mutation lands"
```

---

## Task 13: add_device_smoke + reload_devices_smoke

**Files:**
- Create: `rust-junosmcp/tests/add_device_smoke.rs`
- Create: `rust-junosmcp/tests/reload_devices_smoke.rs`

- [ ] **Step 1: add_device_smoke.rs**

```rust
//! Stdio smoke for add_device: full add → reload → router_list cycle.

mod common;
use common::{call_tool, spawn_stdio_server_with_args, write_inventory_in};
use serde_json::json;

#[test]
fn add_then_reload_then_router_list_shows_new_device() {
    let dir = tempfile::tempdir().unwrap();
    let inv_path = write_inventory_in(
        dir.path(),
        "devices.json",
        r#"{"core-1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server_with_args(&[
        "-f", inv_path.to_str().unwrap(),
        "--allow-password-auth-add",
    ]);

    let r = call_tool(
        &mut child,
        "add_device",
        json!({
            "device_name":"core-3",
            "device_ip":"10.0.0.3",
            "device_port":22,
            "username":"automation",
            "auth":{"type":"ssh_key","private_key_path":"/tmp/k"}
        }),
    );
    assert_eq!(r["added"], "core-3");

    let list = call_tool(&mut child, "get_router_list", json!({}));
    let names: Vec<String> = serde_json::from_value(list["routers"].clone()).unwrap();
    assert!(names.contains(&"core-3".to_string()));
    assert!(names.contains(&"core-1".to_string()));
}

#[test]
fn add_device_args_fallback_when_required_missing() {
    let dir = tempfile::tempdir().unwrap();
    let inv_path = write_inventory_in(
        dir.path(),
        "devices.json",
        r#"{"core-1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server_with_args(&[
        "-f", inv_path.to_str().unwrap(),
    ]);

    let err = call_tool(&mut child, "add_device", json!({}));
    let s = err.to_string();
    assert!(s.contains("missing required arguments"), "got: {s}");
}

#[test]
fn add_device_inventory_readonly_returns_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let inv_path = write_inventory_in(
        dir.path(),
        "devices.json",
        r#"{"core-1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server_with_args(&[
        "-f", inv_path.to_str().unwrap(),
        "--inventory-readonly",
    ]);

    let err = call_tool(
        &mut child,
        "add_device",
        json!({
            "device_name":"core-3","device_ip":"10.0.0.3","username":"u",
            "auth":{"type":"ssh_key","private_key_path":"/tmp/k"}
        }),
    );
    let s = err.to_string();
    assert!(s.contains("read-only"), "got: {s}");
}

#[test]
fn add_device_password_auth_disabled_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let inv_path = write_inventory_in(
        dir.path(),
        "devices.json",
        r#"{"core-1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server_with_args(&[
        "-f", inv_path.to_str().unwrap(),
    ]);

    let err = call_tool(
        &mut child,
        "add_device",
        json!({
            "device_name":"core-3","device_ip":"10.0.0.3","username":"u",
            "auth":{"type":"password","password":"x"}
        }),
    );
    let s = err.to_string();
    assert!(s.contains("password authentication is not allowed"), "got: {s}");
}
```

(`spawn_stdio_server_with_args` and `write_inventory_in` are extensions of the existing common helpers — add them to `tests/common.rs` if not present.)

- [ ] **Step 2: reload_devices_smoke.rs**

```rust
//! Stdio smoke for reload_devices.

mod common;
use common::{call_tool, spawn_stdio_server_with_args, write_inventory_in};
use serde_json::json;

#[test]
fn reload_no_args_re_reads_current_path() {
    let dir = tempfile::tempdir().unwrap();
    let inv_path = write_inventory_in(
        dir.path(),
        "devices.json",
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server_with_args(&[
        "-f", inv_path.to_str().unwrap(),
    ]);

    // Edit on disk — add a second device.
    std::fs::write(
        &inv_path,
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}},
             "r2":{"ip":"127.0.0.2","username":"u","auth":{"type":"password","password":"x"}}}"#,
    ).unwrap();

    let r = call_tool(&mut child, "reload_devices", json!({}));
    assert_eq!(r["new_router_count"], 2);
    let added: Vec<String> = serde_json::from_value(r["added"].clone()).unwrap();
    assert!(added.contains(&"r2".to_string()));
}

#[test]
fn reload_with_file_name_swaps_inventory() {
    let dir = tempfile::tempdir().unwrap();
    let p1 = write_inventory_in(
        dir.path(),
        "a.json",
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let p2 = write_inventory_in(
        dir.path(),
        "b.json",
        r#"{"r9":{"ip":"127.0.0.9","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server_with_args(&[
        "-f", p1.to_str().unwrap(),
    ]);

    let r = call_tool(&mut child, "reload_devices", json!({"file_name": p2.to_str().unwrap()}));
    assert_eq!(r["new_router_count"], 1);
    let list = call_tool(&mut child, "get_router_list", json!({}));
    let names: Vec<String> = serde_json::from_value(list["routers"].clone()).unwrap();
    assert!(names.contains(&"r9".to_string()));
    assert!(!names.contains(&"r1".to_string()));
}

#[test]
fn reload_inventory_readonly_returns_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let inv_path = write_inventory_in(
        dir.path(),
        "devices.json",
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server_with_args(&[
        "-f", inv_path.to_str().unwrap(),
        "--inventory-readonly",
    ]);

    let err = call_tool(&mut child, "reload_devices", json!({}));
    let s = err.to_string();
    assert!(s.contains("read-only"), "got: {s}");
}
```

- [ ] **Step 3: Run both smoke files**

Run: `cargo test -p rust-junosmcp --test add_device_smoke --test reload_devices_smoke -- --nocapture`
Expected: 7 PASS.

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp/tests/add_device_smoke.rs rust-junosmcp/tests/reload_devices_smoke.rs rust-junosmcp/tests/common.rs
git commit -m "test: stdio smoke for add_device + reload_devices"
```

---

## Task 14: Append a real-device test

**Files:**
- Modify: `rust-junosmcp-core/tests/integration_real_device.rs`

- [ ] **Step 1: Append**

```rust
#[tokio::test]
#[ignore]
async fn live_add_device_persists_then_reload() {
    let host = std::env::var("JMCP_TEST_HOST").expect("JMCP_TEST_HOST set");
    let user = std::env::var("JMCP_TEST_USER").expect("JMCP_TEST_USER set");
    let pass = std::env::var("JMCP_TEST_PASS").expect("JMCP_TEST_PASS set");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devices.json");
    std::fs::write(&path, r#"{}"#).unwrap();

    let inv = std::sync::Arc::new(
        rust_junosmcp_core::inventory::Inventory::load(&path).unwrap(),
    );
    let hash = rust_junosmcp_core::inventory::hash_file(&path).unwrap();
    let dm = std::sync::Arc::new(rust_junosmcp_core::device_manager::DeviceManager::with_path(
        inv, path.clone(), hash, false, true,  // allow_password_auth_add=true for the live test
    ));

    let args = rust_junosmcp_core::tools::AddDeviceArgs {
        device_name: Some("live-test".into()),
        device_ip: Some(host.clone()),
        device_port: Some(22),
        username: Some(user.clone()),
        auth: Some(rust_junosmcp_core::inventory::AuthConfig::Password { password: pass.clone() }),
    };

    let r = rust_junosmcp_core::tools::add_device::handle(args, dm.clone()).await
        .expect("add_device handle ok");
    assert_eq!(r["added"], "live-test");

    // Reload no-args; must observe the device.
    let r2 = rust_junosmcp_core::tools::reload_devices::handle(
        rust_junosmcp_core::tools::ReloadDevicesArgs::default(),
        dm.clone(),
    ).await.expect("reload ok");
    assert_eq!(r2["new_router_count"], 1);
    assert!(dm.inventory().get("live-test").is_ok());
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo test -p rust-junosmcp-core --test integration_real_device --no-run`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/tests/integration_real_device.rs
git commit -m "test(integration): #[ignore] add+reload live cycle"
```

---

## Task 15: README updates

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add the inventory mutation subsection**

After the "v0.2 follow-up: Templates (released)" subsection, add:

```markdown
### v0.2 follow-up: Inventory mutation (released)

- `add_device` — add a Junos device to the in-memory inventory and persist to `devices.json`. Atomic write (tempfile + rename), preserves `_blocklist_defaults`, per-device `blocklist`, and other top-level fields. SHA-256-based TOCTOU guard rejects calls that race with external edits.
- `reload_devices` — re-read the current `--device-mapping` (no args) or swap to a new inventory file (`file_name`). Reports added / removed / changed device names.
- New CLI flags: `--inventory-readonly` (rejects both tools unconditionally), `--allow-password-auth-add` (permits `auth.type=password` in `add_device`; mutually exclusive with `--inventory-readonly`).
- SIGHUP now also re-reads the inventory in addition to the token store.

**Documented sharp edge:** `add_device` does not modify the token store. If a token has `--routers 'edge-*'` and you `add_device` for `core-3`, the existing token will not see the new router. Mint a new token or rotate scopes after `add_device`.
```

- [ ] **Step 2: Add the new flags to the CLI section**

Find the CLI options listing in README.md and append:

```
      --inventory-readonly
          Reject add_device and reload_devices unconditionally
      --allow-password-auth-add
          Permit add_device to accept auth.type=password (mutually exclusive
          with --inventory-readonly)
```

- [ ] **Step 3: Update the top-of-file callout**

Replace the v0.2.1 callout with v0.2.2:

```markdown
> ## v0.2.2 released
>
> Reaches full upstream tool-surface parity (11 tools): adds
> `render_and_apply_j2_template` (templates with YAML/JSON vars sniff),
> `add_device` (atomic devices.json write), and `reload_devices` (file
> swap). New CLI flags `--inventory-readonly` and
> `--allow-password-auth-add`. SIGHUP now also reloads inventory.
>
> See the [v0.2.2 release notes](https://github.com/fastrevmd-lab/RustJunosMCP/releases/tag/v0.2.2).
```

- [ ] **Step 4: Drop the "Coming after v0.2" line**

Remove the now-stale `Coming after v0.2: add_device / reload_devices interactive tools.` line — parity is reached.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: announce inventory mutation tools (add_device, reload_devices)"
```

---

## Task 16: Final verification + version bump + PR

**Files:**
- Modify: `Cargo.toml` (workspace, version bump)
- Modify: `README.md` (LXC tarball name)

- [ ] **Step 1: Bump version to 0.2.2**

In workspace `Cargo.toml`:

```diff
-version      = "0.2.1"
+version      = "0.2.2"
```

Update LXC tarball references in README.md from `0.2.1` → `0.2.2`.

- [ ] **Step 2: Build the workspace**

Run: `cargo build --workspace`
Expected: clean.

- [ ] **Step 3: Test the workspace**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 4: Clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 5: Format check**

Run: `cargo fmt --all -- --check`
Expected: no diff. If diff: run `cargo fmt --all` and commit.

- [ ] **Step 6: Audit**

Run: `cargo audit`
Expected: no new advisories.

- [ ] **Step 7: Commit version + push**

```bash
git add Cargo.toml Cargo.lock README.md
git commit -m "chore(release): bump workspace version to 0.2.2"
git push -u origin <inventory-branch-name>
```

- [ ] **Step 8: Open PR #7**

```bash
gh pr create --title "feat: add_device + reload_devices (sub-project #4 PR #7)" --body "$(cat <<'EOF'
## Summary

Sub-project #4 PR #7 / 2 — closes the upstream parity gap. Tool surface
now matches Juniper/junos-mcp-server exactly (11 tools).

- `add_device` — atomic devices.json write, preserves `_blocklist_defaults` and per-device blocklists. SHA-256 TOCTOU guard. rmcp elicitation pass-through with args fallback.
- `reload_devices` — optional `file_name` for path-swap; default re-reads current `--device-mapping`. Reports added/removed/changed.
- `DeviceManager` switched to `Arc<ArcSwap<Inventory>>` for hot-swap; reads still snapshot at handler entry.
- New CLI flags: `--inventory-readonly` (rejects both tools), `--allow-password-auth-add` (mutually exclusive with `--inventory-readonly`).
- SIGHUP now also re-reads the inventory in addition to the token store.
- v0.2.2 release: full upstream parity reached.

Spec: `docs/superpowers/specs/2026-05-05-templates-inventory-design.md`
Plan: `docs/superpowers/plans/2026-05-05-inventory-mutation.md`

## Test plan

- [x] `cargo build --workspace`
- [x] `cargo test --workspace`
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [x] `cargo fmt --all -- --check`
- [x] `cargo audit`
- [x] Stdio smoke for add_device (4 tests) and reload_devices (3 tests).
- [x] Tool count assertion: `lists_eleven_tools`.
- [ ] Real device live add+reload (`#[ignore]`, run manually with JMCP_TEST_HOST etc).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Cross-task notes

**rmcp elicitation:** The plan ships `try_elicit_add_device` as a pass-through. If the implementer finds the rmcp 0.8.5 elicitation API ergonomic, expanding the helper into a real elicit call is acceptable and welcome. If awkward, the pass-through plus the `MissingArguments` error is the documented contract.

**TOCTOU vs convenience:** A common operator workflow is `add_device → reload_devices → add_device`. The hash check refreshes on every successful `add_device` (Step 8 of Task 8 — the post-write `hash_file` call), so back-to-back adds work without manual reload.

**`_blocklist_defaults` and per-device `blocklist`:** preserved automatically because the round-trip uses `serde_json::Value`. Verify by inspecting the on-disk file after `add_device` runs.

**Why no `remove_device`:** out of scope for parity (upstream Python doesn't have it). Trivial to add as a future sub-project if operators ask for it.

**Self-review (writing-plans Step "Self-Review"):**

1. **Spec coverage:**
   - §4.2 (add_device tool surface, validation, write path) → Tasks 6, 7, 8.
   - §4.3 (reload_devices) → Task 9.
   - §5 (architecture: ArcSwap, atomic write, TOCTOU, round-trip preservation) → Tasks 1, 2, 3, 8.
   - §6 (deps: arc-swap, tempfile, sha2, indexmap via serde_json/preserve_order) → Tasks 1, 2, 3.
   - §7 (CLI flags + mutual exclusion) → Task 5.
   - §8 (KNOWN_TOOLS, sharp edge documented) → Tasks 10, 15.
   - §9.1/§9.2 (unit + smoke tests) → Tasks 7, 8, 9, 12, 13.
   - §9.4 (real-device tests) → Task 14.
   - §9.5 (verification checklist) → Task 16.
   - §10 (README + release notes) → Task 15.

2. **Placeholder scan:** No "TBD". One explicit "if X already exists, adapt" in Task 8 Step 1 (regarding nested-vs-flat inventory layout) — that's a reasonable question for the implementer to answer by reading 20 lines of `inventory.rs`, not a placeholder.

3. **Type consistency:**
   - `AddDeviceArgs` field names match between Tasks 6, 7, 8 (Option<String> for the user-facing fields, Option<u32> for port, Option<AuthConfig> for auth).
   - `ReloadDevicesArgs` field name `file_name` matches between Tasks 6, 9, 13.
   - `DeviceManager::with_path(inv, path, hash, readonly, allow_pw)` signature consistent across Tasks 2, 7, 9, 14.
   - `JmcpError` variant names match between Task 4 and use sites in Tasks 7, 8, 9.
   - `KNOWN_TOOLS` list matches `EXPECTED_TOOLS` (both extended with the same two strings in Task 10 and Task 12).

If `Inventory::is_empty()`, `Inventory::len()`, `Inventory::names()`, or `DeviceEntry` struct fields differ from what Tasks 9 and 8 assume, the implementer should add minimal accessors (no behavior change). All other types are explicit.
