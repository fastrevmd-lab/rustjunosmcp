# Rust JunosMCP v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build v0.1 of `rust-junosmcp` — a stdio MCP server with 6 Junos tools, drop-in compatible with Juniper/junos-mcp-server's `devices.json`, plus Docker + LXC artifacts.

**Architecture:** Cargo workspace with `rust-junosmcp-core` (pure logic + tool handlers over rustEZ) and `rust-junosmcp` (rmcp wiring + CLI). Open-per-call connections; no pooling in this repo.

**Tech Stack:** Rust 2021, tokio, rmcp (`#[tool_router]` macros, stdio transport), rustez 0.8 (Junos client), thiserror, clap, serde, schemars, tracing.

**Spec:** [`docs/superpowers/specs/2026-05-03-rust-junosmcp-design.md`](../specs/2026-05-03-rust-junosmcp-design.md)

---

## Followups identified during planning

These are real divergences from the spec discovered when verifying rustEZ's actual API. Each becomes an issue against rustEZ. None block v0.1 — workarounds noted in the relevant tasks.

1. **rustEZ — `Facts` should derive `Serialize`.** Today it's `Debug, Clone` only. v0.1 hand-builds the JSON in `gather_device_facts`. File issue.
2. **rustEZ — `ConfigManager::commit_with_comment(&str)`.** Today only `commit()` exists. v0.1 sends the commit-with-comment via raw RPC through `RpcExecutor::call_xml`. File issue.
3. **rustEZ — `DeviceBuilder::key_file` takes `&str`, not `&Path`.** Cosmetic; v0.1 converts `Path → str` at the call site.

---

## Task index

- Task 0 — Workspace skeleton
- Task 1 — JmcpError enum + Display tests
- Task 2 — AuthConfig with secret redaction
- Task 3 — DeviceEntry deserialization
- Task 4 — Inventory load + validation
- Task 5 — Inventory accessors (get / names)
- Task 6 — DeviceManager::open + ssh_config rejection
- Task 7 — Pure-logic helpers (config_format, rollback version, facts → JSON)
- Task 8 — Tool input structs (schemars / serde)
- Task 9 — `get_router_list` handler
- Task 10 — `execute_junos_command` handler
- Task 11 — `get_junos_config` handler
- Task 12 — `junos_config_diff` handler
- Task 13 — `gather_device_facts` handler
- Task 14 — `load_and_commit_config` handler (with raw-RPC commit comment)
- Task 15 — Binary crate skeleton + clap CLI
- Task 16 — rmcp `ServerHandler` + `#[tool_router]` registration
- Task 17 — `main.rs` glue + transport selection
- Task 18 — stdio smoke test (spawn binary, list_tools)
- Task 19 — Dockerfile (distroless)
- Task 20 — LXC packaging (systemd unit + install.sh + package-lxc.sh)
- Task 21 — `devices-template.json` + README
- Task 22 — GitHub Actions CI

---

## File map

**`rust-junosmcp-core/`**

| File | Responsibility |
|---|---|
| `src/lib.rs` | Re-exports public API |
| `src/error.rs` | `JmcpError` enum |
| `src/inventory.rs` | `DeviceEntry`, `AuthConfig`, `Inventory` |
| `src/device_manager.rs` | `DeviceManager` over `rustez::Device` |
| `src/helpers.rs` | Pure helpers: `parse_config_format`, `clamp_rollback_version`, `facts_to_json` |
| `src/tools/mod.rs` | Tool re-exports + shared `Args`/`Output` types |
| `src/tools/router_list.rs` | `get_router_list` |
| `src/tools/execute_command.rs` | `execute_junos_command` |
| `src/tools/get_config.rs` | `get_junos_config` |
| `src/tools/config_diff.rs` | `junos_config_diff` |
| `src/tools/facts.rs` | `gather_device_facts` |
| `src/tools/load_commit.rs` | `load_and_commit_config` |
| `tests/integration_real_device.rs` | `#[ignore]`'d real-device tests |

**`rust-junosmcp/`**

| File | Responsibility |
|---|---|
| `src/main.rs` | tokio entry, tracing init, transport dispatch |
| `src/cli.rs` | clap argument parser |
| `src/server.rs` | `JmcpHandler`, `#[tool_router]` glue, `serve_stdio` |
| `tests/stdio_smoke.rs` | Spawn binary, drive MCP `initialize` + `tools/list` |

**Repo-level**

| File | Responsibility |
|---|---|
| `Cargo.toml` | workspace root |
| `Dockerfile` | distroless build |
| `scripts/package-lxc.sh` | tarball builder |
| `packaging/systemd/rust-junosmcp.service` | hardened unit |
| `packaging/lxc/install.sh` | post-extract installer |
| `devices-template.json` | 1:1 with Python repo |
| `.github/workflows/ci.yml` | build + test |
| `README.md` | install / configure / security |

---

## Task 0: Workspace skeleton

**Files:**
- Create: `Cargo.toml`
- Create: `rust-junosmcp-core/Cargo.toml`
- Create: `rust-junosmcp-core/src/lib.rs`
- Create: `rust-junosmcp/Cargo.toml`
- Create: `rust-junosmcp/src/main.rs`

- [ ] **Step 1: Workspace root `Cargo.toml`**

```toml
[workspace]
members = ["rust-junosmcp-core", "rust-junosmcp"]
resolver = "2"

[workspace.package]
version      = "0.1.0"
edition      = "2021"
license      = "MIT OR Apache-2.0"
repository   = "https://github.com/mechubsec/rustjunosmcp"
authors      = ["fastrevmd-lab"]

[workspace.dependencies]
tokio        = { version = "1", features = ["full"] }
serde        = { version = "1", features = ["derive"] }
serde_json   = "1"
thiserror    = "2"
tracing      = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
schemars     = "0.8"
anyhow       = "1"
rustez       = { path = "../rustEZ/rustez" }
# rmcp 0.x — pinned at task 16; placeholder here
```

> **Note on `rustez` path dep:** v0.1 uses a path dependency to `../rustEZ/rustez` (one directory up from this repo). When rustez 0.9 is released to crates.io with the followups listed above, switch to a version requirement.

- [ ] **Step 2: `rust-junosmcp-core/Cargo.toml`**

```toml
[package]
name        = "rust-junosmcp-core"
version.workspace     = true
edition.workspace     = true
license.workspace     = true
repository.workspace  = true
authors.workspace     = true
description = "Core logic and Junos tool handlers for rust-junosmcp."

[dependencies]
tokio        = { workspace = true }
serde        = { workspace = true }
serde_json   = { workspace = true }
thiserror    = { workspace = true }
tracing      = { workspace = true }
schemars     = { workspace = true }
rustez       = { workspace = true }

[dev-dependencies]
tempfile     = "3"
```

- [ ] **Step 3: `rust-junosmcp-core/src/lib.rs`**

```rust
//! Core logic for rust-junosmcp: inventory, device manager, and MCP tool handlers
//! built on top of [`rustez`].
//!
//! The binary crate `rust-junosmcp` wires this into the rmcp transport.
```

- [ ] **Step 4: `rust-junosmcp/Cargo.toml`**

```toml
[package]
name        = "rust-junosmcp"
version.workspace    = true
edition.workspace    = true
license.workspace    = true
repository.workspace = true
authors.workspace    = true
description = "MCP server for Juniper Junos devices, built on rustEZ."

[[bin]]
name = "rust-junosmcp"
path = "src/main.rs"

[dependencies]
rust-junosmcp-core = { path = "../rust-junosmcp-core" }
tokio              = { workspace = true }
serde              = { workspace = true }
serde_json         = { workspace = true }
tracing            = { workspace = true }
tracing-subscriber = { workspace = true }
anyhow             = { workspace = true }
# clap + rmcp pinned in later tasks
```

- [ ] **Step 5: Placeholder `rust-junosmcp/src/main.rs`**

```rust
fn main() {
    eprintln!("rust-junosmcp v0.1 - skeleton");
}
```

- [ ] **Step 6: Build and verify**

Run: `cargo build`
Expected: workspace compiles cleanly (warnings about unused deps OK at this stage).

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml rust-junosmcp-core/ rust-junosmcp/
git commit -m "feat: workspace skeleton with two member crates"
```

---

## Task 1: JmcpError enum + Display tests

**Files:**
- Create: `rust-junosmcp-core/src/error.rs`
- Modify: `rust-junosmcp-core/src/lib.rs` (add `pub mod error;`)

- [ ] **Step 1: Write the failing test (`rust-junosmcp-core/src/error.rs`)**

```rust
//! Error type surfaced through the MCP server.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum JmcpError {
    #[error("router '{0}' not found in device mapping")]
    UnknownRouter(String),

    #[error("invalid devices.json: {0}")]
    InventoryInvalid(String),

    #[error("private key file not found: {0}")]
    KeyFileMissing(PathBuf),

    #[error("ssh_config jumphost is not yet supported in the Rust port (router '{0}')")]
    SshConfigUnsupported(String),

    #[error("invalid config_format '{0}' (expected set, text, or xml)")]
    BadFormat(String),

    #[error("rollback version {0} out of range (1..=49)")]
    BadRollbackVersion(i64),

    #[error("operation timed out after {0:?}")]
    Timeout(std::time::Duration),

    #[error(transparent)]
    Rustez(#[from] rustez::RustEzError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_router_displays_router_name() {
        let e = JmcpError::UnknownRouter("r99".into());
        assert_eq!(e.to_string(), "router 'r99' not found in device mapping");
    }

    #[test]
    fn ssh_config_unsupported_mentions_v0_2() {
        let e = JmcpError::SshConfigUnsupported("r1".into());
        let s = e.to_string();
        assert!(s.contains("ssh_config"));
        assert!(s.contains("r1"));
    }

    #[test]
    fn bad_format_shows_invalid_value() {
        let e = JmcpError::BadFormat("yaml".into());
        assert_eq!(
            e.to_string(),
            "invalid config_format 'yaml' (expected set, text, or xml)"
        );
    }

    #[test]
    fn bad_rollback_version_shows_value_and_range() {
        let e = JmcpError::BadRollbackVersion(99);
        assert_eq!(
            e.to_string(),
            "rollback version 99 out of range (1..=49)"
        );
    }
}
```

- [ ] **Step 2: Wire into lib.rs**

Modify `rust-junosmcp-core/src/lib.rs` to add:

```rust
pub mod error;
pub use error::JmcpError;
```

- [ ] **Step 3: Run tests, expect PASS**

Run: `cargo test -p rust-junosmcp-core --lib error::tests`
Expected: 4 tests pass.

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp-core/src/error.rs rust-junosmcp-core/src/lib.rs
git commit -m "feat(core): JmcpError enum with Display tests"
```

---

## Task 2: AuthConfig with secret redaction

**Files:**
- Create: `rust-junosmcp-core/src/inventory.rs` (partial — AuthConfig only)
- Modify: `rust-junosmcp-core/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Add to `rust-junosmcp-core/src/inventory.rs`:

```rust
//! `devices.json` parsing and validation.
//!
//! Drop-in compatible with Juniper/junos-mcp-server.

use serde::Deserialize;
use std::path::PathBuf;

/// Authentication config for a Junos device. Tagged enum mirrors the Python
/// repo's `auth.type` discriminator.
#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    Password { password: String },
    SshKey { private_key_path: PathBuf },
}

// Hand-written Debug to redact passwords. Never derive Debug on this enum.
impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password { .. } => f.debug_struct("Password")
                .field("password", &"<redacted>")
                .finish(),
            Self::SshKey { private_key_path } => f.debug_struct("SshKey")
                .field("private_key_path", private_key_path)
                .finish(),
        }
    }
}

#[cfg(test)]
mod auth_tests {
    use super::*;

    #[test]
    fn password_debug_does_not_leak_secret() {
        let auth = AuthConfig::Password { password: "hunter2".into() };
        let s = format!("{auth:?}");
        assert!(!s.contains("hunter2"), "debug output leaked the password: {s}");
        assert!(s.contains("redacted"));
    }

    #[test]
    fn ssh_key_debug_shows_path() {
        let auth = AuthConfig::SshKey { private_key_path: "/tmp/k.pem".into() };
        let s = format!("{auth:?}");
        assert!(s.contains("/tmp/k.pem"));
    }

    #[test]
    fn deserialize_password() {
        let json = r#"{"type":"password","password":"x"}"#;
        let parsed: AuthConfig = serde_json::from_str(json).unwrap();
        match parsed {
            AuthConfig::Password { password } => assert_eq!(password, "x"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn deserialize_ssh_key() {
        let json = r#"{"type":"ssh_key","private_key_path":"/k.pem"}"#;
        let parsed: AuthConfig = serde_json::from_str(json).unwrap();
        match parsed {
            AuthConfig::SshKey { private_key_path } =>
                assert_eq!(private_key_path, std::path::PathBuf::from("/k.pem")),
            _ => panic!("wrong variant"),
        }
    }
}
```

- [ ] **Step 2: Wire into lib.rs**

Update `rust-junosmcp-core/src/lib.rs`:

```rust
pub mod error;
pub mod inventory;
pub use error::JmcpError;
pub use inventory::AuthConfig;
```

- [ ] **Step 3: Run tests, expect PASS**

Run: `cargo test -p rust-junosmcp-core --lib inventory::auth_tests`
Expected: 4 tests pass.

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp-core/src/inventory.rs rust-junosmcp-core/src/lib.rs
git commit -m "feat(core): AuthConfig with redacted Debug"
```

---

## Task 3: DeviceEntry deserialization

**Files:**
- Modify: `rust-junosmcp-core/src/inventory.rs`

- [ ] **Step 1: Append `DeviceEntry` and tests**

Add to `rust-junosmcp-core/src/inventory.rs`:

```rust
fn default_port() -> u16 { 22 }

/// One entry in `devices.json`.
#[derive(Clone, Debug, Deserialize)]
pub struct DeviceEntry {
    pub ip: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: String,
    pub auth: AuthConfig,
    /// Optional path to OpenSSH config file (jumphost). Parsed but not yet
    /// honored — see [`crate::error::JmcpError::SshConfigUnsupported`].
    #[serde(default)]
    pub ssh_config: Option<PathBuf>,
}

#[cfg(test)]
mod entry_tests {
    use super::*;

    #[test]
    fn parses_password_entry_with_default_port() {
        let json = r#"{
            "ip":"10.0.0.1",
            "username":"admin",
            "auth":{"type":"password","password":"x"}
        }"#;
        let e: DeviceEntry = serde_json::from_str(json).unwrap();
        assert_eq!(e.ip, "10.0.0.1");
        assert_eq!(e.port, 22);
        assert_eq!(e.username, "admin");
        assert!(e.ssh_config.is_none());
    }

    #[test]
    fn parses_ssh_key_entry_with_explicit_port_and_ssh_config() {
        let json = r#"{
            "ip":"10.0.0.2",
            "port":830,
            "username":"netconf",
            "ssh_config":"/home/u/.ssh/config_jh",
            "auth":{"type":"ssh_key","private_key_path":"/k.pem"}
        }"#;
        let e: DeviceEntry = serde_json::from_str(json).unwrap();
        assert_eq!(e.port, 830);
        assert_eq!(e.ssh_config, Some(PathBuf::from("/home/u/.ssh/config_jh")));
    }

    #[test]
    fn rejects_missing_required_fields() {
        let json = r#"{"username":"admin","auth":{"type":"password","password":"x"}}"#;
        let r: Result<DeviceEntry, _> = serde_json::from_str(json);
        assert!(r.is_err(), "expected error for missing 'ip'");
    }
}
```

- [ ] **Step 2: Run tests, expect PASS**

Run: `cargo test -p rust-junosmcp-core --lib inventory::entry_tests`
Expected: 3 tests pass.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/src/inventory.rs
git commit -m "feat(core): DeviceEntry deserialization"
```

---

## Task 4: Inventory load + validation

**Files:**
- Modify: `rust-junosmcp-core/src/inventory.rs`
- Create: `rust-junosmcp-core/tests/inventory_fixtures/` (test files inline via `tempfile`)

- [ ] **Step 1: Append `Inventory` + tests**

Add to `rust-junosmcp-core/src/inventory.rs`:

```rust
use crate::error::JmcpError;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Inventory {
    devices: HashMap<String, DeviceEntry>,
    source_path: PathBuf,
}

impl Inventory {
    /// Load and validate a `devices.json` file.
    pub fn load(path: &Path) -> Result<Self, JmcpError> {
        let bytes = std::fs::read(path)?;
        let devices: HashMap<String, DeviceEntry> = serde_json::from_slice(&bytes)
            .map_err(|e| JmcpError::InventoryInvalid(e.to_string()))?;
        Self::validate(&devices)?;
        Ok(Self {
            devices,
            source_path: path.to_path_buf(),
        })
    }

    fn validate(devices: &HashMap<String, DeviceEntry>) -> Result<(), JmcpError> {
        for (name, entry) in devices {
            if entry.ip.trim().is_empty() {
                return Err(JmcpError::InventoryInvalid(
                    format!("router '{name}': ip is empty"),
                ));
            }
            if entry.port == 0 {
                return Err(JmcpError::InventoryInvalid(
                    format!("router '{name}': port must be non-zero"),
                ));
            }
            if entry.username.trim().is_empty() {
                return Err(JmcpError::InventoryInvalid(
                    format!("router '{name}': username is empty"),
                ));
            }
            if let AuthConfig::SshKey { private_key_path } = &entry.auth {
                if !private_key_path.exists() {
                    return Err(JmcpError::KeyFileMissing(private_key_path.clone()));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod load_tests {
    use super::*;
    use std::io::Write;

    fn write(name: &str, json: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new()
            .prefix(name)
            .suffix(".json")
            .tempfile()
            .unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f
    }

    #[test]
    fn loads_valid_password_only_inventory() {
        let f = write("ok", r#"{
            "r1":{"ip":"1.2.3.4","username":"u","auth":{"type":"password","password":"x"}}
        }"#);
        let inv = Inventory::load(f.path()).unwrap();
        assert_eq!(inv.devices.len(), 1);
    }

    #[test]
    fn rejects_zero_port() {
        let f = write("p0", r#"{
            "r1":{"ip":"1.2.3.4","port":0,"username":"u","auth":{"type":"password","password":"x"}}
        }"#);
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn rejects_empty_ip() {
        let f = write("ip", r#"{
            "r1":{"ip":"","username":"u","auth":{"type":"password","password":"x"}}
        }"#);
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn rejects_missing_key_file() {
        let f = write("missing", r#"{
            "r1":{"ip":"1.2.3.4","username":"u",
                  "auth":{"type":"ssh_key","private_key_path":"/nope/missing.pem"}}
        }"#);
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::KeyFileMissing(_))));
    }

    #[test]
    fn accepts_existing_key_file() {
        let key = tempfile::NamedTempFile::new().unwrap();
        let json = format!(r#"{{
            "r1":{{"ip":"1.2.3.4","username":"u",
                   "auth":{{"type":"ssh_key","private_key_path":"{}"}}}}
        }}"#, key.path().display());
        let f = write("withkey", &json);
        let inv = Inventory::load(f.path()).unwrap();
        assert_eq!(inv.devices.len(), 1);
    }

    #[test]
    fn rejects_invalid_json() {
        let f = write("bad", "{not json");
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }
}
```

- [ ] **Step 2: Run tests, expect PASS**

Run: `cargo test -p rust-junosmcp-core --lib inventory::load_tests`
Expected: 6 tests pass.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/src/inventory.rs
git commit -m "feat(core): Inventory load + validation"
```

---

## Task 5: Inventory accessors (get / names)

**Files:**
- Modify: `rust-junosmcp-core/src/inventory.rs`

- [ ] **Step 1: Append accessors + tests**

Add to `rust-junosmcp-core/src/inventory.rs`:

```rust
impl Inventory {
    /// Look up a device by name.
    pub fn get(&self, name: &str) -> Result<&DeviceEntry, JmcpError> {
        self.devices.get(name)
            .ok_or_else(|| JmcpError::UnknownRouter(name.to_string()))
    }

    /// Sorted list of router names. Used by `get_router_list`.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.devices.keys().cloned().collect();
        names.sort();
        names
    }

    /// Source path the inventory was loaded from. Used by v0.2 `reload_devices`.
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }
}

#[cfg(test)]
mod accessor_tests {
    use super::*;
    use std::io::Write;

    fn build(json: &str) -> Inventory {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Inventory::load(f.path()).unwrap()
    }

    #[test]
    fn get_returns_known_router() {
        let inv = build(r#"{
            "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#);
        assert_eq!(inv.get("r1").unwrap().ip, "1.1.1.1");
    }

    #[test]
    fn get_returns_unknown_router_error() {
        let inv = build(r#"{
            "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#);
        let r = inv.get("nope");
        assert!(matches!(r, Err(JmcpError::UnknownRouter(ref s)) if s == "nope"));
    }

    #[test]
    fn names_returns_sorted() {
        let inv = build(r#"{
            "z":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}},
            "a":{"ip":"1.1.1.2","username":"u","auth":{"type":"password","password":"x"}}
        }"#);
        assert_eq!(inv.names(), vec!["a".to_string(), "z".to_string()]);
    }
}
```

- [ ] **Step 2: Re-export from lib.rs**

Update `rust-junosmcp-core/src/lib.rs`:

```rust
pub use inventory::{AuthConfig, DeviceEntry, Inventory};
```

- [ ] **Step 3: Run tests, expect PASS**

Run: `cargo test -p rust-junosmcp-core --lib inventory::accessor_tests`
Expected: 3 tests pass.

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp-core/src/inventory.rs rust-junosmcp-core/src/lib.rs
git commit -m "feat(core): Inventory get/names/source_path accessors"
```

---

## Task 6: DeviceManager::open + ssh_config rejection

**Files:**
- Create: `rust-junosmcp-core/src/device_manager.rs`
- Modify: `rust-junosmcp-core/src/lib.rs`

- [ ] **Step 1: Write the failing test + impl**

Create `rust-junosmcp-core/src/device_manager.rs`:

```rust
//! Connection lifecycle management. Open-per-call — every tool invocation
//! opens a fresh `rustez::Device`, runs its operation, and closes it.

use crate::error::JmcpError;
use crate::inventory::{AuthConfig, Inventory};
use rustez::Device;
use std::sync::Arc;

#[derive(Clone)]
pub struct DeviceManager {
    inventory: Arc<Inventory>,
}

impl DeviceManager {
    pub fn new(inventory: Arc<Inventory>) -> Self {
        Self { inventory }
    }

    /// Open a fresh `rustez::Device` for the named router. Caller is
    /// responsible for `close()`.
    pub async fn open(&self, router_name: &str) -> Result<Device, JmcpError> {
        let entry = self.inventory.get(router_name)?;

        // ssh_config jumphost is v0.2 work — fail loudly so the LLM
        // doesn't think it silently used the jumphost.
        if entry.ssh_config.is_some() {
            return Err(JmcpError::SshConfigUnsupported(router_name.into()));
        }

        let mut builder = Device::connect(&entry.ip)
            .port(entry.port)
            .username(&entry.username);

        builder = match &entry.auth {
            AuthConfig::Password { password } => builder.password(password),
            AuthConfig::SshKey { private_key_path } => {
                let path_str = private_key_path
                    .to_str()
                    .ok_or_else(|| JmcpError::InventoryInvalid(
                        format!("private_key_path is not valid UTF-8: {}",
                                private_key_path.display())
                    ))?;
                builder.key_file(path_str)
            }
        };

        Ok(builder.open().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn build_inventory(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    #[tokio::test]
    async fn unknown_router_returns_unknown_router_error() {
        let inv = build_inventory(r#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#);
        let dm = DeviceManager::new(inv);
        let r = dm.open("nope").await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(ref s)) if s == "nope"));
    }

    #[tokio::test]
    async fn ssh_config_set_returns_unsupported_error() {
        let inv = build_inventory(r#"{
            "r1":{"ip":"127.0.0.1","username":"u",
                  "ssh_config":"/tmp/never-used",
                  "auth":{"type":"password","password":"x"}}
        }"#);
        let dm = DeviceManager::new(inv);
        let r = dm.open("r1").await;
        assert!(matches!(r, Err(JmcpError::SshConfigUnsupported(ref s)) if s == "r1"));
    }
}
```

- [ ] **Step 2: Wire into lib.rs**

Update `rust-junosmcp-core/src/lib.rs`:

```rust
pub mod device_manager;
pub use device_manager::DeviceManager;
```

Also add `tokio` to `[dev-dependencies]` of `rust-junosmcp-core/Cargo.toml` if not already present (the workspace `tokio` is in `[dependencies]`; for `#[tokio::test]` it's already available).

- [ ] **Step 3: Run tests, expect PASS**

Run: `cargo test -p rust-junosmcp-core --lib device_manager::tests`
Expected: 2 tests pass. (Real-device connection is not exercised — both tests hit early-return paths.)

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp-core/src/device_manager.rs rust-junosmcp-core/src/lib.rs
git commit -m "feat(core): DeviceManager with ssh_config rejection"
```

---

## Task 7: Pure-logic helpers

**Files:**
- Create: `rust-junosmcp-core/src/helpers.rs`
- Modify: `rust-junosmcp-core/src/lib.rs`

- [ ] **Step 1: Write helpers + tests**

Create `rust-junosmcp-core/src/helpers.rs`:

```rust
//! Pure helper functions, easily unit-testable without device contact.

use crate::error::JmcpError;
use rustez::{ConfigPayload, Facts};
use serde_json::{json, Value};

/// Map the optional `config_format` string from the MCP tool input to
/// a `rustez::ConfigPayload` constructor closure. Default = "set".
pub fn build_config_payload(
    text: String,
    fmt: Option<&str>,
) -> Result<ConfigPayload, JmcpError> {
    match fmt.unwrap_or("set") {
        "set"  => Ok(ConfigPayload::Set(text)),
        "text" => Ok(ConfigPayload::Text(text)),
        "xml"  => Ok(ConfigPayload::Xml(text)),
        other  => Err(JmcpError::BadFormat(other.into())),
    }
}

/// Clamp an LLM-provided rollback version to the Junos-supported range 1..=49.
pub fn validate_rollback_version(v: i64) -> Result<u32, JmcpError> {
    if (1..=49).contains(&v) {
        Ok(v as u32)
    } else {
        Err(JmcpError::BadRollbackVersion(v))
    }
}

/// Hand-build a JSON object from `rustez::Facts`. rustez::Facts does not
/// derive Serialize today (see followup #1); update this when it does.
pub fn facts_to_json(f: &Facts) -> Value {
    json!({
        "hostname": f.hostname,
        "model": f.model,
        "version": f.version,
        "serial_number": f.serial_number,
        "personality": format!("{:?}", f.personality),
        "domain": f.domain,
        "fqdn": f.fqdn,
        "is_cluster": f.is_cluster,
        "route_engines": f.route_engines.iter().map(|re| json!({
            "status": format!("{:?}", re),
        })).collect::<Vec<_>>(),
        "master_re": f.master_re,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_config_payload_defaults_to_set() {
        let p = build_config_payload("set system foo".into(), None).unwrap();
        assert!(matches!(p, ConfigPayload::Set(ref s) if s == "set system foo"));
    }

    #[test]
    fn build_config_payload_accepts_text() {
        let p = build_config_payload("system { foo; }".into(), Some("text")).unwrap();
        assert!(matches!(p, ConfigPayload::Text(_)));
    }

    #[test]
    fn build_config_payload_accepts_xml() {
        let p = build_config_payload("<foo/>".into(), Some("xml")).unwrap();
        assert!(matches!(p, ConfigPayload::Xml(_)));
    }

    #[test]
    fn build_config_payload_rejects_unknown() {
        let r = build_config_payload("x".into(), Some("yaml"));
        assert!(matches!(r, Err(JmcpError::BadFormat(ref s)) if s == "yaml"));
    }

    #[test]
    fn rollback_version_accepts_1_through_49() {
        assert_eq!(validate_rollback_version(1).unwrap(), 1);
        assert_eq!(validate_rollback_version(49).unwrap(), 49);
    }

    #[test]
    fn rollback_version_rejects_zero() {
        let r = validate_rollback_version(0);
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(0))));
    }

    #[test]
    fn rollback_version_rejects_50() {
        let r = validate_rollback_version(50);
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(50))));
    }

    #[test]
    fn rollback_version_rejects_negative() {
        let r = validate_rollback_version(-3);
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(-3))));
    }
}
```

- [ ] **Step 2: Wire into lib.rs**

Update `rust-junosmcp-core/src/lib.rs`:

```rust
pub mod helpers;
```

- [ ] **Step 3: Run tests, expect PASS**

Run: `cargo test -p rust-junosmcp-core --lib helpers::tests`
Expected: 8 tests pass.

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp-core/src/helpers.rs rust-junosmcp-core/src/lib.rs
git commit -m "feat(core): pure helpers for config_format, rollback version, facts JSON"
```

---

## Task 8: Tool input structs

**Files:**
- Create: `rust-junosmcp-core/src/tools/mod.rs`
- Modify: `rust-junosmcp-core/src/lib.rs`

- [ ] **Step 1: Write input structs + tests**

Create `rust-junosmcp-core/src/tools/mod.rs`:

```rust
//! MCP tool argument types. Each tool gets a typed input struct that
//! `schemars` derives a JSON schema from for advertisement to the client.

use schemars::JsonSchema;
use serde::Deserialize;

pub mod router_list;
pub mod execute_command;
pub mod get_config;
pub mod config_diff;
pub mod facts;
pub mod load_commit;

fn default_timeout() -> u64 { 360 }
fn default_version() -> i64 { 1 }
fn default_set_format() -> String { "set".into() }
fn default_commit_comment() -> String { "Configuration loaded via MCP".into() }

#[derive(Debug, Deserialize, JsonSchema, Default)]
pub struct EmptyArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteCommandArgs {
    /// The name of the router.
    pub router_name: String,
    /// The command to execute on the router.
    pub command: String,
    /// Command timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetConfigArgs {
    pub router_name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ConfigDiffArgs {
    pub router_name: String,
    /// Rollback version to compare against (1-49).
    #[serde(default = "default_version")]
    pub version: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GatherFactsArgs {
    pub router_name: String,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LoadCommitArgs {
    pub router_name: String,
    /// The configuration text to load.
    pub config_text: String,
    /// Format: set, text, or xml.
    #[serde(default = "default_set_format")]
    pub config_format: String,
    /// Commit comment recorded in the device commit log.
    #[serde(default = "default_commit_comment")]
    pub commit_comment: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_command_defaults_timeout() {
        let v = serde_json::json!({"router_name":"r1","command":"show version"});
        let a: ExecuteCommandArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.timeout, 360);
    }

    #[test]
    fn config_diff_defaults_version_to_1() {
        let v = serde_json::json!({"router_name":"r1"});
        let a: ConfigDiffArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.version, 1);
    }

    #[test]
    fn load_commit_defaults_format_and_comment() {
        let v = serde_json::json!({"router_name":"r1","config_text":"set x"});
        let a: LoadCommitArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.config_format, "set");
        assert_eq!(a.commit_comment, "Configuration loaded via MCP");
    }

    #[test]
    fn execute_command_rejects_missing_required() {
        let v = serde_json::json!({"router_name":"r1"});
        let r: Result<ExecuteCommandArgs, _> = serde_json::from_value(v);
        assert!(r.is_err());
    }
}
```

- [ ] **Step 2: Create empty tool module stubs (so `mod` declarations resolve)**

Create each of:
- `rust-junosmcp-core/src/tools/router_list.rs` → `// stub`
- `rust-junosmcp-core/src/tools/execute_command.rs` → `// stub`
- `rust-junosmcp-core/src/tools/get_config.rs` → `// stub`
- `rust-junosmcp-core/src/tools/config_diff.rs` → `// stub`
- `rust-junosmcp-core/src/tools/facts.rs` → `// stub`
- `rust-junosmcp-core/src/tools/load_commit.rs` → `// stub`

- [ ] **Step 3: Wire into lib.rs**

Update `rust-junosmcp-core/src/lib.rs`:

```rust
pub mod tools;
```

- [ ] **Step 4: Run tests, expect PASS**

Run: `cargo test -p rust-junosmcp-core --lib tools::tests`
Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/ rust-junosmcp-core/src/lib.rs
git commit -m "feat(core): tool input argument structs with schemars schemas"
```

---

## Task 9: `get_router_list` handler

**Files:**
- Modify: `rust-junosmcp-core/src/tools/router_list.rs`

- [ ] **Step 1: Write the failing test + impl**

Replace `rust-junosmcp-core/src/tools/router_list.rs`:

```rust
//! `get_router_list` — return the inventory's router names. Pure, no device contact.

use crate::error::JmcpError;
use crate::inventory::Inventory;
use serde_json::{json, Value};
use std::sync::Arc;

pub async fn handle(inv: Arc<Inventory>) -> Result<Value, JmcpError> {
    Ok(json!(inv.names()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_inv(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    #[tokio::test]
    async fn returns_sorted_names() {
        let inv = make_inv(r#"{
            "z":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}},
            "a":{"ip":"1.1.1.2","username":"u","auth":{"type":"password","password":"x"}}
        }"#);
        let v = handle(inv).await.unwrap();
        assert_eq!(v, json!(["a", "z"]));
    }
}
```

- [ ] **Step 2: Run tests, expect PASS**

Run: `cargo test -p rust-junosmcp-core --lib tools::router_list`
Expected: 1 test passes.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/src/tools/router_list.rs
git commit -m "feat(core): get_router_list handler"
```

---

## Task 10: `execute_junos_command` handler

**Files:**
- Modify: `rust-junosmcp-core/src/tools/execute_command.rs`

> **Note on testing the device-touching tools (Tasks 10–14):** Each handler delegates to `rustez::Device` methods that require a real Junos device. We don't introduce a trait for mocking — over-engineering for v0.1. Unit tests cover input validation paths only. Real-device behavior is exercised in Task 22's `tests/integration_real_device.rs` (`#[ignore]`'d, gated on env vars).

- [ ] **Step 1: Write the failing test + impl**

Replace `rust-junosmcp-core/src/tools/execute_command.rs`:

```rust
//! `execute_junos_command` — run an operational CLI command on one router.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::tools::ExecuteCommandArgs;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

pub async fn handle(
    args: ExecuteCommandArgs,
    dm: Arc<DeviceManager>,
) -> Result<Value, JmcpError> {
    let timeout = Duration::from_secs(args.timeout);
    let mut dev = dm.open(&args.router_name).await?;

    let result = tokio::time::timeout(timeout, dev.cli(&args.command))
        .await
        .map_err(|_| JmcpError::Timeout(timeout))?;

    let _ = dev.close().await; // best-effort
    Ok(json!(result?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    #[tokio::test]
    async fn unknown_router_propagates_error() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(br#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#).unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let dm  = Arc::new(DeviceManager::new(inv));
        let r = handle(
            ExecuteCommandArgs {
                router_name: "nope".into(),
                command: "show version".into(),
                timeout: 5,
            },
            dm,
        ).await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }
}
```

- [ ] **Step 2: Run tests, expect PASS**

Run: `cargo test -p rust-junosmcp-core --lib tools::execute_command`
Expected: 1 test passes (early-return path; no device contact).

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/src/tools/execute_command.rs
git commit -m "feat(core): execute_junos_command handler"
```

---

## Task 11: `get_junos_config` handler

**Files:**
- Modify: `rust-junosmcp-core/src/tools/get_config.rs`

- [ ] **Step 1: Write impl**

Replace `rust-junosmcp-core/src/tools/get_config.rs`:

```rust
//! `get_junos_config` — return full text-format running config.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::tools::GetConfigArgs;
use serde_json::{json, Value};
use std::sync::Arc;

pub async fn handle(
    args: GetConfigArgs,
    dm: Arc<DeviceManager>,
) -> Result<Value, JmcpError> {
    let mut dev = dm.open(&args.router_name).await?;
    let cfg_text = dev.cli("show configuration").await?;
    let _ = dev.close().await;
    Ok(json!(cfg_text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    #[tokio::test]
    async fn unknown_router_propagates_error() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(br#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#).unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let dm  = Arc::new(DeviceManager::new(inv));
        let r = handle(GetConfigArgs { router_name: "nope".into() }, dm).await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }
}
```

- [ ] **Step 2: Run tests, expect PASS**

Run: `cargo test -p rust-junosmcp-core --lib tools::get_config`
Expected: 1 test passes.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/src/tools/get_config.rs
git commit -m "feat(core): get_junos_config handler"
```

---

## Task 12: `junos_config_diff` handler

**Files:**
- Modify: `rust-junosmcp-core/src/tools/config_diff.rs`

- [ ] **Step 1: Write impl + version-clamp test**

Replace `rust-junosmcp-core/src/tools/config_diff.rs`:

```rust
//! `junos_config_diff` — `show | compare rollback N` for N in 1..=49.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::validate_rollback_version;
use crate::tools::ConfigDiffArgs;
use serde_json::{json, Value};
use std::sync::Arc;

pub async fn handle(
    args: ConfigDiffArgs,
    dm: Arc<DeviceManager>,
) -> Result<Value, JmcpError> {
    let version = validate_rollback_version(args.version)?;
    let mut dev = dm.open(&args.router_name).await?;
    let cmd = format!("show | compare rollback {version}");
    let diff = dev.cli(&cmd).await?;
    let _ = dev.close().await;
    Ok(json!(diff))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    fn dm() -> Arc<DeviceManager> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(br#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#).unwrap();
        Arc::new(DeviceManager::new(Arc::new(Inventory::load(f.path()).unwrap())))
    }

    #[tokio::test]
    async fn rejects_version_zero_before_connecting() {
        let r = handle(
            ConfigDiffArgs { router_name: "r1".into(), version: 0 },
            dm(),
        ).await;
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(0))));
    }

    #[tokio::test]
    async fn rejects_version_50_before_connecting() {
        let r = handle(
            ConfigDiffArgs { router_name: "r1".into(), version: 50 },
            dm(),
        ).await;
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(50))));
    }
}
```

- [ ] **Step 2: Run tests, expect PASS**

Run: `cargo test -p rust-junosmcp-core --lib tools::config_diff`
Expected: 2 tests pass (validation runs before any device contact).

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/src/tools/config_diff.rs
git commit -m "feat(core): junos_config_diff handler with version clamp"
```

---

## Task 13: `gather_device_facts` handler

**Files:**
- Modify: `rust-junosmcp-core/src/tools/facts.rs`

- [ ] **Step 1: Write impl**

Replace `rust-junosmcp-core/src/tools/facts.rs`:

```rust
//! `gather_device_facts` — return device facts as a JSON object.
//!
//! Hand-builds the JSON because `rustez::Facts` does not derive `Serialize`
//! (followup #1).

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::facts_to_json;
use crate::tools::GatherFactsArgs;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

pub async fn handle(
    args: GatherFactsArgs,
    dm: Arc<DeviceManager>,
) -> Result<Value, JmcpError> {
    let timeout = Duration::from_secs(args.timeout);
    let mut dev = dm.open(&args.router_name).await?;

    let facts_result = tokio::time::timeout(timeout, dev.facts())
        .await
        .map_err(|_| JmcpError::Timeout(timeout))?;
    let facts = facts_result?;
    let value = facts_to_json(facts);

    let _ = dev.close().await;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    #[tokio::test]
    async fn unknown_router_propagates_error() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(br#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#).unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let dm  = Arc::new(DeviceManager::new(inv));
        let r = handle(
            GatherFactsArgs { router_name: "nope".into(), timeout: 5 },
            dm,
        ).await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }
}
```

- [ ] **Step 2: Run tests, expect PASS**

Run: `cargo test -p rust-junosmcp-core --lib tools::facts`
Expected: 1 test passes.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/src/tools/facts.rs
git commit -m "feat(core): gather_device_facts handler"
```

---

## Task 14: `load_and_commit_config` handler (with raw-RPC commit comment)

**Files:**
- Modify: `rust-junosmcp-core/src/tools/load_commit.rs`

- [ ] **Step 1: Write impl**

Replace `rust-junosmcp-core/src/tools/load_commit.rs`:

```rust
//! `load_and_commit_config` — lock candidate, load, diff, commit (with comment),
//! unlock. Rollback on commit failure. Returns `{success, diff, error?}`.
//!
//! Commit comment is sent via raw RPC because `rustez::ConfigManager` does not
//! yet expose `commit_with_comment` (followup #2).

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::build_config_payload;
use crate::tools::LoadCommitArgs;
use serde_json::{json, Value};
use std::sync::Arc;

/// XML-escape the commit comment for safe inclusion in the raw RPC body.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('\'', "&apos;")
     .replace('"', "&quot;")
}

pub async fn handle(
    args: LoadCommitArgs,
    dm: Arc<DeviceManager>,
) -> Result<Value, JmcpError> {
    let payload = build_config_payload(args.config_text, Some(&args.config_format))?;
    let comment_xml = format!(
        "<commit><log>{}</log></commit>",
        xml_escape(&args.commit_comment),
    );

    let mut dev = dm.open(&args.router_name).await?;
    let mut cfg = dev.config()?;

    cfg.lock().await?;
    if let Err(e) = cfg.load(payload).await {
        let _ = cfg.unlock().await;
        let _ = dev.close().await;
        return Err(JmcpError::Rustez(e));
    }
    let diff = cfg.diff().await?.unwrap_or_default();

    // Commit with comment via raw RPC (followup #2).
    let commit_result = dev.rpc()?.call_xml(&comment_xml).await;

    let result = match commit_result {
        Ok(_) => json!({ "success": true, "diff": diff }),
        Err(e) => {
            // Discard the candidate so the next session starts clean.
            // rollback(0) discards uncommitted changes.
            if let Ok(mut cfg2) = dev.config() {
                let _ = cfg2.rollback(0).await;
                let _ = cfg2.unlock().await;
            }
            json!({ "success": false, "diff": diff, "error": e.to_string() })
        }
    };

    // Best-effort unlock + close.
    if let Ok(mut cfg2) = dev.config() {
        let _ = cfg2.unlock().await;
    }
    let _ = dev.close().await;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    #[test]
    fn xml_escape_handles_specials() {
        assert_eq!(xml_escape("a & <b> 'c' \"d\""),
                   "a &amp; &lt;b&gt; &apos;c&apos; &quot;d&quot;");
    }

    #[tokio::test]
    async fn unknown_router_propagates_error() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(br#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#).unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let dm  = Arc::new(DeviceManager::new(inv));
        let r = handle(
            LoadCommitArgs {
                router_name: "nope".into(),
                config_text: "set system foo".into(),
                config_format: "set".into(),
                commit_comment: "test".into(),
            },
            dm,
        ).await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn invalid_format_rejected_before_connect() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(br#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#).unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let dm  = Arc::new(DeviceManager::new(inv));
        let r = handle(
            LoadCommitArgs {
                router_name: "r1".into(),
                config_text: "x".into(),
                config_format: "yaml".into(),
                commit_comment: "test".into(),
            },
            dm,
        ).await;
        assert!(matches!(r, Err(JmcpError::BadFormat(ref s)) if s == "yaml"));
    }
}
```

- [ ] **Step 2: Run tests, expect PASS**

Run: `cargo test -p rust-junosmcp-core --lib tools::load_commit`
Expected: 3 tests pass (no real device required for these paths).

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/src/tools/load_commit.rs
git commit -m "feat(core): load_and_commit_config with raw-RPC commit comment"
```

---

## Task 15: Binary crate skeleton + clap CLI

**Files:**
- Modify: `rust-junosmcp/Cargo.toml`
- Create: `rust-junosmcp/src/cli.rs`
- Modify: `rust-junosmcp/src/main.rs`

- [ ] **Step 1: Add clap dep**

Update `rust-junosmcp/Cargo.toml` `[dependencies]`:

```toml
clap = { version = "4", features = ["derive"] }
```

- [ ] **Step 2: Write CLI parser + tests**

Create `rust-junosmcp/src/cli.rs`:

```rust
//! Command-line arguments. v0.1 only supports stdio transport. The
//! `streamable-http` value is parsed but rejected at runtime so the user
//! sees a clear error instead of silent fallback.

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Transport {
    Stdio,
    StreamableHttp,
}

#[derive(Debug, Parser)]
#[command(name = "rust-junosmcp", version, about = "Junos MCP server (Rust)")]
pub struct Cli {
    /// JSON file with device mapping (Juniper junos-mcp-server compatible).
    #[arg(short = 'f', long, default_value = "devices.json")]
    pub device_mapping: PathBuf,

    /// Transport. v0.1 only supports stdio.
    #[arg(short = 't', long, default_value = "stdio", value_enum)]
    pub transport: Transport,

    /// Bind host (accepted for forward-compat; only used when streamable-http lands in v0.2).
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub host: String,

    /// Bind port (accepted for forward-compat; only used when streamable-http lands in v0.2).
    #[arg(short = 'p', long, default_value_t = 30030)]
    pub port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn defaults() {
        let cli = Cli::parse_from(["rust-junosmcp"]);
        assert_eq!(cli.device_mapping, PathBuf::from("devices.json"));
        assert_eq!(cli.transport, Transport::Stdio);
        assert_eq!(cli.host, "127.0.0.1");
        assert_eq!(cli.port, 30030);
    }

    #[test]
    fn parses_short_flags() {
        let cli = Cli::parse_from(["rust-junosmcp", "-f", "/etc/jmcp/d.json"]);
        assert_eq!(cli.device_mapping, PathBuf::from("/etc/jmcp/d.json"));
    }

    #[test]
    fn parses_streamable_http_value() {
        let cli = Cli::parse_from(["rust-junosmcp", "-t", "streamable-http"]);
        assert_eq!(cli.transport, Transport::StreamableHttp);
    }
}
```

- [ ] **Step 3: Update placeholder main.rs to compile against cli.rs**

Replace `rust-junosmcp/src/main.rs`:

```rust
mod cli;

fn main() {
    eprintln!("rust-junosmcp v{} - skeleton", env!("CARGO_PKG_VERSION"));
}
```

- [ ] **Step 4: Run tests, expect PASS**

Run: `cargo test -p rust-junosmcp --bin rust-junosmcp cli::tests`
Expected: 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp/Cargo.toml rust-junosmcp/src/cli.rs rust-junosmcp/src/main.rs
git commit -m "feat(bin): clap CLI parser with stdio + streamable-http transport enum"
```

---

## Task 16: rmcp `ServerHandler` + `#[tool_router]` registration

**Files:**
- Modify: `rust-junosmcp/Cargo.toml`
- Create: `rust-junosmcp/src/server.rs`

- [ ] **Step 1: Add rmcp + supporting deps**

Update `rust-junosmcp/Cargo.toml` `[dependencies]`:

```toml
rmcp = { version = "0.8", features = ["server", "macros", "transport-io", "schemars"] }
schemars = { workspace = true }
```

> If the rmcp 0.8 API differs from these snippets, adjust call sites — the documented surface used here (`#[tool_router]`, `#[tool]`, `Parameters<T>`, `service.serve((stdin, stdout))`) is the canonical pattern as of 2026-04. Confirm with `cargo doc --open -p rmcp`.

- [ ] **Step 2: Write the handler module**

Create `rust-junosmcp/src/server.rs`:

```rust
//! rmcp `ServerHandler` wrapping the core tool functions.
//!
//! Each `#[tool]` method is a thin adapter: it takes the typed `Parameters<T>`
//! struct, calls into `rust_junosmcp_core::tools::<name>::handle`, and converts
//! the `Result<serde_json::Value, JmcpError>` into the appropriate rmcp content.

use rmcp::handler::server::{
    router::tool::ToolRouter,
    wrapper::Parameters,
};
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo, Implementation};
use rmcp::{ServerHandler, tool, tool_router};
use rust_junosmcp_core::{
    DeviceManager, Inventory,
    tools::{
        ConfigDiffArgs, ExecuteCommandArgs, GatherFactsArgs, GetConfigArgs, LoadCommitArgs,
        config_diff, execute_command, facts, get_config, load_commit, router_list,
    },
};
use serde_json::Value;
use std::sync::Arc;

#[derive(Clone)]
pub struct JmcpHandler {
    inv: Arc<Inventory>,
    dm: Arc<DeviceManager>,
}

impl JmcpHandler {
    pub fn new(inv: Arc<Inventory>, dm: Arc<DeviceManager>) -> Self {
        Self { inv, dm }
    }

    fn to_call_result(r: Result<Value, rust_junosmcp_core::JmcpError>) -> CallToolResult {
        match r {
            Ok(Value::String(s)) => CallToolResult::success(vec![Content::text(s)]),
            Ok(other) => CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&other).unwrap_or_else(|e| e.to_string()),
            )]),
            Err(e) => CallToolResult::error(vec![Content::text(e.to_string())]),
        }
    }
}

#[tool_router(server_handler)]
impl JmcpHandler {
    #[tool(name = "get_router_list", description = "Get list of available Junos routers")]
    async fn get_router_list(
        &self,
        Parameters(_): Parameters<rust_junosmcp_core::tools::EmptyArgs>,
    ) -> CallToolResult {
        Self::to_call_result(router_list::handle(self.inv.clone()).await)
    }

    #[tool(name = "gather_device_facts", description = "Gather Junos device facts from the router")]
    async fn gather_device_facts(
        &self,
        Parameters(args): Parameters<GatherFactsArgs>,
    ) -> CallToolResult {
        Self::to_call_result(facts::handle(args, self.dm.clone()).await)
    }

    #[tool(name = "execute_junos_command", description = "Execute a Junos command on the router")]
    async fn execute_junos_command(
        &self,
        Parameters(args): Parameters<ExecuteCommandArgs>,
    ) -> CallToolResult {
        Self::to_call_result(execute_command::handle(args, self.dm.clone()).await)
    }

    #[tool(name = "get_junos_config", description = "Get the configuration of the router")]
    async fn get_junos_config(
        &self,
        Parameters(args): Parameters<GetConfigArgs>,
    ) -> CallToolResult {
        Self::to_call_result(get_config::handle(args, self.dm.clone()).await)
    }

    #[tool(name = "junos_config_diff",
           description = "Get the configuration diff against a rollback version")]
    async fn junos_config_diff(
        &self,
        Parameters(args): Parameters<ConfigDiffArgs>,
    ) -> CallToolResult {
        Self::to_call_result(config_diff::handle(args, self.dm.clone()).await)
    }

    #[tool(name = "load_and_commit_config",
           description = "Load and commit configuration on a Junos router")]
    async fn load_and_commit_config(
        &self,
        Parameters(args): Parameters<LoadCommitArgs>,
    ) -> CallToolResult {
        Self::to_call_result(load_commit::handle(args, self.dm.clone()).await)
    }
}

impl ServerHandler for JmcpHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: Default::default(),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "jmcp-server".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            instructions: Some(
                "Junos MCP server (Rust port). Use get_router_list to enumerate \
                 available routers, then run operational commands or load config."
                    .into(),
            ),
        }
    }

    fn tool_router(&self) -> &ToolRouter<Self> {
        Self::tool_router_static()
    }
}
```

> The exact `ServerInfo` field shape and `enable_tools()` builder name come from rmcp's docs. If the macro `tool_router_static()` is named differently in the version you pull (e.g., `__tool_router()`), update accordingly — the macro names are documented in `rmcp::attr::tool_router` rustdoc.

- [ ] **Step 3: Build to verify the macros expand cleanly**

Run: `cargo build -p rust-junosmcp`
Expected: compiles. If it fails because of an rmcp API drift, fix the snippet above before proceeding — do not work around at runtime.

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp/Cargo.toml rust-junosmcp/src/server.rs
git commit -m "feat(bin): JmcpHandler with rmcp #[tool_router] for 6 tools"
```

---

## Task 17: `main.rs` glue + transport dispatch

**Files:**
- Modify: `rust-junosmcp/src/main.rs`

- [ ] **Step 1: Wire it all together**

Replace `rust-junosmcp/src/main.rs`:

```rust
mod cli;
mod server;

use anyhow::{bail, Context, Result};
use clap::Parser;
use cli::{Cli, Transport};
use rmcp::ServiceExt;
use rust_junosmcp_core::{DeviceManager, Inventory};
use server::JmcpHandler;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Logs to stderr — stdout is reserved for MCP framing on stdio transport.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .init();

    let args = Cli::parse();

    if matches!(args.transport, Transport::StreamableHttp) {
        bail!(
            "streamable-http transport is not supported in v0.1. \
             Use --transport stdio. HTTP support is planned for v0.2."
        );
    }

    let inventory = Arc::new(
        Inventory::load(&args.device_mapping)
            .with_context(|| format!("loading {}", args.device_mapping.display()))?,
    );
    tracing::info!(
        devices = inventory.names().len(),
        path = %args.device_mapping.display(),
        "loaded inventory"
    );

    let dev_manager = Arc::new(DeviceManager::new(inventory.clone()));
    let handler = JmcpHandler::new(inventory, dev_manager);

    let service = handler.serve((tokio::io::stdin(), tokio::io::stdout())).await
        .context("starting MCP stdio service")?;
    service.waiting().await.context("MCP service exited with error")?;
    Ok(())
}
```

- [ ] **Step 2: Build to verify**

Run: `cargo build -p rust-junosmcp`
Expected: compiles cleanly.

- [ ] **Step 3: Smoke-run with no devices.json**

Run: `cargo run -p rust-junosmcp -- -f /no/such/file.json`
Expected: process exits non-zero with `"loading /no/such/file.json"` in the error chain.

- [ ] **Step 4: Smoke-run with --transport streamable-http**

Run: `cargo run -p rust-junosmcp -- -t streamable-http`
Expected: exits non-zero with the v0.1-only error message.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp/src/main.rs
git commit -m "feat(bin): main.rs wires inventory + DeviceManager + JmcpHandler over stdio"
```

---

## Task 18: stdio smoke test (spawn binary, drive `tools/list`)

**Files:**
- Create: `rust-junosmcp/tests/stdio_smoke.rs`
- Modify: `rust-junosmcp/Cargo.toml` (add `[[test]]` + dev-deps)

- [ ] **Step 1: Add dev-deps**

Update `rust-junosmcp/Cargo.toml`:

```toml
[dev-dependencies]
tempfile = "3"
serde_json = { workspace = true }
tokio = { workspace = true }
```

- [ ] **Step 2: Write the smoke test**

Create `rust-junosmcp/tests/stdio_smoke.rs`:

```rust
//! Spawn the `rust-junosmcp` binary, send MCP `initialize` + `tools/list` over
//! stdin, parse responses on stdout, assert we advertise the 6 v0.1 tools.

use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const EXPECTED_TOOLS: &[&str] = &[
    "get_router_list",
    "gather_device_facts",
    "execute_junos_command",
    "get_junos_config",
    "junos_config_diff",
    "load_and_commit_config",
];

fn binary_path() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // workspace root
    p.push("target");
    p.push(if cfg!(debug_assertions) { "debug" } else { "release" });
    p.push("rust-junosmcp");
    p
}

#[test]
fn lists_six_tools() {
    // Build first so the binary exists.
    let status = Command::new("cargo")
        .args(["build", "-p", "rust-junosmcp"])
        .status()
        .expect("cargo build");
    assert!(status.success(), "cargo build failed");

    // Empty inventory file is enough for `tools/list`.
    let inv = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(inv.path(), "{}").unwrap();

    let mut child = Command::new(binary_path())
        .args(["-f", inv.path().to_str().unwrap(), "-t", "stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rust-junosmcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    // MCP framing is JSON-RPC delimited by newlines.
    fn send(stdin: &mut impl Write, msg: &Value) {
        let line = serde_json::to_string(msg).unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    send(&mut stdin, &json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": { "name": "smoke", "version": "0.1" }
        }
    }));
    send(&mut stdin, &json!({
        "jsonrpc": "2.0", "method": "notifications/initialized"
    }));
    send(&mut stdin, &json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
    }));

    // Read until we see the tools/list response.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut tools_response: Option<Value> = None;
    use std::io::{BufRead, BufReader};
    let mut reader = BufReader::new(&mut stdout);
    while Instant::now() < deadline && tools_response.is_none() {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 { break; }
        let v: Value = match serde_json::from_str(line.trim()) { Ok(v) => v, Err(_) => continue };
        if v.get("id") == Some(&json!(2)) {
            tools_response = Some(v);
        }
    }

    let _ = child.kill();
    let resp = tools_response.expect("did not receive tools/list response within 15s");
    let tools = resp.pointer("/result/tools").expect("missing /result/tools").as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t.get("name").and_then(Value::as_str).unwrap()).collect();
    for expected in EXPECTED_TOOLS {
        assert!(names.contains(expected),
                "missing tool {expected}; got {names:?}");
    }
    assert_eq!(names.len(), EXPECTED_TOOLS.len(),
               "extra/missing tools: got {names:?}");
}
```

- [ ] **Step 3: Run the smoke test**

Run: `cargo test -p rust-junosmcp --test stdio_smoke -- --nocapture`
Expected: PASS within ~15s. If it times out, stderr-tee the child to debug protocol-version mismatches.

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp/Cargo.toml rust-junosmcp/tests/stdio_smoke.rs
git commit -m "test: stdio smoke test verifies all 6 tools are advertised"
```

---

## Task 19: Dockerfile (distroless)

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`

- [ ] **Step 1: Write `.dockerignore`**

```
target
.git
.github
docs
README.md
*.md
.serena
.vscode
.idea
```

- [ ] **Step 2: Write `Dockerfile`**

```dockerfile
# syntax=docker/dockerfile:1.6
FROM rust:1.83-slim AS builder
WORKDIR /src

# rustEZ is a workspace path dependency; the build context expects it copied
# adjacent. The CI workflow handles that; for local builds, point the COPY
# at a pre-staged build context.
COPY . .

RUN cargo build --release --bin rust-junosmcp

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/mechubsec/rustjunosmcp"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=builder /src/target/release/rust-junosmcp /usr/local/bin/rust-junosmcp
ENV RUST_LOG=info
USER nonroot
ENTRYPOINT ["/usr/local/bin/rust-junosmcp", "-f", "/etc/jmcp/devices.json"]
```

> **Build context note:** because rustez is a path dependency at `../rustEZ/rustez`, the docker build must be invoked from a parent directory that contains both repos, with a build context that includes both:
>
> ```bash
> docker build -f RustJunosMCP/Dockerfile -t rust-junosmcp:0.1 .
> ```
>
> The README (Task 21) documents this caveat. When rustEZ is published to crates.io, the Dockerfile becomes single-context.

- [ ] **Step 3: Test the build (only if both repos are siblings)**

Run from the parent of `RustJunosMCP`:
```bash
docker build -f RustJunosMCP/Dockerfile -t rust-junosmcp:test .
```
Expected: image builds. Skip this step if Docker isn't installed; we don't gate the plan on it.

- [ ] **Step 4: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "build: Dockerfile with distroless runtime"
```

---

## Task 20: LXC packaging (systemd unit + install.sh + package-lxc.sh)

**Files:**
- Create: `packaging/systemd/rust-junosmcp.service`
- Create: `packaging/lxc/install.sh`
- Create: `scripts/package-lxc.sh`

- [ ] **Step 1: Write the systemd unit**

Create `packaging/systemd/rust-junosmcp.service`:

```ini
[Unit]
Description=Rust JunosMCP server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=jmcp
Group=jmcp
ExecStart=/usr/local/bin/rust-junosmcp -f /etc/jmcp/devices.json
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/jmcp
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

# v0.1 NOTE: stdio transport is not a great fit for systemd-managed daemons.
# The unit is shipped now for forward-compat; primary v0.1 usage is via
# `pct exec 115 -- rust-junosmcp -f /etc/jmcp/devices.json` invoked by the
# MCP client. Once v0.2's streamable-http transport lands, this unit becomes
# the canonical way to run the server.

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Write the post-extract installer**

Create `packaging/lxc/install.sh`:

```bash
#!/usr/bin/env bash
# Post-extract installer for rust-junosmcp tarball deployment.
# Run inside the target LXC after `tar xzf` extracts files to /.
set -euo pipefail

# Create service user if missing.
if ! id -u jmcp >/dev/null 2>&1; then
    useradd --system --create-home --home-dir /var/lib/jmcp \
            --shell /usr/sbin/nologin jmcp
fi

mkdir -p /etc/jmcp /var/lib/jmcp
chown -R jmcp:jmcp /var/lib/jmcp
chmod 755 /usr/local/bin/rust-junosmcp

# Only install example if no real devices.json yet.
if [[ ! -f /etc/jmcp/devices.json ]]; then
    cp -n /etc/jmcp/devices.json.example /etc/jmcp/devices.json || true
    chmod 600 /etc/jmcp/devices.json
    chown jmcp:jmcp /etc/jmcp/devices.json
    echo ">> Edit /etc/jmcp/devices.json with your real devices, then:"
    echo ">>   systemctl daemon-reload && systemctl enable --now rust-junosmcp"
fi

systemctl daemon-reload || true
echo ">> rust-junosmcp installed. Service unit: rust-junosmcp.service"
```

- [ ] **Step 3: Write the packaging script**

Create `scripts/package-lxc.sh`:

```bash
#!/usr/bin/env bash
# Build a release tarball for LXC / Debian deployment.
# Output: dist/rust-junosmcp_<version>_amd64.tar.gz
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION=$(grep -E '^version' Cargo.toml | head -n1 | cut -d'"' -f2 || true)
if [[ -z "${VERSION:-}" ]]; then
    VERSION=$(grep -E '^version' rust-junosmcp/Cargo.toml | head -n1 | cut -d'"' -f2)
fi

echo ">> Building release binary..."
cargo build --release --bin rust-junosmcp

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

PKG="rust-junosmcp_${VERSION}_amd64"
PKGROOT="$STAGING/$PKG"

mkdir -p "$PKGROOT/usr/local/bin"
mkdir -p "$PKGROOT/etc/jmcp"
mkdir -p "$PKGROOT/etc/systemd/system"

cp target/release/rust-junosmcp                    "$PKGROOT/usr/local/bin/rust-junosmcp"
cp devices-template.json                           "$PKGROOT/etc/jmcp/devices.json.example"
cp packaging/systemd/rust-junosmcp.service         "$PKGROOT/etc/systemd/system/"
cp packaging/lxc/install.sh                        "$PKGROOT/install.sh"
chmod +x "$PKGROOT/install.sh"
chmod +x "$PKGROOT/usr/local/bin/rust-junosmcp"

mkdir -p dist
tar -czf "dist/$PKG.tar.gz" -C "$STAGING" "$PKG"
echo ">> Wrote dist/$PKG.tar.gz"
```

- [ ] **Step 4: Make scripts executable**

```bash
chmod +x scripts/package-lxc.sh packaging/lxc/install.sh
```

- [ ] **Step 5: Verify the tarball builds**

Run: `./scripts/package-lxc.sh`
Expected: `dist/rust-junosmcp_0.1.0_amd64.tar.gz` exists; `tar tzf dist/rust-junosmcp_0.1.0_amd64.tar.gz` shows binary, unit, install.sh, devices.json.example.

- [ ] **Step 6: Commit**

```bash
git add packaging/ scripts/package-lxc.sh
git commit -m "build: LXC tarball packaging with hardened systemd unit"
```

---

## Task 21: `devices-template.json` + README

**Files:**
- Create: `devices-template.json`
- Create: `README.md`

- [ ] **Step 1: Write `devices-template.json`** (1:1 with Python repo)

```json
{
    "r1": {
        "ip": "ip",
        "port": 22,
        "username": "user",
        "auth": {
            "type": "password",
            "password": "pwd"
        }
    },
    "r2": {
        "ip": "ip",
        "port": 22,
        "username": "user",
        "auth": {
            "type": "ssh_key",
            "private_key_path": "/path/to/private/key.pem"
        }
    },
    "r3": {
        "ip": "ip",
        "port": 22,
        "username": "user",
        "ssh_config": "~/.ssh/config_dc",
        "auth": {
            "type": "ssh_key",
            "private_key_path": "/path/to/private/key.pem"
        }
    },
    "r4": {
        "ip": "ip",
        "port": 22,
        "username": "user",
        "ssh_config": "/home/user/.ssh/config_jumphost",
        "auth": {
            "type": "password",
            "password": "pwd"
        }
    }
}
```

- [ ] **Step 2: Write `README.md`**

```markdown
# rust-junosmcp

A [Model Context Protocol](https://modelcontextprotocol.io/) server for Juniper Junos
devices, written in Rust. Drop-in compatible with [Juniper/junos-mcp-server](https://github.com/Juniper/junos-mcp-server)
on the inventory format and tool surface, but built on async Rust ([rustEZ](https://github.com/mechubsec/rustez) + [rustnetconf](https://github.com/mechubsec/rustnetconf))
instead of PyEZ.

## v0.1 scope

- 6 tools: `get_router_list`, `gather_device_facts`, `execute_junos_command`,
  `get_junos_config`, `junos_config_diff`, `load_and_commit_config`.
- stdio transport only.
- `devices.json` drop-in compatible (`auth.type` ∈ {`password`, `ssh_key`}).
- Docker image (distroless) and LXC release tarball with systemd unit.

**Coming in v0.2:** PFE commands, batch execution, Jinja2 templates,
streamable-http transport, bearer-token auth, blocklist guardrails,
`add_device` / `reload_devices` interactive tools.

## Security warning

This server lets an LLM run commands and push configuration changes against
your Junos devices. Read [Juniper/junos-mcp-server's security notice](https://github.com/Juniper/junos-mcp-server#important-security-notice)
before deploying. The same warnings apply.

- Prefer SSH key authentication over passwords.
- Review configurations before allowing commit tools to run.
- Restrict network access to the MCP server.
- Don't deploy to untrusted networks.

## Quick start (local)

```bash
# Clone alongside rustEZ (path dependency in v0.1).
git clone https://github.com/mechubsec/rustez.git
git clone https://github.com/mechubsec/rustjunosmcp.git
cd RustJunosMCP

# Build.
cargo build --release

# Configure devices.
cp devices-template.json devices.json
$EDITOR devices.json   # set ip / username / auth

# Run as MCP stdio server.
./target/release/rust-junosmcp -f devices.json
```

## Claude Desktop config

```json
{
  "mcpServers": {
    "junos": {
      "command": "/path/to/rust-junosmcp",
      "args": ["-f", "/path/to/devices.json"]
    }
  }
}
```

## Docker

```bash
# Build (must run from parent dir containing both RustJunosMCP and rustEZ).
docker build -f RustJunosMCP/Dockerfile -t rust-junosmcp:0.1 .

# Run.
docker run --rm -i \
  -v $PWD/devices.json:/etc/jmcp/devices.json:ro \
  -v $PWD/keys:/etc/jmcp/keys:ro \
  rust-junosmcp:0.1
```

## LXC (Proxmox)

```bash
# Build the tarball.
./scripts/package-lxc.sh

# Push and install on VM 115 (Debian 12 / Ubuntu 24.04 LXC).
pct push 115 dist/rust-junosmcp_0.1.0_amd64.tar.gz /tmp/jmcp.tar.gz
pct exec 115 -- bash -c "tar xzf /tmp/jmcp.tar.gz -C /tmp && /tmp/rust-junosmcp_0.1.0_amd64/install.sh"

# Edit /etc/jmcp/devices.json on the LXC, then:
pct exec 115 -- systemctl enable --now rust-junosmcp
```

> **v0.1 caveat on the systemd unit:** stdio doesn't suit a long-running
> daemon. The unit is shipped for forward-compat with v0.2's HTTP transport.
> For v0.1, the practical pattern is invoking the binary on demand from an
> MCP client running outside the LXC.

## CLI

```
rust-junosmcp 0.1.0
Junos MCP server (Rust)

Usage: rust-junosmcp [OPTIONS]

Options:
  -f, --device-mapping <DEVICE_MAPPING>  [default: devices.json]
  -t, --transport <TRANSPORT>            [default: stdio] [possible values: stdio, streamable-http]
  -H, --host <HOST>                      [default: 127.0.0.1]
  -p, --port <PORT>                      [default: 30030]
  -h, --help                             Print help
  -V, --version                          Print version
```

`--transport streamable-http` is parsed but rejected at runtime in v0.1.

## Testing against a real device

```bash
JMCP_TEST_HOST=10.0.0.1 \
JMCP_TEST_USER=admin \
JMCP_TEST_PASS=secret \
cargo test -p rust-junosmcp-core --test integration_real_device -- --ignored --nocapture
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
```

- [ ] **Step 3: Add license files**

Copy `LICENSE-MIT` and `LICENSE-APACHE` from `../rustEZ/` (same texts, same dual license):

```bash
cp ../rustEZ/LICENSE-MIT     LICENSE-MIT
cp ../rustEZ/LICENSE-APACHE  LICENSE-APACHE
```

- [ ] **Step 4: Commit**

```bash
git add devices-template.json README.md LICENSE-MIT LICENSE-APACHE
git commit -m "docs: README, license, and devices.json template"
```

---

## Task 22: Real-device integration tests

**Files:**
- Create: `rust-junosmcp-core/tests/integration_real_device.rs`

- [ ] **Step 1: Write the test file**

Create `rust-junosmcp-core/tests/integration_real_device.rs`:

```rust
//! Real-device integration tests. `#[ignore]`'d by default; run with:
//!
//! ```text
//! JMCP_TEST_HOST=10.0.0.1 JMCP_TEST_USER=admin JMCP_TEST_PASS=secret \
//!   cargo test -p rust-junosmcp-core --test integration_real_device -- --ignored
//! ```

use rust_junosmcp_core::{
    DeviceManager, Inventory,
    tools::{
        ConfigDiffArgs, ExecuteCommandArgs, GatherFactsArgs, GetConfigArgs,
        config_diff, execute_command, facts, get_config, router_list,
    },
};
use std::io::Write;
use std::sync::Arc;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing env var {name}"))
}

fn build_dm() -> Arc<DeviceManager> {
    let host = env("JMCP_TEST_HOST");
    let user = env("JMCP_TEST_USER");
    let pass = env("JMCP_TEST_PASS");
    let json = format!(r#"{{
        "lab":{{"ip":"{host}","username":"{user}",
                "auth":{{"type":"password","password":"{pass}"}}}}
    }}"#);
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(json.as_bytes()).unwrap();
    let inv = Arc::new(Inventory::load(f.path()).unwrap());
    Arc::new(DeviceManager::new(inv))
}

#[tokio::test]
#[ignore]
async fn router_list_returns_lab() {
    // Inventory was built above; we exercise the handler against it.
    let inv = {
        let host = env("JMCP_TEST_HOST");
        let user = env("JMCP_TEST_USER");
        let pass = env("JMCP_TEST_PASS");
        let json = format!(r#"{{
            "lab":{{"ip":"{host}","username":"{user}",
                    "auth":{{"type":"password","password":"{pass}"}}}}
        }}"#);
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    };
    let v = router_list::handle(inv).await.unwrap();
    assert_eq!(v, serde_json::json!(["lab"]));
}

#[tokio::test]
#[ignore]
async fn execute_show_version() {
    let dm = build_dm();
    let v = execute_command::handle(
        ExecuteCommandArgs {
            router_name: "lab".into(),
            command: "show version".into(),
            timeout: 30,
        },
        dm,
    ).await.unwrap();
    assert!(v.as_str().unwrap().contains("Junos") || v.as_str().unwrap().contains("Hostname"));
}

#[tokio::test]
#[ignore]
async fn get_running_config() {
    let dm = build_dm();
    let v = get_config::handle(
        GetConfigArgs { router_name: "lab".into() },
        dm,
    ).await.unwrap();
    let body = v.as_str().unwrap();
    assert!(!body.is_empty());
    assert!(body.contains("system") || body.contains("version"));
}

#[tokio::test]
#[ignore]
async fn diff_against_rollback_1() {
    let dm = build_dm();
    let v = config_diff::handle(
        ConfigDiffArgs { router_name: "lab".into(), version: 1 },
        dm,
    ).await.unwrap();
    assert!(v.is_string());
}

#[tokio::test]
#[ignore]
async fn gather_facts() {
    let dm = build_dm();
    let v = facts::handle(
        GatherFactsArgs { router_name: "lab".into(), timeout: 30 },
        dm,
    ).await.unwrap();
    assert!(v.get("hostname").is_some());
    assert!(v.get("version").is_some());
}
```

- [ ] **Step 2: Verify it compiles even without env vars**

Run: `cargo test -p rust-junosmcp-core --test integration_real_device --no-run`
Expected: builds. (Tests are `#[ignore]`'d so no env vars needed for compilation.)

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/tests/integration_real_device.rs
git commit -m "test: real-device integration tests (ignored, env-gated)"
```

---

## Task 23: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -D warnings

jobs:
  build-and-test:
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout RustJunosMCP
        uses: actions/checkout@v4
        with:
          path: RustJunosMCP

      - name: Checkout rustEZ (path dep)
        uses: actions/checkout@v4
        with:
          repository: mechubsec/rustez
          path: rustEZ

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt

      - name: Cache cargo
        uses: Swatinem/rust-cache@v2
        with:
          workspaces: RustJunosMCP

      - name: Format check
        working-directory: RustJunosMCP
        run: cargo fmt --all -- --check

      - name: Clippy
        working-directory: RustJunosMCP
        run: cargo clippy --workspace --all-targets -- -D warnings

      - name: Build
        working-directory: RustJunosMCP
        run: cargo build --workspace

      - name: Unit + smoke tests
        working-directory: RustJunosMCP
        run: cargo test --workspace

  audit:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          path: RustJunosMCP
      - uses: actions/checkout@v4
        with:
          repository: mechubsec/rustez
          path: rustEZ
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install cargo-audit --locked
      - working-directory: RustJunosMCP
        run: cargo audit
```

- [ ] **Step 2: Validate the YAML**

Run (locally if `actionlint` available, otherwise skip): `actionlint .github/workflows/ci.yml`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: GitHub Actions workflow for build, test, clippy, audit"
```

---

## Self-review checklist

After completing all tasks, verify against the spec:

- [ ] §5 Workspace layout — Tasks 0, 8 (the directory tree matches)
- [ ] §6 Inventory format — Tasks 2, 3, 4, 5
- [ ] §7 DeviceManager open-per-call + ssh_config rejection — Task 6
- [ ] §8 6 tools with exact names + schemas — Tasks 9–14
- [ ] §9 rmcp wiring + CLI — Tasks 15, 16, 17
- [ ] §10 JmcpError variants — Task 1
- [ ] §11 Unit + integration + smoke testing — Tasks 1–14, 18, 22
- [ ] §12 Security (cargo audit, clippy, distroless) — Tasks 19, 23
- [ ] §13 Docker + LXC artifacts — Tasks 19, 20
- [ ] §13.3 CI — Task 23
- [ ] §14 Followups — captured in this plan's "Followups identified during planning"

If any spec requirement isn't covered, add a task before handing off to execution.
