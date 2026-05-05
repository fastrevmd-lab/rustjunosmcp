# Blocklist Guardrails Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-device deny/allow rule filtering on `execute_junos_command` and `load_and_commit_config` inputs, configured in `devices.json` with top-level defaults plus per-device overrides.

**Architecture:** A new pure `policy` module in `rust-junosmcp-core` compiles glob rules at startup and evaluates each tool call before any device interaction. Most-specific match wins; device-level rules tiebreak top-level defaults. Inventory parsing is extended via a flatten-wrapper struct so v0.1 files keep loading unchanged.

**Tech Stack:** Rust 2021, `globset` 0.4, `serde`, `thiserror`, `tracing`, existing rustez/rmcp wiring.

**Spec:** `docs/superpowers/specs/2026-05-04-blocklist-guardrails-design.md`

---

## File map

**Create:**
- `rust-junosmcp-core/src/policy.rs` — `Policy`, `CompiledRule`, `Decision`, `RuleSource`, `compile_rules`, specificity scoring.

**Modify:**
- `rust-junosmcp-core/Cargo.toml` — add `globset` dep.
- `rust-junosmcp-core/src/lib.rs` — register `policy` module and re-exports.
- `rust-junosmcp-core/src/error.rs` — three new `JmcpError` variants.
- `rust-junosmcp-core/src/inventory.rs` — `Action`, `RuleSpec`, `BlocklistRules`, `InventoryFile` wrapper, `_blocklist_defaults` accessor, per-device `blocklist` field.
- `rust-junosmcp-core/src/tools/execute_command.rs` — add `policy: &Policy` parameter, check before connect.
- `rust-junosmcp-core/src/tools/load_commit.rs` — add `policy: &Policy` parameter, check before connect.
- `rust-junosmcp/src/server.rs` — `JmcpHandler` carries `Arc<Policy>`, threads it to the two affected tool methods.
- `rust-junosmcp/src/main.rs` — build `Policy` after `Inventory`, log startup summary.
- `rust-junosmcp/tests/stdio_smoke.rs` — add a second test that drives a denied call.
- `README.md` — short blocklist section + Juniper-compat footnote.
- `devices-template.json` — add `_blocklist_defaults` and an example per-device `blocklist`.

---

## Conventions

- Run all `cargo` invocations from the repo root with explicit `-p` to keep CI scoped (the `rustez` path-dep in `../rustEZ/rustez` shares a workspace).
- Build/test commands always:
  ```bash
  cargo build -p rust-junosmcp-core -p rust-junosmcp
  cargo test  -p rust-junosmcp-core -p rust-junosmcp
  ```
- One commit per task. Commit messages follow the existing repo style (`feat(core):`, `feat(bin):`, `test:`, `docs:`).

---

## Task 1: Add `globset` dependency and empty `policy` module

**Files:**
- Modify: `rust-junosmcp-core/Cargo.toml`
- Create: `rust-junosmcp-core/src/policy.rs`
- Modify: `rust-junosmcp-core/src/lib.rs`

- [ ] **Step 1: Add `globset` to core dependencies**

In `rust-junosmcp-core/Cargo.toml`, append to `[dependencies]`:

```toml
globset      = "0.4"
```

- [ ] **Step 2: Create `policy.rs` with a placeholder doc comment**

```rust
//! Pure rule-evaluation logic for the blocklist guardrails.
//!
//! `Policy` is built once at startup from the parsed [`Inventory`](crate::Inventory)
//! and is cheap to clone via `Arc`. Tool handlers consult it before any device
//! interaction.
```

- [ ] **Step 3: Register the module in `lib.rs`**

After line 10 of `rust-junosmcp-core/src/lib.rs`, add:

```rust
pub mod policy;
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo build -p rust-junosmcp-core`
Expected: build succeeds; `globset` is fetched and compiled.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/Cargo.toml rust-junosmcp-core/src/policy.rs rust-junosmcp-core/src/lib.rs
git commit -m "feat(core): add globset dep and empty policy module"
```

---

## Task 2: Add `JmcpError` variants for the policy layer

**Files:**
- Modify: `rust-junosmcp-core/src/error.rs`

- [ ] **Step 1: Write failing tests for the three new variants**

Append inside the existing `mod tests` block in `rust-junosmcp-core/src/error.rs`:

```rust
#[test]
fn denied_displays_tool_router_and_rule() {
    let e = JmcpError::Denied {
        tool: "execute_junos_command",
        router: "r1".into(),
        pattern: "request system *".into(),
        source: "defaults",
        input_excerpt: "request system reboot".into(),
        line_number: None,
    };
    let s = e.to_string();
    assert!(s.contains("execute_junos_command"));
    assert!(s.contains("r1"));
    assert!(s.contains("request system *"));
    assert!(s.contains("defaults"));
    assert!(s.contains("request system reboot"));
}

#[test]
fn config_format_not_allowed_with_rules_names_format() {
    let e = JmcpError::ConfigFormatNotAllowedWithRules {
        format: "xml".into(),
    };
    let s = e.to_string();
    assert!(s.contains("xml"));
    assert!(s.contains("set"));
}

#[test]
fn blocklist_rule_invalid_names_scope_and_pattern() {
    let glob_err = globset::Glob::new("[unterminated").unwrap_err();
    let e = JmcpError::BlocklistRuleInvalid {
        scope: "_blocklist_defaults.commands".into(),
        pattern: "[unterminated".into(),
        source: glob_err,
    };
    let s = e.to_string();
    assert!(s.contains("_blocklist_defaults.commands"));
    assert!(s.contains("[unterminated"));
}
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cargo test -p rust-junosmcp-core error::tests::denied_displays_tool_router_and_rule`
Expected: FAIL — variants don't exist yet.

- [ ] **Step 3: Add the variants**

In `rust-junosmcp-core/src/error.rs`, inside the `JmcpError` enum (after the existing `Json` variant), add:

```rust
    #[error("denied by blocklist: {tool} on '{router}' matched rule '{pattern}' \
             (action=deny, source={source}); input: {input_excerpt}")]
    Denied {
        tool: &'static str,
        router: String,
        pattern: String,
        source: &'static str,
        input_excerpt: String,
        line_number: Option<usize>,
    },

    #[error("config blocklist rules require config_format=set; got '{format}'")]
    ConfigFormatNotAllowedWithRules { format: String },

    #[error("invalid blocklist rule for {scope}: pattern '{pattern}': {source}")]
    BlocklistRuleInvalid {
        scope: String,
        pattern: String,
        #[source]
        source: globset::Error,
    },
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rust-junosmcp-core error::tests`
Expected: PASS (all error tests, old + new).

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/error.rs
git commit -m "feat(core): JmcpError variants for blocklist denial and rule errors"
```

---

## Task 3: Add inventory rule types (`Action`, `RuleSpec`, `BlocklistRules`)

**Files:**
- Modify: `rust-junosmcp-core/src/inventory.rs`

- [ ] **Step 1: Write failing tests for the parsing-layer types**

Append a new test module at the end of `rust-junosmcp-core/src/inventory.rs`:

```rust
#[cfg(test)]
mod rule_type_tests {
    use super::*;

    #[test]
    fn rule_spec_parses_deny() {
        let json = r#"{"action":"deny","pattern":"request system *"}"#;
        let r: RuleSpec = serde_json::from_str(json).unwrap();
        assert_eq!(r.pattern, "request system *");
        assert!(matches!(r.action, Action::Deny));
    }

    #[test]
    fn rule_spec_parses_allow() {
        let json = r#"{"action":"allow","pattern":"show *"}"#;
        let r: RuleSpec = serde_json::from_str(json).unwrap();
        assert!(matches!(r.action, Action::Allow));
    }

    #[test]
    fn rule_spec_rejects_unknown_action() {
        let json = r#"{"action":"audit","pattern":"x"}"#;
        let r: Result<RuleSpec, _> = serde_json::from_str(json);
        assert!(r.is_err());
    }

    #[test]
    fn blocklist_rules_default_to_empty_lists() {
        let json = r#"{}"#;
        let b: BlocklistRules = serde_json::from_str(json).unwrap();
        assert!(b.commands.is_empty());
        assert!(b.config.is_empty());
    }
}
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cargo test -p rust-junosmcp-core inventory::rule_type_tests`
Expected: FAIL — types don't exist.

- [ ] **Step 3: Define the types**

In `rust-junosmcp-core/src/inventory.rs`, after the existing `AuthConfig` block (around line 80), add:

```rust
/// `deny` blocks the tool call; `allow` overrides a broader deny.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Deny,
    Allow,
}

/// One author-side rule: an action and a glob pattern.
#[derive(Clone, Debug, Deserialize)]
pub struct RuleSpec {
    pub action: Action,
    pub pattern: String,
}

/// Per-domain rule lists (commands → execute_junos_command,
/// config → load_and_commit_config).
#[derive(Clone, Debug, Default, Deserialize)]
pub struct BlocklistRules {
    #[serde(default)]
    pub commands: Vec<RuleSpec>,
    #[serde(default)]
    pub config: Vec<RuleSpec>,
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rust-junosmcp-core inventory::rule_type_tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/inventory.rs
git commit -m "feat(core): Action/RuleSpec/BlocklistRules parsing types"
```

---

## Task 4: Wire `blocklist` field into `DeviceEntry` and `_blocklist_defaults` into the inventory file

**Files:**
- Modify: `rust-junosmcp-core/src/inventory.rs`

- [ ] **Step 1: Write failing tests**

Append to the existing `mod load_tests` block in `inventory.rs`:

```rust
#[test]
fn loads_inventory_with_blocklist_defaults_and_per_device_blocklist() {
    let f = write(
        "bl",
        r#"{
            "_blocklist_defaults": {
                "commands": [
                    {"action":"deny","pattern":"request system *"}
                ],
                "config": [
                    {"action":"deny","pattern":"delete *"}
                ]
            },
            "r1": {
                "ip":"1.2.3.4","username":"u",
                "auth":{"type":"password","password":"x"},
                "blocklist": {
                    "commands": [
                        {"action":"allow","pattern":"request system reboot"}
                    ]
                }
            }
        }"#,
    );
    let inv = Inventory::load(f.path()).unwrap();
    let defaults = inv.blocklist_defaults().expect("defaults present");
    assert_eq!(defaults.commands.len(), 1);
    assert_eq!(defaults.config.len(), 1);
    let r1 = inv.get("r1").unwrap();
    let r1_bl = r1.blocklist.as_ref().expect("r1 has blocklist");
    assert_eq!(r1_bl.commands.len(), 1);
    assert!(r1_bl.config.is_empty());
}

#[test]
fn v0_1_inventory_without_blocklist_loads_unchanged() {
    let f = write(
        "v01",
        r#"{
            "r1":{"ip":"1.2.3.4","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
    );
    let inv = Inventory::load(f.path()).unwrap();
    assert!(inv.blocklist_defaults().is_none());
    assert!(inv.get("r1").unwrap().blocklist.is_none());
}

#[test]
fn missing_blocklist_subkeys_default_to_empty() {
    let f = write(
        "empty",
        r#"{
            "_blocklist_defaults": {},
            "r1":{
                "ip":"1.2.3.4","username":"u",
                "auth":{"type":"password","password":"x"},
                "blocklist": {}
            }
        }"#,
    );
    let inv = Inventory::load(f.path()).unwrap();
    let d = inv.blocklist_defaults().unwrap();
    assert!(d.commands.is_empty() && d.config.is_empty());
    let r1bl = inv.get("r1").unwrap().blocklist.as_ref().unwrap();
    assert!(r1bl.commands.is_empty() && r1bl.config.is_empty());
}
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cargo test -p rust-junosmcp-core inventory::load_tests::loads_inventory_with_blocklist_defaults_and_per_device_blocklist`
Expected: FAIL — `blocklist_defaults` accessor doesn't exist; `blocklist` field doesn't exist on `DeviceEntry`.

- [ ] **Step 3: Add `blocklist` field to `DeviceEntry`**

In `inventory.rs`, modify the `DeviceEntry` struct (around line 88) to append after `ssh_config`:

```rust
    /// Optional per-device blocklist rules. Merged with `_blocklist_defaults`
    /// at policy build time. See [`BlocklistRules`].
    #[serde(default)]
    pub blocklist: Option<BlocklistRules>,
```

- [ ] **Step 4: Replace the load path with the `InventoryFile` wrapper**

Replace the `Inventory` struct, `Inventory::load`, and `Inventory::validate` in `inventory.rs` (currently around lines 147–191) with:

```rust
#[derive(Debug, Clone)]
pub struct Inventory {
    devices: HashMap<String, DeviceEntry>,
    blocklist_defaults: Option<BlocklistRules>,
    source_path: PathBuf,
}

#[derive(Deserialize)]
struct InventoryFile {
    #[serde(default, rename = "_blocklist_defaults")]
    blocklist_defaults: Option<BlocklistRules>,
    #[serde(flatten)]
    devices: HashMap<String, DeviceEntry>,
}

impl Inventory {
    /// Load and validate a `devices.json` file.
    pub fn load(path: &Path) -> Result<Self, JmcpError> {
        let bytes = std::fs::read(path)?;
        let file: InventoryFile = serde_json::from_slice(&bytes)
            .map_err(|e| JmcpError::InventoryInvalid(e.to_string()))?;
        Self::validate(&file.devices)?;
        Ok(Self {
            devices: file.devices,
            blocklist_defaults: file.blocklist_defaults,
            source_path: path.to_path_buf(),
        })
    }

    fn validate(devices: &HashMap<String, DeviceEntry>) -> Result<(), JmcpError> {
        for (name, entry) in devices {
            if entry.ip.trim().is_empty() {
                return Err(JmcpError::InventoryInvalid(format!(
                    "router '{name}': ip is empty"
                )));
            }
            if entry.port == 0 {
                return Err(JmcpError::InventoryInvalid(format!(
                    "router '{name}': port must be non-zero"
                )));
            }
            if entry.username.trim().is_empty() {
                return Err(JmcpError::InventoryInvalid(format!(
                    "router '{name}': username is empty"
                )));
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
```

- [ ] **Step 5: Add the `blocklist_defaults` accessor**

In the second `impl Inventory { ... }` block (around line 280), after `source_path`, add:

```rust
    /// Top-level blocklist defaults merged into every device's effective rule
    /// set. `None` if the file has no `_blocklist_defaults` key.
    pub fn blocklist_defaults(&self) -> Option<&BlocklistRules> {
        self.blocklist_defaults.as_ref()
    }
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p rust-junosmcp-core inventory`
Expected: PASS — both new and existing tests.

- [ ] **Step 7: Commit**

```bash
git add rust-junosmcp-core/src/inventory.rs
git commit -m "feat(core): _blocklist_defaults + per-device blocklist in inventory parsing"
```

---

## Task 5: `CompiledRule` with specificity score, plus `compile_rules`

**Files:**
- Modify: `rust-junosmcp-core/src/policy.rs`

- [ ] **Step 1: Write failing tests**

Replace the contents of `rust-junosmcp-core/src/policy.rs` with:

```rust
//! Pure rule-evaluation logic for the blocklist guardrails.
//!
//! `Policy` is built once at startup from the parsed [`Inventory`](crate::Inventory)
//! and is cheap to clone via `Arc`. Tool handlers consult it before any device
//! interaction.

use crate::error::JmcpError;
use crate::inventory::{Action, RuleSpec};
use globset::{Glob, GlobMatcher};

/// Origin of a rule, used for tiebreaking equal-specificity matches and for
/// the human-readable error message on denial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleSource {
    Defaults,
    Device,
}

impl RuleSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Defaults => "defaults",
            Self::Device => "device",
        }
    }
}

/// A glob rule with its compiled matcher and pre-computed specificity score.
#[derive(Debug)]
pub struct CompiledRule {
    pub pattern: String,
    pub action: Action,
    pub source: RuleSource,
    pub matcher: GlobMatcher,
    /// Higher = more specific. Tuple is `(literal_chars, total_len)`.
    pub specificity: (usize, usize),
}

/// Count non-wildcard, non-character-class literal characters in a glob pattern.
/// `*`, `?`, and `[...]` ranges are wildcards; everything else (including
/// escaped characters) counts.
pub(crate) fn count_literal_chars(pattern: &str) -> usize {
    let mut count = 0usize;
    let mut in_class = false;
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if in_class {
            if c == ']' {
                in_class = false;
            }
            continue;
        }
        match c {
            '*' | '?' => continue,
            '[' => {
                in_class = true;
                continue;
            }
            '\\' => {
                if chars.next().is_some() {
                    count += 1;
                }
            }
            _ => count += 1,
        }
    }
    count
}

/// Compile a list of `RuleSpec`s into `CompiledRule`s, attaching the given
/// `source` and a scope label used in compile-time error messages.
pub(crate) fn compile_rules(
    rules: &[RuleSpec],
    scope: &str,
    source: RuleSource,
) -> Result<Vec<CompiledRule>, JmcpError> {
    rules
        .iter()
        .map(|r| {
            let glob = Glob::new(&r.pattern).map_err(|e| JmcpError::BlocklistRuleInvalid {
                scope: scope.to_string(),
                pattern: r.pattern.clone(),
                source: e,
            })?;
            let literal_chars = count_literal_chars(&r.pattern);
            Ok(CompiledRule {
                pattern: r.pattern.clone(),
                action: r.action,
                source,
                matcher: glob.compile_matcher(),
                specificity: (literal_chars, r.pattern.len()),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(action: Action, pattern: &str) -> RuleSpec {
        RuleSpec {
            action,
            pattern: pattern.into(),
        }
    }

    #[test]
    fn count_literals_handles_wildcards_and_classes() {
        assert_eq!(count_literal_chars("request system reboot"), 21);
        assert_eq!(count_literal_chars("request system *"), 15);
        assert_eq!(count_literal_chars("*"), 0);
        assert_eq!(count_literal_chars("?abc"), 3);
        assert_eq!(count_literal_chars("ab[cd]ef"), 4); // class doesn't count
        assert_eq!(count_literal_chars(r"\*literal"), 8); // escaped * counts as literal
    }

    #[test]
    fn compile_rules_succeeds_on_valid_globs() {
        let r = vec![
            spec(Action::Deny, "request system *"),
            spec(Action::Allow, "show version"),
        ];
        let compiled = compile_rules(&r, "test", RuleSource::Defaults).unwrap();
        assert_eq!(compiled.len(), 2);
        assert_eq!(compiled[0].specificity, (15, 16));
        assert_eq!(compiled[0].source, RuleSource::Defaults);
    }

    #[test]
    fn compile_rules_errors_with_scope_on_bad_glob() {
        let r = vec![spec(Action::Deny, "[unterminated")];
        let err = compile_rules(&r, "_blocklist_defaults.commands", RuleSource::Defaults)
            .unwrap_err();
        match err {
            JmcpError::BlocklistRuleInvalid {
                scope, pattern, ..
            } => {
                assert_eq!(scope, "_blocklist_defaults.commands");
                assert_eq!(pattern, "[unterminated");
            }
            _ => panic!("expected BlocklistRuleInvalid, got {err:?}"),
        }
    }
}
```

- [ ] **Step 2: Run tests to confirm they pass (TDD step 2 collapses with step 4 here because compile_rules is also the implementation)**

Run: `cargo test -p rust-junosmcp-core policy::tests`
Expected: PASS.

- [ ] **Step 3: Verify the rest of the crate still compiles**

Run: `cargo build -p rust-junosmcp-core`
Expected: build succeeds.

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp-core/src/policy.rs
git commit -m "feat(core): compile glob rules with specificity score"
```

---

## Task 6: `Policy::build` — combine defaults + per-device rules

**Files:**
- Modify: `rust-junosmcp-core/src/policy.rs`

- [ ] **Step 1: Write failing tests**

Append inside `mod tests` in `policy.rs`:

```rust
    use crate::Inventory;
    use std::io::Write;

    fn inv_from(json: &str) -> Inventory {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Inventory::load(f.path()).unwrap()
    }

    #[test]
    fn build_handles_inventory_with_no_rules() {
        let inv = inv_from(
            r#"{"r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let p = Policy::build(&inv).unwrap();
        // r1 has no rules of either kind.
        assert!(p.command_rules_for("r1").is_empty());
        assert!(p.config_rules_for("r1").is_empty());
    }

    #[test]
    fn build_merges_defaults_and_device_rules() {
        let inv = inv_from(
            r#"{
                "_blocklist_defaults": {
                    "commands": [{"action":"deny","pattern":"request system *"}]
                },
                "r1":{
                    "ip":"1.1.1.1","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {
                        "commands": [{"action":"allow","pattern":"request system reboot"}]
                    }
                }
            }"#,
        );
        let p = Policy::build(&inv).unwrap();
        let r1_cmds = p.command_rules_for("r1");
        assert_eq!(r1_cmds.len(), 2);
        // One Defaults, one Device.
        assert!(r1_cmds.iter().any(|r| r.source == RuleSource::Defaults));
        assert!(r1_cmds.iter().any(|r| r.source == RuleSource::Device));
    }

    #[test]
    fn build_propagates_compile_error_with_device_scope() {
        let inv = inv_from(
            r#"{
                "r1":{
                    "ip":"1.1.1.1","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {
                        "commands": [{"action":"deny","pattern":"[bad"}]
                    }
                }
            }"#,
        );
        let err = Policy::build(&inv).unwrap_err();
        match err {
            JmcpError::BlocklistRuleInvalid { scope, .. } => {
                assert!(
                    scope.contains("r1"),
                    "scope should mention router name, got {scope}"
                );
                assert!(scope.contains("commands"));
            }
            _ => panic!("expected BlocklistRuleInvalid, got {err:?}"),
        }
    }
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cargo test -p rust-junosmcp-core policy::tests::build_handles_inventory_with_no_rules`
Expected: FAIL — `Policy` and methods don't exist.

- [ ] **Step 3: Implement `Policy` and `build`**

In `policy.rs`, add (above the `#[cfg(test)]` block):

```rust
use crate::inventory::BlocklistRules;
use std::collections::HashMap;

/// Compiled, per-device blocklist policy. Built once at startup from the
/// parsed inventory.
#[derive(Debug)]
pub struct Policy {
    /// Compiled defaults (commands, config) shared by every device.
    default_commands: Vec<CompiledRule>,
    default_config: Vec<CompiledRule>,
    /// Per-device additions to defaults.
    device_commands: HashMap<String, Vec<CompiledRule>>,
    device_config: HashMap<String, Vec<CompiledRule>>,
}

impl Policy {
    /// Compile every glob in the inventory. Returns the first compile error
    /// encountered, scoped to its source location.
    pub fn build(inv: &crate::Inventory) -> Result<Self, JmcpError> {
        let (default_commands, default_config) = match inv.blocklist_defaults() {
            Some(d) => (
                compile_rules(
                    &d.commands,
                    "_blocklist_defaults.commands",
                    RuleSource::Defaults,
                )?,
                compile_rules(
                    &d.config,
                    "_blocklist_defaults.config",
                    RuleSource::Defaults,
                )?,
            ),
            None => (Vec::new(), Vec::new()),
        };

        let mut device_commands = HashMap::new();
        let mut device_config = HashMap::new();
        for name in inv.names() {
            let entry = inv.get(&name)?;
            if let Some(bl) = entry.blocklist.as_ref() {
                let cmd_scope = format!("device '{name}'.blocklist.commands");
                let cfg_scope = format!("device '{name}'.blocklist.config");
                device_commands.insert(
                    name.clone(),
                    compile_rules(&bl.commands, &cmd_scope, RuleSource::Device)?,
                );
                device_config.insert(
                    name.clone(),
                    compile_rules(&bl.config, &cfg_scope, RuleSource::Device)?,
                );
            }
        }

        Ok(Self {
            default_commands,
            default_config,
            device_commands,
            device_config,
        })
    }

    /// Effective command rules for a device = defaults ⊕ device.
    pub fn command_rules_for(&self, router: &str) -> Vec<&CompiledRule> {
        self.default_commands
            .iter()
            .chain(
                self.device_commands
                    .get(router)
                    .into_iter()
                    .flat_map(|v| v.iter()),
            )
            .collect()
    }

    /// Effective config rules for a device = defaults ⊕ device.
    pub fn config_rules_for(&self, router: &str) -> Vec<&CompiledRule> {
        self.default_config
            .iter()
            .chain(
                self.device_config
                    .get(router)
                    .into_iter()
                    .flat_map(|v| v.iter()),
            )
            .collect()
    }

    /// Counts for the startup info log.
    pub fn rule_counts(&self) -> PolicyCounts {
        let devices_with_rules = self
            .device_commands
            .keys()
            .chain(self.device_config.keys())
            .collect::<std::collections::HashSet<_>>()
            .len();
        PolicyCounts {
            default_commands: self.default_commands.len(),
            default_config: self.default_config.len(),
            devices_with_rules,
        }
    }
}

/// Summary numbers for startup logging.
#[derive(Debug, Clone, Copy)]
pub struct PolicyCounts {
    pub default_commands: usize,
    pub default_config: usize,
    pub devices_with_rules: usize,
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rust-junosmcp-core policy::tests`
Expected: PASS.

- [ ] **Step 5: Re-export `Policy` from `lib.rs`**

In `rust-junosmcp-core/src/lib.rs`, after the existing `pub use` lines, add:

```rust
pub use policy::Policy;
```

- [ ] **Step 6: Verify the full crate builds**

Run: `cargo build -p rust-junosmcp-core`
Expected: success.

- [ ] **Step 7: Commit**

```bash
git add rust-junosmcp-core/src/policy.rs rust-junosmcp-core/src/lib.rs
git commit -m "feat(core): Policy::build merges defaults and per-device rules"
```

---

## Task 7: `Policy::check_command` — decision algorithm

**Files:**
- Modify: `rust-junosmcp-core/src/policy.rs`

- [ ] **Step 1: Write failing tests**

Append inside `mod tests` in `policy.rs`:

```rust
    use crate::policy::Decision;

    fn build_policy(json: &str) -> Policy {
        Policy::build(&inv_from(json)).unwrap()
    }

    #[test]
    fn no_rules_allows() {
        let p = build_policy(
            r#"{"r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        assert!(matches!(p.check_command("r1", "show version"), Decision::Allow));
    }

    #[test]
    fn equal_specificity_device_wins() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"commands":[{"action":"deny","pattern":"request system *"}]},
                "r1":{
                    "ip":"1.1.1.1","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {"commands":[{"action":"allow","pattern":"request system *"}]}
                }
            }"#,
        );
        assert!(matches!(p.check_command("r1", "request system reboot"), Decision::Allow));
    }

    #[test]
    fn more_specific_device_allow_overrides_broader_top_deny() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"commands":[{"action":"deny","pattern":"request system *"}]},
                "r1":{
                    "ip":"1.1.1.1","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {"commands":[{"action":"allow","pattern":"request system reboot"}]}
                }
            }"#,
        );
        assert!(matches!(p.check_command("r1", "request system reboot"), Decision::Allow));
        assert!(matches!(
            p.check_command("r1", "request system halt"),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn whitespace_is_normalized() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"commands":[{"action":"deny","pattern":"request system reboot"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        assert!(matches!(
            p.check_command("r1", "  request   system\treboot  "),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn deny_carries_matched_rule_metadata() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"commands":[{"action":"deny","pattern":"request system *"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        match p.check_command("r1", "request system reboot") {
            Decision::Deny { rule, source, line_number } => {
                assert_eq!(rule.pattern, "request system *");
                assert_eq!(source, RuleSource::Defaults);
                assert!(line_number.is_none());
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cargo test -p rust-junosmcp-core policy::tests::no_rules_allows`
Expected: FAIL — `Decision` and `check_command` don't exist.

- [ ] **Step 3: Implement `Decision` and `check_command`**

In `policy.rs`, above the `Policy` impl, add:

```rust
/// Outcome of a policy check.
#[derive(Debug)]
pub enum Decision<'a> {
    Allow,
    Deny {
        rule: &'a CompiledRule,
        source: RuleSource,
        /// Set only for config-domain checks; identifies the offending line
        /// (1-indexed, comment lines counted).
        line_number: Option<usize>,
    },
}

/// Trim and collapse runs of whitespace to a single space.
pub(crate) fn normalize_input(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_ws = false;
    for c in s.trim().chars() {
        if c.is_whitespace() {
            if !last_was_ws {
                out.push(' ');
                last_was_ws = true;
            }
        } else {
            out.push(c);
            last_was_ws = false;
        }
    }
    out
}

/// Pick the most-specific matching rule. Tiebreak: device > defaults.
fn evaluate<'a>(
    rules: &'a [&'a CompiledRule],
    candidate: &str,
) -> Option<&'a CompiledRule> {
    rules
        .iter()
        .filter(|r| r.matcher.is_match(candidate))
        .copied()
        .max_by(|a, b| {
            a.specificity
                .cmp(&b.specificity)
                .then_with(|| match (a.source, b.source) {
                    (RuleSource::Device, RuleSource::Defaults) => std::cmp::Ordering::Greater,
                    (RuleSource::Defaults, RuleSource::Device) => std::cmp::Ordering::Less,
                    _ => std::cmp::Ordering::Equal,
                })
        })
}
```

Then add the method on `Policy` (inside the existing `impl Policy { ... }` block):

```rust
    /// Decide whether `command` is allowed on `router`. Whitespace-normalized
    /// before matching.
    pub fn check_command<'a>(&'a self, router: &str, command: &str) -> Decision<'a> {
        let normalized = normalize_input(command);
        let rules = self.command_rules_for(router);
        match evaluate(&rules, &normalized) {
            Some(rule) if rule.action == Action::Deny => Decision::Deny {
                rule,
                source: rule.source,
                line_number: None,
            },
            _ => Decision::Allow,
        }
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rust-junosmcp-core policy::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/policy.rs
git commit -m "feat(core): Policy::check_command with most-specific match"
```

---

## Task 8: `Policy::check_config` — per-line eval, format gate

**Files:**
- Modify: `rust-junosmcp-core/src/policy.rs`

- [ ] **Step 1: Write failing tests**

Append inside `mod tests`:

```rust
    #[test]
    fn config_no_rules_allows_any_format() {
        let p = build_policy(
            r#"{"r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let r = p.check_config("r1", "xml", "<configuration/>").unwrap();
        assert!(matches!(r, Decision::Allow));
    }

    #[test]
    fn config_non_set_format_with_rules_present_errors() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let err = p.check_config("r1", "xml", "<x/>").unwrap_err();
        match err {
            JmcpError::ConfigFormatNotAllowedWithRules { format } => {
                assert_eq!(format, "xml");
            }
            other => panic!("expected ConfigFormatNotAllowedWithRules, got {other:?}"),
        }
    }

    #[test]
    fn config_per_line_match_rejects_first_offending_line() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let payload = "set interfaces ge-0/0/0 description ok\ndelete protocols bgp\nset system host-name r1";
        match p.check_config("r1", "set", payload).unwrap() {
            Decision::Deny { line_number, rule, .. } => {
                assert_eq!(line_number, Some(2));
                assert_eq!(rule.pattern, "delete *");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn config_comment_lines_are_skipped() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let payload = "# delete this is just a comment\nset system host-name r1";
        let r = p.check_config("r1", "set", payload).unwrap();
        assert!(matches!(r, Decision::Allow));
    }

    #[test]
    fn config_per_line_allow_carve_out_works() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{
                    "ip":"1.1.1.1","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {"config":[{"action":"allow","pattern":"delete interfaces ge-0/0/0"}]}
                }
            }"#,
        );
        let payload = "delete interfaces ge-0/0/0\nset interfaces ge-0/0/0 description new";
        let r = p.check_config("r1", "set", payload).unwrap();
        assert!(matches!(r, Decision::Allow));
    }
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cargo test -p rust-junosmcp-core policy::tests::config_no_rules_allows_any_format`
Expected: FAIL — `check_config` doesn't exist.

- [ ] **Step 3: Implement `check_config`**

Inside the `impl Policy { ... }` block, add:

```rust
    /// Decide whether `config_text` is allowed on `router` for the given
    /// `config_format`. Returns `Err` if `config_format != "set"` and the
    /// device has any effective config rules.
    pub fn check_config<'a>(
        &'a self,
        router: &str,
        config_format: &str,
        config_text: &str,
    ) -> Result<Decision<'a>, JmcpError> {
        let rules = self.config_rules_for(router);
        if rules.is_empty() {
            return Ok(Decision::Allow);
        }
        if config_format != "set" {
            return Err(JmcpError::ConfigFormatNotAllowedWithRules {
                format: config_format.to_string(),
            });
        }

        for (idx, raw_line) in config_text.lines().enumerate() {
            let line = normalize_input(raw_line);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rule) = evaluate(&rules, &line) {
                if rule.action == Action::Deny {
                    return Ok(Decision::Deny {
                        rule,
                        source: rule.source,
                        line_number: Some(idx + 1),
                    });
                }
            }
        }
        Ok(Decision::Allow)
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rust-junosmcp-core policy::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/policy.rs
git commit -m "feat(core): Policy::check_config with per-line eval and format gate"
```

---

## Task 9: Wire `Policy` into `execute_junos_command` handler

**Files:**
- Modify: `rust-junosmcp-core/src/tools/execute_command.rs`

- [ ] **Step 1: Write failing tests**

Replace the `#[cfg(test)] mod tests { ... }` block in `execute_command.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use crate::policy::{Decision, Policy};
    use std::io::Write;

    fn inv_with(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    #[tokio::test]
    async fn unknown_router_propagates_error() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            ExecuteCommandArgs {
                router_name: "nope".into(),
                command: "show version".into(),
                timeout: 5,
            },
            dm,
            pol,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn denied_command_short_circuits_before_connect() {
        // ip:port is intentionally unreachable; the test asserts we never
        // reach the connect path by looking at the error variant — connect
        // failure would be a Rustez/Timeout error, not Denied.
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"commands":[{"action":"deny","pattern":"request system *"}]},
                "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            ExecuteCommandArgs {
                router_name: "r1".into(),
                command: "request system reboot".into(),
                timeout: 1,
            },
            dm,
            pol,
        )
        .await;
        match r {
            Err(JmcpError::Denied { tool, router, pattern, .. }) => {
                assert_eq!(tool, "execute_junos_command");
                assert_eq!(router, "r1");
                assert_eq!(pattern, "request system *");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }
}
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cargo test -p rust-junosmcp-core tools::execute_command::tests`
Expected: FAIL — `handle` only takes two args today; `Decision` import unused.

- [ ] **Step 3: Update `handle` to accept and consult `Policy`**

Replace the body of `rust-junosmcp-core/src/tools/execute_command.rs` with:

```rust
//! `execute_junos_command` — run an operational CLI command on one router.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::policy::{Decision, Policy};
use crate::tools::ExecuteCommandArgs;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

/// Truncate `s` to at most 120 chars on a char boundary.
fn excerpt(s: &str) -> String {
    if s.len() <= 120 {
        return s.to_string();
    }
    let mut end = 120;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

pub async fn handle(
    args: ExecuteCommandArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
) -> Result<Value, JmcpError> {
    // Fail fast on unknown routers so the policy check has a valid target.
    let _ = dm.inventory().get(&args.router_name)?;

    if let Decision::Deny { rule, source, .. } =
        policy.check_command(&args.router_name, &args.command)
    {
        let pattern = rule.pattern.clone();
        let source_str = source.as_str();
        tracing::warn!(
            tool = "execute_junos_command",
            router = %args.router_name,
            matched_rule = %pattern,
            rule_source = %source_str,
            input_excerpt = %excerpt(&args.command),
            "blocklist denied request",
        );
        return Err(JmcpError::Denied {
            tool: "execute_junos_command",
            router: args.router_name.clone(),
            pattern,
            source: source_str,
            input_excerpt: excerpt(&args.command),
            line_number: None,
        });
    }

    let timeout = Duration::from_secs(args.timeout);
    let mut dev = dm.open(&args.router_name).await?;

    let result = tokio::time::timeout(timeout, dev.cli(&args.command))
        .await
        .map_err(|_| JmcpError::Timeout(timeout))?;

    let _ = dev.close().await;
    Ok(json!(result?))
}
```

The test relies on a new `DeviceManager::inventory()` accessor. Add this method to `rust-junosmcp-core/src/device_manager.rs`, inside the existing `impl DeviceManager { ... }` block (after the `open` method):

```rust
    /// Borrow the inventory used to resolve devices. Used by tool handlers
    /// that need to validate router names before running other checks.
    pub fn inventory(&self) -> &Inventory {
        &self.inventory
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rust-junosmcp-core tools::execute_command::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/execute_command.rs rust-junosmcp-core/src/device_manager.rs
git commit -m "feat(core): execute_junos_command consults blocklist policy"
```

---

## Task 10: Wire `Policy` into `load_and_commit_config` handler

**Files:**
- Modify: `rust-junosmcp-core/src/tools/load_commit.rs`

- [ ] **Step 1: Write failing tests**

Replace the existing `#[cfg(test)] mod tests` block in `load_commit.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use crate::policy::Policy;
    use std::io::Write;

    fn inv_with(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    #[tokio::test]
    async fn unknown_router_propagates_error() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            LoadCommitArgs {
                router_name: "nope".into(),
                config_text: "set system foo".into(),
                config_format: "set".into(),
                commit_comment: "test".into(),
            },
            dm,
            pol,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn invalid_format_rejected_before_connect() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            LoadCommitArgs {
                router_name: "r1".into(),
                config_text: "x".into(),
                config_format: "yaml".into(),
                commit_comment: "test".into(),
            },
            dm,
            pol,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadFormat(ref s)) if s == "yaml"));
    }

    #[tokio::test]
    async fn non_set_format_with_rules_present_returns_format_error() {
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            LoadCommitArgs {
                router_name: "r1".into(),
                config_text: "<x/>".into(),
                config_format: "xml".into(),
                commit_comment: "test".into(),
            },
            dm,
            pol,
        )
        .await;
        match r {
            Err(JmcpError::ConfigFormatNotAllowedWithRules { format }) => {
                assert_eq!(format, "xml");
            }
            other => panic!("expected ConfigFormatNotAllowedWithRules, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn denied_payload_short_circuits_before_connect() {
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            LoadCommitArgs {
                router_name: "r1".into(),
                config_text: "set foo\ndelete protocols bgp".into(),
                config_format: "set".into(),
                commit_comment: "test".into(),
            },
            dm,
            pol,
        )
        .await;
        match r {
            Err(JmcpError::Denied {
                tool,
                line_number,
                pattern,
                ..
            }) => {
                assert_eq!(tool, "load_and_commit_config");
                assert_eq!(line_number, Some(2));
                assert_eq!(pattern, "delete *");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }
}
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cargo test -p rust-junosmcp-core tools::load_commit::tests`
Expected: FAIL — `handle` signature only takes two args.

- [ ] **Step 3: Update `handle` to accept and consult `Policy`**

Replace the body of `rust-junosmcp-core/src/tools/load_commit.rs` (preserving the existing rustez logic) with:

```rust
//! `load_and_commit_config` — lock candidate, load, diff, commit (with comment),
//! unlock. Rollback on commit failure. Returns `{success, diff, error?}`.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::build_config_payload;
use crate::policy::{Decision, Policy};
use crate::tools::LoadCommitArgs;
use serde_json::{json, Value};
use std::sync::Arc;

fn excerpt(s: &str) -> String {
    if s.len() <= 120 {
        return s.to_string();
    }
    let mut end = 120;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

pub async fn handle(
    args: LoadCommitArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
) -> Result<Value, JmcpError> {
    // Confirm the router exists before consulting the policy.
    let _ = dm.inventory().get(&args.router_name)?;

    // The format gate is part of the policy check; downstream
    // build_config_payload still validates the value separately.
    match policy.check_config(&args.router_name, &args.config_format, &args.config_text)? {
        Decision::Allow => {}
        Decision::Deny {
            rule,
            source,
            line_number,
        } => {
            let pattern = rule.pattern.clone();
            let source_str = source.as_str();
            let denied_excerpt = excerpt(&args.config_text);
            tracing::warn!(
                tool = "load_and_commit_config",
                router = %args.router_name,
                matched_rule = %pattern,
                rule_source = %source_str,
                line_number = ?line_number,
                input_excerpt = %denied_excerpt,
                "blocklist denied request",
            );
            return Err(JmcpError::Denied {
                tool: "load_and_commit_config",
                router: args.router_name.clone(),
                pattern,
                source: source_str,
                input_excerpt: denied_excerpt,
                line_number,
            });
        }
    }

    let payload = build_config_payload(args.config_text, Some(&args.config_format))?;

    let mut dev = dm.open(&args.router_name).await?;
    let mut cfg = dev.config()?;

    cfg.lock().await?;
    if let Err(e) = cfg.load(payload).await {
        let _ = cfg.unlock().await;
        let _ = dev.close().await;
        return Err(JmcpError::from(e));
    }
    let diff = cfg.diff().await?.unwrap_or_default();

    let commit_result = cfg.commit_with_comment(&args.commit_comment).await;

    let result = match commit_result {
        Ok(_) => json!({ "success": true, "diff": diff }),
        Err(e) => {
            let _ = cfg.rollback(0).await;
            json!({ "success": false, "diff": diff, "error": e.to_string() })
        }
    };

    let _ = cfg.unlock().await;
    let _ = dev.close().await;
    Ok(result)
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rust-junosmcp-core tools::load_commit::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/load_commit.rs
git commit -m "feat(core): load_and_commit_config consults blocklist policy"
```

---

## Task 11: Thread `Arc<Policy>` through the rmcp `JmcpHandler`

**Files:**
- Modify: `rust-junosmcp/src/server.rs`

- [ ] **Step 1: Update `JmcpHandler` to carry the policy and pass it to the two affected tools**

Replace the relevant parts of `rust-junosmcp/src/server.rs`:

**Update imports** (lines 10–16): include `Policy`:

```rust
use rust_junosmcp_core::{
    tools::{
        config_diff, execute_command, facts, get_config, load_commit, router_list, ConfigDiffArgs,
        ExecuteCommandArgs, GatherFactsArgs, GetConfigArgs, LoadCommitArgs,
    },
    DeviceManager, Inventory, Policy,
};
```

**Update the struct** (lines 20–24):

```rust
#[derive(Clone)]
pub struct JmcpHandler {
    inv: Arc<Inventory>,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
}
```

**Update the constructor** (lines 26–29):

```rust
impl JmcpHandler {
    pub fn new(inv: Arc<Inventory>, dm: Arc<DeviceManager>, policy: Arc<Policy>) -> Self {
        Self { inv, dm, policy }
    }
```

**Update the two affected tool methods**:

- `execute_junos_command` body (line 76):

  ```rust
          Self::to_call_result(
              execute_command::handle(args, self.dm.clone(), self.policy.clone()).await,
          )
  ```

- `load_and_commit_config` body (line 109):

  ```rust
          Self::to_call_result(
              load_commit::handle(args, self.dm.clone(), self.policy.clone()).await,
          )
  ```

- [ ] **Step 2: Verify the binary still compiles** (this will fail at the `JmcpHandler::new` call site in `main.rs`; that's expected and fixed in the next task)

Run: `cargo build -p rust-junosmcp`
Expected: FAIL with "expected 3 arguments, found 2" at `main.rs:43`. This is the planned breakage; do not fix yet — the next task wires `main.rs`.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp/src/server.rs
git commit -m "feat(bin): JmcpHandler carries Arc<Policy>"
```

---

## Task 12: Build `Policy` in `main.rs` and log startup summary

**Files:**
- Modify: `rust-junosmcp/src/main.rs`

- [ ] **Step 1: Update imports and the wiring path**

Replace the body of `rust-junosmcp/src/main.rs` with:

```rust
mod cli;
mod server;

use anyhow::{bail, Context, Result};
use clap::Parser;
use cli::{Cli, Transport};
use rmcp::ServiceExt;
use rust_junosmcp_core::{DeviceManager, Inventory, Policy};
use server::JmcpHandler;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
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

    let policy = Arc::new(
        Policy::build(&inventory).context("compiling blocklist policy")?,
    );
    let counts = policy.rule_counts();
    tracing::info!(
        default_command_rules = counts.default_commands,
        default_config_rules = counts.default_config,
        devices_with_rules = counts.devices_with_rules,
        total_devices = inventory.names().len(),
        "blocklist policy loaded"
    );

    let dev_manager = Arc::new(DeviceManager::new(inventory.clone()));
    let handler = JmcpHandler::new(inventory, dev_manager, policy);

    let service = handler
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await
        .context("starting MCP stdio service")?;
    service
        .waiting()
        .await
        .context("MCP service exited with error")?;
    Ok(())
}
```

- [ ] **Step 2: Build everything**

Run: `cargo build -p rust-junosmcp-core -p rust-junosmcp`
Expected: success.

- [ ] **Step 3: Run the full test suite**

Run: `cargo test -p rust-junosmcp-core -p rust-junosmcp`
Expected: all tests pass (including the unmodified stdio smoke test).

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp/src/main.rs
git commit -m "feat(bin): build blocklist Policy at startup and log rule counts"
```

---

## Task 13: stdio smoke test — denied call returns an MCP tool error

**Files:**
- Modify: `rust-junosmcp/tests/stdio_smoke.rs`

- [ ] **Step 1: Add a second test that drives a denied execute_junos_command**

Append the following test function to `rust-junosmcp/tests/stdio_smoke.rs` (re-use the helpers from the existing test by hoisting them or duplicating; the version below duplicates only the `send` helper for clarity):

```rust
#[test]
fn denied_command_returns_tool_error() {
    let status = std::process::Command::new("cargo")
        .args(["build", "-p", "rust-junosmcp"])
        .status()
        .expect("cargo build");
    assert!(status.success(), "cargo build failed");

    // Inventory with a deny rule and one (unreachable) device. The deny
    // short-circuits before any connection attempt, so unreachability is fine.
    let inv = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        inv.path(),
        r#"{
            "_blocklist_defaults":{"commands":[{"action":"deny","pattern":"request system *"}]},
            "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
    )
    .unwrap();

    let mut child = Command::new(binary_path())
        .args(["-f", inv.path().to_str().unwrap(), "-t", "stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rust-junosmcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    fn send(stdin: &mut impl Write, msg: &Value) {
        let line = serde_json::to_string(msg).unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    send(
        &mut stdin,
        &json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{
                "protocolVersion":"2025-03-26","capabilities":{},
                "clientInfo":{"name":"smoke","version":"0.1"}
            }
        }),
    );
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    send(
        &mut stdin,
        &json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{
                "name":"execute_junos_command",
                "arguments":{
                    "router_name":"r1",
                    "command":"request system reboot",
                    "timeout":1
                }
            }
        }),
    );

    use std::io::{BufRead, BufReader};
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut response: Option<Value> = None;
    let mut reader = BufReader::new(&mut stdout);
    while Instant::now() < deadline && response.is_none() {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let v: Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("id") == Some(&json!(2)) {
            response = Some(v);
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    let resp = response.expect("did not receive tools/call response within 15s");
    // rmcp surfaces tool errors as a CallToolResult with `isError: true` and
    // text content; assert both shape and message content.
    let result = resp.pointer("/result").expect("missing /result");
    assert_eq!(result.get("isError"), Some(&json!(true)));
    let body = serde_json::to_string(result).unwrap();
    assert!(
        body.contains("denied by blocklist"),
        "expected denial message in: {body}"
    );
    assert!(
        body.contains("request system *"),
        "expected matched-rule pattern in: {body}"
    );
}
```

- [ ] **Step 2: Run the smoke tests**

Run: `cargo test -p rust-junosmcp --test stdio_smoke`
Expected: both tests pass (`lists_six_tools`, `denied_command_returns_tool_error`).

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp/tests/stdio_smoke.rs
git commit -m "test: stdio smoke verifies blocklist denial flows back as tool error"
```

---

## Task 14: README and `devices-template.json`

**Files:**
- Modify: `README.md`
- Modify: `devices-template.json`

- [ ] **Step 1: Update README**

In `README.md`, find the `## v0.1 scope` section. Below the "Coming in v0.2" paragraph, insert:

```markdown
## Blocklist guardrails (v0.2)

`devices.json` may carry an optional `_blocklist_defaults` block plus an
optional `blocklist` field on each device entry. Rules use simple globs
(`*`, `?`) and an `action` of `"deny"` or `"allow"`. Most-specific match
wins; per-device rules tiebreak top-level defaults. See
[`devices-template.json`](devices-template.json) for an example, and
[`docs/superpowers/specs/2026-05-04-blocklist-guardrails-design.md`](docs/superpowers/specs/2026-05-04-blocklist-guardrails-design.md)
for the full design.

The blocklist applies to `execute_junos_command` and `load_and_commit_config`.
For `load_and_commit_config`, `config_format` must be `set` whenever the
device has any effective config rules; `text` and `xml` payloads are
rejected pre-flight in that case.

> **Compat note:** files using `_blocklist_defaults` or per-device
> `blocklist` are not cross-compatible with Juniper/junos-mcp-server's
> inventory format. Files without these fields remain drop-in compatible.
```

- [ ] **Step 2: Update `devices-template.json`**

Replace `devices-template.json` with:

```json
{
    "_blocklist_defaults": {
        "commands": [
            {"action": "deny", "pattern": "request system *"},
            {"action": "deny", "pattern": "clear system commit"}
        ],
        "config": [
            {"action": "deny", "pattern": "delete *"}
        ]
    },
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
        },
        "blocklist": {
            "commands": [
                {"action": "allow", "pattern": "request system reboot"}
            ]
        }
    }
}
```

- [ ] **Step 3: Verify the template parses**

Run: `cargo test -p rust-junosmcp-core inventory::load_tests`
Expected: PASS (template isn't directly tested, but a malformed JSON in the file would break the existing pattern). Optionally:

```bash
cargo run -p rust-junosmcp -- -f devices-template.json -t stdio < /dev/null || true
```

Expected: process starts, logs `loaded inventory` and `blocklist policy loaded`, then exits when stdin closes.

- [ ] **Step 4: Commit**

```bash
git add README.md devices-template.json
git commit -m "docs: blocklist guardrails section + example in devices template"
```

---

## Final verification

- [ ] Run the full repo CI commands from the workspace root:
  ```bash
  cargo fmt --all -- --check
  cargo clippy -p rust-junosmcp-core -p rust-junosmcp -- -D warnings
  cargo test  -p rust-junosmcp-core -p rust-junosmcp
  ```
  Expected: all pass.

- [ ] Confirm git log shows 14 new commits since the spec commit:
  ```bash
  git log --oneline 3bcc44f..HEAD
  ```
  Expected: 14 entries (one per task).
