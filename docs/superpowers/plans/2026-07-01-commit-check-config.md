# commit_check_config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dedicated `commit_check_config` MCP tool that validates a Junos candidate configuration (`commit check`) without ever committing it.

**Architecture:** A new core handler `commit_check::handle` mirrors `load_commit::handle` but replaces the commit step with rustez `Config::commit_check()` followed by `rollback(0)` to discard the candidate. A thin `#[tool]` adapter in `server.rs` wires it with the same tool/router scope checks. The tool is registered in both `SERVER_TOOLS` and `KNOWN_TOOLS` (least-privilege scope), bumping the surface from 15 to 16.

**Tech Stack:** Rust, rmcp 0.8.5, rustez 0.12.0 (`Config::commit_check`), tokio, serde/schemars.

## Global Constraints

- rustez pinned at `0.12.0` — `Config::commit_check()` already exists; **no dependency change**.
- Tool surface goes 15 → 16. `SERVER_TOOLS` (rust-junosmcp/src/server.rs) and `KNOWN_TOOLS` (rust-junosmcp-auth/src/file.rs) MUST stay set-equal — enforced by `server_tools_matches_known_tools_as_set` (RJMCP-SEC-001).
- Response shape: `{success, diff, error?}` with `checked_only: true` added on success. Single `error` string (not `errors[]`), matching `load_and_commit_config`.
- The tool NEVER commits. No `commit_comment`, no `confirm_timeout_mins`.
- Keep the existing blocklist policy gate (`policy.check_config`) on the validate path.
- `cargo fmt` before every commit (CI runs `cargo fmt -- --check`).
- New tool name string (used verbatim everywhere): `commit_check_config`.

---

### Task 1: Core handler + args (`commit_check::handle`, `CommitCheckArgs`)

**Files:**
- Create: `rust-junosmcp-core/src/tools/commit_check.rs`
- Modify: `rust-junosmcp-core/src/tools/mod.rs` (add `pub mod commit_check;`, add `CommitCheckArgs`, add arg tests)
- Test: unit tests inside `commit_check.rs` and in `mod.rs`

**Interfaces:**
- Consumes: `DeviceManager`, `Policy`, `JmcpError` (existing); helpers `validate_input_length`, `build_config_payload`, `excerpt`; `Decision`, `Policy::check_config`; rustez `Config::{lock, load, diff, commit_check, rollback, unlock}`.
- Produces: `pub async fn commit_check::handle(args: CommitCheckArgs, dm: Arc<DeviceManager>, policy: Arc<Policy>) -> Result<Value, JmcpError>` and `pub struct CommitCheckArgs { router_name: String, config_text: String, config_format: String, timeout: u64 }`.

- [ ] **Step 1: Add `CommitCheckArgs` to `mod.rs`**

In `rust-junosmcp-core/src/tools/mod.rs`, add the module declaration alongside the others (keep alphabetical-ish grouping — place after `pub mod config_diff;`):

```rust
pub mod commit_check;
```

Add the args struct after the `LoadCommitArgs` struct (around line 113):

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CommitCheckArgs {
    pub router_name: String,
    /// The configuration text to validate.
    pub config_text: String,
    /// Format: set, text, or xml.
    #[serde(default = "default_set_format")]
    pub config_format: String,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}
```

- [ ] **Step 2: Add the failing args tests to `mod.rs`**

In the `#[cfg(test)] mod tests` block of `mod.rs`, add:

```rust
#[test]
fn commit_check_defaults_format_and_timeout() {
    let v = serde_json::json!({"router_name":"r1","config_text":"set x"});
    let a: CommitCheckArgs = serde_json::from_value(v).unwrap();
    assert_eq!(a.config_format, "set");
    assert_eq!(a.timeout, 360);
}

#[test]
fn commit_check_rejects_missing_config_text() {
    let v = serde_json::json!({"router_name":"r1"});
    let r: Result<CommitCheckArgs, _> = serde_json::from_value(v);
    assert!(r.is_err());
}
```

- [ ] **Step 3: Write `commit_check.rs` with the four short-circuit tests (failing)**

Create `rust-junosmcp-core/src/tools/commit_check.rs`. Start with the handler and tests. The handler body is written in full here (it compiles and the short-circuit tests pass without a live device):

```rust
//! `commit_check_config` — lock candidate, load, diff, run commit-check
//! (validate only), roll back the candidate, unlock. NEVER commits.
//! Returns `{success, diff, error?}` (+ `checked_only: true` on success).

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::{build_config_payload, excerpt, validate_input_length};
use crate::policy::{Decision, Policy};
use crate::tools::CommitCheckArgs;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

pub async fn handle(
    args: CommitCheckArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
) -> Result<Value, JmcpError> {
    validate_input_length("config_text", &args.config_text)?;
    // Confirm the router exists before consulting the policy.
    let _ = dm.inventory().get(&args.router_name)?;

    // Same blocklist gate as load_and_commit_config: a denied pattern stays
    // denied even for validate-only (defense-in-depth).
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
                tool = "commit_check_config",
                router = %args.router_name,
                matched_rule = %pattern,
                rule_source = %source_str,
                line_number = ?line_number,
                input_excerpt = %denied_excerpt,
                "blocklist denied request",
            );
            return Err(JmcpError::Denied {
                tool: "commit_check_config",
                router: args.router_name.clone(),
                pattern,
                rule_source: source_str,
                input_excerpt: denied_excerpt,
                line_number,
            });
        }
    }

    let payload = build_config_payload(args.config_text, Some(&args.config_format))?;
    let timeout_dur = Duration::from_secs(args.timeout);

    let result = tokio::time::timeout(timeout_dur, async {
        let mut dev = dm.open(&args.router_name).await?;
        let mut cfg = dev.config()?;

        cfg.lock().await?;
        if let Err(e) = cfg.load(payload).await {
            let _ = cfg.unlock().await;
            return Err(JmcpError::from(e));
        }
        let diff = cfg.diff().await?.unwrap_or_default();

        let check_result = cfg.commit_check().await;

        // Always discard the candidate — nothing must persist in the private DB.
        let _ = cfg.rollback(0).await;
        let _ = cfg.unlock().await;

        let result = match check_result {
            Ok(_) => json!({ "success": true, "diff": diff, "checked_only": true }),
            Err(e) => json!({ "success": false, "diff": diff, "error": e.to_string() }),
        };
        Ok::<_, JmcpError>(result)
    })
    .await
    .map_err(|_| JmcpError::Timeout(timeout_dur))??;

    Ok(result)
}

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
            CommitCheckArgs {
                router_name: "nope".into(),
                config_text: "set system foo".into(),
                config_format: "set".into(),
                timeout: 5,
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
            CommitCheckArgs {
                router_name: "r1".into(),
                config_text: "x".into(),
                config_format: "yaml".into(),
                timeout: 5,
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
            CommitCheckArgs {
                router_name: "r1".into(),
                config_text: "<x/>".into(),
                config_format: "xml".into(),
                timeout: 5,
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
            CommitCheckArgs {
                router_name: "r1".into(),
                config_text: "set foo\ndelete protocols bgp".into(),
                config_format: "set".into(),
                timeout: 5,
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
                assert_eq!(tool, "commit_check_config");
                assert_eq!(line_number, Some(2));
                assert_eq!(pattern, "delete *");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }
}
```

- [ ] **Step 4: Run to verify tests fail first, then pass**

First confirm the tests were red before the handler existed is moot (handler written in same step), so just build + test:

Run: `cargo test -p rust-junosmcp-core commit_check`
Expected: the 4 handler tests + 2 args tests PASS (6 passed). If `JmcpError::Denied` field names differ, fix to match `error.rs`.

- [ ] **Step 5: fmt + full core test + commit**

Run: `cargo fmt && cargo test -p rust-junosmcp-core`
Expected: all core tests PASS.

```bash
git add rust-junosmcp-core/src/tools/commit_check.rs rust-junosmcp-core/src/tools/mod.rs
git commit -m "feat(core): add commit_check handler + CommitCheckArgs (#95)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_019mPwHV2n6YmBTd5j8HcAAJ"
```

---

### Task 2: Register scope in auth `KNOWN_TOOLS`

**Files:**
- Modify: `rust-junosmcp-auth/src/file.rs:9-25` (`KNOWN_TOOLS` array)
- Test: existing auth-crate KNOWN_TOOLS tests

**Interfaces:**
- Consumes: nothing new.
- Produces: `"commit_check_config"` present in `KNOWN_TOOLS` (kept alphabetical).

- [ ] **Step 1: Add the tool to `KNOWN_TOOLS`**

In `rust-junosmcp-auth/src/file.rs`, insert into the alphabetical list (between `add_device` and `execute_junos_command`):

```rust
pub const KNOWN_TOOLS: &[&str] = &[
    "add_device",
    "commit_check_config",
    "execute_junos_command",
    "execute_junos_command_batch",
    "execute_junos_pfe_command",
    "fetch_file",
    "gather_device_facts",
    "get_junos_config",
    "get_router_list",
    "junos_config_diff",
    "list_staged_files",
    "load_and_commit_config",
    "reload_devices",
    "render_and_apply_j2_template",
    "transfer_file",
    "upgrade_junos",
];
```

- [ ] **Step 2: Build the auth crate**

Run: `cargo test -p rust-junosmcp-auth`
Expected: PASS (KNOWN_TOOLS tests still green; count-sensitive tests, if any, updated). If a test asserts a specific KNOWN_TOOLS length, bump it by 1.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-auth/src/file.rs
git commit -m "feat(auth): register commit_check_config in KNOWN_TOOLS (#95)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_019mPwHV2n6YmBTd5j8HcAAJ"
```

---

### Task 3: Tool adapter + `SERVER_TOOLS` + tripwire bump

**Files:**
- Modify: `rust-junosmcp/src/server.rs` — imports (lines 12-19), `SERVER_TOOLS` (221-237), tripwire test (248-250), new `#[tool]` method (after the `load_and_commit_config` adapter ~line 393)

**Interfaces:**
- Consumes: `commit_check::handle` and `CommitCheckArgs` from Task 1; `"commit_check_config"` scope from Task 2.
- Produces: MCP tool `commit_check_config`; `SERVER_TOOLS` set-equal to `KNOWN_TOOLS`.

- [ ] **Step 1: Bump the tripwire test to fail first**

In `rust-junosmcp/src/server.rs`, rename and update the count test (this is the RED step — build will fail to compile only if names drift, but the assert will fail until `SERVER_TOOLS` gains the entry):

```rust
    #[test]
    fn server_tools_len_is_16() {
        assert_eq!(SERVER_TOOLS.len(), 16);
    }
```

Run: `cargo test -p rust-junosmcp server_tools`
Expected: `server_tools_len_is_16` FAILS (len is 15) and `server_tools_matches_known_tools_as_set` FAILS (only-in-known=commit_check_config).

- [ ] **Step 2: Add imports**

Update the `use rust_junosmcp_core::tools::{...}` block: add `commit_check` to the module list and `CommitCheckArgs` to the type list:

```rust
    tools::{
        add_device, batch, commit_check, config_diff, execute_command, facts, fetch_file,
        get_config, list_staged_files, load_commit, pfe, reload_devices, router_list, template,
        transfer_file, upgrade_junos, AddDeviceArgs, CommitCheckArgs, ConfigDiffArgs,
        ExecuteBatchArgs, ExecuteCommandArgs, ExecutePfeArgs, FetchFileArgs, GatherFactsArgs,
        GetConfigArgs, ListStagedFilesArgs, LoadCommitArgs, ReloadDevicesArgs, TemplateArgs,
        TransferFileArgs, UpgradeJunosArgs,
    },
```

- [ ] **Step 3: Add the tool to `SERVER_TOOLS`**

Insert `"commit_check_config"` into the `SERVER_TOOLS` array (order is source-declaration order per the comment; place it right after `"load_and_commit_config"`):

```rust
    "load_and_commit_config",
    "commit_check_config",
    "execute_junos_pfe_command",
```

- [ ] **Step 4: Add the `#[tool]` adapter**

Immediately after the `load_and_commit_config` method (after its closing `}` ~line 393), add:

```rust
    #[tool(
        name = "commit_check_config",
        description = "Validate a candidate configuration on a Junos router without committing (commit check). Loads config into a private candidate, runs commit-check, returns {success, diff, error?}, then discards the candidate. Never activates config."
    )]
    async fn commit_check_config(
        &self,
        Parameters(args): Parameters<CommitCheckArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "commit_check_config") {
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "commit_check_config", &args.router_name) {
            return Self::scope_to_call_result(e);
        }
        Self::to_call_result(
            commit_check::handle(args, self.dm.clone(), self.policy.load_full()).await,
        )
    }
```

- [ ] **Step 5: fmt + run the tripwire + full server tests**

Run: `cargo fmt && cargo test -p rust-junosmcp`
Expected: `server_tools_len_is_16` PASS, `server_tools_matches_known_tools_as_set` PASS, all others PASS.

- [ ] **Step 6: Commit**

```bash
git add rust-junosmcp/src/server.rs
git commit -m "feat(server): expose commit_check_config MCP tool (#95)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_019mPwHV2n6YmBTd5j8HcAAJ"
```

---

### Task 4: Workspace build + docs

**Files:**
- Modify: `README.md` (tool list / count), `CHANGELOG.md` (new entry)

**Interfaces:**
- Consumes: everything from Tasks 1-3.
- Produces: user-facing documentation of the 16th tool.

- [ ] **Step 1: Full workspace build + test**

Run: `cargo fmt -- --check && cargo build --workspace && cargo test --workspace`
Expected: clean fmt, build OK, all tests PASS.

- [ ] **Step 2: Update README**

In `README.md`, find the tool list (search for `load_and_commit_config`) and add a bullet for `commit_check_config` next to it, described as: "Validate a candidate config (commit check) without committing — loads, diffs, checks, discards." Update any "N tools" count from 15 to 16.

- [ ] **Step 3: Update CHANGELOG**

Add an `Unreleased` (or next-version) entry:

```markdown
### Added
- `commit_check_config` MCP tool (#95): non-destructive `commit check` —
  loads a candidate, returns `{success, diff, error?}`, then discards it.
  Never activates config. Own token scope (least-privilege). Tool surface 15 → 16.
```

- [ ] **Step 4: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: document commit_check_config tool (#95)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_019mPwHV2n6YmBTd5j8HcAAJ"
```

---

### Task 5: Live smoke test (post-deploy, LXC 601)

**Files:** none (operational verification).

**Interfaces:**
- Consumes: deployed binary on LXC 601 with `commit_check_config` in the token scope.

- [ ] **Step 1: Deploy**

Build release, stop the systemd unit, `pct push` the binary, restart, `--version` check. (Follow the standard deploy recipe from memory `rust_junosmcp_container_601.md`; stop the unit before push to avoid `text file busy`.)

- [ ] **Step 2: Valid-change smoke**

Call `commit_check_config` against a vSRX (e.g. `vSRX-test10`) with a benign valid `set` change (e.g. `set system host-name test-cc`).
Expected: `{success: true, diff: "<non-empty>", checked_only: true}`.

- [ ] **Step 3: Confirm no activation**

Run `get_junos_config` / `execute_junos_command "show configuration system host-name"`.
Expected: host-name UNCHANGED — the candidate was discarded.

- [ ] **Step 4: Invalid-reference smoke**

Call `commit_check_config` with a change referencing a non-existent object (e.g. `set security policies from-zone trust to-zone untrust policy p1 then permit application-services advanced-anti-malware-policy nonexistent_profile`).
Expected: `{success: false, diff: "...", error: "<reference/constraint error text>"}`.

- [ ] **Step 5: Confirm candidate cleared after failure**

Run `execute_junos_command "show system commit"` or attempt a fresh lock.
Expected: no lingering locked/loaded candidate; the failed check left nothing behind.

---

## Self-Review

**Spec coverage:**
- Dedicated tool (not flag) → Task 3. ✔
- rustez `commit_check()` + `rollback(0)` discard → Task 1 handler. ✔
- `{success, diff, error?}` + `checked_only` → Task 1. ✔
- Blocklist policy kept → Task 1 Step 3. ✔
- Scope in SERVER_TOOLS + KNOWN_TOOLS + tripwire bump to 16 → Tasks 2 & 3. ✔
- Unit tests (unknown router, bad format, format-with-rules, denied) + args tests → Task 1. ✔
- Live smoke (valid pass, no activation, invalid fail) → Task 5. ✔
- Docs (README/CHANGELOG) → Task 4. ✔

**Placeholder scan:** No TBD/TODO; all code blocks complete. ✔

**Type consistency:** `commit_check::handle(CommitCheckArgs, Arc<DeviceManager>, Arc<Policy>) -> Result<Value, JmcpError>` used identically in Task 1 (def) and Task 3 (call). `CommitCheckArgs` fields identical across mod.rs, handler tests, and server adapter. Tool-name string `commit_check_config` identical in handler `tracing`/`Denied`, KNOWN_TOOLS, SERVER_TOOLS, and adapter. ✔

**Risk note for implementer:** In Task 1 Step 4, if `JmcpError::Denied` field names/shape differ from what `load_commit.rs` uses, copy the exact construction from `rust-junosmcp-core/src/tools/load_commit.rs` (it is the canonical reference for every short-circuit path in this handler).
