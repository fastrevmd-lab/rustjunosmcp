# Config-channel recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `discard_candidate` recovery tool (#107 remainder) and an actionable parse-error hint on `junos_config_diff` (#108).

**Architecture:** A new `discard_candidate` MCP tool that locks → `rollback(0)` → unlocks the candidate (modeled on `commit_check`), wired with its own token scope (surface 16→17). Separately, `config_diff` gains a pure `parse_error_hint` helper that enriches config-parse failures with guidance.

**Tech Stack:** Rust, rmcp, rustez (`Config::{lock, rollback, unlock}`), serde/schemars.

## Global Constraints

- New tool name (verbatim everywhere): `discard_candidate`. Tool surface **16 → 17**: `SERVER_TOOLS` (server.rs) and `KNOWN_TOOLS` (rust-junosmcp-auth/src/file.rs) MUST stay set-equal; bump the tripwire `server_tools_len_is_16` → `server_tools_len_is_17`.
- `discard_candidate` never changes the running config (candidate-only); no confirmation gate; own least-privilege scope.
- #108: enrich a config-diff error ONLY when its text matches a config-parse signature (`juniper.conf` or `parse error`, case-insensitive); other errors propagate unchanged; success path unchanged.
- `cargo fmt -- --check` + `cargo clippy` clean; `cargo test --workspace` 0 failures.

---

### Task 1: `discard_candidate` tool

**Files:**
- Create: `rust-junosmcp-core/src/tools/discard_candidate.rs`
- Modify: `rust-junosmcp-core/src/tools/mod.rs` (`pub mod discard_candidate;` + `DiscardCandidateArgs` + arg test)
- Modify: `rust-junosmcp/src/server.rs` (imports, `SERVER_TOOLS`, tripwire, adapter)
- Modify: `rust-junosmcp-auth/src/file.rs` (`KNOWN_TOOLS`)

**Interfaces:**
- Produces: `discard_candidate::handle(args: DiscardCandidateArgs, dm: Arc<DeviceManager>) -> Result<Value, JmcpError>`; `pub struct DiscardCandidateArgs { router_name: String, timeout: u64 }`.

- [ ] **Step 1: Add `DiscardCandidateArgs` + module decl in `mod.rs`**

In `rust-junosmcp-core/src/tools/mod.rs`, add `pub mod discard_candidate;` alongside the other `pub mod` lines. Add the struct (after `CommitCheckArgs`):

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DiscardCandidateArgs {
    /// The target router. Accepts `router` or `router_name`.
    #[serde(alias = "router")]
    pub router_name: String,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}
```

Add an arg-default test in the `mod tests` block:

```rust
#[test]
fn discard_candidate_defaults_timeout_and_router_alias() {
    let a: DiscardCandidateArgs = serde_json::from_value(serde_json::json!({"router":"r1"})).unwrap();
    assert_eq!(a.router_name, "r1");
    assert_eq!(a.timeout, 360);
}
```

- [ ] **Step 2: Create the handler + failing test**

Create `rust-junosmcp-core/src/tools/discard_candidate.rs`:

```rust
//! `discard_candidate` — discard uncommitted candidate config (rollback 0),
//! returning the candidate to the running config. Never changes the running
//! config. Recovers a candidate left dirty ("configuration database modified").

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::tools::DiscardCandidateArgs;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

pub async fn handle(args: DiscardCandidateArgs, dm: Arc<DeviceManager>) -> Result<Value, JmcpError> {
    // Confirm the router exists before connecting.
    let _ = dm.inventory().get(&args.router_name)?;
    let timeout_dur = Duration::from_secs(args.timeout);

    let result = tokio::time::timeout(timeout_dur, async {
        let mut dev = dm.open(&args.router_name).await?;
        let mut cfg = dev.config()?;
        cfg.lock().await?;
        // Discard any uncommitted candidate changes; always unlock afterward.
        let rolled_back = cfg.rollback(0).await;
        let _ = cfg.unlock().await;
        rolled_back?;
        Ok::<_, JmcpError>(json!({
            "success": true,
            "message": "candidate configuration discarded (rolled back to running)"
        }))
    })
    .await
    .map_err(|_| JmcpError::Timeout(timeout_dur))??;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
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
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            DiscardCandidateArgs { router_name: "nope".into(), timeout: 5 },
            dm,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }
}
```

- [ ] **Step 3: Run the handler + arg tests**

Run: `cargo test -p rust-junosmcp-core discard_candidate 2>&1 | tail -12`
Expected: `unknown_router_propagates_error` + `discard_candidate_defaults_timeout_and_router_alias` PASS (both short-circuit before any network I/O). The `cfg.rollback` path itself needs a live device (not unit-tested — same limitation as `commit_check`).

- [ ] **Step 4: Add to `KNOWN_TOOLS` (auth crate)**

In `rust-junosmcp-auth/src/file.rs`, insert `"discard_candidate"` into the alphabetical `KNOWN_TOOLS` array (between `"commit_check_config"` and `"execute_junos_command"`):

```rust
    "commit_check_config",
    "discard_candidate",
    "execute_junos_command",
```

- [ ] **Step 5: Wire the server adapter + `SERVER_TOOLS` + tripwire**

In `rust-junosmcp/src/server.rs`:

(a) Imports — add `discard_candidate` to the module list and `DiscardCandidateArgs` to the type list in the `use rust_junosmcp_core::tools::{…}` block (alphabetical: `discard_candidate` after `config_diff`; `DiscardCandidateArgs` after `ConfigDiffArgs`).

(b) `SERVER_TOOLS` — add `"discard_candidate"` (place it after `"commit_check_config"`).

(c) Tripwire — rename/bump:
```rust
    #[test]
    fn server_tools_len_is_17() {
        assert_eq!(SERVER_TOOLS.len(), 17);
    }
```

(d) Adapter — add after the `commit_check_config` method:
```rust
    #[tool(
        name = "discard_candidate",
        description = "Discard uncommitted candidate configuration changes on a Junos router (rollback 0), returning the candidate to the running config. Never changes the running config. Use to recover a candidate left dirty (e.g. 'configuration database modified')."
    )]
    async fn discard_candidate(
        &self,
        Parameters(args): Parameters<DiscardCandidateArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "discard_candidate") {
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "discard_candidate", &args.router_name) {
            return Self::scope_to_call_result(e);
        }
        Self::to_call_result(discard_candidate::handle(args, self.dm.clone()).await)
    }
```

- [ ] **Step 6: Build + server tripwire + full core**

Run: `cargo test -p rust-junosmcp server_tools 2>&1 | tail -8`
Expected: `server_tools_len_is_17` PASS, `server_tools_matches_known_tools_as_set` PASS.
Run: `cargo test -p rust-junosmcp-core discard_candidate 2>&1 | tail -6`
Expected: PASS.

- [ ] **Step 7: fmt + clippy + commit**

Run: `cargo fmt && cargo fmt -- --check && cargo clippy --workspace 2>&1 | tail -3`
```bash
git add rust-junosmcp-core/src/tools/discard_candidate.rs rust-junosmcp-core/src/tools/mod.rs rust-junosmcp/src/server.rs rust-junosmcp-auth/src/file.rs
git commit -m "feat: add discard_candidate recovery tool (#107)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_019mPwHV2n6YmBTd5j8HcAAJ"
```

---

### Task 2: `junos_config_diff` parse-error hint (#108)

**Files:**
- Modify: `rust-junosmcp-core/src/error.rs` (add `ConfigParseHint(String)` variant)
- Modify: `rust-junosmcp-core/src/tools/config_diff.rs` (`parse_error_hint` helper + wire + tests)

**Interfaces:**
- Produces: `fn parse_error_hint(err_text: &str) -> Option<String>` (private in config_diff.rs); `JmcpError::ConfigParseHint(String)`.

- [ ] **Step 1: Add the error variant**

In `rust-junosmcp-core/src/error.rs`, add a variant near the other string-carrying ones (e.g. after `Validation(String)`):

```rust
    /// A `junos_config_diff` failed because the on-box config won't parse for
    /// the current mode; message carries the raw error + an actionable hint.
    #[error("{0}")]
    ConfigParseHint(String),
```

(Match the existing `#[error(...)]`/thiserror style used by neighboring variants.)

- [ ] **Step 2: Write the failing helper tests**

In `rust-junosmcp-core/src/tools/config_diff.rs`, add to the `mod tests` block:

```rust
#[test]
fn parse_error_hint_matches_config_parse_failure() {
    let raw = "netconf error: RPC error: server error: [OperationFailed] \
               /config/juniper.conf:256:(12) fpc value outside range 0..3 for '7/0/0' in 'ge-7/0/0'";
    let hint = parse_error_hint(raw).expect("should produce a hint");
    assert!(hint.contains(raw), "hint must preserve the raw error");
    assert!(hint.to_ascii_lowercase().contains("failed to parse"), "hint must explain: {hint}");
    assert!(hint.contains("junos_config_diff"), "hint should tell the caller what to retry");
}

#[test]
fn parse_error_hint_matches_parse_error_phrase() {
    assert!(parse_error_hint("syntax error\nparse error at line 3").is_some());
}

#[test]
fn parse_error_hint_ignores_unrelated_errors() {
    assert!(parse_error_hint("connection refused").is_none());
    assert!(parse_error_hint("netconf error: timed out").is_none());
}
```

- [ ] **Step 3: Run — verify failure**

Run: `cargo test -p rust-junosmcp-core config_diff::tests::parse_error_hint 2>&1 | tail -10`
Expected: FAIL — `parse_error_hint` not defined.

- [ ] **Step 4: Implement the helper + wire it in**

In `rust-junosmcp-core/src/tools/config_diff.rs`, add the helper (above `handle`):

```rust
/// Return an enriched, actionable error message when a config-diff failure
/// looks like an on-box config-parse error (the committed config won't parse
/// for the device's current mode). Returns `None` for unrelated errors.
fn parse_error_hint(err_text: &str) -> Option<String> {
    let lower = err_text.to_ascii_lowercase();
    if lower.contains("juniper.conf") || lower.contains("parse error") {
        Some(format!(
            "{err_text} (the on-box configuration failed to parse for the current mode — \
             common right after a chassis-cluster enable/disable. Fix or load a valid \
             config on the device, then retry junos_config_diff.)"
        ))
    } else {
        None
    }
}
```

Change the `handle` body's compare call. Replace:
```rust
        let diff = dev.cli(&cmd).await?;
        Ok::<_, JmcpError>(diff)
```
with:
```rust
        match dev.cli(&cmd).await {
            Ok(diff) => Ok::<_, JmcpError>(diff),
            Err(e) => {
                let text = e.to_string();
                match parse_error_hint(&text) {
                    Some(hint) => Err(JmcpError::ConfigParseHint(hint)),
                    None => Err(JmcpError::from(e)),
                }
            }
        }
```

- [ ] **Step 5: Run — verify pass**

Run: `cargo test -p rust-junosmcp-core config_diff 2>&1 | tail -12`
Expected: the 3 new `parse_error_hint` tests PASS; the pre-existing `rejects_version_zero…` / `rejects_version_50…` tests still PASS.

- [ ] **Step 6: fmt + clippy + full workspace + commit**

Run: `cargo fmt && cargo fmt -- --check && cargo clippy --workspace 2>&1 | tail -3 && cargo test --workspace 2>&1 | grep -E "FAILED|error\[" || echo "workspace clean"`
Expected: clean; 0 failures.
```bash
git add rust-junosmcp-core/src/error.rs rust-junosmcp-core/src/tools/config_diff.rs
git commit -m "feat(core): junos_config_diff surfaces a hint on on-box config parse failure (#108)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_019mPwHV2n6YmBTd5j8HcAAJ"
```

---

## Self-Review

**Spec coverage:**
- `discard_candidate` handler (lock→rollback(0)→unlock) + args (`router` alias, timeout) → Task 1 Steps 1-2. ✔
- Scope wiring: SERVER_TOOLS + KNOWN_TOOLS + tripwire→17 + adapter → Task 1 Steps 4-5. ✔
- `config_diff` parse-error hint gated on `juniper.conf`/`parse error`; success + unrelated errors unchanged → Task 2 Steps 4. ✔
- Tests: discard short-circuit + arg default; parse_error_hint match/non-match; existing tests pass → Task 1 Step 3, Task 2 Steps 2/5. ✔
- No `load override`, no fake diff, no load_and_commit change → out of scope, not touched. ✔

**Placeholder scan:** No TBD/TODO; all code complete. The error-variant style ("match neighboring thiserror style") is concrete — `#[error("{0}")]` is shown.

**Type consistency:** `discard_candidate::handle(DiscardCandidateArgs, Arc<DeviceManager>) -> Result<Value, JmcpError>` used in Task 1 handler + server adapter. `DiscardCandidateArgs { router_name, timeout }` consistent across mod.rs, handler tests, adapter. `parse_error_hint(&str) -> Option<String>` + `JmcpError::ConfigParseHint(String)` consistent in Task 2. Tool name `discard_candidate` identical in handler/adapter/SERVER_TOOLS/KNOWN_TOOLS/tripwire.

**Risk note for implementer:** (1) `rollback(0)` requires the config DB; `cfg.lock()` may fail if another session holds the lock — that error propagates (the caller learns the DB is locked elsewhere), which is correct. (2) Keep the `discard_candidate` string identical in all 5 places or the `server_tools_matches_known_tools_as_set` tripwire fails. (3) `JmcpError::from(e)` for the rustez error must still work — it does (`Rustez(Box<RustEzError>)` variant + existing `From`).
