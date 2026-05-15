# `upgrade_junos` MCP tool — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the `upgrade_junos` MCP tool for standalone Junos devices per spec `docs/superpowers/specs/2026-05-15-upgrade-junos-design.md`.

**Architecture:** New module `rust-junosmcp-core/src/tools/upgrade_junos.rs` modeled on `transfer_file.rs`. Pure preflight evaluator + async I/O glue separation makes the majority of logic unit-testable without NETCONF mocking. Reuses `Arc<TransferLocks>` for per-router serialization. Two-call confirm protocol: call 1 returns `ConfirmationRequired` error with plan; call 2 with `confirm: true` executes phases 1-7.

**Tech Stack:** Rust 2021, tokio, serde, schemars, thiserror, sha2, rmcp 0.8.5, rustez 0.10.1.

**Reference spec:** `docs/superpowers/specs/2026-05-15-upgrade-junos-design.md`

**Reference module to imitate:** `rust-junosmcp-core/src/tools/transfer_file.rs`

**Workflow checklist before every commit:**
```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
CI enforces `cargo fmt -- --check`; missing this will fail CI.

---

## Task 1: Add 7 new `JmcpError` variants

**Files:**
- Modify: `rust-junosmcp-core/src/error.rs`

These variants are the public error surface of `upgrade_junos`. Each uses the existing `[code=<snake>]` Display convention so MCP callers can pattern-match. `ConfirmationRequired` carries the JSON payload as a `serde_json::Value` so the tool can build the structured plan and surface it as an error message.

- [ ] **Step 1: Write failing tests for all 7 new variants' `Display` output**

Add at the bottom of the `#[cfg(test)] mod tests` block in `rust-junosmcp-core/src/error.rs`:

```rust
    #[test]
    fn confirmation_required_display_includes_code_and_router() {
        let payload = serde_json::json!({
            "router": "vsrx-test18",
            "current_version": "24.4R1.9",
            "target_version": "25.4R1.12",
        });
        let s = JmcpError::ConfirmationRequired { payload: payload.clone() }.to_string();
        assert!(s.contains("[code=confirmation_required]"), "got {s}");
        assert!(s.contains("vsrx-test18"), "got {s}");
        assert!(s.contains("25.4R1.12"), "got {s}");
    }

    #[test]
    fn upgrade_cluster_unsupported_display_includes_code_and_router() {
        let s = JmcpError::UpgradeClusterUnsupported {
            router: "vsrx-test19".into(),
        }
        .to_string();
        assert!(s.contains("[code=cluster_unsupported]"), "got {s}");
        assert!(s.contains("vsrx-test19"), "got {s}");
    }

    #[test]
    fn upgrade_commit_confirmed_active_display_includes_code_and_rollback() {
        let s = JmcpError::UpgradeCommitConfirmedActive {
            router: "vsrx-test10".into(),
            rollback_secs: 540,
        }
        .to_string();
        assert!(s.contains("[code=commit_confirmed_active]"), "got {s}");
        assert!(s.contains("vsrx-test10"), "got {s}");
        assert!(s.contains("540"), "got {s}");
    }

    #[test]
    fn upgrade_install_timeout_display_includes_code() {
        let s = JmcpError::UpgradeInstallTimeout {
            router: "vsrx-test10".into(),
            elapsed: std::time::Duration::from_secs(3600),
        }
        .to_string();
        assert!(s.contains("[code=install_timeout]"), "got {s}");
        assert!(s.contains("vsrx-test10"), "got {s}");
    }

    #[test]
    fn upgrade_reboot_timeout_display_includes_code_and_secs() {
        let s = JmcpError::UpgradeRebootTimeout {
            router: "vsrx-test10".into(),
            waited_secs: 480,
        }
        .to_string();
        assert!(s.contains("[code=reboot_timeout]"), "got {s}");
        assert!(s.contains("vsrx-test10"), "got {s}");
        assert!(s.contains("480"), "got {s}");
    }

    #[test]
    fn upgrade_postverify_mismatch_display_includes_versions() {
        let s = JmcpError::UpgradePostVerifyMismatch {
            router: "vsrx-test10".into(),
            expected: "25.4R1.12".into(),
            observed: "24.4R1.9".into(),
        }
        .to_string();
        assert!(s.contains("[code=postverify_mismatch]"), "got {s}");
        assert!(s.contains("25.4R1.12"), "got {s}");
        assert!(s.contains("24.4R1.9"), "got {s}");
    }

    #[test]
    fn upgrade_outer_timeout_display_includes_code_and_duration() {
        let s = JmcpError::UpgradeOuterTimeout(std::time::Duration::from_secs(900)).to_string();
        assert!(s.contains("[code=upgrade_outer_timeout]"), "got {s}");
        assert!(s.contains("900s"), "got {s}");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test -p rust-junosmcp-core error::tests
```

Expected: 7 compile errors (variants don't exist).

- [ ] **Step 3: Add the 7 new variants to the `JmcpError` enum**

Insert these variants in `rust-junosmcp-core/src/error.rs` after the existing `TransferOuterTimeout` variant (around line 81):

```rust
    #[error(
        "confirmation required [code=confirmation_required]: re-call with confirm=true to proceed; plan: {payload}"
    )]
    ConfirmationRequired { payload: serde_json::Value },

    #[error(
        "cluster device unsupported [code=cluster_unsupported]: router '{router}' is a chassis cluster; upgrade_junos v1 supports standalone devices only (ISSU support deferred to v2)"
    )]
    UpgradeClusterUnsupported { router: String },

    #[error(
        "active commit-confirmed window [code=commit_confirmed_active]: router '{router}' has a pending rollback in {rollback_secs}s; run `commit` or `rollback` first, then retry"
    )]
    UpgradeCommitConfirmedActive { router: String, rollback_secs: u64 },

    #[error(
        "install RPC timed out [code=install_timeout]: router '{router}' after {elapsed:?}; the install may still be running on the device — check from console or retry once the device is reachable"
    )]
    UpgradeInstallTimeout {
        router: String,
        elapsed: std::time::Duration,
    },

    #[error(
        "device did not return after reboot [code=reboot_timeout]: router '{router}' did not reopen NETCONF within {waited_secs}s; check console / hardware status"
    )]
    UpgradeRebootTimeout { router: String, waited_secs: u64 },

    #[error(
        "post-upgrade version mismatch [code=postverify_mismatch]: router '{router}' expected '{expected}', got '{observed}'; the install may have rolled back or failed silently"
    )]
    UpgradePostVerifyMismatch {
        router: String,
        expected: String,
        observed: String,
    },

    #[error(
        "upgrade outer timeout [code=upgrade_outer_timeout] after {0:?}; raise the `timeout` arg or check device responsiveness"
    )]
    UpgradeOuterTimeout(std::time::Duration),
```

- [ ] **Step 4: Run tests to verify they pass + the whole suite still passes**

```bash
cargo test -p rust-junosmcp-core
```

Expected: all green; 7 new tests pass.

- [ ] **Step 5: Format + clippy**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
git add rust-junosmcp-core/src/error.rs
git commit -m "$(cat <<'EOF'
feat(upgrade_junos): add 7 new JmcpError variants

ConfirmationRequired, UpgradeClusterUnsupported, UpgradeCommitConfirmedActive,
UpgradeInstallTimeout, UpgradeRebootTimeout, UpgradePostVerifyMismatch,
UpgradeOuterTimeout. Each follows the existing [code=<snake>] Display
convention. See docs/superpowers/specs/2026-05-15-upgrade-junos-design.md.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Add `UpgradeJunosArgs` struct + default helpers

**Files:**
- Modify: `rust-junosmcp-core/src/tools/mod.rs`

- [ ] **Step 1: Write failing tests for arg parsing**

Add to the `#[cfg(test)] mod tests` block in `rust-junosmcp-core/src/tools/mod.rs`:

```rust
    #[test]
    fn upgrade_junos_args_defaults() {
        let v = serde_json::json!({
            "router_name": "vsrx-test10",
            "source_path": "junos-25.4R1.12.tgz",
            "target_version": "25.4R1.12"
        });
        let a: UpgradeJunosArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.router_name, "vsrx-test10");
        assert_eq!(a.source_path, "junos-25.4R1.12.tgz");
        assert_eq!(a.target_version, "25.4R1.12");
        assert!(!a.confirm);
        assert_eq!(a.timeout, 900);
        assert_eq!(a.reboot_wait_secs, 480);
    }

    #[test]
    fn upgrade_junos_args_rejects_missing_required() {
        for missing in [
            serde_json::json!({"source_path":"x.tgz","target_version":"25.4R1.12"}),
            serde_json::json!({"router_name":"r1","target_version":"25.4R1.12"}),
            serde_json::json!({"router_name":"r1","source_path":"x.tgz"}),
        ] {
            let r: Result<UpgradeJunosArgs, _> = serde_json::from_value(missing);
            assert!(r.is_err(), "should reject missing required");
        }
    }

    #[test]
    fn upgrade_junos_args_accepts_confirm_true() {
        let v = serde_json::json!({
            "router_name": "r1",
            "source_path": "x.tgz",
            "target_version": "25.4R1.12",
            "confirm": true
        });
        let a: UpgradeJunosArgs = serde_json::from_value(v).unwrap();
        assert!(a.confirm);
    }

    #[test]
    fn upgrade_junos_args_accepts_custom_timeouts() {
        let v = serde_json::json!({
            "router_name": "r1",
            "source_path": "x.tgz",
            "target_version": "25.4R1.12",
            "timeout": 1800,
            "reboot_wait_secs": 720
        });
        let a: UpgradeJunosArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.timeout, 1800);
        assert_eq!(a.reboot_wait_secs, 720);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test -p rust-junosmcp-core tools::tests::upgrade_junos
```

Expected: compile errors — `UpgradeJunosArgs` doesn't exist.

- [ ] **Step 3: Add default helpers + the struct**

In `rust-junosmcp-core/src/tools/mod.rs`, add after `default_list_staged_timeout()` (around line 29):

```rust
fn default_upgrade_timeout() -> u64 {
    900
}
fn default_reboot_wait_secs() -> u64 {
    480
}
```

Add `pub mod upgrade_junos;` near line 19 (after `pub mod transfer_file;`).

Add the args struct at the bottom of the public structs section (after `ListStagedFilesArgs`):

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpgradeJunosArgs {
    /// Target router (must exist in inventory and use ssh_key auth).
    pub router_name: String,
    /// Basename of the staged image under the staging dir. Validated
    /// against the same ASCII allowlist as transfer_file.
    pub source_path: String,
    /// Expected target version string, e.g. "25.4R1.12". Post-install
    /// `show version` must match exactly or the call fails with
    /// UpgradePostVerifyMismatch.
    pub target_version: String,
    /// REQUIRED to perform the destructive upgrade. Defaults to false.
    /// When false the tool runs read-only pre-flight and returns the
    /// upgrade plan as a ConfirmationRequired error.
    #[serde(default)]
    pub confirm: bool,
    /// Per-call outer timeout in seconds. Default 900 (15 min).
    #[serde(default = "default_upgrade_timeout")]
    pub timeout: u64,
    /// Wall-clock budget for NETCONF to reopen after install + reboot.
    /// Default 480 (8 min).
    #[serde(default = "default_reboot_wait_secs")]
    pub reboot_wait_secs: u64,
}
```

- [ ] **Step 4: Create the empty module file**

Create `rust-junosmcp-core/src/tools/upgrade_junos.rs` with just:

```rust
//! `upgrade_junos` MCP tool. Upgrades a standalone Junos device by
//! staging an image via transfer_file, installing it with
//! `request system software add ... reboot`, waiting for NETCONF to
//! reopen, and verifying `show version` matches `target_version`.
//!
//! See docs/superpowers/specs/2026-05-15-upgrade-junos-design.md.
//! Cluster (ISSU) support deferred to v2.
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cargo test -p rust-junosmcp-core tools::tests::upgrade_junos
```

Expected: all 4 new tests pass.

- [ ] **Step 6: Format + clippy + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
git add rust-junosmcp-core/src/tools/mod.rs rust-junosmcp-core/src/tools/upgrade_junos.rs
git commit -m "$(cat <<'EOF'
feat(upgrade_junos): add UpgradeJunosArgs tool arg struct

Required: router_name, source_path, target_version.
Optional: confirm (default false), timeout (default 900s),
reboot_wait_secs (default 480s). Empty module file placeholder.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Pure helper `parse_junos_version`

**Files:**
- Modify: `rust-junosmcp-core/src/tools/upgrade_junos.rs`

Parses the version field from `show version | match Junos:` output. Real-device samples (captured 2026-05-14 from vSRX-test18):

```text
Hostname: vsrx-test18
Model: vsrx
Junos: 24.4R1.9
```

The relevant line we filter on is `Junos: <version>`.

- [ ] **Step 1: Write failing tests**

Append to `rust-junosmcp-core/src/tools/upgrade_junos.rs`:

```rust
#[cfg(test)]
mod parse_version_tests {
    use super::*;

    #[test]
    fn parses_vsrx_version() {
        let s = "Hostname: vsrx-test18\nModel: vsrx\nJunos: 24.4R1.9\n";
        assert_eq!(parse_junos_version(s).as_deref(), Some("24.4R1.9"));
    }

    #[test]
    fn parses_filtered_line() {
        let s = "Junos: 25.4R1.12";
        assert_eq!(parse_junos_version(s).as_deref(), Some("25.4R1.12"));
    }

    #[test]
    fn parses_mx_dash_x_release() {
        // MX-series flex-x releases use a trailing -X qualifier.
        let s = "Junos: 22.4R3-S2.5";
        assert_eq!(parse_junos_version(s).as_deref(), Some("22.4R3-S2.5"));
    }

    #[test]
    fn returns_none_when_no_junos_line() {
        assert!(parse_junos_version("Hostname: x\nModel: vsrx\n").is_none());
    }

    #[test]
    fn returns_none_on_empty() {
        assert!(parse_junos_version("").is_none());
    }

    #[test]
    fn tolerates_extra_whitespace() {
        let s = "   Junos:    25.4R1.12   \n";
        assert_eq!(parse_junos_version(s).as_deref(), Some("25.4R1.12"));
    }

    #[test]
    fn picks_first_junos_line_in_cluster_output() {
        // node0/node1 both report Junos lines; for standalone-version
        // intent we take the first match. (Cluster detection happens
        // upstream and refuses, so we never proceed in that case.)
        let s = "node0:\nHostname: a\nJunos: 22.4R3.10\n\nnode1:\nJunos: 22.4R3.10";
        assert_eq!(parse_junos_version(s).as_deref(), Some("22.4R3.10"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test -p rust-junosmcp-core upgrade_junos::parse_version_tests
```

Expected: compile errors — `parse_junos_version` doesn't exist.

- [ ] **Step 3: Implement `parse_junos_version`**

Add at the top of `rust-junosmcp-core/src/tools/upgrade_junos.rs` (after the doc comment):

```rust
/// Parse the version string from `show version | match Junos:` output.
/// Looks for a line of the form `Junos: <version>` (case-sensitive,
/// whitespace tolerant) and returns the version token. Returns `None`
/// when no `Junos:` line is present.
///
/// In cluster output (`node0:\n...Junos:...\nnode1:\n...Junos:...`)
/// the first match wins; cluster detection runs upstream of this and
/// refuses with `UpgradeClusterUnsupported`, so we never reach the
/// second-node case in the destructive path.
pub fn parse_junos_version(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Junos:") {
            let v = rest.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p rust-junosmcp-core upgrade_junos::parse_version_tests
```

Expected: 7 green.

- [ ] **Step 5: Format + clippy + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
git add rust-junosmcp-core/src/tools/upgrade_junos.rs
git commit -m "$(cat <<'EOF'
feat(upgrade_junos): add parse_junos_version pure helper

Extracts the version string from `show version | match Junos:`.
Tolerates whitespace, handles vSRX + MX dash-X release qualifiers,
returns first match in cluster output.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Pure helper `detect_cluster_active`

**Files:**
- Modify: `rust-junosmcp-core/src/tools/upgrade_junos.rs`

Detects active chassis cluster from `show chassis cluster status` output. Standalone vSRX returns an error or "not configured"; clustered vSRX returns a status table with `node0`/`node1`.

- [ ] **Step 1: Write failing tests**

Append to `rust-junosmcp-core/src/tools/upgrade_junos.rs`:

```rust
#[cfg(test)]
mod cluster_tests {
    use super::*;

    const STANDALONE_NOT_CONFIGURED: &str = "\
error: Chassis cluster is not enabled.";

    const ACTIVE_CLUSTER: &str = "\
Monitor Failure codes:
    CS  Cold Sync monitoring        FL  Fabric Connection monitoring
    GR  GRES monitoring             HW  Hardware monitoring

Cluster ID: 1
Node                  Priority Status         Preempt Manual   Monitor-failures

Redundancy group: 0 , Failover count: 1
node0                 100      primary        no      no       None
node1                 1        secondary      no      no       None
";

    #[test]
    fn not_configured_is_standalone() {
        assert!(!detect_cluster_active(STANDALONE_NOT_CONFIGURED));
    }

    #[test]
    fn active_cluster_detected() {
        assert!(detect_cluster_active(ACTIVE_CLUSTER));
    }

    #[test]
    fn empty_output_is_standalone() {
        assert!(!detect_cluster_active(""));
    }

    #[test]
    fn unrelated_output_is_standalone() {
        assert!(!detect_cluster_active("Hostname: vsrx-test18\nJunos: 25.4R1.12"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test -p rust-junosmcp-core upgrade_junos::cluster_tests
```

Expected: compile errors — function not defined.

- [ ] **Step 3: Implement `detect_cluster_active`**

Append to `rust-junosmcp-core/src/tools/upgrade_junos.rs` (above the `#[cfg(test)] mod cluster_tests`):

```rust
/// Detect whether `show chassis cluster status` reports an active
/// chassis cluster. The standalone vSRX response is either an error
/// line (`error: Chassis cluster is not enabled.`) or absent entirely;
/// the active-cluster response contains a `Cluster ID:` line and per-
/// node rows (`node0`, `node1`). We treat the presence of `Cluster ID:`
/// as the canonical signal.
pub fn detect_cluster_active(output: &str) -> bool {
    output.lines().any(|line| {
        let t = line.trim();
        t.starts_with("Cluster ID:")
    })
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p rust-junosmcp-core upgrade_junos::cluster_tests
```

Expected: 4 green.

- [ ] **Step 5: Format + clippy + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
git add rust-junosmcp-core/src/tools/upgrade_junos.rs
git commit -m "$(cat <<'EOF'
feat(upgrade_junos): add detect_cluster_active pure helper

Returns true iff `show chassis cluster status` contains a
`Cluster ID:` line. Standalone vSRX returns an error and is
classified as not-clustered.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Pure helper `detect_active_commit_confirmed`

**Files:**
- Modify: `rust-junosmcp-core/src/tools/upgrade_junos.rs`

Detects an active commit-confirmed rollback window from `show system commit` output. Junos prints a "commit confirmed, rollback in <N>m<S>s" line during the window.

- [ ] **Step 1: Write failing tests**

Append to `rust-junosmcp-core/src/tools/upgrade_junos.rs`:

```rust
#[cfg(test)]
mod commit_confirmed_tests {
    use super::*;

    #[test]
    fn no_rollback_line_returns_none() {
        let s = "0   2026-05-14 11:00:00 UTC by root via cli\n";
        assert!(detect_active_commit_confirmed(s).is_none());
    }

    #[test]
    fn empty_returns_none() {
        assert!(detect_active_commit_confirmed("").is_none());
    }

    #[test]
    fn detects_rollback_minutes_and_seconds() {
        let s = "commit confirmed, rollback in 9m30s\n0   2026-05-14 ...";
        let got = detect_active_commit_confirmed(s);
        assert_eq!(got, Some(570), "9*60 + 30 = 570, got {got:?}");
    }

    #[test]
    fn detects_rollback_seconds_only() {
        let s = "commit confirmed, rollback in 45s";
        assert_eq!(detect_active_commit_confirmed(s), Some(45));
    }

    #[test]
    fn detects_rollback_minutes_only() {
        let s = "commit confirmed, rollback in 5m";
        assert_eq!(detect_active_commit_confirmed(s), Some(300));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test -p rust-junosmcp-core upgrade_junos::commit_confirmed_tests
```

- [ ] **Step 3: Implement `detect_active_commit_confirmed`**

Append to `rust-junosmcp-core/src/tools/upgrade_junos.rs` (above the test mod):

```rust
/// Detect an active commit-confirmed rollback window from
/// `show system commit` output. Junos prints `commit confirmed,
/// rollback in <N>m<S>s` while the window is open. Returns the
/// remaining time in seconds, or `None` if no active window.
pub fn detect_active_commit_confirmed(output: &str) -> Option<u64> {
    for line in output.lines() {
        let t = line.trim();
        let needle = "rollback in ";
        if let Some(idx) = t.find(needle) {
            let tail = &t[idx + needle.len()..];
            // Stop at first whitespace or end-of-line.
            let token: String = tail.chars().take_while(|c| !c.is_whitespace()).collect();
            return parse_rollback_duration(&token);
        }
    }
    None
}

fn parse_rollback_duration(token: &str) -> Option<u64> {
    // Forms: "9m30s", "5m", "45s".
    let mut total_secs: u64 = 0;
    let mut num: u64 = 0;
    let mut have_num = false;
    for c in token.chars() {
        if let Some(d) = c.to_digit(10) {
            num = num.checked_mul(10)?.checked_add(d as u64)?;
            have_num = true;
        } else if c == 'm' {
            if !have_num {
                return None;
            }
            total_secs = total_secs.checked_add(num.checked_mul(60)?)?;
            num = 0;
            have_num = false;
        } else if c == 's' {
            if !have_num {
                return None;
            }
            total_secs = total_secs.checked_add(num)?;
            num = 0;
            have_num = false;
        } else {
            return None;
        }
    }
    if have_num {
        // Trailing digits with no suffix → not parseable.
        return None;
    }
    Some(total_secs)
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p rust-junosmcp-core upgrade_junos::commit_confirmed_tests
```

Expected: 5 green.

- [ ] **Step 5: Format + clippy + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
git add rust-junosmcp-core/src/tools/upgrade_junos.rs
git commit -m "$(cat <<'EOF'
feat(upgrade_junos): add detect_active_commit_confirmed pure helper

Parses Junos `commit confirmed, rollback in <N>m<S>s` window
indicator from `show system commit`. Supports m+s, m-only, s-only.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Pure helper `diff_baseline`

**Files:**
- Modify: `rust-junosmcp-core/src/tools/upgrade_junos.rs`

Computes per-command added/removed line diff between pre and post baselines. Operator-facing, informational. Trim whitespace per line; ignore empty lines; preserve ordering of `added` and `removed` to first-seen order in their source.

- [ ] **Step 1: Write failing tests**

Append to `rust-junosmcp-core/src/tools/upgrade_junos.rs`:

```rust
#[cfg(test)]
mod diff_tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn empty_baselines_produce_empty_diff() {
        let pre: BTreeMap<String, String> = BTreeMap::new();
        let post: BTreeMap<String, String> = BTreeMap::new();
        let diff = diff_baseline(&pre, &post);
        assert!(diff.is_empty());
    }

    #[test]
    fn equal_outputs_have_empty_added_and_removed() {
        let mut pre = BTreeMap::new();
        pre.insert("show version".to_string(), "Junos: 24.4R1.9".to_string());
        let post = pre.clone();
        let diff = diff_baseline(&pre, &post);
        let d = &diff["show version"];
        assert!(d.added.is_empty());
        assert!(d.removed.is_empty());
    }

    #[test]
    fn added_line_appears_in_added() {
        let mut pre = BTreeMap::new();
        let mut post = BTreeMap::new();
        pre.insert("show alarms".into(), "no alarms".into());
        post.insert("show alarms".into(), "no alarms\n1 alarms currently active".into());
        let diff = diff_baseline(&pre, &post);
        let d = &diff["show alarms"];
        assert_eq!(d.added, vec!["1 alarms currently active".to_string()]);
        assert!(d.removed.is_empty());
    }

    #[test]
    fn removed_line_appears_in_removed() {
        let mut pre = BTreeMap::new();
        let mut post = BTreeMap::new();
        pre.insert("show interfaces".into(), "ge-0/0/0 up up\nge-0/0/1 up up".into());
        post.insert("show interfaces".into(), "ge-0/0/0 up up".into());
        let diff = diff_baseline(&pre, &post);
        let d = &diff["show interfaces"];
        assert!(d.added.is_empty());
        assert_eq!(d.removed, vec!["ge-0/0/1 up up".to_string()]);
    }

    #[test]
    fn whitespace_only_lines_ignored() {
        let mut pre = BTreeMap::new();
        let mut post = BTreeMap::new();
        pre.insert("c".into(), "a\n   \nb".into());
        post.insert("c".into(), "a\nb".into());
        let diff = diff_baseline(&pre, &post);
        assert!(diff["c"].added.is_empty());
        assert!(diff["c"].removed.is_empty());
    }

    #[test]
    fn commands_only_in_post_are_all_added() {
        let pre: BTreeMap<String, String> = BTreeMap::new();
        let mut post = BTreeMap::new();
        post.insert("new cmd".into(), "x\ny".into());
        let diff = diff_baseline(&pre, &post);
        assert_eq!(diff["new cmd"].added, vec!["x".to_string(), "y".to_string()]);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test -p rust-junosmcp-core upgrade_junos::diff_tests
```

- [ ] **Step 3: Implement `BaselineDiff` + `diff_baseline`**

Append to `rust-junosmcp-core/src/tools/upgrade_junos.rs` (above the test mod):

```rust
use std::collections::BTreeMap;

/// Per-command line-set diff. `added` = lines present in `post` but not
/// `pre`; `removed` = lines present in `pre` but not `post`. Order
/// follows first-seen in the source string. Whitespace-only lines are
/// ignored.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BaselineDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

/// Compute a per-command diff of baseline outputs. Commands present in
/// only one side are reported with the full content in the appropriate
/// `added` or `removed` list. Commands present in neither side are
/// absent from the result.
pub fn diff_baseline(
    pre: &BTreeMap<String, String>,
    post: &BTreeMap<String, String>,
) -> BTreeMap<String, BaselineDiff> {
    let mut out: BTreeMap<String, BaselineDiff> = BTreeMap::new();
    let mut keys: std::collections::BTreeSet<&String> = std::collections::BTreeSet::new();
    keys.extend(pre.keys());
    keys.extend(post.keys());
    for k in keys {
        let pre_lines: Vec<&str> = pre
            .get(k)
            .map(|s| s.lines().map(str::trim).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default();
        let post_lines: Vec<&str> = post
            .get(k)
            .map(|s| s.lines().map(str::trim).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default();
        let pre_set: std::collections::HashSet<&str> = pre_lines.iter().copied().collect();
        let post_set: std::collections::HashSet<&str> = post_lines.iter().copied().collect();
        let added: Vec<String> = post_lines
            .iter()
            .filter(|l| !pre_set.contains(*l))
            .map(|s| s.to_string())
            .collect();
        let removed: Vec<String> = pre_lines
            .iter()
            .filter(|l| !post_set.contains(*l))
            .map(|s| s.to_string())
            .collect();
        out.insert(k.clone(), BaselineDiff { added, removed });
    }
    out
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p rust-junosmcp-core upgrade_junos::diff_tests
```

Expected: 6 green.

- [ ] **Step 5: Format + clippy + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
git add rust-junosmcp-core/src/tools/upgrade_junos.rs
git commit -m "$(cat <<'EOF'
feat(upgrade_junos): add diff_baseline pure helper + BaselineDiff struct

Per-command added/removed line diff over pre/post baseline maps.
First-seen ordering, whitespace-only line filtering, set-based equality.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Pure preflight evaluator + types

**Files:**
- Modify: `rust-junosmcp-core/src/tools/upgrade_junos.rs`

This is the decision core: given gathered facts (NETCONF output strings + local image info + args), decide whether to refuse, skip, ask for confirmation, or proceed. Pure → fully unit-testable.

- [ ] **Step 1: Write failing tests**

Append to `rust-junosmcp-core/src/tools/upgrade_junos.rs`:

```rust
#[cfg(test)]
mod preflight_tests {
    use super::*;

    fn args() -> crate::tools::UpgradeJunosArgs {
        crate::tools::UpgradeJunosArgs {
            router_name: "vsrx-test10".into(),
            source_path: "junos-25.4R1.12.tgz".into(),
            target_version: "25.4R1.12".into(),
            confirm: false,
            timeout: 900,
            reboot_wait_secs: 480,
        }
    }

    fn baseline_facts() -> PreflightFacts {
        PreflightFacts {
            cluster_status_output: "error: Chassis cluster is not enabled.".into(),
            version_output: "Junos: 24.4R1.9".into(),
            commit_output: "0   2026-05-14 ...\n".into(),
            storage_output: "\
Filesystem  Size Used Avail Capacity Mounted on
/dev/x      10G  2.1G 7.0G  23%      /.mount/var
".into(),
            local_image_size: 1_000_000_000,
            local_image_sha256: [0; 32],
            image_basename: "junos-25.4R1.12.tgz".into(),
        }
    }

    #[test]
    fn refuses_cluster_device() {
        let mut f = baseline_facts();
        f.cluster_status_output = "Cluster ID: 1\nnode0 primary".into();
        let d = evaluate_preflight(&f, &args());
        assert!(matches!(d, PreflightDecision::ClusterUnsupported));
    }

    #[test]
    fn returns_already_at_target_when_version_matches() {
        let mut f = baseline_facts();
        f.version_output = "Junos: 25.4R1.12".into();
        let d = evaluate_preflight(&f, &args());
        match d {
            PreflightDecision::AlreadyAtTarget { current_version } => {
                assert_eq!(current_version, "25.4R1.12");
            }
            other => panic!("expected AlreadyAtTarget, got {other:?}"),
        }
    }

    #[test]
    fn refuses_active_commit_confirmed() {
        let mut f = baseline_facts();
        f.commit_output = "commit confirmed, rollback in 9m30s\n".into();
        let d = evaluate_preflight(&f, &args());
        match d {
            PreflightDecision::CommitConfirmedActive { rollback_secs } => {
                assert_eq!(rollback_secs, 570);
            }
            other => panic!("expected CommitConfirmedActive, got {other:?}"),
        }
    }

    #[test]
    fn refuses_insufficient_disk_for_2x_plus_headroom() {
        let mut f = baseline_facts();
        // 7.0G ~ 7.5GB; require 2*1G + 32MiB = 2.03GB → plenty.
        // Force shortfall: image 4G needs 8G+headroom, only 7G free.
        f.local_image_size = 4_000_000_000;
        let d = evaluate_preflight(&f, &args());
        match d {
            PreflightDecision::InsufficientDisk { free, required } => {
                assert!(free < required, "free={free} required={required}");
            }
            other => panic!("expected InsufficientDisk, got {other:?}"),
        }
    }

    #[test]
    fn returns_confirmation_required_when_confirm_false() {
        let f = baseline_facts();
        let d = evaluate_preflight(&f, &args());
        match d {
            PreflightDecision::ConfirmationRequired(payload) => {
                assert_eq!(payload["router"], "vsrx-test10");
                assert_eq!(payload["current_version"], "24.4R1.9");
                assert_eq!(payload["target_version"], "25.4R1.12");
                assert_eq!(payload["image_basename"], "junos-25.4R1.12.tgz");
                assert_eq!(payload["image_size_bytes"], 1_000_000_000);
                assert!(payload["warning"].as_str().unwrap().contains("DESTRUCTIVE"));
                assert!(payload["warning"].as_str().unwrap().contains("REBOOT"));
            }
            other => panic!("expected ConfirmationRequired, got {other:?}"),
        }
    }

    #[test]
    fn returns_proceed_when_confirm_true_and_everything_ok() {
        let f = baseline_facts();
        let mut a = args();
        a.confirm = true;
        let d = evaluate_preflight(&f, &a);
        assert!(matches!(d, PreflightDecision::Proceed));
    }

    #[test]
    fn unparseable_version_yields_proceed_block() {
        let mut f = baseline_facts();
        f.version_output = "garbage no junos line".into();
        let d = evaluate_preflight(&f, &args());
        assert!(matches!(d, PreflightDecision::UnparseableVersion));
    }

    #[test]
    fn check_order_cluster_before_already_at_target() {
        // Even if version matches, cluster refusal must win to prevent
        // returning success on a misclassified cluster device.
        let mut f = baseline_facts();
        f.cluster_status_output = "Cluster ID: 1\n".into();
        f.version_output = "Junos: 25.4R1.12".into();
        let d = evaluate_preflight(&f, &args());
        assert!(matches!(d, PreflightDecision::ClusterUnsupported));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test -p rust-junosmcp-core upgrade_junos::preflight_tests
```

- [ ] **Step 3: Implement types + `evaluate_preflight`**

Append to `rust-junosmcp-core/src/tools/upgrade_junos.rs` (above the test mod):

```rust
/// Minimum free-disk headroom on top of `2 × image_size`. Junos install
/// needs working space for unpack + new partition; 2× is a safe rule of
/// thumb on top of the local image size, plus 32 MiB for slack.
pub const UPGRADE_DISK_HEADROOM_BYTES: u64 = 32 * 1024 * 1024;

/// Estimated outage duration baked into the ConfirmationRequired
/// payload. Derived from the 2026-05-14 vSRX-test18 timing (7 min
/// total = 420 s) with a small headroom margin.
pub const ESTIMATED_OUTAGE_SECONDS: u64 = 420;

/// Raw outputs + local image facts handed to the pure preflight
/// evaluator. Everything I/O happens upstream; this struct is the
/// boundary between "talk to the world" and "decide what to do".
#[derive(Debug, Clone)]
pub struct PreflightFacts {
    pub cluster_status_output: String,
    pub version_output: String,
    pub commit_output: String,
    pub storage_output: String,
    pub local_image_size: u64,
    pub local_image_sha256: [u8; 32],
    pub image_basename: String,
}

/// The decision the pure evaluator returns. Each variant maps to a
/// concrete handle() outcome: an error, a skip-success, a confirmation
/// payload, or "go ahead".
#[derive(Debug)]
pub enum PreflightDecision {
    ClusterUnsupported,
    UnparseableVersion,
    UnparseableStorage,
    AlreadyAtTarget { current_version: String },
    CommitConfirmedActive { rollback_secs: u64 },
    InsufficientDisk { free: u64, required: u64 },
    ConfirmationRequired(serde_json::Value),
    Proceed,
}

/// Pure preflight decision. Order of checks (each short-circuits):
/// 1. Cluster → refuse (highest priority — never proceed on cluster)
/// 2. Version parseable
/// 3. Already-at-target → skip-success
/// 4. Active commit-confirmed → refuse
/// 5. Storage parseable + disk headroom OK
/// 6. confirm=false → ConfirmationRequired
/// 7. else → Proceed
pub fn evaluate_preflight(
    facts: &PreflightFacts,
    args: &crate::tools::UpgradeJunosArgs,
) -> PreflightDecision {
    if detect_cluster_active(&facts.cluster_status_output) {
        return PreflightDecision::ClusterUnsupported;
    }
    let current_version = match parse_junos_version(&facts.version_output) {
        Some(v) => v,
        None => return PreflightDecision::UnparseableVersion,
    };
    if current_version == args.target_version {
        return PreflightDecision::AlreadyAtTarget { current_version };
    }
    if let Some(rollback_secs) = detect_active_commit_confirmed(&facts.commit_output) {
        return PreflightDecision::CommitConfirmedActive { rollback_secs };
    }
    let free = match crate::tools::transfer_file::parse_storage_free_bytes(
        &facts.storage_output,
    ) {
        Ok(b) => b,
        Err(_) => return PreflightDecision::UnparseableStorage,
    };
    let required = facts
        .local_image_size
        .saturating_mul(2)
        .saturating_add(UPGRADE_DISK_HEADROOM_BYTES);
    if free < required {
        return PreflightDecision::InsufficientDisk { free, required };
    }
    if !args.confirm {
        let payload = serde_json::json!({
            "code": "confirmation_required",
            "router": args.router_name,
            "current_version": current_version,
            "target_version": args.target_version,
            "image_basename": facts.image_basename,
            "image_size_bytes": facts.local_image_size,
            "device_var_free_bytes": free,
            "estimated_outage_seconds": ESTIMATED_OUTAGE_SECONDS,
            "preflight_blockers": [],
            "warning": "DESTRUCTIVE: this will install a new Junos image and REBOOT the device, causing an outage of approximately 5–7 minutes. Re-call with confirm=true to proceed."
        });
        return PreflightDecision::ConfirmationRequired(payload);
    }
    PreflightDecision::Proceed
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p rust-junosmcp-core upgrade_junos::preflight_tests
```

Expected: 8 green.

- [ ] **Step 5: Format + clippy + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
git add rust-junosmcp-core/src/tools/upgrade_junos.rs
git commit -m "$(cat <<'EOF'
feat(upgrade_junos): add pure preflight evaluator

PreflightFacts (input) + PreflightDecision (output) + evaluate_preflight
core decision function. Check order: cluster → version-parse →
already-at-target → commit-confirmed → disk → confirm-false. Reuses
transfer_file::parse_storage_free_bytes.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: `UpgradeConfig` + `handle()` skeleton (early-exit paths)

**Files:**
- Modify: `rust-junosmcp-core/src/tools/upgrade_junos.rs`
- Modify: `rust-junosmcp-core/src/lib.rs` (re-export `UpgradeConfig` if needed)

This task gives us a `handle()` function that:
1. Wraps the workflow in `tokio::time::timeout(args.timeout, ...)` and converts expiry → `UpgradeOuterTimeout`.
2. Validates `source_path` basename (reuses `validate_source_basename`).
3. Looks up inventory, refuses password auth (reuses `UnsupportedAuth`).
4. Verifies staged file exists, is not a symlink, is a regular file (mirrors transfer_file's checks).
5. Acquires the per-router `TransferLocks` permit.
6. Calls a stub `gather_facts()` (returns `unimplemented!()` for now) — Task 9 fills it in.
7. Calls `evaluate_preflight` and translates the `PreflightDecision` into the right return.

**Files:**
- Modify: `rust-junosmcp-core/src/tools/upgrade_junos.rs`

- [ ] **Step 1: Write failing tests for early-exit paths**

Append:

```rust
#[cfg(test)]
mod handle_early_exit_tests {
    use super::*;
    use crate::device_manager::DeviceManager;
    use crate::inventory::Inventory;
    use crate::tools::{transfer_file::TransferLocks, UpgradeJunosArgs};
    use std::io::Write;
    use std::sync::Arc;

    fn cfg(dir: &std::path::Path) -> UpgradeConfig {
        UpgradeConfig {
            transfer_cfg: crate::tools::transfer_file::TransferConfig {
                staging_dir: dir.to_path_buf(),
                known_hosts_file: "/etc/jmcp/known_hosts".into(),
                scp_runner: crate::tools::transfer_file::MockScpRunner::ok(),
                transfer_locks: Arc::new(TransferLocks::default()),
            },
        }
    }

    fn build_inv(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    fn args(router: &str, source: &str) -> UpgradeJunosArgs {
        UpgradeJunosArgs {
            router_name: router.into(),
            source_path: source.into(),
            target_version: "25.4R1.12".into(),
            confirm: false,
            timeout: 10,
            reboot_wait_secs: 5,
        }
    }

    #[tokio::test]
    async fn rejects_bad_basename() {
        let dir = tempfile::tempdir().unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"ssh_key","private_key_path":"/tmp/k"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(args("r1", "../etc/passwd"), dm, cfg(dir.path())).await;
        assert!(matches!(r, Err(crate::error::JmcpError::BadSourcePath(_))));
    }

    #[tokio::test]
    async fn unknown_router_propagates() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("img.tgz"), b"abc").unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"ssh_key","private_key_path":"/tmp/k"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(args("nope", "img.tgz"), dm, cfg(dir.path())).await;
        assert!(matches!(r, Err(crate::error::JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn rejects_password_auth_before_transfer() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("img.tgz"), b"abc").unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(args("r1", "img.tgz"), dm, cfg(dir.path())).await;
        assert!(matches!(r, Err(crate::error::JmcpError::UnsupportedAuth(ref s)) if s == "r1"));
    }

    #[tokio::test]
    async fn rejects_missing_staged_file() {
        let dir = tempfile::tempdir().unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"ssh_key","private_key_path":"/tmp/k"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(args("r1", "missing.tgz"), dm, cfg(dir.path())).await;
        assert!(matches!(r, Err(crate::error::JmcpError::BadSourcePath(_))));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test -p rust-junosmcp-core upgrade_junos::handle_early_exit_tests
```

Expected: compile errors (`UpgradeConfig` / `handle` undefined).

- [ ] **Step 3: Implement `UpgradeConfig` and `handle()` early-exit + stub `gather_facts`**

Append to `rust-junosmcp-core/src/tools/upgrade_junos.rs`:

```rust
use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::inventory::AuthConfig;
use crate::tools::transfer_file::{
    sha256_file, validate_source_basename, TransferConfig,
};
use crate::tools::UpgradeJunosArgs;
use std::path::Path;
use std::sync::Arc;

/// Tool-level config. Holds the shared `TransferConfig` so that:
/// - `transfer_file` and `upgrade_junos` use the same per-router locks
/// - staging dir + known hosts paths are configured in one place
/// - the mockable `ScpRunner` is reachable when this tool calls into
///   `transfer_file::handle` for the actual image push
#[derive(Clone)]
pub struct UpgradeConfig {
    pub transfer_cfg: TransferConfig,
}

/// Stub: Task 9 replaces this with the real async NETCONF gather.
/// Lives here so handle() can be wired up first and exercised by
/// early-exit tests (which never reach this code path).
#[allow(dead_code)]
async fn gather_facts(
    _router: &str,
    _dm: Arc<DeviceManager>,
    _image_basename: String,
    _local_size: u64,
    _local_sha: [u8; 32],
) -> Result<PreflightFacts, JmcpError> {
    Err(JmcpError::Validation(
        "gather_facts stub called; implement in Task 9".into(),
    ))
}

pub async fn handle(
    args: UpgradeJunosArgs,
    dm: Arc<DeviceManager>,
    cfg: UpgradeConfig,
) -> Result<serde_json::Value, JmcpError> {
    let timeout = std::time::Duration::from_secs(args.timeout);
    tokio::time::timeout(timeout, run(args, dm, cfg))
        .await
        .map_err(|_| JmcpError::UpgradeOuterTimeout(timeout))?
}

async fn run(
    args: UpgradeJunosArgs,
    dm: Arc<DeviceManager>,
    cfg: UpgradeConfig,
) -> Result<serde_json::Value, JmcpError> {
    // 1. Basename validation (same allowlist as transfer_file).
    validate_source_basename(&args.source_path)?;

    // 2. Inventory lookup + auth check up front. We snapshot what we
    //    need so the borrow drops before any await on dm.open().
    {
        let inv = dm.inventory();
        let entry = inv.get(&args.router_name)?;
        match &entry.auth {
            AuthConfig::Password { .. } => {
                return Err(JmcpError::UnsupportedAuth(args.router_name.clone()));
            }
            AuthConfig::SshKey { .. } => {}
        }
    }

    // 3. Staged file checks (mirror transfer_file pre-flight).
    let local_path = cfg.transfer_cfg.staging_dir.join(&args.source_path);
    let meta = std::fs::symlink_metadata(&local_path).map_err(|_| {
        JmcpError::BadSourcePath(format!(
            "staged file not found or unreadable: {}",
            local_path.display()
        ))
    })?;
    if meta.file_type().is_symlink() {
        return Err(JmcpError::BadSourcePath(format!(
            "staged path is a symlink, refusing to follow: {}",
            local_path.display()
        )));
    }
    if !meta.is_file() {
        return Err(JmcpError::BadSourcePath(format!(
            "staged path is not a regular file: {}",
            local_path.display()
        )));
    }

    // 4. Acquire per-router transfer lock (shared with transfer_file).
    let _permit = cfg
        .transfer_cfg
        .transfer_locks
        .acquire(&args.router_name)
        .await;

    // 5. Local sha256 + size (streamed, blocks of 64 KiB).
    let (local_sha, local_size) = sha256_file(&local_path).await?;

    // 6. Gather NETCONF facts. Stub until Task 9 wires it up.
    let facts = gather_facts(
        &args.router_name,
        dm.clone(),
        args.source_path.clone(),
        local_size,
        local_sha,
    )
    .await?;

    // 7. Pure preflight decision.
    dispatch_preflight(&args, &facts, dm.clone(), &cfg).await
}

/// Translate a PreflightDecision into a handle() outcome. Task 9
/// stubs the Proceed arm; Tasks 10-11 fill in the destructive path.
async fn dispatch_preflight(
    args: &UpgradeJunosArgs,
    facts: &PreflightFacts,
    _dm: Arc<DeviceManager>,
    _cfg: &UpgradeConfig,
) -> Result<serde_json::Value, JmcpError> {
    match evaluate_preflight(facts, args) {
        PreflightDecision::ClusterUnsupported => Err(JmcpError::UpgradeClusterUnsupported {
            router: args.router_name.clone(),
        }),
        PreflightDecision::UnparseableVersion => Err(JmcpError::DeviceProbeFailed {
            phase: "version_parse".into(),
            message: "could not parse Junos version from `show version`".into(),
        }),
        PreflightDecision::UnparseableStorage => Err(JmcpError::DeviceProbeFailed {
            phase: "storage_parse".into(),
            message: "could not parse free bytes from `show system storage`".into(),
        }),
        PreflightDecision::AlreadyAtTarget { current_version } => Ok(serde_json::json!({
            "status": "already_at_target",
            "router": args.router_name,
            "current_version": current_version,
            "target_version": args.target_version,
            "message": "device already running target version; no action taken"
        })),
        PreflightDecision::CommitConfirmedActive { rollback_secs } => {
            Err(JmcpError::UpgradeCommitConfirmedActive {
                router: args.router_name.clone(),
                rollback_secs,
            })
        }
        PreflightDecision::InsufficientDisk { free, required } => {
            Err(JmcpError::InsufficientDisk {
                free,
                required,
                message: format!("device '{}' /var/tmp (install needs 2× image + 32 MiB headroom)", args.router_name),
            })
        }
        PreflightDecision::ConfirmationRequired(payload) => {
            Err(JmcpError::ConfirmationRequired { payload })
        }
        PreflightDecision::Proceed => Err(JmcpError::Validation(
            "destructive path not yet implemented (Task 10/11)".into(),
        )),
    }
}
```

Helper: open the `Path` import once (`use std::path::Path;`) only if you reference it elsewhere; remove if unused after compile.

- [ ] **Step 4: Run early-exit tests to verify they pass**

```bash
cargo test -p rust-junosmcp-core upgrade_junos::handle_early_exit_tests
```

Expected: 4 green. (The tests fail BEFORE `gather_facts` is called, so the stub is never reached.)

- [ ] **Step 5: Full suite + clippy + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git add rust-junosmcp-core/src/tools/upgrade_junos.rs
git commit -m "$(cat <<'EOF'
feat(upgrade_junos): handle() skeleton + UpgradeConfig + early-exit paths

Validates basename, inventory, auth, staged-file checks BEFORE any
NETCONF I/O. Acquires shared TransferLocks permit. Stub gather_facts
+ dispatch_preflight wire the pure evaluator into the call shape.
Destructive Proceed arm is intentionally unimplemented until Task 10.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: `gather_facts` — async NETCONF reads

**Files:**
- Modify: `rust-junosmcp-core/src/tools/upgrade_junos.rs`

Opens a pooled NETCONF session and runs the four read-only commands needed to build `PreflightFacts`. Errors are surfaced as `DeviceProbeFailed { phase, ... }` so the caller knows which probe failed.

This task has no new unit tests — the pure evaluator already covers every decision branch. We add a single live-gated smoke test that runs only when `JMCP_LIVE_UPGRADE_TARGET` is set (Task 13). For now this is glue code.

- [ ] **Step 1: Replace the `gather_facts` stub with a real implementation**

In `rust-junosmcp-core/src/tools/upgrade_junos.rs`, replace the entire `async fn gather_facts(...)` stub from Task 8 with:

```rust
async fn gather_facts(
    router: &str,
    dm: Arc<DeviceManager>,
    image_basename: String,
    local_size: u64,
    local_sha: [u8; 32],
) -> Result<PreflightFacts, JmcpError> {
    let mut dev = dm.open(router).await?;

    let cluster_status_output =
        run_probe(&mut dev, "show chassis cluster status", "cluster_probe").await?;
    let version_output =
        run_probe(&mut dev, "show version | match Junos:", "version_probe").await?;
    let commit_output = run_probe(&mut dev, "show system commit", "commit_probe").await?;
    let storage_output = run_probe(
        &mut dev,
        "show system storage no-forwarding",
        "storage_probe",
    )
    .await?;

    Ok(PreflightFacts {
        cluster_status_output,
        version_output,
        commit_output,
        storage_output,
        local_image_size: local_size,
        local_image_sha256: local_sha,
        image_basename,
    })
}

async fn run_probe(
    dev: &mut crate::device_manager::PooledDevice,
    command: &str,
    phase: &'static str,
) -> Result<String, JmcpError> {
    dev.cli(command)
        .await
        .map_err(|e| JmcpError::DeviceProbeFailed {
            phase: phase.into(),
            message: e.to_string(),
        })
}
```

Note: `cluster_status_output` may return an `rpc-error` for standalone devices ("Chassis cluster is not enabled"). That body is `Ok(...)` from `dev.cli()` because rustez doesn't treat CLI-level error output as a transport error; `detect_cluster_active` correctly returns `false` on that string. If `dev.cli` itself errors transport-wise we surface `DeviceProbeFailed`.

If the actual `dev.cli` signature on the `PooledDevice` differs from what's referenced above, mirror the call shape already used in `transfer_file::handle` (which does `dev.cli("show system storage no-forwarding").await`). Adjust the function signature/types accordingly — no other changes needed.

- [ ] **Step 2: Format + clippy + full test suite**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: all green; no new tests in this task, but the early-exit tests in Task 8 must still pass (they short-circuit before `gather_facts`).

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/src/tools/upgrade_junos.rs
git commit -m "$(cat <<'EOF'
feat(upgrade_junos): implement gather_facts NETCONF reads

Runs 4 read-only commands via pooled session: `show chassis cluster
status`, `show version | match Junos:`, `show system commit`,
`show system storage no-forwarding`. Errors surface as
DeviceProbeFailed { phase }. The pure evaluator (Task 7) drives all
decisions from these strings.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Destructive path — baseline capture + transfer + install

**Files:**
- Modify: `rust-junosmcp-core/src/tools/upgrade_junos.rs`

Wires up phases 1-3 from the spec. Pure helper `expected_install_session_drop` classifies the install RPC outcome; the rest is glue.

- [ ] **Step 1: Add the baseline command list + install-error classifier with unit tests**

Append to `rust-junosmcp-core/src/tools/upgrade_junos.rs`:

```rust
/// Commands captured in pre- and post- baselines. Order matters for
/// stable response shape; informational only.
pub const BASELINE_COMMANDS: &[&str] = &[
    "show version",
    "show interfaces terse | except \"\\.[0-9]+ \"",
    "show route summary",
    "show security flow session summary",
    "show system alarms",
    "show system core-dumps no-forwarding",
];

/// Classify whether the error returned by `dev.cli("request system
/// software add ... reboot")` is the *expected* session-drop produced
/// when the device starts rebooting mid-RPC, vs a real failure.
///
/// rustez surfaces session drops as connection-closed / I/O errors;
/// we look for substrings indicating EOF, connection-reset, broken-pipe.
/// Real install failures (RPC error from Junos, syntax error, etc.)
/// land in the JmcpError::Rustez path with different text.
pub fn install_error_indicates_session_drop(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    [
        "connection closed",
        "connection reset",
        "broken pipe",
        "unexpected eof",
        "early eof",
        "channel closed",
        "session closed",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod install_classifier_tests {
    use super::*;

    #[test]
    fn detects_connection_closed() {
        assert!(install_error_indicates_session_drop("Connection closed by peer"));
    }

    #[test]
    fn detects_broken_pipe() {
        assert!(install_error_indicates_session_drop("io error: Broken pipe"));
    }

    #[test]
    fn detects_eof() {
        assert!(install_error_indicates_session_drop("rustez: unexpected EOF on channel"));
    }

    #[test]
    fn does_not_misclassify_syntax_error() {
        assert!(!install_error_indicates_session_drop("error: syntax error, expecting <name>"));
    }

    #[test]
    fn does_not_misclassify_rpc_error() {
        assert!(!install_error_indicates_session_drop("rpc-error: package not found"));
    }
}
```

- [ ] **Step 2: Run classifier tests**

```bash
cargo test -p rust-junosmcp-core upgrade_junos::install_classifier_tests
```

Expected: 5 green.

- [ ] **Step 3: Implement phases 1-3 of the destructive path**

In `dispatch_preflight`, replace the `PreflightDecision::Proceed` arm with a call to a new `run_destructive` function. Append `run_destructive` to the module:

```rust
async fn run_destructive(
    args: &UpgradeJunosArgs,
    facts: &PreflightFacts,
    dm: Arc<DeviceManager>,
    cfg: &UpgradeConfig,
) -> Result<serde_json::Value, JmcpError> {
    use std::time::Instant;
    let started = Instant::now();
    let preflight_secs = started.elapsed().as_secs();

    // Phase 1: pre-baseline.
    let pre_baseline = capture_baseline(&args.router_name, dm.clone()).await?;
    let phase1_done = Instant::now();

    // Phase 2: transfer via transfer_file::handle (idempotent skip).
    let transfer_args = crate::tools::TransferFileArgs {
        router_name: args.router_name.clone(),
        source_path: args.source_path.clone(),
        force: false,
        verify: true,
        timeout: 600,
    };
    let _transfer_result = crate::tools::transfer_file::handle(
        transfer_args,
        dm.clone(),
        cfg.transfer_cfg.clone(),
    )
    .await?;
    let phase2_done = Instant::now();

    // Phase 3: install + reboot. Open a fresh session via the pool.
    let install_stdout = match dm.open(&args.router_name).await {
        Ok(mut dev) => {
            let cmd = format!(
                "request system software add /var/tmp/{} no-copy reboot",
                args.source_path
            );
            match dev.cli(&cmd).await {
                Ok(out) => out,
                Err(e) => {
                    if install_error_indicates_session_drop(&e.to_string()) {
                        // Expected: device started rebooting mid-RPC.
                        String::new()
                    } else {
                        return Err(JmcpError::DeviceProbeFailed {
                            phase: "install_rpc".into(),
                            message: e.to_string(),
                        });
                    }
                }
            }
        }
        Err(e) => return Err(e),
    };
    let phase3_done = Instant::now();

    // Stash everything we have so far for Tasks 11.
    Err(JmcpError::Validation(format!(
        "post-install phases 4-7 not yet implemented (Task 11); install_stdout_len={}, \
         elapsed_so_far={:?}, baseline_keys={}",
        install_stdout.len(),
        started.elapsed(),
        pre_baseline.len()
    )))?;
    let _ = (preflight_secs, phase1_done, phase2_done, phase3_done, facts);
    unreachable!("Task 11 fills this in");
}

async fn capture_baseline(
    router: &str,
    dm: Arc<DeviceManager>,
) -> Result<std::collections::BTreeMap<String, String>, JmcpError> {
    let mut out = std::collections::BTreeMap::new();
    let mut dev = dm.open(router).await?;
    for cmd in BASELINE_COMMANDS {
        match dev.cli(cmd).await {
            Ok(s) => {
                out.insert((*cmd).to_string(), s);
            }
            Err(e) => {
                // Baseline failures are informational, not blocking — record
                // the error text and continue. (If the session itself died,
                // the next iteration will surface DeviceProbeFailed; we let
                // that bubble up as a real probe failure.)
                out.insert((*cmd).to_string(), format!("<error capturing: {e}>"));
            }
        }
    }
    Ok(out)
}
```

Then update `dispatch_preflight`'s `Proceed` arm:

```rust
        PreflightDecision::Proceed => run_destructive(args, facts, _dm.clone(), _cfg).await,
```

Remove the underscore prefixes from `_dm` and `_cfg` parameters in `dispatch_preflight` now that they're used.

- [ ] **Step 4: Format + clippy + tests**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: full suite green. The destructive path's `unreachable!` is gated behind `Proceed` which is unreachable in unit tests (no NETCONF mocking).

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/upgrade_junos.rs
git commit -m "$(cat <<'EOF'
feat(upgrade_junos): destructive path phases 1-3 (baseline + transfer + install)

capture_baseline runs the 6 baseline commands and stashes outputs.
Transfer reuses transfer_file::handle (idempotent skip, shared
TransferLocks). Install issues `request system software add ... reboot`
and tolerates the expected session-drop via install_error_indicates_session_drop.
Phases 4-7 (reboot wait, post-verify, response) follow in Task 11.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Destructive path — reboot wait + post-verify + response

**Files:**
- Modify: `rust-junosmcp-core/src/tools/upgrade_junos.rs`

Final phases. The reboot-wait loop is testable via a small abstraction trick: extract the "try to open a session" call behind a closure-injected helper so we can unit-test the timing/backoff logic separately. Keep it pragmatic — the spec calls for NETCONF-only with a fixed cadence.

- [ ] **Step 1: Add unit tests for response shape builder**

Append:

```rust
#[cfg(test)]
mod response_tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn build_success_response_has_expected_keys() {
        let mut pre = BTreeMap::new();
        pre.insert("show version".into(), "Junos: 24.4R1.9".into());
        let mut post = BTreeMap::new();
        post.insert("show version".into(), "Junos: 25.4R1.12".into());

        let sha = [0xab; 32];
        let v = build_success_response(BuildSuccessArgs {
            router: "vsrx-test10",
            from_version: "24.4R1.9",
            to_version: "25.4R1.12",
            image_basename: "junos-25.4R1.12.tgz",
            image_sha256: &sha,
            elapsed_seconds: 423,
            preflight_secs: 4,
            transfer_secs: 84,
            install_secs: 218,
            reboot_wait_secs: 112,
            postverify_secs: 5,
            pre_baseline: &pre,
            post_baseline: &post,
        });
        assert_eq!(v["status"], "upgraded");
        assert_eq!(v["router"], "vsrx-test10");
        assert_eq!(v["from_version"], "24.4R1.9");
        assert_eq!(v["to_version"], "25.4R1.12");
        assert_eq!(v["image_basename"], "junos-25.4R1.12.tgz");
        assert_eq!(v["elapsed_seconds"], 423);
        assert_eq!(v["phase_timings"]["preflight_secs"], 4);
        assert_eq!(v["phase_timings"]["transfer_secs"], 84);
        assert!(v["pre_baseline"]["show version"].as_str().unwrap().contains("24.4R1.9"));
        assert!(v["post_baseline"]["show version"].as_str().unwrap().contains("25.4R1.12"));
        // Diff: post added "Junos: 25.4R1.12", pre had "Junos: 24.4R1.9"
        assert!(v["baseline_diff"]["show version"]["added"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x.as_str().unwrap().contains("25.4R1.12")));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p rust-junosmcp-core upgrade_junos::response_tests
```

Expected: compile errors — `build_success_response` doesn't exist.

- [ ] **Step 3: Implement `build_success_response`, reboot wait, and final destructive body**

Replace the placeholder `Err(JmcpError::Validation(...))?; ... unreachable!()` at the end of `run_destructive` with the real Phase 4-7 implementation. Add the response builder and the wait loop:

```rust
pub struct BuildSuccessArgs<'a> {
    pub router: &'a str,
    pub from_version: &'a str,
    pub to_version: &'a str,
    pub image_basename: &'a str,
    pub image_sha256: &'a [u8; 32],
    pub elapsed_seconds: u64,
    pub preflight_secs: u64,
    pub transfer_secs: u64,
    pub install_secs: u64,
    pub reboot_wait_secs: u64,
    pub postverify_secs: u64,
    pub pre_baseline: &'a std::collections::BTreeMap<String, String>,
    pub post_baseline: &'a std::collections::BTreeMap<String, String>,
}

pub fn build_success_response(a: BuildSuccessArgs) -> serde_json::Value {
    let diff = diff_baseline(a.pre_baseline, a.post_baseline);
    serde_json::json!({
        "status": "upgraded",
        "router": a.router,
        "from_version": a.from_version,
        "to_version": a.to_version,
        "image_basename": a.image_basename,
        "image_sha256": crate::tools::transfer_file::hex32(a.image_sha256),
        "elapsed_seconds": a.elapsed_seconds,
        "phase_timings": {
            "preflight_secs": a.preflight_secs,
            "transfer_secs": a.transfer_secs,
            "install_secs": a.install_secs,
            "reboot_wait_secs": a.reboot_wait_secs,
            "postverify_secs": a.postverify_secs,
        },
        "pre_baseline": a.pre_baseline,
        "post_baseline": a.post_baseline,
        "baseline_diff": diff,
    })
}

/// Wait for NETCONF to reopen. Initial 30 s sleep (device is rebooting),
/// then retry `dm.open(router)` every 15 s with a 10 s per-attempt
/// deadline until either success or `budget` exhausted.
async fn wait_for_netconf(
    router: &str,
    dm: Arc<DeviceManager>,
    budget: std::time::Duration,
) -> Result<(), JmcpError> {
    let start = std::time::Instant::now();
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    loop {
        let attempt_deadline = std::time::Duration::from_secs(10);
        let dm_inner = dm.clone();
        let router_str = router.to_string();
        let attempt = tokio::time::timeout(attempt_deadline, async move {
            dm_inner.open(&router_str).await
        })
        .await;
        match attempt {
            Ok(Ok(_dev)) => return Ok(()),
            _ => {
                if start.elapsed() >= budget {
                    return Err(JmcpError::UpgradeRebootTimeout {
                        router: router.to_string(),
                        waited_secs: budget.as_secs(),
                    });
                }
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            }
        }
    }
}
```

Now replace the final lines of `run_destructive` (the `Err(...)?; let _ = ...; unreachable!()`) with the real phase 4-7 body:

```rust
    // Phase 4: wait for NETCONF.
    wait_for_netconf(
        &args.router_name,
        dm.clone(),
        std::time::Duration::from_secs(args.reboot_wait_secs),
    )
    .await?;
    let phase4_done = Instant::now();

    // Phase 5: post-verify version.
    let mut dev = dm.open(&args.router_name).await?;
    let post_version_output = run_probe(&mut dev, "show version | match Junos:", "postverify_probe")
        .await?;
    let observed = parse_junos_version(&post_version_output).ok_or_else(|| {
        JmcpError::DeviceProbeFailed {
            phase: "postverify_parse".into(),
            message: "could not parse post-install Junos version".into(),
        }
    })?;
    if observed != args.target_version {
        return Err(JmcpError::UpgradePostVerifyMismatch {
            router: args.router_name.clone(),
            expected: args.target_version.clone(),
            observed,
        });
    }
    drop(dev); // release the probe session before capture_baseline reopens
    let phase5_done = Instant::now();

    // Phase 6: post-baseline.
    let post_baseline = capture_baseline(&args.router_name, dm.clone()).await?;

    // Phase 7: assemble success response.
    let from_version = parse_junos_version(&facts.version_output)
        .unwrap_or_else(|| "<unknown>".to_string());
    Ok(build_success_response(BuildSuccessArgs {
        router: &args.router_name,
        from_version: &from_version,
        to_version: &args.target_version,
        image_basename: &args.source_path,
        image_sha256: &facts.local_image_sha256,
        elapsed_seconds: started.elapsed().as_secs(),
        preflight_secs,
        transfer_secs: (phase2_done - phase1_done).as_secs(),
        install_secs: (phase3_done - phase2_done).as_secs(),
        reboot_wait_secs: (phase4_done - phase3_done).as_secs(),
        postverify_secs: (phase5_done - phase4_done).as_secs(),
        pre_baseline: &pre_baseline,
        post_baseline: &post_baseline,
    }))
```

You will also need to make the helper `hex32` `pub(crate)` exposed for our cross-module use — it is already `pub(crate)` in `transfer_file.rs`. If clippy complains about unused imports or warnings, address them before commit.

- [ ] **Step 4: Format + clippy + tests**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: all green. The response builder test exercises the diff inclusion.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/upgrade_junos.rs
git commit -m "$(cat <<'EOF'
feat(upgrade_junos): destructive path phases 4-7 (wait + verify + response)

wait_for_netconf: 30s initial sleep then 15s-cadence dm.open() retries
with 10s per-attempt deadline until reboot_wait_secs budget exhausted.
Post-verify: parse_junos_version(show version) must equal target_version.
build_success_response assembles status, phase timings, baselines, and
diff_baseline output.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Wire `UpgradeConfig` into `main.rs` and register MCP tool in `server.rs`

**Files:**
- Modify: `rust-junosmcp/src/main.rs`
- Modify: `rust-junosmcp/src/server.rs`
- Modify: `rust-junosmcp-core/src/lib.rs` (re-export if needed)

- [ ] **Step 1: Re-export `UpgradeConfig` from the core crate**

In `rust-junosmcp-core/src/lib.rs`, locate the existing `pub use` block that re-exports `TransferConfig` and add `UpgradeConfig` alongside it:

```rust
pub use tools::transfer_file::{OpenSshScpRunner, TransferConfig};
pub use tools::upgrade_junos::UpgradeConfig;
```

If the existing re-export shape is different, mirror whatever pattern `TransferConfig` already uses.

- [ ] **Step 2: Build `UpgradeConfig` in `main.rs` and pass to handler**

In `rust-junosmcp/src/main.rs`, after the existing `let transfer_cfg = TransferConfig { ... };` block (around line 89-97), add:

```rust
    let upgrade_cfg = rust_junosmcp_core::UpgradeConfig {
        transfer_cfg: transfer_cfg.clone(),
    };
```

Update the `JmcpHandler::new(...)` call (currently `JmcpHandler::new(dev_manager.clone(), policy, transfer_cfg)`) to also pass `upgrade_cfg`:

```rust
    let handler = JmcpHandler::new(dev_manager.clone(), policy, transfer_cfg, upgrade_cfg);
```

- [ ] **Step 3: Update `JmcpHandler` struct + constructor in `server.rs`**

In `rust-junosmcp/src/server.rs`, add to the struct (around line 57):

```rust
#[derive(Clone)]
pub struct JmcpHandler {
    dm: Arc<DeviceManager>,
    policy: Arc<arc_swap::ArcSwap<Policy>>,
    transfer_cfg: rust_junosmcp_core::TransferConfig,
    upgrade_cfg: rust_junosmcp_core::UpgradeConfig,
}
```

Update `new(...)`:

```rust
impl JmcpHandler {
    pub fn new(
        dm: Arc<DeviceManager>,
        policy: Arc<Policy>,
        transfer_cfg: rust_junosmcp_core::TransferConfig,
        upgrade_cfg: rust_junosmcp_core::UpgradeConfig,
    ) -> Self {
        Self {
            dm,
            policy: Arc::new(arc_swap::ArcSwap::from(policy)),
            transfer_cfg,
            upgrade_cfg,
        }
    }
```

- [ ] **Step 4: Add `upgrade_junos` to the imports + `#[tool]` method**

In `rust-junosmcp/src/server.rs`, extend the import block at the top:

```rust
use rust_junosmcp_core::{
    tools::{
        add_device, batch, config_diff, execute_command, facts, get_config, list_staged_files,
        load_commit, pfe, reload_devices, router_list, template, transfer_file, upgrade_junos,
        AddDeviceArgs, ConfigDiffArgs, ExecuteBatchArgs, ExecuteCommandArgs, ExecutePfeArgs,
        GatherFactsArgs, GetConfigArgs, ListStagedFilesArgs, LoadCommitArgs, ReloadDevicesArgs,
        TemplateArgs, TransferFileArgs, UpgradeJunosArgs,
    },
    DeviceManager, Policy,
};
```

In the `#[tool_router] impl JmcpHandler { ... }` block, append a new `#[tool]` method right after the existing `transfer_file` method (find the existing transfer_file `#[tool]` to anchor on):

```rust
    #[tool(
        name = "upgrade_junos",
        description = "DESTRUCTIVE: installs a new Junos image and REBOOTS the device. Outage ~5-7 min. Requires confirm=true to proceed; first call with confirm=false returns a ConfirmationRequired error containing the upgrade plan (current version, target version, image, free disk, estimated outage). v1 supports standalone devices only; chassis clusters are refused."
    )]
    async fn upgrade_junos(
        &self,
        Parameters(args): Parameters<UpgradeJunosArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "upgrade_junos") {
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "upgrade_junos", &args.router_name) {
            return Self::scope_to_call_result(e);
        }
        Self::to_call_result(
            upgrade_junos::handle(args, self.dm.clone(), self.upgrade_cfg.clone()).await,
        )
    }
```

If there are other places (e.g., `test_transfer_cfg()` in server.rs tests) that construct a `JmcpHandler`, you'll need to provide an `UpgradeConfig` there too. Search for `JmcpHandler::new(` and update each call site.

- [ ] **Step 5: Update integration test if present**

If `rust-junosmcp-core/tests/integration_real_device.rs` constructs an `UpgradeConfig` (it shouldn't yet — Task 13 adds the live upgrade smoke test), skip this. Otherwise add the field per the pattern used for `TransferConfig`.

- [ ] **Step 6: Format + clippy + tests**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: full suite green. Wiring touches multiple files; rust-analyzer will complain at every callsite if you missed one — fix in turn.

- [ ] **Step 7: Commit**

```bash
git add rust-junosmcp-core/src/lib.rs rust-junosmcp/src/main.rs rust-junosmcp/src/server.rs
git commit -m "$(cat <<'EOF'
feat(upgrade_junos): register MCP tool + wire UpgradeConfig

Adds 14th MCP tool: upgrade_junos. JmcpHandler now carries an
UpgradeConfig built in main.rs from the shared TransferConfig (so
TransferLocks are process-wide across both tools). Tool description
declares the DESTRUCTIVE + confirm-required contract per spec.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: Live integration test (gated)

**Files:**
- Modify: `rust-junosmcp-core/tests/integration_real_device.rs` (or create a new gated `tests/integration_upgrade_junos.rs`)

This test only runs when three env vars are set; CI never sets them, so this is lab-only. It exercises the full Phase 0-7 against a real vSRX.

- [ ] **Step 1: Create the gated test**

Create `rust-junosmcp-core/tests/integration_upgrade_junos.rs`:

```rust
//! Live upgrade_junos smoke test. Gated behind three env vars; if any
//! is unset the test exits 0 (skipped). Expected runtime ~7-10 min.
//!
//! Requires a real Junos device reachable from the test host with
//! ssh_key auth.
//!
//! Run:
//!   JMCP_LIVE_UPGRADE_TARGET=vsrx-test18 \
//!   JMCP_LIVE_UPGRADE_IMAGE=junos-vsrx-x86-64-25.4R1.12.tgz \
//!   JMCP_LIVE_UPGRADE_TARGET_VERSION=25.4R1.12 \
//!   cargo test -p rust-junosmcp-core --test integration_upgrade_junos -- --nocapture

use rust_junosmcp_core::tools::transfer_file::{TransferConfig, TransferLocks, OpenSshScpRunner};
use rust_junosmcp_core::tools::upgrade_junos::{handle, UpgradeConfig};
use rust_junosmcp_core::tools::UpgradeJunosArgs;
use rust_junosmcp_core::{DeviceManager, Inventory};
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_upgrade_round_trip() {
    let Ok(router) = std::env::var("JMCP_LIVE_UPGRADE_TARGET") else {
        eprintln!("skipping: JMCP_LIVE_UPGRADE_TARGET not set");
        return;
    };
    let Ok(image) = std::env::var("JMCP_LIVE_UPGRADE_IMAGE") else {
        eprintln!("skipping: JMCP_LIVE_UPGRADE_IMAGE not set");
        return;
    };
    let Ok(target_version) = std::env::var("JMCP_LIVE_UPGRADE_TARGET_VERSION") else {
        eprintln!("skipping: JMCP_LIVE_UPGRADE_TARGET_VERSION not set");
        return;
    };
    let inventory_path = std::env::var("JMCP_LIVE_INVENTORY")
        .unwrap_or_else(|_| "/etc/jmcp/devices.json".to_string());
    let staging_dir =
        std::env::var("JMCP_LIVE_STAGING").unwrap_or_else(|_| "/var/lib/jmcp/staging".to_string());

    let inv = Arc::new(Inventory::load(std::path::Path::new(&inventory_path)).unwrap());
    let dm = Arc::new(DeviceManager::new(inv));
    let transfer_cfg = TransferConfig {
        staging_dir: staging_dir.into(),
        known_hosts_file: "/etc/jmcp/known_hosts".into(),
        scp_runner: Arc::new(OpenSshScpRunner),
        transfer_locks: Arc::new(TransferLocks::default()),
    };
    let cfg = UpgradeConfig {
        transfer_cfg,
    };
    let args = UpgradeJunosArgs {
        router_name: router.clone(),
        source_path: image.clone(),
        target_version: target_version.clone(),
        confirm: true,
        timeout: 1800,        // 30 min ceiling
        reboot_wait_secs: 600, // 10 min reboot budget
    };
    let result = handle(args, dm, cfg).await;
    eprintln!("upgrade result: {result:?}");
    let v = result.expect("upgrade should succeed end-to-end");
    assert_eq!(v["status"], "upgraded");
    assert_eq!(v["router"], router);
    assert_eq!(v["to_version"], target_version);
}
```

- [ ] **Step 2: Verify the test compiles + is skipped when env vars unset**

```bash
cargo test -p rust-junosmcp-core --test integration_upgrade_junos
```

Expected: compiles, runs, prints `skipping: JMCP_LIVE_UPGRADE_TARGET not set`, passes.

- [ ] **Step 3: Format + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
git add rust-junosmcp-core/tests/integration_upgrade_junos.rs
git commit -m "$(cat <<'EOF'
test(upgrade_junos): add gated live smoke test

Runs full Phase 0-7 against a real vSRX when JMCP_LIVE_UPGRADE_TARGET,
JMCP_LIVE_UPGRADE_IMAGE, and JMCP_LIVE_UPGRADE_TARGET_VERSION are all
set. Skips silently otherwise so CI is unaffected.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: Version bump + CHANGELOG entry

**Files:**
- Modify: `Cargo.toml`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Bump workspace version `0.4.1` → `0.5.0`**

In `Cargo.toml`, change line 6:

```toml
version      = "0.5.0"
```

- [ ] **Step 2: Add `[0.5.0]` entry to `CHANGELOG.md`**

Insert at the top of `CHANGELOG.md` between the title block and the existing `## [0.4.1]` section:

```markdown
## [0.5.0] — TBD

Feature release: new `upgrade_junos` MCP tool brings the standalone
vSRX upgrade workflow into the tool surface. Tool count 13 → 14.

### Added

- **`upgrade_junos` tool** — single MCP call automates the proven
  standalone vSRX upgrade workflow: pre-baseline → transfer →
  install + reboot → wait for NETCONF → post-verify → post-baseline
  → response. Two-call confirm protocol: first call returns a
  `ConfirmationRequired` JSON-RPC error carrying the full upgrade
  plan (current version, target version, image, free disk,
  estimated outage); operator re-calls with `confirm=true` to
  perform the destructive workflow. Reuses the v0.4.1
  `TransferLocks` semaphore so transfer_file + upgrade_junos
  serialize per-router. Cluster (ISSU) devices are auto-detected
  and refused — separate v2 tool planned.
- 7 new structured `JmcpError` variants:
  `ConfirmationRequired`, `UpgradeClusterUnsupported`,
  `UpgradeCommitConfirmedActive`, `UpgradeInstallTimeout`,
  `UpgradeRebootTimeout`, `UpgradePostVerifyMismatch`,
  `UpgradeOuterTimeout`. All follow the `[code=<snake>]` Display
  convention.

### Tooling

- Workspace version bumped to `0.5.0`.

```

- [ ] **Step 3: Refresh Cargo.lock + full test sweep**

```bash
cargo build --workspace
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "$(cat <<'EOF'
chore: bump workspace version to 0.5.0 + CHANGELOG

Feature release adds upgrade_junos MCP tool (13 → 14 tools).
See docs/superpowers/specs/2026-05-15-upgrade-junos-design.md.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 15: Final CI sweep + open PR

**Files:** none

- [ ] **Step 1: Final sweep — exactly what CI runs**

```bash
cargo fmt -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

All three must pass cleanly. Any failure here means CI will block the PR.

- [ ] **Step 2: Push branch and open PR**

```bash
git push -u origin <feature-branch>
gh pr create --title "feat: add upgrade_junos MCP tool (v0.5.0)" --body "$(cat <<'EOF'
## Summary

- Adds 14th MCP tool: `upgrade_junos` (standalone Junos devices only).
- Two-call confirm protocol: call 1 returns ConfirmationRequired with plan;
  call 2 with `confirm=true` executes phases 1-7.
- Forward-only: any failure returns structured error with diagnostics; no
  auto-rollback.
- Idempotent: already-at-target skips with `status: "already_at_target"`.
- Cluster devices refused with `UpgradeClusterUnsupported`; separate v2 tool
  for ISSU planned.
- Reuses v0.4.1 `TransferLocks` so transfer_file + upgrade_junos serialize
  per-router.
- 7 new structured error variants (`[code=...]` convention).
- Workspace bumped to v0.5.0.

Design spec: `docs/superpowers/specs/2026-05-15-upgrade-junos-design.md`
Implementation plan: `docs/superpowers/plans/2026-05-15-upgrade-junos.md`

## Test plan

- [x] `cargo fmt -- --check`
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [x] `cargo test --workspace` (mocked tests only, no NETCONF dependency)
- [ ] Live smoke: `JMCP_LIVE_UPGRADE_TARGET=vsrx-test18 JMCP_LIVE_UPGRADE_IMAGE=... JMCP_LIVE_UPGRADE_TARGET_VERSION=... cargo test -p rust-junosmcp-core --test integration_upgrade_junos -- --nocapture`
- [ ] Deploy to LXC 601 and confirm `--version` reports `0.5.0`
- [ ] Confirm tool count shows 14 in `get_router_list`+tool-list output

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: After merge — release + memory updates**

(Out of plan scope, captured here for completeness.) After the PR merges:

1. Tag and release `v0.5.0` (`gh release create v0.5.0 --generate-notes` after editing notes).
2. Build + deploy binary to LXC 601 (remember: `systemctl stop` before `pct push`, then start — per `feedback_pct_push_text_file_busy.md`).
3. Verify with `pct exec 601 -- /usr/local/bin/rust-junosmcp --version`.
4. Write new memory entries:
   - `upgrade_junos_v1.md` — args, response shape, error codes, release tag
   - `upgrade_junos_cluster_v2_roadmap.md` — ISSU plan + cluster-detection helper reuse
5. Update `junos_upgrade_manual_workflow.md` — mark superseded by tool for standalone.
6. Update `MEMORY.md` index with the two new entries.
7. Update `rust_junosmcp_container_601.md` with `v0.5.0` after deploy.

---

## Self-review checklist

After the plan was written, this list was walked against the spec:

| Spec section | Implemented in task |
|---|---|
| Tool surface (args) | Task 2 |
| 7 new errors | Task 1 |
| Two-call confirm protocol | Tasks 7, 8 (preflight evaluator + dispatch) |
| Phase 0 preflight checks (cluster, version, commit-confirmed, disk) | Tasks 4, 3, 5, 7 |
| Phase 1 pre-baseline capture | Task 10 |
| Phase 2 transfer via transfer_file | Task 10 |
| Phase 3 install + reboot + session-drop tolerance | Task 10 |
| Phase 4 NETCONF wait loop | Task 11 |
| Phase 5 post-verify hard gate | Task 11 |
| Phase 6 post-baseline | Task 11 |
| Phase 7 response + baseline diff | Tasks 6, 11 |
| Per-router lock (reuse TransferLocks) | Task 8 |
| Auto-detect cluster + refuse | Tasks 4, 7 |
| Tool registration | Task 12 |
| Live integration test | Task 13 |
| Version bump + CHANGELOG | Task 14 |

No gaps identified. Helpers (`parse_junos_version`, `detect_cluster_active`, `detect_active_commit_confirmed`, `diff_baseline`, `build_success_response`, `install_error_indicates_session_drop`) are referenced consistently across tasks. Types (`PreflightFacts`, `PreflightDecision`, `UpgradeConfig`, `BuildSuccessArgs`, `BaselineDiff`) are defined exactly once and reused. Each task's tests fail before implementation and pass after, matching the TDD red→green pattern.
