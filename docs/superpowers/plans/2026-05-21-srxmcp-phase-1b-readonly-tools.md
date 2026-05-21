# `rust-srxmcp` Phase 1B — Read-only SRX status tools (srxmcp-v0.1.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `rust-srxmcp-core` with four typed, read-only SRX status tools (`get_chassis_cluster_status`, `check_srx_feature_license`, `get_srx_security_services_status`, `vpn_lifecycle_report`), bringing the `rust-srxmcp` MCP tool surface from 1 → 5. Ship as `srxmcp-v0.1.0`.

**Architecture:** One workflow module per tool plus three shared modules (`error.rs`, `absence.rs`, `xml.rs`) inside `rust-srxmcp-core`. Tools reuse `rust-junosmcp-core`'s `DeviceManager` + session pool unchanged. NETCONF replies are parsed via `quick-xml` against in-repo fixtures captured from the live lab. The four `#[tool]` methods land on `JmcpSrxHandler` next to the existing `srxmcp_status`.

**Tech Stack:** Rust 2021, tokio, rmcp 0.8, rustez 0.12 / rustnetconf 0.12 (already in workspace), quick-xml (pulled in transitively by rustnetconf), schemars, serde, thiserror, time.

**Spec:** `docs/superpowers/specs/2026-05-21-srxmcp-phase-1b-readonly-tools-design.md`

---

## File Structure

**`rust-srxmcp-core/` (modified — was an empty placeholder):**
- Modify: `rust-srxmcp-core/Cargo.toml` — add real deps
- Create: `rust-srxmcp-core/src/lib.rs` — module exports
- Create: `rust-srxmcp-core/src/error.rs` — `SrxError` taxonomy
- Create: `rust-srxmcp-core/src/absence.rs` — `SrxState`, `SrxToolResponse<T>`, helpers
- Create: `rust-srxmcp-core/src/xml.rs` — `multi_re_split`, `find_child`, `text_of`
- Create: `rust-srxmcp-core/src/workflows/mod.rs`
- Create: `rust-srxmcp-core/src/workflows/cluster_status.rs`
- Create: `rust-srxmcp-core/src/workflows/license.rs`
- Create: `rust-srxmcp-core/src/workflows/services_status.rs`
- Create: `rust-srxmcp-core/src/workflows/vpn_report.rs`

**Fixtures (created from live lab captures):**
- `rust-srxmcp-core/tests/fixtures/cluster_status/{standalone_not_configured.xml, clustered_healthy.xml, node_unreachable.xml}`
- `rust-srxmcp-core/tests/fixtures/license/{eval_trial.xml, permanent.xml, none_installed.xml}`
- `rust-srxmcp-core/tests/fixtures/services_status/{standalone_vsrx.xml, clustered.xml, sub_not_configured.xml}` (one per sub-RPC for the third case)
- `rust-srxmcp-core/tests/fixtures/vpn_report/{no_sas.xml, active_tunnel.xml, ike_only.xml, not_configured.xml}` (per RPC, two files each: `*_ike.xml` and `*_ipsec.xml`)

**`rust-srxmcp/` (modified):**
- Modify: `rust-srxmcp/Cargo.toml` — bump `version` to `0.1.0`, depend on `rust-srxmcp-core` for the real workflow API
- Modify: `rust-srxmcp/src/server.rs` — register four new `#[tool]` methods on `JmcpSrxHandler`
- Modify: `rust-srxmcp/CHANGELOG.md` — `0.1.0` entry
- Modify: `rust-srxmcp/README.md` — list the new tools
- Create: `rust-srxmcp/tests/live_smoke.rs` — `#[ignore]`d live smoke per tool

**Memory (added at the end):**
- Create: `~/.claude/projects/-home-mharman-RustJunosMCP/memory/srxmcp_v0_1_0_released.md`
- Modify: `~/.claude/projects/-home-mharman-RustJunosMCP/memory/MEMORY.md`
- Modify: `~/.claude/projects/-home-mharman-RustJunosMCP/memory/rust_junosmcp_container_601.md`

**Task PR ordering (one merged PR per major task; matches spec §Sequencing):**

1. Task 1 — Foundational `rust-srxmcp-core` types (`error`, `absence`, `xml`)
2. Task 2 — `get_chassis_cluster_status`
3. Task 3 — `check_srx_feature_license`
4. Task 4 — `get_srx_security_services_status`
5. Task 5 — Lab tunnel setup (Appendix A) — blocks Task 6 fixture (2)
6. Task 6 — `vpn_lifecycle_report`
7. Task 7 — Version bump + CHANGELOG + tag + deploy + smoke + memory

---

## Task 1: Foundational types — `error`, `absence`, `xml`

**Goal of this task:** Land the shared scaffolding so every tool task that follows is a thin, additive change.

**Files:**
- Modify: `rust-srxmcp-core/Cargo.toml`
- Create: `rust-srxmcp-core/src/lib.rs`
- Create: `rust-srxmcp-core/src/error.rs`
- Create: `rust-srxmcp-core/src/absence.rs`
- Create: `rust-srxmcp-core/src/xml.rs`
- Create: `rust-srxmcp-core/src/workflows/mod.rs`

### Steps

- [ ] **Step 1: Update `rust-srxmcp-core/Cargo.toml` with real deps**

Replace the existing `[dependencies]` placeholder block:

```toml
[dependencies]
rust-junosmcp-core = { path = "../rust-junosmcp-core" }
rustez             = { workspace = true }
serde              = { workspace = true, features = ["derive"] }
serde_json         = { workspace = true }
thiserror          = { workspace = true }
tracing            = { workspace = true }
schemars           = { workspace = true }
quick-xml          = "0.36"
time               = { version = "0.3", features = ["serde", "parsing", "formatting", "macros"] }
tokio              = { workspace = true, features = ["macros", "rt", "time"] }

[dev-dependencies]
pretty_assertions  = "1"
tokio              = { workspace = true, features = ["macros", "rt-multi-thread", "time"] }
```

- [ ] **Step 2: Write `rust-srxmcp-core/src/lib.rs`**

```rust
//! Core workflows + shared types for `rust-srxmcp`.
//!
//! This crate is consumed by the `rust-srxmcp` binary. It owns the typed
//! tool response envelope (`SrxToolResponse<T>`), absence semantics
//! (`SrxState`), the multi-RE XML helper, the `SrxError` taxonomy, and
//! one `workflows::<tool>` module per Phase 1B tool.

pub mod absence;
pub mod error;
pub mod workflows;
pub mod xml;

pub use absence::{SrxState, SrxToolResponse};
pub use error::SrxError;
```

- [ ] **Step 3: Write the failing `SrxError` shape test**

Create `rust-srxmcp-core/src/error.rs` with the test first:

```rust
//! Error taxonomy for SRX workflows.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SrxError {
    #[error("transport: {0}")]
    Transport(#[from] rust_junosmcp_core::JmcpError),

    #[error("rpc error: {tag} ({severity}) — {message}")]
    Rpc {
        tag: String,
        severity: String,
        message: String,
    },

    #[error("xml parse: {0}")]
    Parse(String),

    #[error("schema mismatch in {rpc}: missing required element <{element}>")]
    SchemaMismatch {
        rpc: &'static str,
        element: &'static str,
    },

    #[error("invalid input: {0}")]
    InvalidInput(String),
}

impl SrxError {
    /// Convenience builder used by per-tool parsers.
    pub fn schema(rpc: &'static str, element: &'static str) -> Self {
        Self::SchemaMismatch { rpc, element }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_mismatch_displays_rpc_and_element() {
        let e = SrxError::schema("get-chassis-cluster-status-information", "cluster-id");
        let s = e.to_string();
        assert!(s.contains("get-chassis-cluster-status-information"), "{s}");
        assert!(s.contains("cluster-id"), "{s}");
    }

    #[test]
    fn rpc_variant_includes_tag_and_message() {
        let e = SrxError::Rpc {
            tag: "data-missing".into(),
            severity: "error".into(),
            message: "configuration database empty".into(),
        };
        let s = e.to_string();
        assert!(s.contains("data-missing"));
        assert!(s.contains("configuration database empty"));
    }
}
```

- [ ] **Step 4: Run the error tests to make sure they pass**

Run: `cargo test -p rust-srxmcp-core --lib error::tests`
Expected: 2/2 passing.

- [ ] **Step 5: Write `absence.rs` with TDD — the helpers come first as failing tests**

Create `rust-srxmcp-core/src/absence.rs`:

```rust
//! Absence semantics — `SrxState` + the `SrxToolResponse<T>` envelope.

use schemars::JsonSchema;
use serde::Serialize;

#[derive(Debug, Serialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SrxState {
    Active,
    NotConfigured,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SrxToolResponse<T: JsonSchema + Serialize> {
    pub state: SrxState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_xml: Option<String>,
}

impl<T: JsonSchema + Serialize> SrxToolResponse<T> {
    pub fn active(data: T) -> Self {
        Self { state: SrxState::Active, data: Some(data), reason: None, raw_xml: None }
    }

    pub fn not_configured(reason: impl Into<String>) -> Self {
        Self {
            state: SrxState::NotConfigured,
            data: None,
            reason: Some(reason.into()),
            raw_xml: None,
        }
    }

    pub fn with_raw(mut self, raw: String) -> Self {
        self.raw_xml = Some(raw);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Debug, Serialize, JsonSchema)]
    struct Body { ok: bool }

    #[test]
    fn active_serializes_with_data_no_reason() {
        let r = SrxToolResponse::<Body>::active(Body { ok: true });
        let j = serde_json::to_value(&r).unwrap();
        assert_eq!(j["state"], "active");
        assert_eq!(j["data"]["ok"], true);
        assert!(j.get("reason").is_none());
        assert!(j.get("raw_xml").is_none());
    }

    #[test]
    fn not_configured_serializes_with_reason_no_data() {
        let r = SrxToolResponse::<Body>::not_configured("disabled");
        let j = serde_json::to_value(&r).unwrap();
        assert_eq!(j["state"], "not_configured");
        assert_eq!(j["reason"], "disabled");
        assert!(j.get("data").is_none());
    }

    #[test]
    fn with_raw_attaches_xml() {
        let r = SrxToolResponse::<Body>::active(Body { ok: true })
            .with_raw("<x/>".into());
        let j = serde_json::to_value(&r).unwrap();
        assert_eq!(j["raw_xml"], "<x/>");
    }
}
```

- [ ] **Step 6: Run absence tests**

Run: `cargo test -p rust-srxmcp-core --lib absence::tests`
Expected: 3/3 passing.

- [ ] **Step 7: Write the failing `multi_re_split` test FIRST in `xml.rs`**

Create `rust-srxmcp-core/src/xml.rs`. Define the public types & test before the implementation:

```rust
//! XML helpers shared across SRX workflows. Thin wrapper around quick-xml
//! that keeps every tool out of the multi-RE envelope business.

use quick_xml::events::Event;
use quick_xml::Reader;

/// One node's payload after stripping the multi-RE envelope.
///
/// `re_name` is `""` for standalone devices, `"node0"` / `"node1"` for
/// clustered devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReNode {
    pub re_name: String,
    /// Raw XML for everything inside this node's `<multi-routing-engine-item>`
    /// (or the full document body for standalone devices).
    pub inner_xml: String,
}

/// Split an `<rpc-reply>` body into per-RE chunks. Returns a single-element
/// vec with `re_name == ""` for standalone devices.
pub fn multi_re_split(reply_xml: &str) -> Result<Vec<ReNode>, crate::SrxError> {
    let mut reader = Reader::from_str(reply_xml);
    reader.config_mut().trim_text(true);
    let mut nodes = Vec::new();
    let mut depth = 0_usize;
    let mut in_envelope = false;
    let mut current_name: Option<String> = None;
    let mut current_inner: Option<String> = None;
    let mut capture_depth = 0_usize;
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(crate::SrxError::Parse(e.to_string())),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = std::str::from_utf8(e.name().as_ref()).unwrap_or("").to_string();
                depth += 1;
                if name == "multi-routing-engine-results" {
                    in_envelope = true;
                } else if in_envelope && name == "multi-routing-engine-item" {
                    current_name = None;
                    current_inner = Some(String::new());
                    capture_depth = depth;
                } else if current_inner.is_some() && capture_depth > 0 && depth > capture_depth + 1 {
                    // collect raw XML inside the item
                    if let Some(inner) = current_inner.as_mut() {
                        inner.push_str(&reader.read_event_xml_raw_around(&e));
                    }
                } else if current_inner.is_some() && name == "re-name" {
                    // resolved below in Text event
                }
                let _ = name;
            }
            Ok(Event::End(_e)) => {
                if depth > 0 { depth -= 1; }
                if in_envelope && depth == capture_depth.saturating_sub(1) && current_inner.is_some() {
                    nodes.push(ReNode {
                        re_name: current_name.take().unwrap_or_default(),
                        inner_xml: current_inner.take().unwrap_or_default(),
                    });
                    capture_depth = 0;
                }
            }
            Ok(Event::Text(t)) => {
                // re-name capture
                if current_inner.is_some() && current_name.is_none() {
                    if let Ok(s) = t.unescape() {
                        let s = s.trim();
                        // crude heuristic: the only <re-name> text we ever see inside an item
                        if (s == "node0" || s == "node1" || s == "re0" || s == "re1") && current_name.is_none() {
                            current_name = Some(s.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
        buf.clear();
    }
    if !in_envelope {
        // Standalone device: return the full body as a single ReNode.
        return Ok(vec![ReNode { re_name: String::new(), inner_xml: reply_xml.to_string() }]);
    }
    Ok(nodes)
}

/// Find the first child element matching `name` and return its inner text,
/// trimmed. Returns `None` if absent.
pub fn text_of(xml: &str, name: &str) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut matching = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Err(_) | Ok(Event::Eof) => return None,
            Ok(Event::Start(e)) => {
                if e.name().as_ref() == name.as_bytes() { matching = true; }
            }
            Ok(Event::Text(t)) if matching => {
                return t.unescape().ok().map(|s| s.trim().to_string());
            }
            Ok(Event::End(_)) => matching = false,
            _ => {}
        }
        buf.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_reply_returns_one_node_empty_name() {
        let xml = "<rpc-reply><a><b>x</b></a></rpc-reply>";
        let v = multi_re_split(xml).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].re_name, "");
        assert!(v[0].inner_xml.contains("<b>x</b>"));
    }

    #[test]
    fn multi_re_envelope_yields_per_node() {
        let xml = r#"
<rpc-reply>
  <multi-routing-engine-results>
    <multi-routing-engine-item>
      <re-name>node0</re-name>
      <chassis-cluster-status><cluster-id>1</cluster-id></chassis-cluster-status>
    </multi-routing-engine-item>
    <multi-routing-engine-item>
      <re-name>node1</re-name>
      <chassis-cluster-status><cluster-id>1</cluster-id></chassis-cluster-status>
    </multi-routing-engine-item>
  </multi-routing-engine-results>
</rpc-reply>"#;
        let v = multi_re_split(xml).unwrap();
        let names: Vec<_> = v.iter().map(|n| n.re_name.as_str()).collect();
        assert!(names.contains(&"node0"));
        assert!(names.contains(&"node1"));
    }

    #[test]
    fn text_of_returns_first_match() {
        let xml = "<a><b>hello</b><b>world</b></a>";
        assert_eq!(text_of(xml, "b").as_deref(), Some("hello"));
        assert!(text_of(xml, "missing").is_none());
    }
}
```

> **Note for implementer:** `read_event_xml_raw_around` doesn't exist in quick-xml — that's a placeholder for the implementer to choose how to capture inner XML. Simplest workable approach: keep a `Vec<u8>` of byte ranges via `reader.buffer_position()` and copy from the original `reply_xml`. If that proves brittle, fall back to building an intermediate DOM with `roxmltree` (add as a dep) and writing nodes back to string. Adjust the implementation but keep the test assertions and the public signature exactly as written.

- [ ] **Step 8: Run xml tests to verify they pass**

Run: `cargo test -p rust-srxmcp-core --lib xml::tests`
Expected: 3/3 passing.

If `multi_re_split` does not pass cleanly with quick-xml alone, swap in `roxmltree` (add to deps) and re-implement — the public API + tests stay the same.

- [ ] **Step 9: Add empty `workflows/mod.rs`**

```rust
//! One module per Phase 1B tool. Each exposes a single public
//! `async fn run(&PooledDevice, args) -> Result<SrxToolResponse<T>, SrxError>`.

// Wired in subsequent tasks:
// pub mod cluster_status;
// pub mod license;
// pub mod services_status;
// pub mod vpn_report;
```

- [ ] **Step 10: Verify the crate builds clean**

Run: `cargo build -p rust-srxmcp-core && cargo test -p rust-srxmcp-core && cargo clippy -p rust-srxmcp-core -- -D warnings && cargo fmt -p rust-srxmcp-core -- --check`
Expected: all green.

- [ ] **Step 11: Commit foundational types**

```bash
git checkout -b feat/srxmcp-phase1b-foundations
git add rust-srxmcp-core/Cargo.toml rust-srxmcp-core/src
git commit -m "feat(srxmcp-core): add SrxError/SrxToolResponse/xml helpers for Phase 1B

Lays the foundational types referenced by every Phase 1B tool. No workflows
yet — those land in follow-up PRs (cluster_status, license, services_status,
vpn_report). Adds rustez, quick-xml, time, tracing, schemars, thiserror deps
to the previously empty rust-srxmcp-core crate.

Refs design: docs/superpowers/specs/2026-05-21-srxmcp-phase-1b-readonly-tools-design.md"
```

- [ ] **Step 12: Push, open PR, merge after CI green**

```bash
git push -u origin feat/srxmcp-phase1b-foundations
gh pr create --title "feat(srxmcp-core): Phase 1B foundational types" --body "$(cat <<'EOF'
## Summary
- Adds `SrxError`, `SrxState`, `SrxToolResponse<T>`, and `multi_re_split` to the previously empty `rust-srxmcp-core` crate.
- No tool wiring yet — purely foundational. Workflow modules land in subsequent PRs.

## Test plan
- [x] `cargo test -p rust-srxmcp-core`
- [x] `cargo clippy -p rust-srxmcp-core -- -D warnings`
- [x] `cargo fmt --check`

Refs: docs/superpowers/specs/2026-05-21-srxmcp-phase-1b-readonly-tools-design.md
EOF
)"
```

Wait for CI green, then rebase-merge via the GitHub UI or `gh pr merge --rebase`.

---

## Task 2: `get_chassis_cluster_status`

**Goal of this task:** First end-to-end tool. Simplest RPC, exercises multi-RE on the real lab cluster `vSRX-test19-20`.

**Files:**
- Create: `rust-srxmcp-core/src/workflows/cluster_status.rs`
- Modify: `rust-srxmcp-core/src/workflows/mod.rs` (unhide `cluster_status`)
- Create: `rust-srxmcp-core/tests/fixtures/cluster_status/standalone_not_configured.xml`
- Create: `rust-srxmcp-core/tests/fixtures/cluster_status/clustered_healthy.xml`
- Create: `rust-srxmcp-core/tests/fixtures/cluster_status/node_unreachable.xml`
- Modify: `rust-srxmcp-core/src/lib.rs` — re-export `cluster_status::*`
- Modify: `rust-srxmcp/src/server.rs` — add `get_chassis_cluster_status` `#[tool]` method
- Modify: `rust-srxmcp/Cargo.toml` — depend on `rmcp` is already present; nothing new

### Steps

- [ ] **Step 1: Capture lab fixtures**

Branch: `git checkout main && git pull && git checkout -b feat/srxmcp-cluster-status`

Capture via the existing rust-junosmcp endpoint at `:30031`. Use the `execute_junos_command` MCP tool with `| display xml` against vSRX-test10 (standalone) and vSRX-test19-20 (cluster). Save raw replies to fixture files. Strip the `<rpc-reply>` wrapper if present — fixtures should contain the body.

For `node_unreachable.xml`, hand-edit `clustered_healthy.xml`: replace node1's `<chassis-cluster-status>` content with a `<rpc-error><error-tag>operation-failed</error-tag><error-message>node unreachable</error-message></rpc-error>`.

- [ ] **Step 2: Write the failing parser test**

Create `rust-srxmcp-core/src/workflows/cluster_status.rs`:

```rust
//! `get_chassis_cluster_status` — chassis-cluster topology + health snapshot.

use crate::absence::{SrxState, SrxToolResponse};
use crate::error::SrxError;
use crate::xml::multi_re_split;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ClusterStatusArgs {
    pub router: String,
    #[serde(default)]
    pub include_raw: bool,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct ClusterStatusData {
    pub cluster_id: u16,
    pub nodes: Vec<ClusterNode>,
    pub redundancy_groups: Vec<RedundancyGroup>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct ClusterNode {
    pub name: String,
    pub priority: u16,
    pub status: String,
    pub monitor_failures: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct RedundancyGroup {
    pub group_id: u16,
    pub failover_count: u32,
    pub members: Vec<RgMember>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct RgMember {
    pub node: String,
    pub priority: u16,
    pub status: String,
    pub preempt: bool,
    pub manual: bool,
    pub monitor_failures: Vec<String>,
}

/// Pure parser — used by tests and by `run()`.
pub fn parse(reply_xml: &str) -> Result<SrxToolResponse<ClusterStatusData>, SrxError> {
    // 1. multi_re_split — flatten the envelope.
    // 2. find the first <chassis-cluster-status> child of any node.
    // 3. If none present AND any <rpc-error> tag application='not-configured': NotConfigured.
    // 4. Otherwise extract cluster-id, cluster-node entries, redundancy-group entries.
    todo!("implement parser against fixtures in tests/fixtures/cluster_status/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn load(name: &str) -> String {
        std::fs::read_to_string(
            format!("tests/fixtures/cluster_status/{name}")
        ).unwrap()
    }

    #[test]
    fn standalone_returns_not_configured() {
        let xml = load("standalone_not_configured.xml");
        let r = parse(&xml).unwrap();
        assert_eq!(r.state, SrxState::NotConfigured);
        assert!(r.data.is_none());
        assert!(r.reason.as_deref().unwrap_or("").contains("cluster"));
    }

    #[test]
    fn clustered_healthy_two_nodes_two_rgs() {
        let xml = load("clustered_healthy.xml");
        let r = parse(&xml).unwrap();
        assert_eq!(r.state, SrxState::Active);
        let d = r.data.unwrap();
        assert_eq!(d.cluster_id, 1);
        assert_eq!(d.nodes.len(), 2);
        assert!(d.nodes.iter().any(|n| n.name == "node0" && n.status == "primary"));
        assert!(d.nodes.iter().any(|n| n.name == "node1" && n.status == "secondary"));
        assert_eq!(d.redundancy_groups.len(), 2);
        for n in &d.nodes {
            assert!(n.monitor_failures.is_empty(), "{n:?}");
        }
    }

    #[test]
    fn node_unreachable_still_active_one_node_present() {
        let xml = load("node_unreachable.xml");
        let r = parse(&xml).unwrap();
        assert_eq!(r.state, SrxState::Active);
        let d = r.data.unwrap();
        // Only the live node has full data; the unreachable node is dropped.
        assert_eq!(d.nodes.len(), 1);
        assert_eq!(d.nodes[0].name, "node0");
    }
}
```

- [ ] **Step 3: Run the test — verify it fails**

Run: `cargo test -p rust-srxmcp-core --lib workflows::cluster_status::tests`
Expected: 3/3 fail with `not yet implemented` / `todo!` panic.

- [ ] **Step 4: Implement `parse()` to pass all three tests**

Replace the `todo!()` body. Use `multi_re_split(reply_xml)?` then for each `ReNode`, search for `<chassis-cluster-status>` inside `inner_xml` via a second `quick_xml::Reader` pass. Extract:
- `<cluster-id>` → `u16`
- All `<cluster-status-information><cluster-node>` (Junos varies — match either `<cluster-node>` directly under `<chassis-cluster-status>` or under a `<cluster-status-information>` wrapper)
- Inside each node: `<name>`, `<priority>`, `<status>`, `<failures>` (`"None"` → empty vec, else comma-split + trim)
- All `<redundancy-group>` entries: `<group-id>`, `<failover-count>`, then nested `<node>` members with same shape as cluster nodes plus `<preempt>` (`"yes"`/`"no"`) and `<manual-failover>`

Treat any `<rpc-error>` with `<error-tag>application/not-configured</error-tag>` OR an empty body as `not_configured("chassis cluster disabled")`.

If a per-node payload contains `<rpc-error>` instead of `<chassis-cluster-status>`, skip that node (don't add it to the result) — this is the partial-cluster case.

- [ ] **Step 5: Run tests until 3/3 pass**

Run: `cargo test -p rust-srxmcp-core --lib workflows::cluster_status::tests`
Expected: 3/3 PASS. Iterate parser until green.

- [ ] **Step 6: Add `run()` against a live `PooledDevice`**

Append to `cluster_status.rs`:

```rust
use rust_junosmcp_core::device_manager::PooledDevice;

pub async fn run(
    device: &mut PooledDevice,
    args: ClusterStatusArgs,
) -> Result<SrxToolResponse<ClusterStatusData>, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    let mut exec = device.rpc();
    let reply = exec
        .call("get-chassis-cluster-status-information", &[])
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let mut parsed = parse(&reply)?;
    if args.include_raw {
        parsed = parsed.with_raw(reply);
    }
    Ok(parsed)
}
```

> **Note:** Confirm `PooledDevice::rpc()` returns a `rustez::RpcExecutor<'_>`. If `PooledDevice` doesn't directly expose `rpc()`, dereference: `(&mut *device).rpc()`. The `Deref` impl from device_manager.rs:147 makes this work.

- [ ] **Step 7: Wire workflow exports in `lib.rs` and `workflows/mod.rs`**

In `rust-srxmcp-core/src/workflows/mod.rs`:
```rust
pub mod cluster_status;
```

In `rust-srxmcp-core/src/lib.rs` after the existing `pub use`:
```rust
pub use workflows::cluster_status::{
    ClusterStatusArgs, ClusterStatusData, ClusterNode, RedundancyGroup, RgMember,
};
```

- [ ] **Step 8: Add the `#[tool]` method in `rust-srxmcp/src/server.rs`**

Inside the `#[tool_router] impl JmcpSrxHandler { … }` block, add a sibling tool. The handler needs access to the `DeviceManager`, which 0.0.1 doesn't currently hold — so add `device_manager: Arc<DeviceManager>` to `JmcpSrxHandler` first.

Modify `JmcpSrxHandler`:

```rust
use rust_junosmcp_core::device_manager::DeviceManager;

#[derive(Clone)]
pub struct JmcpSrxHandler {
    started: Arc<Instant>,
    device_manager: Arc<DeviceManager>,
}

impl JmcpSrxHandler {
    pub fn new(started: Arc<Instant>, device_manager: Arc<DeviceManager>) -> Self {
        Self { started, device_manager }
    }
    // existing srxmcp_status_body / srxmcp_status_test unchanged
}
```

Update `main.rs` to construct the `DeviceManager` from the loaded inventory + host-key policy (mirror how `rust-junosmcp/src/main.rs` does it) and pass `Arc::new(dm)` into `JmcpSrxHandler::new`.

Then in the `#[tool_router]` impl:

```rust
#[tool(
    name = "get_chassis_cluster_status",
    description = "Chassis-cluster topology + health snapshot. Returns \
                   state=not_configured for standalone SRX devices."
)]
async fn get_chassis_cluster_status(
    &self,
    Parameters(args): Parameters<rust_srxmcp_core::ClusterStatusArgs>,
    _extensions: Extensions,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let mut device = self
        .device_manager
        .open(&args.router)
        .await
        .map_err(|e| rmcp::ErrorData::internal_error(format!("opening device: {e}"), None))?;
    let resp = rust_srxmcp_core::workflows::cluster_status::run(&mut device, args)
        .await
        .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;
    let body = serde_json::to_string_pretty(&resp).map_err(|e| {
        rmcp::ErrorData::internal_error(format!("serializing ClusterStatusData: {e}"), None)
    })?;
    Ok(CallToolResult::success(vec![Content::text(body)]))
}
```

- [ ] **Step 9: Build + test the workspace**

Run: `cargo build -p rust-srxmcp -p rust-srxmcp-core && cargo test -p rust-srxmcp-core && cargo clippy -p rust-srxmcp -p rust-srxmcp-core -- -D warnings && cargo fmt -- --check`
Expected: all green.

- [ ] **Step 10: Commit**

```bash
git add rust-srxmcp-core/src/workflows/cluster_status.rs \
        rust-srxmcp-core/src/workflows/mod.rs \
        rust-srxmcp-core/src/lib.rs \
        rust-srxmcp-core/tests/fixtures/cluster_status \
        rust-srxmcp/src/server.rs \
        rust-srxmcp/src/main.rs
git commit -m "feat(srxmcp): add get_chassis_cluster_status tool

First Phase 1B tool. Parses <get-chassis-cluster-status-information>
NETCONF reply into typed ClusterStatusData. Standalone devices return
state=not_configured; clustered devices yield per-node ClusterNode +
RedundancyGroup arrays. Fixtures captured from vSRX-test10 (standalone)
and vSRX-test19-20 (real cluster).

Refs spec §Tool 3."
```

- [ ] **Step 11: PR + review + merge + deploy & smoke**

```bash
git push -u origin feat/srxmcp-cluster-status
gh pr create --title "feat(srxmcp): get_chassis_cluster_status" --body "..."
```

After merge, deploy to LXC 601 (deferred to final Task 7 — don't bump the version yet; this stays on `0.0.1` until all four tools merged).

---

## Task 3: `check_srx_feature_license`

**Goal of this task:** Exercise the closed enum + absence rule. No multi-RE complications.

**Files:**
- Create: `rust-srxmcp-core/src/workflows/license.rs`
- Modify: `rust-srxmcp-core/src/workflows/mod.rs`
- Modify: `rust-srxmcp-core/src/lib.rs`
- Modify: `rust-srxmcp/src/server.rs`
- Create: `rust-srxmcp-core/tests/fixtures/license/{eval_trial.xml, permanent.xml, none_installed.xml}`

### Steps

- [ ] **Step 1: Capture license fixtures**

Branch: `git checkout main && git pull && git checkout -b feat/srxmcp-license`

Use the live junosmcp to capture `<get-license-summary-information/>` and `<get-license-key-information/>` against vSRX-test10. The lab has eval/trial licenses — save as `eval_trial.xml`. For `permanent.xml`, hand-edit eval_trial to change `<license-type>eval</license-type>` and `<end-date>` to a permanent indicator. For `none_installed.xml`, an empty `<license-summary-information/>` body.

- [ ] **Step 2: Write the failing parser tests**

Create `rust-srxmcp-core/src/workflows/license.rs`:

```rust
use crate::absence::{SrxState, SrxToolResponse};
use crate::error::SrxError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum SrxLicensedFeature {
    Idp, AppId, UtmAntivirus, WebFiltering,
    AntiSpam, SecIntel, AtpCloud, SslProxy,
}

impl SrxLicensedFeature {
    /// Case-insensitive substring patterns matched against the Junos
    /// `<feature-name>` / "Feature" column.
    pub fn record_patterns(&self) -> &'static [&'static str] {
        match self {
            Self::Idp           => &["idp", "intrusion"],
            Self::AppId         => &["application identification", "appid"],
            Self::UtmAntivirus  => &["antivirus", "av-key", "av_key"],
            Self::WebFiltering  => &["web filtering", "url filtering"],
            Self::AntiSpam      => &["anti-spam", "antispam"],
            Self::SecIntel      => &["secintel", "security intelligence"],
            Self::AtpCloud      => &["atp", "advanced threat"],
            Self::SslProxy      => &["ssl proxy", "ssl forward proxy"],
        }
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct LicenseArgs {
    pub router: String,
    pub feature: SrxLicensedFeature,
    #[serde(default)]
    pub include_raw: bool,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct LicenseData {
    pub feature: SrxLicensedFeature,
    pub license_records: Vec<LicenseRecord>,
    pub counts: LicenseCounts,
    #[serde(with = "time::serde::rfc3339::option")]
    pub earliest_expiry: Option<OffsetDateTime>,
    pub all_permanent: bool,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct LicenseCounts { pub used: u32, pub installed: u32, pub needed: u32 }

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct LicenseRecord {
    pub feature_name: String,
    pub license_type: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub end_date: Option<OffsetDateTime>,
}

pub fn parse(
    feature: SrxLicensedFeature,
    summary_xml: &str,
    key_xml: &str,
) -> Result<SrxToolResponse<LicenseData>, SrxError> {
    todo!("filter records by feature.record_patterns() case-insensitive substring match")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(name: &str) -> String {
        std::fs::read_to_string(format!("tests/fixtures/license/{name}")).unwrap()
    }

    #[test]
    fn eval_trial_idp_returns_not_configured_when_lab_has_no_idp_records() {
        // Lab eval/trial licenses don't include IDP — expect not_configured.
        let s = load("eval_trial.xml");
        let r = parse(SrxLicensedFeature::Idp, &s, &s).unwrap();
        assert_eq!(r.state, SrxState::NotConfigured);
    }

    #[test]
    fn permanent_idp_marks_all_permanent_true() {
        let s = load("permanent.xml");
        let r = parse(SrxLicensedFeature::Idp, &s, &s).unwrap();
        assert_eq!(r.state, SrxState::Active);
        let d = r.data.unwrap();
        assert!(d.all_permanent);
        assert!(d.earliest_expiry.is_none());
    }

    #[test]
    fn none_installed_returns_not_configured() {
        let s = load("none_installed.xml");
        let r = parse(SrxLicensedFeature::Idp, &s, &s).unwrap();
        assert_eq!(r.state, SrxState::NotConfigured);
        assert!(r.reason.as_deref().unwrap_or("").to_lowercase().contains("not present"));
    }
}
```

- [ ] **Step 3: Run tests — confirm 3 failures**

Run: `cargo test -p rust-srxmcp-core --lib workflows::license::tests`
Expected: 3/3 fail.

- [ ] **Step 4: Implement `parse()`**

Walk both XMLs once each with quick-xml. Collect every `<feature-name>` text → lowercase compare against `feature.record_patterns()`. For each match, extract the surrounding record's `<license-type>` and `<end-date>` (ISO 8601 — use `time::OffsetDateTime::parse(s, &time::format_description::well_known::Iso8601::DEFAULT)`).

Aggregate `counts` from any sibling `<licenses-used>`/`<licenses-installed>`/`<licenses-needed>` in matched records (sum). `all_permanent = license_records.iter().all(|r| r.end_date.is_none() || license_type=="permanent")`. `earliest_expiry = license_records.iter().filter_map(|r| r.end_date).min()`.

If `license_records.is_empty()` → `SrxToolResponse::not_configured(format!("{:?} not present in installed licenses", feature))`.

- [ ] **Step 5: Run tests until green**

Run: `cargo test -p rust-srxmcp-core --lib workflows::license::tests`
Expected: 3/3 PASS.

- [ ] **Step 6: Add `run()` and wire the `#[tool]` method**

```rust
pub async fn run(
    device: &mut rust_junosmcp_core::device_manager::PooledDevice,
    args: LicenseArgs,
) -> Result<SrxToolResponse<LicenseData>, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    let mut exec = device.rpc();
    let summary = exec.call("get-license-summary-information", &[]).await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let keys = exec.call("get-license-key-information", &[]).await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let mut parsed = parse(args.feature, &summary, &keys)?;
    if args.include_raw {
        parsed = parsed.with_raw(format!("<!-- summary -->\n{summary}\n<!-- keys -->\n{keys}"));
    }
    Ok(parsed)
}
```

Wire into `rust-srxmcp/src/server.rs` analogously to Task 2 Step 8. Tool name: `check_srx_feature_license`. Tool args type: `rust_srxmcp_core::workflows::license::LicenseArgs`.

- [ ] **Step 7: Build + lint + test + commit**

```bash
cargo build -p rust-srxmcp -p rust-srxmcp-core && \
cargo test -p rust-srxmcp-core && \
cargo clippy -p rust-srxmcp -p rust-srxmcp-core -- -D warnings && \
cargo fmt -- --check
git add rust-srxmcp-core/src/workflows/license.rs \
        rust-srxmcp-core/src/workflows/mod.rs \
        rust-srxmcp-core/src/lib.rs \
        rust-srxmcp-core/tests/fixtures/license \
        rust-srxmcp/src/server.rs
git commit -m "feat(srxmcp): add check_srx_feature_license tool

Maps a closed SrxLicensedFeature enum (Idp/AppId/UtmAntivirus/WebFiltering/
AntiSpam/SecIntel/AtpCloud/SslProxy) to the matching license records on the
device. Returns state=not_configured when no records match, including the
expected lab case (eval/trial licenses don't include IDP).

Refs spec §Tool 1."
```

- [ ] **Step 8: PR + merge**

```bash
git push -u origin feat/srxmcp-license
gh pr create --title "feat(srxmcp): check_srx_feature_license" --body "..."
```

---

## Task 4: `get_srx_security_services_status`

**Goal of this task:** Exercise concurrent sub-RPCs via `tokio::try_join!` and per-sub-service absence semantics.

**Files:**
- Create: `rust-srxmcp-core/src/workflows/services_status.rs`
- Modify: `rust-srxmcp-core/src/workflows/mod.rs`
- Modify: `rust-srxmcp-core/src/lib.rs`
- Modify: `rust-srxmcp/src/server.rs`
- Create: `rust-srxmcp-core/tests/fixtures/services_status/{idp_active.xml, appid_active.xml, utm_av_not_configured.xml, secintel_not_configured.xml, atp_not_configured.xml, idp_clustered.xml}`

### Steps

- [ ] **Step 1: Capture fixtures**

Branch: `git checkout main && git pull && git checkout -b feat/srxmcp-services-status`

Capture each sub-RPC reply against vSRX-test10:
- `<get-idp-security-package-version/>` → `idp_active.xml`
- `<get-appid-application-version/>` → `appid_active.xml`
- `<get-utm-anti-virus-status/>` → likely `<rpc-error application='not-configured'>` on vSRX → save as `utm_av_not_configured.xml`
- `<get-secintel-feed-summary/>` → same → `secintel_not_configured.xml`
- `<get-atp-cloud-info/>` → same → `atp_not_configured.xml`

For `idp_clustered.xml`, capture against vSRX-test19-20 (with the multi-RE envelope).

- [ ] **Step 2: Write the failing parser tests**

Create `rust-srxmcp-core/src/workflows/services_status.rs`:

```rust
use crate::absence::{SrxState, SrxToolResponse};
use crate::error::SrxError;
use crate::xml::multi_re_split;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ServicesStatusArgs {
    pub router: String,
    #[serde(default)]
    pub include_raw: bool,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct ServicesStatusData { pub nodes: Vec<NodeServicesStatus> }

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct NodeServicesStatus {
    pub re_name: String,
    pub idp: SubServiceStatus<IdpInfo>,
    pub appid: SubServiceStatus<AppIdInfo>,
    pub utm_av: SubServiceStatus<UtmAvInfo>,
    pub secintel: SubServiceStatus<SecIntelInfo>,
    pub atp_cloud: SubServiceStatus<AtpCloudInfo>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct SubServiceStatus<T: schemars::JsonSchema + Serialize + PartialEq + Eq> {
    pub state: SrxState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct IdpInfo { pub package_version: String, pub detector_version: String }
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct AppIdInfo { pub version: String }
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct UtmAvInfo { pub engine_version: String, pub pattern_version: String }
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct SecIntelInfo { pub feeds: Vec<String> }
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct AtpCloudInfo { pub enrolled: bool, pub realm: Option<String> }

/// Per-sub-RPC parse. `xml` is one sub-RPC's reply (already multi-RE-split
/// for a single node). Returns `Active(data)` / `NotConfigured(reason)`.
pub fn parse_idp(xml: &str) -> SubServiceStatus<IdpInfo> { todo!() }
pub fn parse_appid(xml: &str) -> SubServiceStatus<AppIdInfo> { todo!() }
pub fn parse_utm_av(xml: &str) -> SubServiceStatus<UtmAvInfo> { todo!() }
pub fn parse_secintel(xml: &str) -> SubServiceStatus<SecIntelInfo> { todo!() }
pub fn parse_atp(xml: &str) -> SubServiceStatus<AtpCloudInfo> { todo!() }

#[cfg(test)]
mod tests {
    use super::*;

    fn load(name: &str) -> String {
        std::fs::read_to_string(format!("tests/fixtures/services_status/{name}")).unwrap()
    }

    #[test] fn idp_active_parses() {
        let r = parse_idp(&load("idp_active.xml"));
        assert_eq!(r.state, SrxState::Active);
        assert!(r.data.is_some());
    }
    #[test] fn appid_active_parses() {
        let r = parse_appid(&load("appid_active.xml"));
        assert_eq!(r.state, SrxState::Active);
        assert_eq!(r.data.unwrap().version.is_empty(), false);
    }
    #[test] fn utm_av_not_configured() {
        let r = parse_utm_av(&load("utm_av_not_configured.xml"));
        assert_eq!(r.state, SrxState::NotConfigured);
    }
    #[test] fn secintel_not_configured() {
        let r = parse_secintel(&load("secintel_not_configured.xml"));
        assert_eq!(r.state, SrxState::NotConfigured);
    }
    #[test] fn atp_not_configured() {
        let r = parse_atp(&load("atp_not_configured.xml"));
        assert_eq!(r.state, SrxState::NotConfigured);
    }
}
```

- [ ] **Step 3: Run — expect 5/5 failures (todo! panics)**

Run: `cargo test -p rust-srxmcp-core --lib workflows::services_status::tests`
Expected: 5/5 panic with `not yet implemented`.

- [ ] **Step 4: Implement each `parse_*` to be schema-tolerant**

Each follows the same skeleton:
1. Look for `<rpc-error>` first. If present AND its `<error-tag>` or `<message>` contains `not-configured` (case-insensitive) → return `SubServiceStatus { state: NotConfigured, reason: Some("…"), data: None }`.
2. Otherwise extract the expected fields via `xml::text_of(...)`. If a required field is missing, fall back to `not_configured("schema mismatch")` rather than erroring — this is a per-sub-service result, not a tool-level error.
3. Build the `Active(data)` variant.

- [ ] **Step 5: Run tests until 5/5 pass**

Run: `cargo test -p rust-srxmcp-core --lib workflows::services_status::tests`

- [ ] **Step 6: Add `run()` with `tokio::try_join!`**

```rust
pub async fn run(
    device: &mut rust_junosmcp_core::device_manager::PooledDevice,
    args: ServicesStatusArgs,
) -> Result<SrxToolResponse<ServicesStatusData>, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    // rustnetconf serializes RPCs on the channel — these run sequentially,
    // but the await points keep the executor responsive.
    let mut exec = device.rpc();
    let idp = exec.call("get-idp-security-package-version", &[]).await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let appid = exec.call("get-appid-application-version", &[]).await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let utm = exec.call("get-utm-anti-virus-status", &[]).await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let secintel = exec.call("get-secintel-feed-summary", &[]).await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let atp = exec.call("get-atp-cloud-info", &[]).await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    // Multi-RE: each sub-RPC's reply is itself multi-RE-split. We zip by node name.
    let idp_n = multi_re_split(&idp)?;
    let appid_n = multi_re_split(&appid)?;
    let utm_n = multi_re_split(&utm)?;
    let secintel_n = multi_re_split(&secintel)?;
    let atp_n = multi_re_split(&atp)?;

    let node_names: Vec<String> = idp_n.iter().map(|n| n.re_name.clone()).collect();
    let nodes: Vec<NodeServicesStatus> = node_names.into_iter().enumerate().map(|(i, name)| {
        let pick = |v: &Vec<crate::xml::ReNode>| v.get(i).map(|n| n.inner_xml.as_str()).unwrap_or("");
        NodeServicesStatus {
            re_name: name,
            idp: parse_idp(pick(&idp_n)),
            appid: parse_appid(pick(&appid_n)),
            utm_av: parse_utm_av(pick(&utm_n)),
            secintel: parse_secintel(pick(&secintel_n)),
            atp_cloud: parse_atp(pick(&atp_n)),
        }
    }).collect();

    let all_absent = nodes.iter().all(|n| matches!(n.idp.state, SrxState::NotConfigured)
        && matches!(n.appid.state, SrxState::NotConfigured)
        && matches!(n.utm_av.state, SrxState::NotConfigured)
        && matches!(n.secintel.state, SrxState::NotConfigured)
        && matches!(n.atp_cloud.state, SrxState::NotConfigured));

    let mut resp = if all_absent {
        SrxToolResponse::<ServicesStatusData>::not_configured(
            "no SRX security services configured on this device",
        )
    } else {
        SrxToolResponse::<ServicesStatusData>::active(ServicesStatusData { nodes })
    };
    if args.include_raw {
        resp = resp.with_raw(format!(
            "<!-- idp -->\n{idp}\n<!-- appid -->\n{appid}\n<!-- utm -->\n{utm}\n<!-- secintel -->\n{secintel}\n<!-- atp -->\n{atp}"
        ));
    }
    Ok(resp)
}
```

- [ ] **Step 7: Wire the tool, build, lint, commit, PR, merge**

Mirror Task 2 Step 8 + 9 + 10 + 11. Tool name: `get_srx_security_services_status`.

---

## Task 5: Lab tunnel setup (Appendix A) — prerequisite for Task 6 fixture (2)

**Goal of this task:** Bring up a route-based IPsec tunnel between vSRX-test10 and vSRX-test11 so Task 6's "active tunnel" fixture can be captured.

**This task makes no code changes.** It runs against live lab devices.

### Steps

- [ ] **Step 1: Read the spec appendix**

Read Appendix A of `docs/superpowers/specs/2026-05-21-srxmcp-phase-1b-readonly-tools-design.md`. It contains the full `set` config for both devices.

- [ ] **Step 2: Identify the device external IPs**

```bash
ssh root@pve3.mechub.org 'cat /etc/pve/lxc/601.conf | head -20 && pct exec 601 -- cat /etc/jmcp/devices.json'
```

Note the `Hostname`/`Ip` for `vSRX-test10` and `vSRX-test11`. Substitute into Appendix A for `<TEST10_IP>` / `<TEST11_IP>`. `EXT_IFACE` is `ge-0/0/0.0` on lab vSRX.

- [ ] **Step 3: Apply test10's config via rust-junosmcp `load_and_commit_config`**

Use the live MCP endpoint at `http://192.168.1.194:30031/mcp`. Call `load_and_commit_config` with `router_name: "vSRX-test10"`, `config_format: "set"`, and the test10 block from Appendix A. Confirm clean commit.

- [ ] **Step 4: Apply test11's mirror config**

Same flow against `vSRX-test11`. Mirror image — swap IPs, swap st0.0 to `192.0.2.2/30`, point gateway at `<TEST10_IP>`.

- [ ] **Step 5: Verify the tunnel comes up**

Via `execute_junos_command` against vSRX-test10:
```
show security ike security-associations
show security ipsec security-associations
```
Expected: 1 IKE SA `UP`/`MATURE`, 1 IPsec SA, tunnel id > 0, lifetime ~3600s.

If down, inspect logs (`show log kmd | last 50`) — most common cause is the PSK or proposal mismatch.

- [ ] **Step 6: Save the lab note**

Update `~/.claude/projects/-home-mharman-RustJunosMCP/memory/rust_junosmcp_container_601.md` with a short entry:
> `vSRX-test10 ↔ vSRX-test11` IPsec lab tunnel applied YYYY-MM-DD per Appendix A of `2026-05-21-srxmcp-phase-1b-readonly-tools-design.md`. Used as `vpn_lifecycle_report` smoke target. To tear down: delete `security ike`, `security ipsec`, `interfaces st0`, `routing-options static route 192.0.2.0/30` on both ends.

No PR for this task — it's a lab-state change. The note in memory is the persistence.

---

## Task 6: `vpn_lifecycle_report`

**Goal of this task:** Final tool. Two concurrent RPCs, correlation by remote-address, optional `peer` and `tunnel` filters.

**Files:**
- Create: `rust-srxmcp-core/src/workflows/vpn_report.rs`
- Modify: `rust-srxmcp-core/src/workflows/mod.rs`
- Modify: `rust-srxmcp-core/src/lib.rs`
- Modify: `rust-srxmcp/src/server.rs`
- Create: `rust-srxmcp-core/tests/fixtures/vpn_report/{no_sas_ike.xml, no_sas_ipsec.xml, active_ike.xml, active_ipsec.xml, ike_only_ike.xml, ike_only_ipsec.xml, not_configured_ike.xml, not_configured_ipsec.xml}`

### Steps

- [ ] **Step 1: Capture fixtures (after Task 5 is live)**

Branch: `git checkout main && git pull && git checkout -b feat/srxmcp-vpn-report`

Capture each of `<get-ike-security-associations-information/>` and `<get-security-associations-information/>` from:
- A device with no VPN config (test12 or test16) → `no_sas_*.xml` (empty arrays) and `not_configured_*.xml` (delete `security ike` first to get `application=not-configured`)
- vSRX-test10 with the tunnel up → `active_*.xml`
- For `ike_only_*.xml`: hand-edit `active_ipsec.xml` to remove the IPsec SA element (simulates Phase 2 down)

- [ ] **Step 2: Write failing parser + correlation tests**

Create `rust-srxmcp-core/src/workflows/vpn_report.rs`:

```rust
use crate::absence::{SrxState, SrxToolResponse};
use crate::error::SrxError;
use crate::xml::multi_re_split;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VpnReportArgs {
    pub router: String,
    #[serde(default)]
    pub peer: Option<String>,
    #[serde(default)]
    pub tunnel: Option<String>,
    #[serde(default)]
    pub include_raw: bool,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct VpnReportData { pub nodes: Vec<NodeVpnReport> }

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct NodeVpnReport {
    pub re_name: String,
    pub ike_sas: Vec<IkeSa>,
    pub ipsec_sas: Vec<IpsecSa>,
    pub correlations: Vec<VpnCorrelation>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct IkeSa {
    pub index: u64, pub remote_address: String, pub state: String,
    pub mode: String, pub initiator_cookie: String, pub responder_cookie: String,
    pub lifetime_remaining_seconds: u64,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct IpsecSa {
    pub tunnel_id: u32, pub name: Option<String>, pub gateway: String,
    pub inbound_spi: String, pub outbound_spi: String,
    pub lifetime_remaining_seconds: u64,
    pub lifetime_remaining_kilobytes: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct VpnCorrelation { pub ike_sa_index: u64, pub ipsec_sa_tunnel_ids: Vec<u32> }

pub fn parse_ike(xml: &str) -> Result<Vec<IkeSa>, SrxError> { todo!() }
pub fn parse_ipsec(xml: &str) -> Result<Vec<IpsecSa>, SrxError> { todo!() }

pub fn correlate(ike: &[IkeSa], ipsec: &[IpsecSa]) -> Vec<VpnCorrelation> {
    ike.iter().map(|i| VpnCorrelation {
        ike_sa_index: i.index,
        ipsec_sa_tunnel_ids: ipsec.iter()
            .filter(|p| p.gateway == i.remote_address)
            .map(|p| p.tunnel_id).collect(),
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(n: &str) -> String {
        std::fs::read_to_string(format!("tests/fixtures/vpn_report/{n}")).unwrap()
    }

    #[test] fn no_sas_parses_to_empty() {
        let i = parse_ike(&load("no_sas_ike.xml")).unwrap();
        let p = parse_ipsec(&load("no_sas_ipsec.xml")).unwrap();
        assert!(i.is_empty());
        assert!(p.is_empty());
    }
    #[test] fn active_tunnel_parses_one_each() {
        let i = parse_ike(&load("active_ike.xml")).unwrap();
        let p = parse_ipsec(&load("active_ipsec.xml")).unwrap();
        assert_eq!(i.len(), 1);
        assert_eq!(p.len(), 1);
    }
    #[test] fn correlate_matches_by_remote_address() {
        let ike = vec![IkeSa {
            index: 42, remote_address: "203.0.113.11".into(),
            state: "UP".into(), mode: "Main".into(),
            initiator_cookie: "a".into(), responder_cookie: "b".into(),
            lifetime_remaining_seconds: 28000,
        }];
        let ipsec = vec![IpsecSa {
            tunnel_id: 1, name: Some("st0.0".into()), gateway: "203.0.113.11".into(),
            inbound_spi: "0x1".into(), outbound_spi: "0x2".into(),
            lifetime_remaining_seconds: 3500, lifetime_remaining_kilobytes: None,
        }];
        let c = correlate(&ike, &ipsec);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].ike_sa_index, 42);
        assert_eq!(c[0].ipsec_sa_tunnel_ids, vec![1]);
    }
}
```

- [ ] **Step 3: Run — expect failures**

Run: `cargo test -p rust-srxmcp-core --lib workflows::vpn_report::tests`
Expected: 3/3 fail.

- [ ] **Step 4: Implement `parse_ike` and `parse_ipsec`**

Use a single `quick_xml::Reader` pass per call. Track current element + accumulate field values into a builder. On the closing tag of `<ike-security-associations>` / `<ipsec-security-associations-block>`, push the built struct.

Junos field names (consult fixtures):
- IKE: `<sa-index>` → index, `<sa-remote-address>` → remote_address, `<sa-state>` → state, `<sa-mode>` → mode, `<sa-initiator-cookie>` → initiator_cookie, `<sa-responder-cookie>` → responder_cookie, `<sa-time-limit>` → lifetime_remaining_seconds
- IPsec: `<sa-tunnel-id>` → tunnel_id, `<sa-tunnel-name>` → name, `<sa-gateway>` → gateway, `<sa-spi-inbound>` → inbound_spi, `<sa-spi-outbound>` → outbound_spi, `<sa-life-time>` → lifetime_remaining_seconds, `<sa-life-size>` → lifetime_remaining_kilobytes

- [ ] **Step 5: Run tests until green**

Run: `cargo test -p rust-srxmcp-core --lib workflows::vpn_report::tests`

- [ ] **Step 6: Add `run()` with filters + absence detection**

```rust
pub async fn run(
    device: &mut rust_junosmcp_core::device_manager::PooledDevice,
    args: VpnReportArgs,
) -> Result<SrxToolResponse<VpnReportData>, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    let mut exec = device.rpc();
    let ike = exec.call("get-ike-security-associations-information", &[]).await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let ipsec = exec.call("get-security-associations-information", &[]).await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let both_absent = is_not_configured(&ike) && is_not_configured(&ipsec);
    if both_absent {
        let mut r = SrxToolResponse::<VpnReportData>::not_configured("security ike/ipsec stanza absent");
        if args.include_raw { r = r.with_raw(format!("<!-- ike -->\n{ike}\n<!-- ipsec -->\n{ipsec}")); }
        return Ok(r);
    }

    let ike_n = multi_re_split(&ike)?;
    let ipsec_n = multi_re_split(&ipsec)?;
    let node_names: Vec<String> = ike_n.iter().map(|n| n.re_name.clone()).collect();
    let mut nodes = Vec::new();
    for (i, name) in node_names.into_iter().enumerate() {
        let ike_xml = ike_n.get(i).map(|n| n.inner_xml.as_str()).unwrap_or("");
        let ipsec_xml = ipsec_n.get(i).map(|n| n.inner_xml.as_str()).unwrap_or("");
        let mut ike_sas = parse_ike(ike_xml)?;
        let mut ipsec_sas = parse_ipsec(ipsec_xml)?;
        if let Some(peer) = &args.peer {
            ike_sas.retain(|s| s.remote_address.contains(peer));
            ipsec_sas.retain(|s| s.gateway.contains(peer));
        }
        if let Some(tunnel) = &args.tunnel {
            ipsec_sas.retain(|s| s.name.as_deref().map(|n| n.contains(tunnel)).unwrap_or(false));
        }
        let correlations = correlate(&ike_sas, &ipsec_sas);
        nodes.push(NodeVpnReport { re_name: name, ike_sas, ipsec_sas, correlations });
    }
    let mut resp = SrxToolResponse::<VpnReportData>::active(VpnReportData { nodes });
    if args.include_raw { resp = resp.with_raw(format!("<!-- ike -->\n{ike}\n<!-- ipsec -->\n{ipsec}")); }
    Ok(resp)
}

fn is_not_configured(xml: &str) -> bool {
    let lower = xml.to_ascii_lowercase();
    lower.contains("<rpc-error>") &&
        (lower.contains("not-configured") || lower.contains("syntax error"))
}
```

- [ ] **Step 7: Wire tool, build, lint, commit, PR, merge**

Tool name: `vpn_lifecycle_report`. Mirror Task 2 Step 8 + 9 + 10 + 11.

---

## Task 7: Version bump, CHANGELOG, README, live smoke, release, deploy, memory

**Goal of this task:** Cut `srxmcp-v0.1.0` and ship to LXC 601.

**Files:**
- Modify: `rust-srxmcp/Cargo.toml`
- Modify: `rust-srxmcp-core/Cargo.toml`
- Modify: `rust-srxmcp/CHANGELOG.md`
- Modify: `rust-srxmcp/README.md`
- Create: `rust-srxmcp/tests/live_smoke.rs`
- Create: `~/.claude/projects/-home-mharman-RustJunosMCP/memory/srxmcp_v0_1_0_released.md`
- Modify: `~/.claude/projects/-home-mharman-RustJunosMCP/memory/MEMORY.md`
- Modify: `~/.claude/projects/-home-mharman-RustJunosMCP/memory/rust_junosmcp_container_601.md`

### Steps

- [ ] **Step 1: Bump versions**

Branch: `git checkout main && git pull && git checkout -b release/srxmcp-v0.1.0`

```bash
# rust-srxmcp/Cargo.toml:        version = "0.1.0"
# rust-srxmcp-core/Cargo.toml:   version = "0.1.0"
```

- [ ] **Step 2: Add CHANGELOG entry**

Prepend to `rust-srxmcp/CHANGELOG.md`:

```markdown
## [0.1.0] — 2026-05-2X

Phase 1B — read-only SRX status tools.

### Added
- `get_chassis_cluster_status` — chassis-cluster topology + RG health.
- `check_srx_feature_license` — closed-enum feature → license-record mapping.
- `get_srx_security_services_status` — IDP/AppID/UTM-AV/SecIntel/ATP-Cloud per node.
- `vpn_lifecycle_report` — correlated IKE + IPsec view with optional `peer`/`tunnel` filters.
- `rust-srxmcp-core` populated with shared `SrxError`, `SrxToolResponse<T>`, `multi_re_split`, and one workflow module per tool.
- Fixture-driven unit tests covering `state=active`, `state=not_configured`, partial-cluster, and per-sub-service absence cases.
- `tests/live_smoke.rs` — `#[ignore]`d smoke test per tool against LXC 601.

### Changed
- Tool surface 1 → 5 (`srxmcp_status` + four new tools).
- `JmcpSrxHandler` now holds an `Arc<DeviceManager>` so workflows can acquire pooled NETCONF sessions.

### Notes
- `rust-junosmcp` and `rust-srxmcp` continue to ship independent versions. `rust-junosmcp` remains at its current `0.6.x` line.
```

- [ ] **Step 3: Update README**

Modify `rust-srxmcp/README.md` to list the four new tools under a "Tools" heading.

- [ ] **Step 4: Add the live smoke test**

Create `rust-srxmcp/tests/live_smoke.rs`:

```rust
//! Live smoke against the LXC 601 deployment. Set:
//!   JMCP_SRX_LIVE_URL=http://192.168.1.194:30032/mcp
//!   JMCP_SRX_LIVE_TOKEN=<bearer>
//! Run: `cargo test --test live_smoke -p rust-srxmcp -- --ignored`.

#![cfg(test)]

fn endpoint() -> Option<(String, String)> {
    Some((
        std::env::var("JMCP_SRX_LIVE_URL").ok()?,
        std::env::var("JMCP_SRX_LIVE_TOKEN").ok()?,
    ))
}

#[test]
#[ignore]
fn cluster_status_against_test19_20() {
    let (url, token) = endpoint().expect("JMCP_SRX_LIVE_URL/TOKEN required");
    let resp = call_tool(&url, &token, "get_chassis_cluster_status", serde_json::json!({
        "router": "vSRX-test19-20",
    }));
    assert_eq!(resp["state"], "active");
    assert_eq!(resp["data"]["cluster_id"], 1);
}

#[test]
#[ignore]
fn license_idp_against_test10_is_not_configured_in_lab() {
    let (url, token) = endpoint().expect("JMCP_SRX_LIVE_URL/TOKEN required");
    let resp = call_tool(&url, &token, "check_srx_feature_license", serde_json::json!({
        "router": "vSRX-test10", "feature": "idp",
    }));
    assert_eq!(resp["state"], "not_configured");
}

#[test]
#[ignore]
fn services_status_against_test10() {
    let (url, token) = endpoint().expect("JMCP_SRX_LIVE_URL/TOKEN required");
    let resp = call_tool(&url, &token, "get_srx_security_services_status", serde_json::json!({
        "router": "vSRX-test10",
    }));
    assert_eq!(resp["state"], "active");
}

#[test]
#[ignore]
fn vpn_report_against_test10_after_appendix_a() {
    let (url, token) = endpoint().expect("JMCP_SRX_LIVE_URL/TOKEN required");
    let resp = call_tool(&url, &token, "vpn_lifecycle_report", serde_json::json!({
        "router": "vSRX-test10",
    }));
    assert_eq!(resp["state"], "active");
    let nodes = resp["data"]["nodes"].as_array().unwrap();
    assert!(nodes.iter().any(|n| n["ike_sas"].as_array().unwrap().len() == 1));
}

fn call_tool(url: &str, token: &str, name: &str, args: serde_json::Value) -> serde_json::Value {
    // Minimal MCP streamable-http client — see rust-junosmcp/tests/* for the pattern.
    // Implementer: copy the existing helper or use the `reqwest` crate (add as dev-dep).
    unimplemented!("copy MCP HTTP helper from rust-junosmcp/tests/")
}
```

> **Note:** Look at `rust-junosmcp/tests/` for an existing `call_tool` helper and either re-export from a shared `tests/common.rs` or duplicate it here (small enough that duplication is fine). Add `reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }` to `rust-srxmcp/[dev-dependencies]` if needed.

- [ ] **Step 5: Run the full workspace check**

```bash
cargo build --workspace && \
cargo test --workspace && \
cargo clippy --workspace -- -D warnings && \
cargo fmt -- --check
```

Expected: all green.

- [ ] **Step 6: Commit, PR, merge**

```bash
git add rust-srxmcp/Cargo.toml rust-srxmcp-core/Cargo.toml \
        rust-srxmcp/CHANGELOG.md rust-srxmcp/README.md \
        rust-srxmcp/tests/live_smoke.rs
git commit -m "chore(release): srxmcp-v0.1.0 — Phase 1B read-only tools"
git push -u origin release/srxmcp-v0.1.0
gh pr create --title "chore(release): srxmcp-v0.1.0" --body "Bumps rust-srxmcp + rust-srxmcp-core to 0.1.0; tool surface 1 → 5."
```

After CI green: rebase-merge.

- [ ] **Step 7: Tag and push**

```bash
git checkout main && git pull
git tag -a srxmcp-v0.1.0 -m "rust-srxmcp v0.1.0 — Phase 1B read-only SRX tools"
git push origin srxmcp-v0.1.0
```

- [ ] **Step 8: Build the release binary**

```bash
cargo build --release -p rust-srxmcp
ls -la target/release/rust-srxmcp
target/release/rust-srxmcp --version  # expect "rust-srxmcp 0.1.0"
```

- [ ] **Step 9: Deploy to LXC 601 (stop service first to avoid Text-file-busy)**

```bash
scp target/release/rust-srxmcp root@pve3.mechub.org:/tmp/rust-srxmcp
ssh root@pve3.mechub.org "
  pct exec 601 -- systemctl stop rust-srxmcp.service && \
  pct exec 601 -- cp /usr/local/bin/rust-srxmcp /usr/local/bin/rust-srxmcp.bak-\$(date +%s) && \
  pct push 601 /tmp/rust-srxmcp /usr/local/bin/rust-srxmcp --perms 755 && \
  pct exec 601 -- systemctl start rust-srxmcp.service && \
  sleep 2 && \
  pct exec 601 -- systemctl status rust-srxmcp.service --no-pager | head -10 && \
  pct exec 601 -- /usr/local/bin/rust-srxmcp --version
"
```

Expected: `Active: active (running)` and `rust-srxmcp 0.1.0`.

- [ ] **Step 10: Run live smoke against the deployment**

```bash
export JMCP_SRX_LIVE_URL=http://192.168.1.194:30032/mcp
export JMCP_SRX_LIVE_TOKEN=$(ssh root@pve3.mechub.org 'pct exec 601 -- cat /etc/jmcp/tokens.json' | jq -r '.tokens[0].value')
cargo test --test live_smoke -p rust-srxmcp -- --ignored
```

Expected: 4/4 smoke tests pass.

Also verify `rust-junosmcp:30031` still healthy:
```bash
curl -s -X POST -H "Authorization: Bearer $JMCP_SRX_LIVE_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  http://192.168.1.194:30031/mcp
```
Expected: 14-tool list from `jmcp-server v0.6.2`.

- [ ] **Step 11: Write the release memory note**

Create `~/.claude/projects/-home-mharman-RustJunosMCP/memory/srxmcp_v0_1_0_released.md` with frontmatter:
- `name: srxmcp v0.1.0 released — Phase 1B read-only tools`
- `description: Tool surface 1→5; get_chassis_cluster_status, check_srx_feature_license, get_srx_security_services_status, vpn_lifecycle_report; deployed LXC 601:30032`
- `type: project`

Body: deploy date, smoke results (X/X passed), tag commit SHA, lab tunnel applied y/n.

- [ ] **Step 12: Update the memory index and container memory**

Append to `MEMORY.md`:
```
- [srxmcp-v0.1.0 released](srxmcp_v0_1_0_released.md) — Phase 1B read-only tools; tool surface 1→5; deployed LXC 601:30032
```

Update `rust_junosmcp_container_601.md` header to reflect `srxmcp v0.1.0` (was `v0.0.1`).

- [ ] **Step 13: Confirm `rust-junosmcp` unaffected**

```bash
ssh root@pve3.mechub.org 'pct exec 601 -- /usr/local/bin/rust-junosmcp --version && pct exec 601 -- systemctl status rust-junosmcp.service --no-pager | head -5'
```
Expected: `0.6.2` still active.

---

## Self-Review Notes

**Spec coverage:**
- §Architecture / Crate layout → Task 1 sets it up exactly as documented
- §Shared types `SrxToolResponse<T>` / `SrxState` → Task 1 Step 5
- §`xml::multi_re_split` → Task 1 Step 7
- §`absence` helpers → Task 1 Step 5
- §Tool 1 `check_srx_feature_license` → Task 3
- §Tool 2 `get_srx_security_services_status` → Task 4
- §Tool 3 `get_chassis_cluster_status` → Task 2 (first per the spec's recommended order)
- §Tool 4 `vpn_lifecycle_report` → Task 6
- §Data flow → Tasks 2/3/4/6 Steps 8/6/6/6 implement exactly this pipeline
- §Error handling → Task 1 Step 3 lands `SrxError`; per-tool `parse_*` returns it
- §Partial-cluster failures → Task 2 Step 4 covers per-node `<rpc-error>`
- §Testing fixture matrix → Tasks 2/3/4/6 Step 1+2 land fixtures and assertions
- §Live smoke → Task 7 Step 4 + Step 10
- §Sequencing → Task ordering matches spec recommendation (cluster → license → services → vpn)
- §Deployment → Task 7 Steps 8-10
- §Appendix A → Task 5

**Type consistency:** `SrxLicensedFeature`, `SrxToolResponse<T>`, `SrxState`, `SrxError`, `ClusterStatusData`, `LicenseData`, `ServicesStatusData`, `VpnReportData`, `NodeServicesStatus`, `NodeVpnReport` are used identically across all tasks. The error variant `Transport(JmcpError)` (note: not `DeviceError` as the spec sketched — `rust-junosmcp-core` exposes `JmcpError`, see file `rust-junosmcp-core/src/error.rs:6`) is the only deviation from the spec text and is correct.

**Placeholder check:** Two flagged in-task notes for the implementer (quick-xml inner-XML capture in Task 1 Step 7; `call_tool` helper in Task 7 Step 4). Both give a concrete fallback rather than a TBD.

---

## Execution Handoff

Plan complete. Save to `docs/superpowers/plans/2026-05-21-srxmcp-phase-1b-readonly-tools.md`. Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task, two-stage review (spec compliance then code quality) between tasks, fast iteration in this session
2. **Inline Execution** — execute tasks here using `superpowers:executing-plans`, batch with checkpoints

**Which approach?**
