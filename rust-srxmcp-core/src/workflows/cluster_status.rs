//! `get_chassis_cluster_status` — chassis-cluster topology + health snapshot.
//!
//! The RPC used is `get-chassis-cluster-status-information` (rustez converts
//! underscores to hyphens, so the call is
//! `exec.call("get-chassis-cluster-status-information", &[])`).
//!
//! # Junos XML schema (vSRX 24.x — actual)
//!
//! Standalone devices return an `<xnm:error>` with message containing
//! "not enabled". Clustered devices return:
//!
//! ```xml
//! <chassis-cluster-status>
//!   <cluster-id>N</cluster-id>
//!   <redundancy-group>
//!     <redundancy-group-id>N</redundancy-group-id>
//!     <redundancy-group-failover-count>N</redundancy-group-failover-count>
//!     <device-stats>
//!       <!-- flat repeating groups, 6 children per node -->
//!       <device-name>node0</device-name>
//!       <device-priority>200</device-priority>
//!       <redundancy-group-status>primary</redundancy-group-status>
//!       <preempt>no</preempt>
//!       <failover-mode>no</failover-mode>
//!       <monitor-failures>None</monitor-failures>
//!       <!-- next node's group follows immediately -->
//!       <device-name>node1</device-name>
//!       ...
//!     </device-stats>
//!   </redundancy-group>
//! </chassis-cluster-status>
//! ```

use crate::{SrxError, SrxToolResponse};
use rust_junosmcp_core::device_manager::PooledDevice;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ── Public types ──────────────────────────────────────────────────────────────

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

// ── `run()` — async entry point ───────────────────────────────────────────────

/// Run `get-chassis-cluster-status-information` against a pooled device.
pub async fn run(
    device: &mut PooledDevice,
    args: ClusterStatusArgs,
) -> Result<SrxToolResponse<ClusterStatusData>, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
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

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse the inner content of an `<rpc-reply>` body (as returned by
/// `rustez::RpcExecutor::call`) into a typed `SrxToolResponse`.
///
/// This is the pure unit-testable entry point; `run()` calls it after
/// obtaining the raw XML from the device.
pub fn parse(reply_xml: &str) -> Result<SrxToolResponse<ClusterStatusData>, SrxError> {
    // Detect standalone "not enabled" before trying multi-RE split.
    if is_not_configured(reply_xml) {
        return Ok(SrxToolResponse::not_configured("chassis cluster disabled"));
    }

    // Use multi_re_split to handle both standalone and clustered (wrapped) replies.
    let re_nodes = crate::xml::multi_re_split(reply_xml)?;

    // Collect chassis-cluster-status data from each RE node that has it.
    let mut cluster_id_opt: Option<u16> = None;
    let mut all_rgs: Vec<RedundancyGroup> = Vec::new();

    for re_node in &re_nodes {
        // Skip this node if its inner XML contains a per-node rpc-error.
        if contains_rpc_error(&re_node.inner_xml) {
            tracing::debug!(node = %re_node.re_name, "skipping node with rpc-error");
            continue;
        }

        let doc = roxmltree::Document::parse(&re_node.inner_xml)
            .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;

        let css_node = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "chassis-cluster-status");

        let Some(css) = css_node else {
            continue;
        };

        // Extract top-level cluster-id (first occurrence wins).
        if cluster_id_opt.is_none() {
            if let Some(cid_str) = css
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "cluster-id")
                .and_then(|n| n.text())
            {
                cluster_id_opt = cid_str.trim().parse().ok();
            }
        }

        // Parse each <redundancy-group>.
        for rg_node in css
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "redundancy-group")
        {
            let group_id: u16 = rg_node
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "redundancy-group-id")
                .and_then(|n| n.text())
                .and_then(|t| t.trim().parse().ok())
                .unwrap_or(0);

            let failover_count: u32 = rg_node
                .children()
                .find(|n| {
                    n.is_element() && n.tag_name().name() == "redundancy-group-failover-count"
                })
                .and_then(|n| n.text())
                .and_then(|t| t.trim().parse().ok())
                .unwrap_or(0);

            let members = parse_device_stats(&rg_node);

            // Merge into existing RG if we've already seen this group_id (multi-RE
            // case where both nodes report the same RG).
            if let Some(existing) = all_rgs.iter_mut().find(|r| r.group_id == group_id) {
                for m in members {
                    if !existing.members.iter().any(|em| em.node == m.node) {
                        existing.members.push(m);
                    }
                }
            } else {
                all_rgs.push(RedundancyGroup {
                    group_id,
                    failover_count,
                    members,
                });
            }
        }
    }

    // If we got nothing (all nodes had rpc-errors or no chassis-cluster-status),
    // treat as not-configured.
    if cluster_id_opt.is_none() && all_rgs.is_empty() {
        return Ok(SrxToolResponse::not_configured("chassis cluster disabled"));
    }

    let cluster_id = cluster_id_opt.unwrap_or(0);

    // Derive ClusterNode list from members of RG 0 (management group).
    let nodes = derive_cluster_nodes(cluster_id, &all_rgs);

    Ok(SrxToolResponse::active(ClusterStatusData {
        cluster_id,
        nodes,
        redundancy_groups: all_rgs,
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Check whether the reply XML represents a "chassis cluster not enabled"
/// error from a standalone device.
///
/// Junos 24.x returns `<xnm:error>` (not `<rpc-error>`) with a message
/// containing "not enabled". We also accept the plan's `not-configured`
/// tag and `data-missing` for older Junos versions.
fn is_not_configured(xml: &str) -> bool {
    // xnm:error with "not enabled" message (observed on Junos 24.x vSRX).
    if xml.contains("not enabled") || xml.contains("not configured") {
        return true;
    }
    // Standard rpc-error with not-configured or data-missing tag.
    if xml.contains("<error-tag>not-configured</error-tag>")
        || xml.contains("<error-tag>data-missing</error-tag>")
    {
        return true;
    }
    false
}

/// Return true if the XML fragment contains an `<rpc-error>` element
/// (per-node errors in multi-RE replies).
fn contains_rpc_error(xml: &str) -> bool {
    xml.contains("<rpc-error>") || xml.contains("<nc:rpc-error>")
}

/// Parse the flat repeating member list inside `<device-stats>`.
///
/// Junos 24.x serialises each node's data as a flat run of siblings inside
/// `<device-stats>` (NOT as nested per-node child elements). A new "record"
/// begins whenever a `<device-name>` element is encountered.
fn parse_device_stats(rg_node: &roxmltree::Node<'_, '_>) -> Vec<RgMember> {
    let stats_node = match rg_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "device-stats")
    {
        Some(n) => n,
        None => return Vec::new(),
    };

    // Walk siblings, starting a new record on each <device-name>.
    struct Record {
        name: String,
        priority: u16,
        status: String,
        preempt: bool,
        manual: bool,
        monitor_failures: Vec<String>,
    }

    let mut records: Vec<Record> = Vec::new();

    for child in stats_node.children().filter(|n| n.is_element()) {
        let tag = child.tag_name().name();
        let text = child.text().unwrap_or("").trim().to_string();

        match tag {
            "device-name" => {
                records.push(Record {
                    name: text,
                    priority: 0,
                    status: String::new(),
                    preempt: false,
                    manual: false,
                    monitor_failures: Vec::new(),
                });
            }
            _ => {
                // Apply to the most-recently opened record.
                if let Some(rec) = records.last_mut() {
                    match tag {
                        "device-priority" => {
                            rec.priority = text.parse().unwrap_or(0);
                        }
                        "redundancy-group-status" => {
                            rec.status = text;
                        }
                        "preempt" => {
                            rec.preempt = text.eq_ignore_ascii_case("yes");
                        }
                        "failover-mode" => {
                            // failover-mode "yes" == manual-failover armed.
                            rec.manual = text.eq_ignore_ascii_case("yes");
                        }
                        "monitor-failures" => {
                            rec.monitor_failures = parse_failures(&text);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    records
        .into_iter()
        .map(|r| RgMember {
            node: r.name,
            priority: r.priority,
            status: r.status,
            preempt: r.preempt,
            manual: r.manual,
            monitor_failures: r.monitor_failures,
        })
        .collect()
}

/// Derive a `ClusterNode` vec from the members of RG 0.
///
/// The Junos 24.x schema has no top-level `<cluster-node>` element; node
/// identity is inferred from the `<device-stats>` inside each
/// `<redundancy-group>`. RG 0 is the management group and reliably contains
/// an entry for every live node.
fn derive_cluster_nodes(_cluster_id: u16, rgs: &[RedundancyGroup]) -> Vec<ClusterNode> {
    let rg0 = match rgs.iter().find(|r| r.group_id == 0) {
        Some(r) => r,
        None => return Vec::new(),
    };

    rg0.members
        .iter()
        .map(|m| ClusterNode {
            name: m.node.clone(),
            priority: m.priority,
            status: m.status.clone(),
            monitor_failures: m.monitor_failures.clone(),
        })
        .collect()
}

/// Parse a `<monitor-failures>` text value into a vec.
///
/// `"None"` → empty vec; `"IF,IP"` → `["IF", "IP"]`.
fn parse_failures(text: &str) -> Vec<String> {
    if text.eq_ignore_ascii_case("none") || text.is_empty() {
        return Vec::new();
    }
    text.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SrxState;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/cluster_status")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()))
    }

    // ── Test 1: standalone ────────────────────────────────────────────────────

    #[test]
    fn standalone_not_configured() {
        let xml = fixture("standalone_not_configured.xml");
        let resp = parse(&xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::NotConfigured, "state mismatch");
        assert!(
            resp.reason.as_deref().unwrap_or("").contains("cluster"),
            "reason should mention cluster, got: {:?}",
            resp.reason
        );
        assert!(
            resp.data.is_none(),
            "data should be absent for not_configured"
        );
    }

    // ── Test 2: clustered healthy ─────────────────────────────────────────────

    #[test]
    fn clustered_healthy() {
        let xml = fixture("clustered_healthy.xml");
        let resp = parse(&xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::Active, "state mismatch");

        let data = resp.data.expect("data must be present");
        assert_eq!(data.cluster_id, 1, "cluster_id");
        assert_eq!(data.nodes.len(), 2, "expected 2 nodes");

        let node0 = data
            .nodes
            .iter()
            .find(|n| n.name == "node0")
            .expect("node0");
        assert_eq!(node0.priority, 200, "node0 priority");
        assert_eq!(node0.status, "primary", "node0 status");
        assert!(node0.monitor_failures.is_empty(), "node0 failures");

        let node1 = data
            .nodes
            .iter()
            .find(|n| n.name == "node1")
            .expect("node1");
        assert_eq!(node1.priority, 100, "node1 priority");
        assert_eq!(node1.status, "secondary", "node1 status");
        assert!(node1.monitor_failures.is_empty(), "node1 failures");

        assert_eq!(data.redundancy_groups.len(), 2, "expected 2 RGs");

        let rg0 = data
            .redundancy_groups
            .iter()
            .find(|r| r.group_id == 0)
            .expect("RG 0");
        assert_eq!(rg0.members.len(), 2, "RG0 member count");

        let rg1 = data
            .redundancy_groups
            .iter()
            .find(|r| r.group_id == 1)
            .expect("RG 1");
        // RG1 members should have preempt=true
        let rg1_node0 = rg1
            .members
            .iter()
            .find(|m| m.node == "node0")
            .expect("rg1 node0");
        assert!(rg1_node0.preempt, "rg1 node0 should have preempt=true");
        let rg1_node1 = rg1
            .members
            .iter()
            .find(|m| m.node == "node1")
            .expect("rg1 node1");
        assert!(rg1_node1.preempt, "rg1 node1 should have preempt=true");
    }

    // ── Test 3: node unreachable (partial cluster) ────────────────────────────

    #[test]
    fn node_unreachable_partial_cluster() {
        let xml = fixture("node_unreachable.xml");
        let resp = parse(&xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::Active, "state mismatch");

        let data = resp.data.expect("data must be present");
        // Only node0 should be present (node1 had rpc-error — silently skipped).
        assert_eq!(data.nodes.len(), 1, "expected 1 live node");
        assert_eq!(data.nodes[0].name, "node0", "should be node0");
        assert_eq!(data.nodes[0].status, "primary", "node0 should be primary");
    }

    // ── Unit: parse_failures ──────────────────────────────────────────────────

    #[test]
    fn parse_failures_none_yields_empty() {
        assert!(parse_failures("None").is_empty());
        assert!(parse_failures("none").is_empty());
        assert!(parse_failures("").is_empty());
    }

    #[test]
    fn parse_failures_comma_separated() {
        let v = parse_failures("IF,IP");
        assert_eq!(v, vec!["IF", "IP"]);
    }

    #[test]
    fn parse_failures_trims_whitespace() {
        let v = parse_failures("IF, IP , SP");
        assert_eq!(v, vec!["IF", "IP", "SP"]);
    }
}
