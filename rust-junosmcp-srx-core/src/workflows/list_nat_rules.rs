//! `srx_list_nat_rules` — source, destination, and static NAT rules.
//!
//! # RPC
//!
//! Configuration-sourced, same subtree-filter technique as address/application
//! resolution: **one call per NAT kind** over `security/nat/source`,
//! `security/nat/destination`, `security/nat/static` — these are independent
//! stanzas with different rule-set/rule shapes, so they are not forced through
//! one filter.
//!
//! # Hit counts (MEC-53 §10 Q3 — live-confirmed for source/destination, static was correct)
//!
//! **Live-confirmed against `vsrx-ci` (2026-09-27) via `| display xml rpc`**:
//! `show security nat source rule all` / `show security nat destination rule
//! all` map to `get-source-nat-rule-sets-information` /
//! `get-destination-nat-rule-sets-information` — the spec's hypothesis
//! (`get-source-nat-rule-information` / `get-destination-nat-rule-information`,
//! missing `-sets-`) was wrong for those two; `get-static-nat-rule-information`
//! was correct as hypothesised. All three take an `<all/>` flag child, not
//! empty args — corrected here and in the spec (MEC-53 §12). Joined by
//! `(rule_set, name)`, gated behind `include_hit_counts` (default `false`)
//! like `srx_list_policies`. As with policy hit counts, a failed or
//! unparsable join degrades to `hit_count: None` rather than failing the
//! whole call — it is enrichment, not the tool's core deterministic answer.
//! The reply's internal element shape (beyond the join fields) is still
//! unconfirmed — the capture tool available this session does not structure
//! this RPC's reply.
//!
//! # Junos XML schema (config-sourced elements below are **live-confirmed**
//! for source NAT against `vsrx-ci`'s real, sanitised configuration —
//! including the match container tag and the `-name`-suffixed address form,
//! both of which the spec's original hypothesis got wrong. Destination and
//! static NAT match containers were not live-verifiable — `vsrx-ci` has no
//! destination/static NAT configured — so `dnat-rule-match` /
//! `static-nat-rule-match` below follow Juniper's published schema naming
//! convention by analogy, flagged as **not live-verified**, same discipline
//! as MEC-55 spec §11. Parsing tries the analogous name first and falls back
//! to a bare `<match>` defensively.)
//!
//! ```xml
//! <configuration>
//!   <security>
//!     <nat>
//!       <source>
//!         <rule-set>
//!           <name>trust-to-untrust</name>
//!           <from><zone>trust</zone></from>
//!           <to><zone>untrust</zone></to>
//!           <rule>
//!             <name>rule1</name>
//!             <src-nat-rule-match>
//!               <source-address-name>10.0.0.0/24</source-address-name>
//!               <destination-address>0.0.0.0/0</destination-address>
//!             </src-nat-rule-match>
//!             <then><source-nat><pool><pool-name>my-pool</pool-name></pool></source-nat></then>
//!           </rule>
//!         </rule-set>
//!       </source>
//!     </nat>
//!   </security>
//! </configuration>
//! ```

use crate::workflows::config_fetch::get_configuration_subtree;
use crate::{SrxError, SrxToolResponse};
use ipnet::IpNet;
use rust_junosmcp_core::device_manager::PooledDevice;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cap on total rules returned per NAT kind before `truncated` is set.
pub const DEFAULT_NAT_RULE_LIMIT: u32 = 500;

// ── Public types ──────────────────────────────────────────────────────────────

/// Arguments for `srx_list_nat_rules`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = rust_junosmcp_core::schema_alias::router_name_alias)]
pub struct NatRulesArgs {
    /// Device name (aliased as router_name).
    #[serde(alias = "router_name")]
    pub router: String,
    /// Also fetch and join per-rule hit counts (three extra RPC round trips).
    /// Default false. Unconfirmed RPC tags — see module docs.
    #[serde(default)]
    pub include_hit_counts: bool,
    /// Maximum number of rules to return per NAT kind.
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Include raw XML from device in response. Default false.
    #[serde(default)]
    pub include_raw: bool,
}

fn default_limit() -> u32 {
    DEFAULT_NAT_RULE_LIMIT
}

/// The `from`/`to` selector on a NAT rule-set.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone)]
#[serde(tag = "selector", rename_all = "snake_case")]
pub enum NatZoneOrInterface {
    /// A security zone.
    Zone {
        /// Zone name.
        name: String,
    },
    /// A single interface.
    Interface {
        /// Interface name.
        name: String,
    },
    /// A routing instance.
    RoutingInstance {
        /// Routing instance name.
        name: String,
    },
}

/// Match criteria on a NAT rule. Values are returned unresolved — a match
/// naming an address-set carries the set's name, same as `srx_list_policies`;
/// resolution is `srx_resolve_address`'s job.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone, Default)]
pub struct NatMatch {
    /// Unresolved source address/address-set names.
    pub source_addresses: Vec<String>,
    /// Unresolved destination address/address-set names.
    pub destination_addresses: Vec<String>,
    /// Unresolved application/application-set names.
    pub applications: Vec<String>,
}

/// Source NAT translation.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceTranslation {
    /// Translate via a named address pool.
    Pool {
        /// Pool name.
        pool_name: String,
    },
    /// Translate to the egress interface address.
    Interface,
    /// NAT is explicitly disabled for matching traffic.
    Off,
}

/// Destination NAT translation.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DestinationTranslation {
    /// Translate via a named address pool.
    Pool {
        /// Pool name.
        pool_name: String,
    },
}

/// Static NAT translation.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone)]
pub struct StaticTranslation {
    /// Translated prefix (a `/32` for a host translation, wider for a prefix translation).
    #[schemars(with = "String")]
    pub prefix: IpNet,
}

/// A source NAT rule.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone)]
pub struct SourceNatRule {
    /// Rule-set name.
    pub rule_set: String,
    /// Rule name.
    pub name: String,
    /// Evaluation order within the rule-set.
    pub sequence: u32,
    /// Rule-set's `from` selector.
    pub from: NatZoneOrInterface,
    /// Match criteria.
    #[serde(rename = "match")]
    pub match_: NatMatch,
    /// Translation applied.
    pub translation: SourceTranslation,
    /// Hit count, when requested and the join succeeded.
    pub hit_count: Option<u64>,
}

/// A destination NAT rule.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone)]
pub struct DestinationNatRule {
    /// Rule-set name.
    pub rule_set: String,
    /// Rule name.
    pub name: String,
    /// Evaluation order within the rule-set.
    pub sequence: u32,
    /// Rule-set's `from` selector.
    pub from: NatZoneOrInterface,
    /// Match criteria.
    #[serde(rename = "match")]
    pub match_: NatMatch,
    /// Translation applied.
    pub translation: DestinationTranslation,
    /// Hit count, when requested and the join succeeded.
    pub hit_count: Option<u64>,
}

/// A static NAT rule.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone)]
pub struct StaticNatRule {
    /// Rule-set name.
    pub rule_set: String,
    /// Rule name.
    pub name: String,
    /// Evaluation order within the rule-set.
    pub sequence: u32,
    /// Rule-set's `from` selector.
    pub from: NatZoneOrInterface,
    /// Match criteria.
    #[serde(rename = "match")]
    pub match_: NatMatch,
    /// Translation applied.
    pub translation: StaticTranslation,
    /// Hit count, when requested and the join succeeded.
    pub hit_count: Option<u64>,
}

/// Result of listing NAT rules.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct NatRules {
    /// Source NAT rules.
    pub source: Vec<SourceNatRule>,
    /// Destination NAT rules.
    pub destination: Vec<DestinationNatRule>,
    /// Static NAT rules.
    #[serde(rename = "static")]
    pub static_nat: Vec<StaticNatRule>,
    /// True if any kind was cut short by `limit`.
    pub truncated: bool,
}

// ── `run()` — async entry point ───────────────────────────────────────────────

/// Fetch and parse all three NAT kinds.
pub async fn run(
    device: &mut PooledDevice,
    args: NatRulesArgs,
) -> Result<SrxToolResponse<NatRules>, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let source_xml =
        get_configuration_subtree(&mut exec, "<security><nat><source/></nat></security>").await?;
    let destination_xml =
        get_configuration_subtree(&mut exec, "<security><nat><destination/></nat></security>")
            .await?;
    let static_xml =
        get_configuration_subtree(&mut exec, "<security><nat><static/></nat></security>").await?;

    let hit_counts = if args.include_hit_counts {
        fetch_hit_counts(&mut exec, &args.router).await
    } else {
        HashMap::new()
    };

    let mut parsed = parse(
        &source_xml,
        &destination_xml,
        &static_xml,
        &hit_counts,
        args.limit,
    )?;
    if args.include_raw {
        parsed = parsed.with_raw(format!(
            "<!-- source -->\n{source_xml}\n<!-- destination -->\n{destination_xml}\n<!-- static -->\n{static_xml}"
        ));
    }
    Ok(parsed)
}

/// Best-effort hit-count fetch across all three kinds. Any RPC or parse
/// failure is logged and that kind's counts are simply absent — hit counts
/// are enrichment, never load-bearing for the rule list itself.
async fn fetch_hit_counts(
    exec: &mut rustez::rpc::RpcExecutor<'_>,
    router: &str,
) -> HashMap<(String, String), u64> {
    let mut map = HashMap::new();
    for (rpc, label) in [
        ("get-source-nat-rule-sets-information", "source"),
        ("get-destination-nat-rule-sets-information", "destination"),
        ("get-static-nat-rule-information", "static"),
    ] {
        match exec.call(rpc, &[("all", "")]).await {
            Ok(xml) => match parse_nat_hit_counts(&xml) {
                Ok(m) => map.extend(m),
                Err(e) => tracing::warn!(
                    router,
                    rpc,
                    error = %e,
                    "{label} NAT hit-count reply did not match expected schema"
                ),
            },
            Err(e) => tracing::warn!(router, rpc, error = %e, "{label} NAT hit-count RPC failed"),
        }
    }
    map
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse the three `get-configuration` reply bodies into a typed
/// `SrxToolResponse`. Pure, unit-testable entry point.
pub fn parse(
    source_xml: &str,
    destination_xml: &str,
    static_xml: &str,
    hit_counts: &HashMap<(String, String), u64>,
    limit: u32,
) -> Result<SrxToolResponse<NatRules>, SrxError> {
    let (mut source, source_truncated) = parse_source(source_xml, hit_counts, limit)?;
    let (mut destination, dest_truncated) = parse_destination(destination_xml, hit_counts, limit)?;
    let (mut static_nat, static_truncated) = parse_static(static_xml, hit_counts, limit)?;

    source.truncate(limit as usize);
    destination.truncate(limit as usize);
    static_nat.truncate(limit as usize);

    Ok(SrxToolResponse::active(NatRules {
        source,
        destination,
        static_nat,
        truncated: source_truncated || dest_truncated || static_truncated,
    }))
}

fn parse_source(
    reply_xml: &str,
    hit_counts: &HashMap<(String, String), u64>,
    limit: u32,
) -> Result<(Vec<SourceNatRule>, bool), SrxError> {
    let re_nodes = crate::xml::multi_re_split(reply_xml)?;
    let Some(node) = re_nodes.iter().find(|n| !contains_rpc_error(&n.inner_xml)) else {
        return Ok((Vec::new(), false));
    };
    let sanitized = crate::xml::sanitize_rustez_xml(&node.inner_xml);
    let doc = roxmltree::Document::parse(&sanitized)
        .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;

    let mut rules = Vec::new();
    for rule_set in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "rule-set")
    {
        let rule_set_name = child_text(&rule_set, "name")
            .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "rule-set/name"))?;
        let from = parse_from(&rule_set)?;
        for (i, rule) in rule_set
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "rule")
            .enumerate()
        {
            let name = child_text(&rule, "name")
                .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "rule/name"))?;
            let match_ = parse_match(&rule, &["src-nat-rule-match", "match"])?;
            let then_node = rule
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "then")
                .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "rule/then"))?;
            let sn = then_node
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "source-nat")
                .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "then/source-nat"))?;
            let translation = if sn
                .children()
                .any(|n| n.is_element() && n.tag_name().name() == "off")
            {
                SourceTranslation::Off
            } else if sn
                .children()
                .any(|n| n.is_element() && n.tag_name().name() == "interface")
            {
                SourceTranslation::Interface
            } else if let Some(pool) = sn
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "pool")
            {
                let pool_name = child_text(&pool, "pool-name").ok_or_else(|| {
                    SrxError::schema_mismatch("get-configuration", "source-nat/pool/pool-name")
                })?;
                SourceTranslation::Pool { pool_name }
            } else {
                return Err(SrxError::schema_mismatch("get-configuration", "source-nat"));
            };
            let hit_count = hit_counts
                .get(&(rule_set_name.clone(), name.clone()))
                .copied();
            rules.push(SourceNatRule {
                rule_set: rule_set_name.clone(),
                name,
                sequence: i as u32 + 1,
                from: from.clone(),
                match_,
                translation,
                hit_count,
            });
        }
    }
    let truncated = rules.len() > limit as usize;
    Ok((rules, truncated))
}

fn parse_destination(
    reply_xml: &str,
    hit_counts: &HashMap<(String, String), u64>,
    limit: u32,
) -> Result<(Vec<DestinationNatRule>, bool), SrxError> {
    let re_nodes = crate::xml::multi_re_split(reply_xml)?;
    let Some(node) = re_nodes.iter().find(|n| !contains_rpc_error(&n.inner_xml)) else {
        return Ok((Vec::new(), false));
    };
    let sanitized = crate::xml::sanitize_rustez_xml(&node.inner_xml);
    let doc = roxmltree::Document::parse(&sanitized)
        .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;

    let mut rules = Vec::new();
    for rule_set in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "rule-set")
    {
        let rule_set_name = child_text(&rule_set, "name")
            .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "rule-set/name"))?;
        let from = parse_from(&rule_set)?;
        for (i, rule) in rule_set
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "rule")
            .enumerate()
        {
            let name = child_text(&rule, "name")
                .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "rule/name"))?;
            let match_ = parse_match(&rule, &["dnat-rule-match", "match"])?;
            let then_node = rule
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "then")
                .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "rule/then"))?;
            let dn = then_node
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "destination-nat")
                .ok_or_else(|| {
                    SrxError::schema_mismatch("get-configuration", "then/destination-nat")
                })?;
            let pool = dn
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "pool")
                .ok_or_else(|| {
                    SrxError::schema_mismatch("get-configuration", "destination-nat/pool")
                })?;
            let pool_name = child_text(&pool, "pool-name").ok_or_else(|| {
                SrxError::schema_mismatch("get-configuration", "destination-nat/pool/pool-name")
            })?;
            let hit_count = hit_counts
                .get(&(rule_set_name.clone(), name.clone()))
                .copied();
            rules.push(DestinationNatRule {
                rule_set: rule_set_name.clone(),
                name,
                sequence: i as u32 + 1,
                from: from.clone(),
                match_,
                translation: DestinationTranslation::Pool { pool_name },
                hit_count,
            });
        }
    }
    let truncated = rules.len() > limit as usize;
    Ok((rules, truncated))
}

fn parse_static(
    reply_xml: &str,
    hit_counts: &HashMap<(String, String), u64>,
    limit: u32,
) -> Result<(Vec<StaticNatRule>, bool), SrxError> {
    let re_nodes = crate::xml::multi_re_split(reply_xml)?;
    let Some(node) = re_nodes.iter().find(|n| !contains_rpc_error(&n.inner_xml)) else {
        return Ok((Vec::new(), false));
    };
    let sanitized = crate::xml::sanitize_rustez_xml(&node.inner_xml);
    let doc = roxmltree::Document::parse(&sanitized)
        .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;

    let mut rules = Vec::new();
    for rule_set in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "rule-set")
    {
        let rule_set_name = child_text(&rule_set, "name")
            .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "rule-set/name"))?;
        let from = parse_from(&rule_set)?;
        for (i, rule) in rule_set
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "rule")
            .enumerate()
        {
            let name = child_text(&rule, "name")
                .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "rule/name"))?;
            let match_ = parse_match(&rule, &["static-nat-rule-match", "match"])?;
            let then_node = rule
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "then")
                .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "rule/then"))?;
            let sn = then_node
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "static-nat")
                .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "then/static-nat"))?;
            let prefix_node = sn
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "prefix")
                .ok_or_else(|| {
                    SrxError::schema_mismatch("get-configuration", "static-nat/prefix")
                })?;
            let addr_prefix = child_text(&prefix_node, "addr-prefix").ok_or_else(|| {
                SrxError::schema_mismatch("get-configuration", "static-nat/prefix/addr-prefix")
            })?;
            let prefix: IpNet = addr_prefix
                .parse()
                .map_err(|_| SrxError::Parse(format!("invalid addr-prefix: {addr_prefix}")))?;
            let hit_count = hit_counts
                .get(&(rule_set_name.clone(), name.clone()))
                .copied();
            rules.push(StaticNatRule {
                rule_set: rule_set_name.clone(),
                name,
                sequence: i as u32 + 1,
                from: from.clone(),
                match_,
                translation: StaticTranslation { prefix },
                hit_count,
            });
        }
    }
    let truncated = rules.len() > limit as usize;
    Ok((rules, truncated))
}

/// Parse the (unconfirmed-shape) per-kind NAT hit-count reply into a
/// `(rule_set, rule_name) -> hit_count` map.
fn parse_nat_hit_counts(reply_xml: &str) -> Result<HashMap<(String, String), u64>, SrxError> {
    let re_nodes = crate::xml::multi_re_split(reply_xml)?;
    let mut map = HashMap::new();
    for re_node in &re_nodes {
        if contains_rpc_error(&re_node.inner_xml) {
            continue;
        }
        let sanitized = crate::xml::sanitize_rustez_xml(&re_node.inner_xml);
        let doc = roxmltree::Document::parse(&sanitized)
            .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;
        for rs in doc
            .descendants()
            .filter(|n| n.is_element() && n.tag_name().name() == "rule-set")
        {
            let Some(rule_set_name) = child_text(&rs, "name") else {
                continue;
            };
            for rule in rs
                .children()
                .filter(|n| n.is_element() && n.tag_name().name() == "rule")
            {
                let Some(name) = child_text(&rule, "name") else {
                    continue;
                };
                if let Some(count) =
                    child_text(&rule, "translation-hits").and_then(|t| t.parse::<u64>().ok())
                {
                    map.insert((rule_set_name.clone(), name), count);
                }
            }
        }
    }
    Ok(map)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn contains_rpc_error(xml: &str) -> bool {
    xml.contains("<rpc-error>") || xml.contains("<nc:rpc-error>")
}

fn child_text(node: &roxmltree::Node<'_, '_>, tag_name: &str) -> Option<String> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == tag_name)
        .and_then(|n| n.text())
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

fn parse_from(rule_set: &roxmltree::Node<'_, '_>) -> Result<NatZoneOrInterface, SrxError> {
    let from = rule_set
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "from")
        .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "rule-set/from"))?;
    for child in from.children().filter(|n| n.is_element()) {
        let text = child.text().unwrap_or("").trim().to_string();
        match child.tag_name().name() {
            "zone" => return Ok(NatZoneOrInterface::Zone { name: text }),
            "interface" => return Ok(NatZoneOrInterface::Interface { name: text }),
            "routing-instance" => return Ok(NatZoneOrInterface::RoutingInstance { name: text }),
            _ => {}
        }
    }
    Err(SrxError::schema_mismatch(
        "get-configuration",
        "rule-set/from (zone|interface|routing-instance)",
    ))
}

/// Parse a rule's match block. `container_tags` is tried in order — the
/// live-confirmed container name for this NAT kind first, `"match"` as a
/// defensive fallback (see module docs).
///
/// Junos accepts either a literal prefix (`source-address`) or a reference
/// to a named address-book entry (`source-address-name`) in the same match
/// slot — live capture against `vsrx-ci` showed a real rule mixing both
/// forms in one match block, so both are collected into the same field.
fn parse_match(
    rule: &roxmltree::Node<'_, '_>,
    container_tags: &[&str],
) -> Result<NatMatch, SrxError> {
    let Some(match_node) = rule
        .children()
        .find(|n| n.is_element() && container_tags.contains(&n.tag_name().name()))
    else {
        return Ok(NatMatch::default());
    };
    let source_addresses = match_node
        .children()
        .filter(|n| {
            n.is_element()
                && matches!(n.tag_name().name(), "source-address" | "source-address-name")
        })
        .filter_map(|n| n.text().map(|t| t.trim().to_string()))
        .collect();
    let destination_addresses = match_node
        .children()
        .filter(|n| {
            n.is_element()
                && matches!(
                    n.tag_name().name(),
                    "destination-address" | "destination-address-name"
                )
        })
        .filter_map(|n| n.text().map(|t| t.trim().to_string()))
        .collect();
    let applications = match_node
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "application")
        .filter_map(|n| n.text().map(|t| t.trim().to_string()))
        .collect();
    Ok(NatMatch {
        source_addresses,
        destination_addresses,
        applications,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/list_nat_rules")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()))
    }

    const EMPTY: &str = "<configuration><security><nat/></security></configuration>";

    #[test]
    fn one_rule_of_each_kind() {
        let source = fixture("source_pool.xml");
        let destination = fixture("destination_pool.xml");
        let static_ = fixture("static_prefix.xml");
        let hc = HashMap::new();
        let resp =
            parse(&source, &destination, &static_, &hc, 500).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.source.len(), 1);
        assert_eq!(data.destination.len(), 1);
        assert_eq!(data.static_nat.len(), 1);
        assert!(!data.truncated);
    }

    #[test]
    fn source_nat_pool_translation() {
        let source = fixture("source_pool.xml");
        let hc = HashMap::new();
        let resp = parse(&source, EMPTY, EMPTY, &hc, 500).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(
            data.source[0].translation,
            SourceTranslation::Pool {
                pool_name: "my-pool".into()
            }
        );
        assert_eq!(
            data.source[0].from,
            NatZoneOrInterface::Zone {
                name: "trust".into()
            }
        );
        // Match container is `<src-nat-rule-match>`, confirmed live against
        // vsrx-ci — a bare `<match>` element (the spec's original hypothesis)
        // is not what the device sends, so a regression back to only
        // recognising `<match>` must fail this assertion.
        assert_eq!(
            data.source[0].match_.source_addresses,
            vec!["10.0.0.0/24".to_string()]
        );
        assert_eq!(
            data.source[0].match_.destination_addresses,
            vec!["0.0.0.0/0".to_string()]
        );
    }

    #[test]
    fn source_nat_interface_translation() {
        let source = fixture("source_interface.xml");
        let hc = HashMap::new();
        let resp = parse(&source, EMPTY, EMPTY, &hc, 500).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.source[0].translation, SourceTranslation::Interface);
    }

    #[test]
    fn static_nat_prefix_not_host_translation() {
        let static_ = fixture("static_prefix.xml");
        let hc = HashMap::new();
        let resp = parse(EMPTY, EMPTY, &static_, &hc, 500).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(
            data.static_nat[0].translation.prefix,
            "10.0.0.0/24".parse::<IpNet>().unwrap()
        );
    }

    #[test]
    fn nat_rule_match_carries_unresolved_address_set_name() {
        let source = fixture("source_match_address_set.xml");
        let hc = HashMap::new();
        let resp = parse(&source, EMPTY, EMPTY, &hc, 500).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(
            data.source[0].match_.source_addresses,
            vec!["internal-net-set".to_string()]
        );
    }

    #[test]
    fn hit_counts_join_by_rule_set_and_name() {
        let source = fixture("source_pool.xml");
        let mut hc = HashMap::new();
        hc.insert(("trust-to-untrust".to_string(), "rule1".to_string()), 7u64);
        let resp = parse(&source, EMPTY, EMPTY, &hc, 500).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.source[0].hit_count, Some(7));
    }

    #[test]
    fn empty_config_yields_empty_active_result() {
        let hc = HashMap::new();
        let resp = parse(EMPTY, EMPTY, EMPTY, &hc, 500).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert!(data.source.is_empty());
        assert!(data.destination.is_empty());
        assert!(data.static_nat.is_empty());
    }
}
