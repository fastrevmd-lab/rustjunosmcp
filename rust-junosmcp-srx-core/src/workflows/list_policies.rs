//! `srx_list_policies` — security policies by zone pair, including global
//! policies and (optionally) hit counts.
//!
//! # RPC
//!
//! `get-firewall-policies`, args `from-zone` / `to-zone` (both optional —
//! omit both to enumerate every context pair the device returns) and
//! optional `policy-name` for an exact-match lookup. Fits
//! `rustez::rpc::RpcExecutor::call()`'s flat key/value args, unlike tools 2–4.
//!
//! **Live-confirmed against `vsrx-ci` (2026-09-27, Junos 26.2R1.7) via
//! `| display xml rpc`**: the spec's original hypothesis (`from-zone-name` /
//! `to-zone-name`) was wrong — the real element names have no `-name` suffix.
//! Corrected here and in the `srx-policy-read-spec` document (MEC-53 §12).
//! `show security policies global` maps to a **separate** RPC,
//! `get-global-firewall-policies` — not exercised by this tool, which relies
//! instead on the base call already surfacing global entries (see below).
//!
//! Names on each policy (addresses, applications) are returned **unresolved**
//! on purpose — resolution is `srx_resolve_address` / `srx_resolve_application`'s
//! job, so this tool stays a single deterministic RPC round trip (plus the
//! optional hit-count one) instead of silently fanning out into N more device
//! calls per policy.
//!
//! # Global policies (MEC-53 §10 Q1)
//!
//! A live CLI-text capture against `vsrx-ci` (`show security policies`, no
//! zone args) confirmed that Junos's own text display represents a global
//! policy with `From zones: any` / `To zones: any` — i.e. the same
//! `get-firewall-policies` call this tool makes, with no zone args, does
//! surface global policies contextually as zone `"any"` rather than needing
//! a second, distinct call. This was confirmed against the CLI-text mirror
//! (`execute-junos-command`'s `| display xml` silently falls back to plain
//! text for this RPC — a tool limitation, not a Junos one; see MEC-55's
//! spec §11 for the same gap), **not** independently against the raw
//! RPC-reply XML element names, so treat `from_zone`/`to_zone` `"any"`
//! handling as corroborated, not byte-for-byte verified.
//!
//! # Hit counts (MEC-53 §10 Q2)
//!
//! **Live-confirmed**: `show security policies hit-count` maps to
//! `<get-security-policies-hit-count>`, **not** the spec's hypothesised
//! `get-firewall-policies-hit-count`. Corrected here and in the spec (MEC-53
//! §12). It is opt-in (`include_hit_counts`, default `false`) and, since it
//! is enrichment rather than the tool's core deterministic answer, a failed
//! or unparsable hit-count reply degrades to `hit_count: None` on every
//! policy (logged via `tracing::warn!`) instead of failing the whole call —
//! the policy list itself must never be masked by a failure in the secondary
//! RPC. The hit-count reply's internal element shape is still unconfirmed
//! (same tool limitation noted above prevented capturing structured XML).
//!
//! # Junos XML schema (published `get-firewall-policies-information` schema;
//! RPC/arg names above are live-confirmed, reply element names below are
//! NOT independently confirmed against raw RPC-reply XML — the capture tool
//! available this session does not structure this RPC's reply)
//!
//! ```xml
//! <security-policies-information>
//!   <security-context>
//!     <context-information>
//!       <source-zone-name>trust</source-zone-name>
//!       <destination-zone-name>untrust</destination-zone-name>
//!     </context-information>
//!     <policies>
//!       <policy-information>
//!         <policy-name>policy1</policy-name>
//!         <policy-state>enabled</policy-state>
//!         <policy-identifier>4</policy-identifier>
//!         <policy-sequence-number>1</policy-sequence-number>
//!         <source-addresses>
//!           <source-address><address-name>any</address-name></source-address>
//!         </source-addresses>
//!         <destination-addresses>
//!           <destination-address><address-name>any</address-name></destination-address>
//!         </destination-addresses>
//!         <applications>
//!           <application><application-name>any</application-name></application>
//!         </applications>
//!         <policy-action>
//!           <action-type>permit</action-type>
//!           <policy-log><session-init/><session-close/></policy-log>
//!         </policy-action>
//!       </policy-information>
//!     </policies>
//!   </security-context>
//! </security-policies-information>
//! ```

use crate::{SrxError, SrxToolResponse};
use rust_junosmcp_core::device_manager::PooledDevice;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default page size (Junos branch SRX policy tables are bounded — low
/// thousands — so `limit`/`offset` is a page guard, not a hard cap).
pub const DEFAULT_POLICY_LIMIT: u32 = 500;

// ── Public types ──────────────────────────────────────────────────────────────

/// Arguments for `srx_list_policies`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = rust_junosmcp_core::schema_alias::router_name_alias)]
pub struct PolicyListArgs {
    /// Device name (aliased as router_name).
    #[serde(alias = "router_name")]
    pub router: String,
    /// Restrict to this source zone. Omit with `to_zone` to enumerate all context pairs.
    #[serde(default)]
    pub from_zone: Option<String>,
    /// Restrict to this destination zone. Omit with `from_zone` to enumerate all context pairs.
    #[serde(default)]
    pub to_zone: Option<String>,
    /// Restrict to an exact policy name.
    #[serde(default)]
    pub policy_name: Option<String>,
    /// Also fetch and join per-policy hit counts (a second RPC round trip).
    /// Default false. See module docs for the (live-confirmed) RPC tag.
    #[serde(default)]
    pub include_hit_counts: bool,
    /// Maximum number of policies to return.
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Number of policies to skip before collecting `limit`.
    #[serde(default)]
    pub offset: u32,
    /// Include raw XML from device in response. Default false.
    #[serde(default)]
    pub include_raw: bool,
}

fn default_limit() -> u32 {
    DEFAULT_POLICY_LIMIT
}

/// Policy action, including services attached to a permit (IDP/UTM/etc.).
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum PolicyAction {
    /// Traffic is permitted.
    Permit,
    /// Traffic is silently dropped.
    Deny,
    /// Traffic is dropped with a rejection (e.g. TCP RST / ICMP unreachable).
    Reject,
    /// Traffic is permitted with one or more services attached (IDP, UTM, …).
    PermitWithServices {
        /// Attached service tag names, e.g. `["idp", "utm-policy"]`.
        services: Vec<String>,
    },
}

/// Session logging configuration for a policy.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLog {
    /// No session logging.
    #[default]
    None,
    /// Log at session initiation only.
    SessionInit,
    /// Log at session close only.
    SessionClose,
    /// Log at both session initiation and close.
    Both,
}

/// One security policy entry.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone)]
pub struct SecurityPolicy {
    /// Source zone. `"any"` for a global policy.
    pub from_zone: String,
    /// Destination zone. `"any"` for a global policy.
    pub to_zone: String,
    /// Policy name.
    pub name: String,
    /// Evaluation order within its zone-pair context.
    pub sequence: u32,
    /// Unresolved source address/address-set names.
    pub source_addresses: Vec<String>,
    /// Unresolved destination address/address-set names.
    pub destination_addresses: Vec<String>,
    /// Unresolved application/application-set names.
    pub applications: Vec<String>,
    /// Action taken for matching traffic.
    pub action: PolicyAction,
    /// Session logging configuration.
    pub log: PolicyLog,
    /// Hit count, when `include_hit_counts` was requested and the join
    /// succeeded for this policy. `None` otherwise — never a stand-in zero.
    pub hit_count: Option<u64>,
}

/// Result of listing security policies.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct PolicyListData {
    /// Policies matching the request, after `offset`/`limit`.
    pub policies: Vec<SecurityPolicy>,
    /// True if more policies existed beyond `limit`.
    pub truncated: bool,
    /// Total policies found before `offset`/`limit` was applied.
    pub total_count: u32,
}

// ── `run()` — async entry point ───────────────────────────────────────────────

/// Run `get-firewall-policies` (and optionally the hit-count RPC) against a
/// pooled device.
pub async fn run(
    device: &mut PooledDevice,
    args: PolicyListArgs,
) -> Result<SrxToolResponse<PolicyListData>, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let mut call_args: Vec<(&str, &str)> = Vec::new();
    if let Some(z) = args.from_zone.as_deref() {
        call_args.push(("from-zone", z));
    }
    if let Some(z) = args.to_zone.as_deref() {
        call_args.push(("to-zone", z));
    }
    if let Some(n) = args.policy_name.as_deref() {
        call_args.push(("policy-name", n));
    }
    let reply = exec
        .call("get-firewall-policies", &call_args)
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let hit_counts = if args.include_hit_counts {
        match exec
            .call("get-security-policies-hit-count", &call_args)
            .await
        {
            Ok(xml) => match parse_hit_counts(&xml) {
                Ok(map) => Some(map),
                Err(e) => {
                    tracing::warn!(
                        router = %args.router,
                        error = %e,
                        "get-security-policies-hit-count reply did not match expected schema; \
                         returning policies without hit counts"
                    );
                    None
                }
            },
            Err(e) => {
                tracing::warn!(
                    router = %args.router,
                    error = %e,
                    "get-security-policies-hit-count RPC failed; returning policies without hit counts"
                );
                None
            }
        }
    } else {
        None
    };

    let mut parsed = parse(&reply, hit_counts.as_ref(), args.offset, args.limit)?;
    if args.include_raw {
        parsed = parsed.with_raw(reply);
    }
    Ok(parsed)
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse a `get-firewall-policies` reply body into a typed, paginated
/// `SrxToolResponse`. Pure, unit-testable entry point.
pub fn parse(
    reply_xml: &str,
    hit_counts: Option<&HashMap<(String, String, String), u64>>,
    offset: u32,
    limit: u32,
) -> Result<SrxToolResponse<PolicyListData>, SrxError> {
    let re_nodes = crate::xml::multi_re_split(reply_xml)?;

    // Chassis cluster: policy config is synced, but defensively de-duplicate
    // identical policies by (from_zone, to_zone, name) across nodes rather
    // than assuming a single-element result.
    let mut seen: std::collections::HashSet<(String, String, String)> =
        std::collections::HashSet::new();
    let mut all_policies: Vec<SecurityPolicy> = Vec::new();

    for re_node in &re_nodes {
        if contains_rpc_error(&re_node.inner_xml) {
            tracing::debug!(node = %re_node.re_name, "skipping node with rpc-error");
            continue;
        }
        let doc = roxmltree::Document::parse(&re_node.inner_xml)
            .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;

        for ctx in doc
            .descendants()
            .filter(|n| n.is_element() && n.tag_name().name() == "security-context")
        {
            let ctx_info = ctx
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "context-information");
            let from_zone = ctx_info
                .as_ref()
                .and_then(|c| child_text(c, "source-zone-name"))
                .unwrap_or_else(|| "any".to_string());
            let to_zone = ctx_info
                .as_ref()
                .and_then(|c| child_text(c, "destination-zone-name"))
                .unwrap_or_else(|| "any".to_string());

            let Some(policies_node) = ctx
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "policies")
            else {
                continue;
            };

            for pi in policies_node
                .children()
                .filter(|n| n.is_element() && n.tag_name().name() == "policy-information")
            {
                let policy = parse_policy_information(&pi, &from_zone, &to_zone)?;
                let key = (
                    policy.from_zone.clone(),
                    policy.to_zone.clone(),
                    policy.name.clone(),
                );
                if seen.insert(key) {
                    all_policies.push(policy);
                }
            }
        }
    }

    if let Some(hc) = hit_counts {
        for p in &mut all_policies {
            let key = (p.from_zone.clone(), p.to_zone.clone(), p.name.clone());
            p.hit_count = hc.get(&key).copied();
        }
    }

    let total_count = all_policies.len() as u32;
    let start = offset.min(total_count) as usize;
    let end = start.saturating_add(limit as usize).min(all_policies.len());
    let truncated = (end as u32) < total_count;
    let policies = all_policies[start..end].to_vec();

    Ok(SrxToolResponse::active(PolicyListData {
        policies,
        truncated,
        total_count,
    }))
}

/// Parse the (unconfirmed-shape) hit-count reply into a
/// `(from_zone, to_zone, policy_name) -> hit_count` map.
fn parse_hit_counts(reply_xml: &str) -> Result<HashMap<(String, String, String), u64>, SrxError> {
    let re_nodes = crate::xml::multi_re_split(reply_xml)?;
    let mut map = HashMap::new();
    for re_node in &re_nodes {
        if contains_rpc_error(&re_node.inner_xml) {
            continue;
        }
        let doc = roxmltree::Document::parse(&re_node.inner_xml)
            .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;
        for ctx in doc
            .descendants()
            .filter(|n| n.is_element() && n.tag_name().name() == "security-context")
        {
            let ctx_info = ctx
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "context-information");
            let from_zone = ctx_info
                .as_ref()
                .and_then(|c| child_text(c, "source-zone-name"))
                .unwrap_or_else(|| "any".to_string());
            let to_zone = ctx_info
                .as_ref()
                .and_then(|c| child_text(c, "destination-zone-name"))
                .unwrap_or_else(|| "any".to_string());
            for hc in doc
                .descendants()
                .filter(|n| n.is_element() && n.tag_name().name() == "policy-hit-count")
            {
                let Some(name) = child_text(&hc, "policy-name") else {
                    continue;
                };
                let Some(count) = child_text(&hc, "hit-count").and_then(|t| t.parse::<u64>().ok())
                else {
                    continue;
                };
                map.insert((from_zone.clone(), to_zone.clone(), name), count);
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

fn parse_name_list(
    container: &roxmltree::Node<'_, '_>,
    item_tag: &str,
    name_tag: &str,
) -> Vec<String> {
    container
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == item_tag)
        .filter_map(|item| child_text(&item, name_tag))
        .collect()
}

fn parse_policy_information(
    pi: &roxmltree::Node<'_, '_>,
    from_zone: &str,
    to_zone: &str,
) -> Result<SecurityPolicy, SrxError> {
    let name = child_text(pi, "policy-name")
        .ok_or_else(|| SrxError::schema_mismatch("get-firewall-policies", "policy-name"))?;
    let sequence: u32 = child_text(pi, "policy-sequence-number")
        .and_then(|t| t.parse().ok())
        .unwrap_or(0);

    let source_addresses = pi
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "source-addresses")
        .map(|c| parse_name_list(&c, "source-address", "address-name"))
        .unwrap_or_default();
    let destination_addresses = pi
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "destination-addresses")
        .map(|c| parse_name_list(&c, "destination-address", "address-name"))
        .unwrap_or_default();
    let applications = pi
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "applications")
        .map(|c| parse_name_list(&c, "application", "application-name"))
        .unwrap_or_default();

    let action_node = pi
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "policy-action")
        .ok_or_else(|| SrxError::schema_mismatch("get-firewall-policies", "policy-action"))?;
    let action_type = child_text(&action_node, "action-type")
        .ok_or_else(|| SrxError::schema_mismatch("get-firewall-policies", "action-type"))?;

    let services: Vec<String> = action_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "application-services")
        .map(|svc| {
            svc.children()
                .filter(|n| n.is_element())
                .map(|n| n.tag_name().name().to_string())
                .collect()
        })
        .unwrap_or_default();

    let action = match action_type.as_str() {
        "permit" if !services.is_empty() => PolicyAction::PermitWithServices { services },
        "permit" => PolicyAction::Permit,
        "deny" => PolicyAction::Deny,
        "reject" => PolicyAction::Reject,
        other => {
            return Err(SrxError::Parse(format!(
                "unrecognised policy action-type: {other}"
            )));
        }
    };

    let log = action_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "policy-log")
        .map(|log_node| {
            let init = log_node
                .children()
                .any(|n| n.is_element() && n.tag_name().name() == "session-init");
            let close = log_node
                .children()
                .any(|n| n.is_element() && n.tag_name().name() == "session-close");
            match (init, close) {
                (true, true) => PolicyLog::Both,
                (true, false) => PolicyLog::SessionInit,
                (false, true) => PolicyLog::SessionClose,
                (false, false) => PolicyLog::None,
            }
        })
        .unwrap_or_default();

    Ok(SecurityPolicy {
        from_zone: from_zone.to_string(),
        to_zone: to_zone.to_string(),
        name,
        sequence,
        source_addresses,
        destination_addresses,
        applications,
        action,
        log,
        hit_count: None,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/list_policies")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()))
    }

    #[test]
    fn no_policies_yields_empty_active() {
        let xml = fixture("no_policies.xml");
        let resp = parse(&xml, None, 0, 500).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert!(data.policies.is_empty());
        assert_eq!(data.total_count, 0);
        assert!(!data.truncated);
    }

    #[test]
    fn single_zone_pair_multiple_policies() {
        let xml = fixture("zone_pair_multiple.xml");
        let resp = parse(&xml, None, 0, 500).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.policies.len(), 2);
        assert_eq!(data.policies[0].from_zone, "trust");
        assert_eq!(data.policies[0].to_zone, "untrust");
        assert_eq!(data.policies[0].name, "allow-web");
        assert_eq!(data.policies[0].sequence, 1);
        assert_eq!(data.policies[0].source_addresses, vec!["any".to_string()]);
        assert_eq!(data.policies[0].action, PolicyAction::Permit);
    }

    #[test]
    fn global_policy_uses_any_zone() {
        let xml = fixture("global_policy.xml");
        let resp = parse(&xml, None, 0, 500).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.policies.len(), 1);
        assert_eq!(data.policies[0].from_zone, "any");
        assert_eq!(data.policies[0].to_zone, "any");
    }

    #[test]
    fn permit_with_services_captures_attached_services() {
        let xml = fixture("permit_with_services.xml");
        let resp = parse(&xml, None, 0, 500).expect("parse should not error");
        let data = resp.data.expect("data present");
        match &data.policies[0].action {
            PolicyAction::PermitWithServices { services } => {
                assert!(services.iter().any(|s| s.contains("idp")));
            }
            other => panic!("expected PermitWithServices, got {other:?}"),
        }
    }

    #[test]
    fn clustered_reply_dedupes_identical_policies() {
        let xml = fixture("clustered_identical.xml");
        let resp = parse(&xml, None, 0, 500).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(
            data.policies.len(),
            1,
            "identical policy on both nodes must dedupe"
        );
    }

    #[test]
    fn reserved_word_policy_name_not_special_cased() {
        let xml = fixture("reserved_word_name.xml");
        let resp = parse(&xml, None, 0, 500).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.policies[0].name, "default");
    }

    #[test]
    fn pagination_reports_truncated_and_total_count() {
        let xml = fixture("zone_pair_multiple.xml");
        let resp = parse(&xml, None, 0, 1).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.policies.len(), 1);
        assert_eq!(data.total_count, 2);
        assert!(data.truncated);
    }

    #[test]
    fn hit_counts_join_when_present() {
        let xml = fixture("zone_pair_multiple.xml");
        let mut hc = HashMap::new();
        hc.insert(
            (
                "trust".to_string(),
                "untrust".to_string(),
                "allow-web".to_string(),
            ),
            42u64,
        );
        let resp = parse(&xml, Some(&hc), 0, 500).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.policies[0].hit_count, Some(42));
        assert_eq!(data.policies[1].hit_count, None);
    }
}
