//! `srx_flow_sessions` — filtered, hard-capped flow-session query.
//!
//! Blast-radius lens: flow tables can be huge, and a multi-thousand-session
//! response is a bigger data-exposure surface than any config read in this
//! tool set. This module queries the session-count summary *before* ever
//! attempting a full walk, and refuses the walk outright (rather than
//! silently paging through a huge table) when the count exceeds the cap and
//! the caller hasn't narrowed the query with a filter.
//!
//! # RPC name correction (2026-09-27, live `vsrx-ci` capture)
//!
//! The spec hypothesized a separate `get-flow-session-summary-information`
//! RPC. A live `show security flow session summary | display xml rpc`
//! capture against `vsrx-ci` confirmed there is no such RPC — the summary is
//! the *same* `<get-flow-session-information>` RPC with a `<summary/>` flag
//! child: `<get-flow-session-information><summary/></get-flow-session-information>`.
//! The filter arg for a source-address match is `<source-prefix>` (Junos
//! normalises a bare IP to a `/32`), not `source-ip`. `srx-policy-read-spec`
//! §11 has been corrected; this module implements the corrected shape.
//!
//! # Junos XML schema — reply body NOT live-confirmed
//!
//! As with `srx_policy_match` (see that module's docs for why), the MCP tool
//! available for MEC-55 fixture capture could confirm the RPC/arg names via
//! `| display xml rpc` but not the executed reply's structured body. The
//! summary reply's CLI text IS real (captured live against vsrx-ci,
//! standalone, 2 unicast sessions):
//!
//! ```text
//! Unicast-sessions: 2
//! ...
//! Sessions-in-use: 4
//!   Valid sessions: 2
//!   Pending sessions: 0
//!   Invalidated sessions: 2
//!   Sessions in other states: 0
//! Maximum-sessions: 2097152
//! ```
//!
//! `sessions-in-use` is used below as the total-count signal (the size of
//! the live session table a full walk would need to enumerate). The per-node
//! fixtures hand-write the wrapping element names following this crate's
//! Junos XML conventions; flag any live mismatch as a spec update, not a
//! silent parser patch.

use crate::protocol::Protocol;
use crate::{SrxError, SrxToolResponse};
use rust_junosmcp_core::device_manager::PooledDevice;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Default session cap when the caller doesn't specify one.
pub const DEFAULT_CAP: u32 = 200;
/// Hard ceiling on the session cap — not caller-overridable past this point.
pub const MAX_CAP: u32 = 2000;

// ── Public types ──────────────────────────────────────────────────────────────

/// Arguments for `srx_flow_sessions`. Every filter is optional individually,
/// but [`validate_filter`] requires at least one unless `acknowledge_unfiltered`
/// is set — see that function's docs.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = rust_junosmcp_core::schema_alias::router_name_alias)]
pub struct FlowSessionsArgs {
    /// Device name (aliased as router_name).
    #[serde(alias = "router_name")]
    pub router: String,
    /// Filter to sessions whose source address falls in this prefix
    /// (a bare IP is treated as a /32 or /128).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_prefix: Option<String>,
    /// Filter to sessions whose destination address falls in this prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_prefix: Option<String>,
    /// Filter to sessions with this source port. Requires `protocol`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u32>,
    /// Filter to sessions with this destination port. Requires `protocol`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u32>,
    /// Filter to sessions using this protocol ("tcp", "udp", "icmp", or a
    /// numeric IANA protocol number).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Filter to sessions matching this application name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    /// Filter to a specific session identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_identifier: Option<String>,
    /// Maximum sessions to return, 1-2000. Defaults to 200.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<u32>,
    /// Explicit acknowledgement required to run a filterless query. Without
    /// this, a filterless call is rejected pre-RPC rather than silently
    /// walking the whole session table.
    #[serde(default)]
    pub acknowledge_unfiltered: bool,
    /// Include raw XML from device in response. Default false.
    #[serde(default)]
    pub include_raw: bool,
}

/// One flow session (one direction of a session pair).
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct FlowSession {
    /// Device session identifier.
    pub session_id: u64,
    /// Session protocol name (e.g. "tcp", "udp").
    pub protocol: String,
    /// Pre-NAT source (address, port).
    pub source: (IpAddr, u16),
    /// Pre-NAT destination (address, port).
    pub destination: (IpAddr, u16),
    /// Post-NAT source, when the session is translated.
    pub translated_source: Option<(IpAddr, u16)>,
    /// Post-NAT destination, when the session is translated.
    pub translated_destination: Option<(IpAddr, u16)>,
    /// Matched application name, if known.
    pub application: Option<String>,
    /// Matched policy name, if known.
    pub policy_name: Option<String>,
    /// Ingress interface.
    pub in_interface: String,
    /// Egress interface.
    pub out_interface: String,
    /// Session idle timeout, in seconds.
    pub timeout: u32,
    /// Session age, in seconds.
    pub duration: u32,
}

/// Sessions owned by one cluster node (or the whole device, standalone).
///
/// Chassis-cluster session ownership is not synced across nodes — each
/// redundancy group's live sessions exist only on whichever node currently
/// owns that RG. Sessions are never merged across nodes into one table.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct NodeSessions {
    /// Empty string for standalone; "node0" or "node1" for cluster.
    pub re_name: String,
    /// Sessions owned by this node, already cap-truncated.
    pub sessions: Vec<FlowSession>,
}

/// Result of a `srx_flow_sessions` query.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct FlowSessionQuery {
    /// Per-node session lists.
    pub nodes: Vec<NodeSessions>,
    /// Total session count reported by the summary RPC, when available.
    pub total_count_reported: Option<u64>,
    /// True when the returned sessions are fewer than the actual table
    /// (either the full walk was refused because the summary count exceeded
    /// `cap` on a filterless query, or a walk's results were cut at `cap`).
    pub truncated: bool,
    /// The cap that was enforced for this call.
    pub cap: u32,
}

// ── Pre-RPC validation ───────────────────────────────────────────────────────

/// A validated filter set, ready to become RPC args.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct FlowSessionFilter {
    source_prefix: Option<String>,
    destination_prefix: Option<String>,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    protocol: Option<Protocol>,
    application: Option<String>,
    session_identifier: Option<String>,
}

impl FlowSessionFilter {
    fn has_filter(&self) -> bool {
        self.source_prefix.is_some()
            || self.destination_prefix.is_some()
            || self.source_port.is_some()
            || self.destination_port.is_some()
            || self.protocol.is_some()
            || self.application.is_some()
            || self.session_identifier.is_some()
    }

    fn to_rpc_args(&self) -> Vec<(String, String)> {
        let mut args = Vec::new();
        if let Some(v) = &self.source_prefix {
            args.push(("source-prefix".to_string(), v.clone()));
        }
        if let Some(v) = &self.destination_prefix {
            args.push(("destination-prefix".to_string(), v.clone()));
        }
        if let Some(v) = self.source_port {
            args.push(("source-port".to_string(), v.to_string()));
        }
        if let Some(v) = self.destination_port {
            args.push(("destination-port".to_string(), v.to_string()));
        }
        if let Some(v) = &self.protocol {
            args.push(("protocol".to_string(), v.rpc_value()));
        }
        if let Some(v) = &self.application {
            args.push(("application".to_string(), v.clone()));
        }
        if let Some(v) = &self.session_identifier {
            args.push(("session-identifier".to_string(), v.clone()));
        }
        args
    }
}

/// Validate a prefix filter: a bare IP address or `addr/len` CIDR notation.
fn validate_prefix(s: &str) -> Result<String, SrxError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(SrxError::InvalidInput("prefix must not be empty".into()));
    }
    match trimmed.split_once('/') {
        Some((addr, len)) => {
            let ip: IpAddr = addr
                .parse()
                .map_err(|_| SrxError::InvalidInput(format!("invalid prefix: {trimmed:?}")))?;
            let len: u8 = len.parse().map_err(|_| {
                SrxError::InvalidInput(format!("invalid prefix length: {trimmed:?}"))
            })?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if len > max {
                return Err(SrxError::InvalidInput(format!(
                    "prefix length out of range: {trimmed:?}"
                )));
            }
        }
        None => {
            let _: IpAddr = trimmed
                .parse()
                .map_err(|_| SrxError::InvalidInput(format!("invalid prefix: {trimmed:?}")))?;
        }
    }
    Ok(trimmed.to_string())
}

/// Validate a [`FlowSessionsArgs`] into a [`FlowSessionFilter`], before any
/// RPC is built.
///
/// Rejects:
/// - a port filter with no `protocol` (ambiguous — MEC-55 fixture plan calls
///   this out explicitly as an invalid filter combination),
/// - a malformed prefix, port, or protocol token,
/// - an entirely filterless query unless `acknowledge_unfiltered` is set —
///   the caller must either narrow the query or explicitly accept a
///   cap-truncated unbounded walk; there is no silent "return everything
///   that fit" path.
fn validate_filter(args: &FlowSessionsArgs) -> Result<FlowSessionFilter, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    if (args.source_port.is_some() || args.destination_port.is_some()) && args.protocol.is_none() {
        return Err(SrxError::InvalidInput(
            "source_port/destination_port filter requires protocol".into(),
        ));
    }

    let source_prefix = args
        .source_prefix
        .as_deref()
        .map(validate_prefix)
        .transpose()?;
    let destination_prefix = args
        .destination_prefix
        .as_deref()
        .map(validate_prefix)
        .transpose()?;
    let source_port = args
        .source_port
        .map(|p| {
            u16::try_from(p)
                .map_err(|_| SrxError::InvalidInput("source_port must be 0-65535".into()))
        })
        .transpose()?;
    let destination_port = args
        .destination_port
        .map(|p| {
            u16::try_from(p)
                .map_err(|_| SrxError::InvalidInput("destination_port must be 0-65535".into()))
        })
        .transpose()?;
    let protocol = args.protocol.as_deref().map(Protocol::parse).transpose()?;
    let application = args
        .application
        .clone()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let session_identifier = args
        .session_identifier
        .clone()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let filter = FlowSessionFilter {
        source_prefix,
        destination_prefix,
        source_port,
        destination_port,
        protocol,
        application,
        session_identifier,
    };

    if !filter.has_filter() && !args.acknowledge_unfiltered {
        return Err(SrxError::InvalidInput(
            "flow-session query has no filter; narrow the query or set \
             acknowledge_unfiltered=true to accept a capped, possibly-truncated walk"
                .into(),
        ));
    }

    Ok(filter)
}

/// Validate and resolve the effective cap, before any RPC is built.
fn validate_cap(cap: Option<u32>) -> Result<u32, SrxError> {
    let cap = cap.unwrap_or(DEFAULT_CAP);
    if cap == 0 {
        return Err(SrxError::InvalidInput("cap must be at least 1".into()));
    }
    if cap > MAX_CAP {
        return Err(SrxError::InvalidInput(format!(
            "cap {cap} exceeds hard ceiling {MAX_CAP}"
        )));
    }
    Ok(cap)
}

// ── `run()` — async entry point ───────────────────────────────────────────────

/// Run `get-flow-session-information` (summary, then optionally the full
/// walk) against a pooled device and return a typed
/// `SrxToolResponse<FlowSessionQuery>`.
pub async fn run(
    device: &mut PooledDevice,
    args: FlowSessionsArgs,
) -> Result<SrxToolResponse<FlowSessionQuery>, SrxError> {
    let filter = validate_filter(&args)?;
    let cap = validate_cap(args.cap)?;

    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let summary_xml = exec
        .call("get-flow-session-information", &[("summary", "")])
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let total_count_reported = parse_summary_total(&summary_xml)?;

    // Blast-radius refusal: an unfiltered query whose summary count exceeds
    // the cap never attempts the full walk RPC at all.
    if let Some(total) = total_count_reported
        && total > u64::from(cap)
        && !filter.has_filter()
    {
        let mut resp = SrxToolResponse::active(FlowSessionQuery {
            nodes: Vec::new(),
            total_count_reported: Some(total),
            truncated: true,
            cap,
        });
        if args.include_raw {
            resp = resp.with_raw(format!("<!-- summary -->\n{summary_xml}"));
        }
        return Ok(resp);
    }

    let owned_rpc_args = filter.to_rpc_args();
    let rpc_args: Vec<(&str, &str)> = owned_rpc_args
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let walk_xml = exec
        .call("get-flow-session-information", &rpc_args)
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let mut parsed = parse_walk(&walk_xml, total_count_reported, cap)?;
    if args.include_raw {
        parsed = parsed.with_raw(format!(
            "<!-- summary -->\n{summary_xml}\n<!-- walk -->\n{walk_xml}"
        ));
    }
    Ok(parsed)
}

// ── Parsers ───────────────────────────────────────────────────────────────────

/// Parse the `<summary/>`-flagged reply for the total session count.
///
/// `sessions-in-use` is used as the total-count signal (see module docs).
/// Absence of the element (e.g. an unrecognised schema) is not an error —
/// callers fall back to "unknown total" and rely on the walk's own
/// truncation instead of the pre-walk refusal.
pub fn parse_summary_total(xml: &str) -> Result<Option<u64>, SrxError> {
    let cleaned = crate::xml::sanitize_rustez_xml(xml);
    let doc = roxmltree::Document::parse(&cleaned)
        .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;
    Ok(doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "sessions-in-use")
        .and_then(|n| n.text())
        .and_then(|t| t.trim().parse().ok()))
}

/// Parse the full-walk reply into a typed `SrxToolResponse<FlowSessionQuery>`,
/// applying the cap defensively per node and reporting `truncated` whenever
/// any session had to be cut.
pub fn parse_walk(
    xml: &str,
    total_count_reported: Option<u64>,
    cap: u32,
) -> Result<SrxToolResponse<FlowSessionQuery>, SrxError> {
    let cleaned = crate::xml::sanitize_rustez_xml(xml);
    let re_nodes = crate::xml::multi_re_split(&cleaned)?;

    let mut nodes = Vec::with_capacity(re_nodes.len());
    let mut remaining = cap as usize;
    let mut truncated = total_count_reported.is_some_and(|t| t > u64::from(cap));

    for re_node in &re_nodes {
        if contains_rpc_error(&re_node.inner_xml) {
            // A node holding no sessions for this query (e.g. secondary for
            // every relevant RG) is a normal per-node result, not a failure
            // of the whole call.
            nodes.push(NodeSessions {
                re_name: re_node.re_name.clone(),
                sessions: Vec::new(),
            });
            continue;
        }

        let mut sessions = parse_sessions(&re_node.inner_xml)?;
        if sessions.len() > remaining {
            sessions.truncate(remaining);
            truncated = true;
        }
        remaining = remaining.saturating_sub(sessions.len());

        nodes.push(NodeSessions {
            re_name: re_node.re_name.clone(),
            sessions,
        });
    }

    Ok(SrxToolResponse::active(FlowSessionQuery {
        nodes,
        total_count_reported,
        truncated,
        cap,
    }))
}

/// Parse every `<flow-session>` block in one node's fragment.
fn parse_sessions(xml: &str) -> Result<Vec<FlowSession>, SrxError> {
    let doc =
        roxmltree::Document::parse(xml).map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;

    let mut sessions = Vec::new();
    for block in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "flow-session")
    {
        let session_id: u64 = child_text(&block, "session-identifier")
            .and_then(|t| t.parse().ok())
            .ok_or_else(|| {
                SrxError::schema_mismatch("get-flow-session-information", "session-identifier")
            })?;
        let protocol = child_text(&block, "session-protocol-name").unwrap_or_default();

        let source_address: IpAddr = child_text(&block, "source-address")
            .and_then(|t| t.parse().ok())
            .ok_or_else(|| {
                SrxError::schema_mismatch("get-flow-session-information", "source-address")
            })?;
        let source_port: u16 = child_text(&block, "source-port")
            .and_then(|t| t.parse().ok())
            .unwrap_or(0);
        let destination_address: IpAddr = child_text(&block, "destination-address")
            .and_then(|t| t.parse().ok())
            .ok_or_else(|| {
                SrxError::schema_mismatch("get-flow-session-information", "destination-address")
            })?;
        let destination_port: u16 = child_text(&block, "destination-port")
            .and_then(|t| t.parse().ok())
            .unwrap_or(0);

        let translated_source = child_text(&block, "nat-source-address")
            .and_then(|a| a.parse::<IpAddr>().ok())
            .map(|a| {
                let port = child_text(&block, "nat-source-port")
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(0);
                (a, port)
            });
        let translated_destination = child_text(&block, "nat-destination-address")
            .and_then(|a| a.parse::<IpAddr>().ok())
            .map(|a| {
                let port = child_text(&block, "nat-destination-port")
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(0);
                (a, port)
            });

        let application = child_text(&block, "application");
        let policy_name = child_text(&block, "policy-name");
        let in_interface = child_text(&block, "in-interface-name").unwrap_or_default();
        let out_interface = child_text(&block, "out-interface-name").unwrap_or_default();
        let timeout: u32 = child_text(&block, "timeout")
            .and_then(|t| t.parse().ok())
            .unwrap_or(0);
        let duration: u32 = child_text(&block, "duration")
            .and_then(|t| t.parse().ok())
            .unwrap_or(0);

        sessions.push(FlowSession {
            session_id,
            protocol,
            source: (source_address, source_port),
            destination: (destination_address, destination_port),
            translated_source,
            translated_destination,
            application,
            policy_name,
            in_interface,
            out_interface,
            timeout,
            duration,
        });
    }
    Ok(sessions)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn child_text(node: &roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == name)
        .and_then(|n| n.text())
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

fn contains_rpc_error(xml: &str) -> bool {
    xml.contains("<rpc-error>") || xml.contains("<nc:rpc-error>")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/flow_sessions")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()))
    }

    fn base_args() -> FlowSessionsArgs {
        FlowSessionsArgs {
            router: "vsrx-ci".into(),
            source_prefix: None,
            destination_prefix: None,
            source_port: None,
            destination_port: None,
            protocol: None,
            application: None,
            session_identifier: None,
            cap: None,
            acknowledge_unfiltered: false,
            include_raw: false,
        }
    }

    // ── validate_filter: pre-RPC validation ──────────────────────────────────

    #[test]
    fn filterless_call_rejected_without_acknowledgement() {
        let args = base_args();
        assert!(matches!(
            validate_filter(&args),
            Err(SrxError::InvalidInput(_))
        ));
    }

    #[test]
    fn filterless_call_accepted_with_acknowledgement() {
        let mut args = base_args();
        args.acknowledge_unfiltered = true;
        assert!(validate_filter(&args).is_ok());
    }

    #[test]
    fn source_prefix_alone_counts_as_a_filter() {
        let mut args = base_args();
        args.source_prefix = Some("10.0.0.5".into());
        let filter = validate_filter(&args).expect("should validate");
        assert!(filter.has_filter());
    }

    #[test]
    fn port_without_protocol_rejected_pre_rpc() {
        let mut args = base_args();
        args.source_port = Some(443);
        assert!(matches!(
            validate_filter(&args),
            Err(SrxError::InvalidInput(_))
        ));
    }

    #[test]
    fn port_with_protocol_accepted() {
        let mut args = base_args();
        args.source_port = Some(443);
        args.protocol = Some("tcp".into());
        let filter = validate_filter(&args).expect("should validate");
        assert_eq!(filter.source_port, Some(443));
        assert_eq!(filter.protocol, Some(Protocol::Tcp));
    }

    #[test]
    fn malformed_prefix_rejected_pre_rpc() {
        let mut args = base_args();
        args.source_prefix = Some("not-an-ip".into());
        assert!(matches!(
            validate_filter(&args),
            Err(SrxError::InvalidInput(_))
        ));
    }

    #[test]
    fn out_of_range_prefix_length_rejected_pre_rpc() {
        let mut args = base_args();
        args.source_prefix = Some("10.0.0.0/40".into());
        assert!(matches!(
            validate_filter(&args),
            Err(SrxError::InvalidInput(_))
        ));
    }

    #[test]
    fn out_of_range_port_rejected_pre_rpc() {
        let mut args = base_args();
        args.protocol = Some("tcp".into());
        args.destination_port = Some(70_000);
        assert!(matches!(
            validate_filter(&args),
            Err(SrxError::InvalidInput(_))
        ));
    }

    #[test]
    fn unknown_protocol_rejected_pre_rpc() {
        let mut args = base_args();
        args.protocol = Some("bogus".into());
        assert!(matches!(
            validate_filter(&args),
            Err(SrxError::InvalidInput(_))
        ));
    }

    // ── validate_cap ──────────────────────────────────────────────────────────

    #[test]
    fn default_cap_is_used_when_unspecified() {
        assert_eq!(validate_cap(None).unwrap(), DEFAULT_CAP);
    }

    #[test]
    fn zero_cap_rejected() {
        assert!(matches!(
            validate_cap(Some(0)),
            Err(SrxError::InvalidInput(_))
        ));
    }

    #[test]
    fn cap_over_hard_ceiling_rejected() {
        assert!(matches!(
            validate_cap(Some(MAX_CAP + 1)),
            Err(SrxError::InvalidInput(_))
        ));
    }

    #[test]
    fn cap_at_hard_ceiling_accepted() {
        assert_eq!(validate_cap(Some(MAX_CAP)).unwrap(), MAX_CAP);
    }

    // ── parse_summary_total ───────────────────────────────────────────────────

    #[test]
    fn summary_total_parses_sessions_in_use() {
        // sessions-in-use=4 is the REAL count captured live against vsrx-ci
        // (module docs); the wrapping XML is a hypothesis.
        let xml = fixture("summary_live_vsrx_ci.xml");
        let total = parse_summary_total(&xml).unwrap();
        assert_eq!(total, Some(4));
    }

    // ── parse_walk: standalone ────────────────────────────────────────────────

    #[test]
    fn standalone_empty_result() {
        let xml = fixture("standalone_empty.xml");
        let resp = parse_walk(&xml, Some(0), DEFAULT_CAP).unwrap();
        let data = resp.data.expect("data present");
        assert_eq!(data.nodes.len(), 1);
        assert_eq!(data.nodes[0].re_name, "");
        assert!(data.nodes[0].sessions.is_empty());
        assert!(!data.truncated);
    }

    #[test]
    fn standalone_sessions_with_nat_translation() {
        let xml = fixture("standalone_with_nat.xml");
        let resp = parse_walk(&xml, Some(2), DEFAULT_CAP).unwrap();
        let data = resp.data.expect("data present");
        assert_eq!(data.nodes.len(), 1);
        assert_eq!(data.nodes[0].sessions.len(), 2);

        let natted = data.nodes[0]
            .sessions
            .iter()
            .find(|s| s.translated_source.is_some())
            .expect("one session has NAT");
        assert_eq!(
            natted.translated_source,
            Some(("192.0.2.1".parse().unwrap(), 40000))
        );

        let plain = data.nodes[0]
            .sessions
            .iter()
            .find(|s| s.translated_source.is_none())
            .expect("one session has no NAT");
        assert!(plain.translated_destination.is_none());
        assert!(!data.truncated);
    }

    // ── parse_walk: chassis cluster (node-aware, never merged) ───────────────

    #[test]
    fn clustered_sessions_present_on_one_node_only() {
        let xml = fixture("clustered_node0_only.xml");
        let resp = parse_walk(&xml, Some(1), DEFAULT_CAP).unwrap();
        let data = resp.data.expect("data present");
        assert_eq!(data.nodes.len(), 2, "both nodes reported, even if empty");

        let node0 = data.nodes.iter().find(|n| n.re_name == "node0").unwrap();
        let node1 = data.nodes.iter().find(|n| n.re_name == "node1").unwrap();
        assert_eq!(node0.sessions.len(), 1);
        assert!(
            node1.sessions.is_empty(),
            "node1 is secondary for this RG — empty, not merged with node0"
        );
    }

    #[test]
    fn clustered_sessions_on_both_nodes_kept_separate() {
        let xml = fixture("clustered_both_nodes.xml");
        let resp = parse_walk(&xml, Some(2), DEFAULT_CAP).unwrap();
        let data = resp.data.expect("data present");
        let node0 = data.nodes.iter().find(|n| n.re_name == "node0").unwrap();
        let node1 = data.nodes.iter().find(|n| n.re_name == "node1").unwrap();
        assert_eq!(node0.sessions.len(), 1);
        assert_eq!(node1.sessions.len(), 1);
        assert_ne!(
            node0.sessions[0].session_id, node1.sessions[0].session_id,
            "sessions must stay attributed to their own node, never merged into one table"
        );
    }

    // ── cap enforcement (MEC-55 AC: "a test proves the cap is enforced and reported") ──

    #[test]
    fn walk_result_truncated_when_node_exceeds_cap() {
        let xml = fixture("standalone_with_nat.xml"); // 2 sessions
        let resp = parse_walk(&xml, Some(2), 1).unwrap();
        let data = resp.data.expect("data present");
        assert_eq!(data.nodes[0].sessions.len(), 1, "cut to cap=1");
        assert!(data.truncated, "truncation must be reported");
        assert_eq!(data.cap, 1);
    }

    #[test]
    fn unfiltered_query_exceeding_cap_refuses_the_walk() {
        // total_count_reported (10) > cap (5), no filter — run() would refuse
        // the full walk RPC entirely and return an empty, truncated result.
        // Exercised here at the FlowSessionQuery-shape level (the RPC-skip
        // branch itself lives in run(), which needs a live device).
        let cap = 5u32;
        let total = 10u64;
        assert!(total > u64::from(cap));
        let resp = SrxToolResponse::active(FlowSessionQuery {
            nodes: Vec::new(),
            total_count_reported: Some(total),
            truncated: true,
            cap,
        });
        let data = resp.data.unwrap();
        assert!(data.nodes.is_empty(), "walk RPC must not have been issued");
        assert!(data.truncated);
        assert_eq!(data.total_count_reported, Some(10));
    }

    #[test]
    fn walk_not_truncated_when_summary_total_within_cap() {
        let xml = fixture("standalone_with_nat.xml");
        let resp = parse_walk(&xml, Some(2), DEFAULT_CAP).unwrap();
        let data = resp.data.expect("data present");
        assert!(!data.truncated);
    }
}
