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
//!
//! # Cap-refusal fix (Percy review, 2026-09-27)
//!
//! An earlier revision only refused the full walk when the summary count
//! exceeded the cap *and* the caller had supplied no filter — a `protocol=tcp`
//! or `destination_prefix=0.0.0.0/0` filter (accepted as "narrowing" even
//! though it matches everything) disabled the refusal outright, and an
//! unrecognised summary schema (`sessions-in-use` absent, `Ok(None)`) also
//! skipped it. Fixed by:
//! - sending the query's own filter args on the summary RPC too, so the
//!   reported count is for the *filtered* query, not the whole table;
//! - summing `sessions-in-use` across every `multi-routing-engine-item`
//!   (the previous single-node `.find()` undercounted clusters);
//! - deciding whether to walk from the summary count alone
//!   ([`plan_walk`]), dropping the filter-presence carve-out entirely —
//!   `count > cap` refuses regardless of whether a filter was given, and an
//!   unparseable/missing count now refuses rather than proceeding blind
//!   (fail closed: never walk unless the pre-walk count says it's safe);
//! - dropping the walk body from `include_raw` whenever the result is
//!   truncated, so a customer's full session table can no longer reach the
//!   model by way of the one field the cap doesn't otherwise touch.
//!
//! `/0` prefixes (match every address) are rejected pre-RPC in
//! [`validate_prefix`] for the same reason: they read as a filter but narrow
//! nothing.
//!
//! # Filtered-summary schema fix (Percy re-review, 2026-09-27)
//!
//! The cap-refusal fix above sent every query's filter args on the summary
//! RPC, but the parser only ever looked for `sessions-in-use` — the
//! *unfiltered* total. A live vsrx-ci capture during re-review
//! (`show security flow session summary protocol tcp`) showed a filtered
//! summary reports "Valid sessions" / "Pending sessions" / "Invalidated
//! sessions" / "Sessions in other states" / "Total sessions" and *no*
//! "Sessions-in-use" line at all. Every filtered query therefore parsed
//! `None` and was refused by [`plan_walk`]'s fail-closed rule — safe, but the
//! tool never actually returned sessions for the one case (a narrowed,
//! bounded query) it exists to serve.
//!
//! Fixed by also matching `displayed-session-count` (the filtered "Total
//! sessions" signal, by analogy with the unfiltered `valid-sessions` /
//! `pending-sessions` / ... family already in this module) alongside
//! `sessions-in-use`. As with the rest of this module's reply-body element
//! names, the *value* was captured live; the wrapping tag name is not
//! confirmed at the XML level, because vsrx-ci's `execute-junos-command`
//! strips `| display xml` to CLI text for this RPC. Flag any live mismatch
//! as a spec update, not a silent parser patch — until then this can only
//! ever refuse (fail closed), never guess a table is small when it isn't.
//!
//! The refuse/proceed decision also now carries *why* it refused
//! ([`RefusalReason`]) — `CountExceedsCap` and `CountUnavailable` looked
//! identical to a caller before (both `nodes: []`, `truncated: true`), and
//! "narrow your filter" and "the tool couldn't read the device's count" call
//! for different next actions.
//!
//! Finally, a node's `<rpc-error>` is now only treated as fatal for that node
//! when `error-severity` is absent or `error`. A `warning`-severity
//! `rpc-error` alongside real data (a node emitting a deprecation or
//! advisory notice next to its actual reply) no longer causes that node's
//! count to be dropped from the summary sum or its sessions dropped from the
//! walk — both used to fail *open* on the cap (an undercounted summary looks
//! like a smaller, safer table than it is) rather than closed.

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
    /// Set when this node's reply was an `<rpc-error>` rather than a session
    /// list — distinguishes "this node genuinely has no sessions" from "this
    /// node failed to answer" (a secondary node holding no sessions for the
    /// query is the expected case and looks identical to `sessions: []`
    /// unless this field is checked).
    pub error: Option<String>,
}

/// Why a `srx_flow_sessions` call refused the full walk, when it did.
///
/// Distinguishes "the table is too big for this cap" (narrow the query or
/// raise the cap) from "the tool couldn't read the device's count at all"
/// (a schema mismatch — narrowing the query won't help, since the tool
/// never learned the pre-narrowing count). Before this existed both cases
/// looked identical to a caller: `nodes: []`, `truncated: true`.
#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// The (filtered, cluster-summed) summary count exceeded `cap`.
    CountExceedsCap,
    /// The summary RPC returned no count this parser recognises.
    CountUnavailable,
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
    /// `cap`, or a walk's results were cut at `cap`).
    pub truncated: bool,
    /// Set when the full walk was refused outright (see [`RefusalReason`]).
    /// `None` when the walk ran, whether or not its results were truncated.
    pub refused: Option<RefusalReason>,
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
    session_identifier: Option<u64>,
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
        if let Some(v) = self.session_identifier {
            args.push(("session-identifier".to_string(), v.to_string()));
        }
        args
    }
}

/// Validate a prefix filter: a bare IP address or `addr/len` CIDR notation.
///
/// Rejects `/0` (matches every address of that family): it reads as a filter
/// but narrows nothing, which would otherwise let a caller dodge the
/// filterless-query rejection below without actually bounding the query.
///
/// Error messages never echo the caller-supplied value — it's customer data
/// (spec §6) and would otherwise land unredacted in logs/audit via the
/// error's `Display` impl.
fn validate_prefix(s: &str) -> Result<String, SrxError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(SrxError::InvalidInput("prefix must not be empty".into()));
    }
    match trimmed.split_once('/') {
        Some((addr, len)) => {
            let ip: IpAddr = addr
                .parse()
                .map_err(|_| SrxError::InvalidInput("invalid prefix address".into()))?;
            let len: u8 = len
                .parse()
                .map_err(|_| SrxError::InvalidInput("invalid prefix length".into()))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if len == 0 {
                return Err(SrxError::InvalidInput(
                    "prefix length must be at least 1 (/0 matches every address, which is not a \
                     valid filter)"
                        .into(),
                ));
            }
            if len > max {
                return Err(SrxError::InvalidInput("prefix length out of range".into()));
            }
        }
        None => {
            let _: IpAddr = trimmed
                .parse()
                .map_err(|_| SrxError::InvalidInput("invalid prefix".into()))?;
        }
    }
    Ok(trimmed.to_string())
}

/// Validate a free-text identifier token (an `application` name) before it
/// reaches the RPC. `rustez::build_rpc_xml` escapes the value, so this is not
/// an injection guard — it's a type/length check so a caller can't hand the
/// device an arbitrarily large or control-character-laden string.
fn validate_identifier_token(field: &'static str, s: &str) -> Result<String, SrxError> {
    if s.len() > 63 {
        return Err(SrxError::InvalidInput(format!(
            "{field} must be 63 characters or fewer"
        )));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(SrxError::InvalidInput(format!(
            "{field} must match [A-Za-z0-9._-]+"
        )));
    }
    Ok(s.to_string())
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
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| validate_identifier_token("application", s))
        .transpose()?;
    let session_identifier = args
        .session_identifier
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<u64>().map_err(|_| {
                SrxError::InvalidInput("session_identifier must be a non-negative integer".into())
            })
        })
        .transpose()?;

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

    // The summary RPC gets the query's own filter args too, so the reported
    // count is for what the walk would actually return, not the whole table.
    let owned_rpc_args = filter.to_rpc_args();
    let filter_rpc_args: Vec<(&str, &str)> = owned_rpc_args
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let mut summary_call_args: Vec<(&str, &str)> = Vec::with_capacity(filter_rpc_args.len() + 1);
    summary_call_args.push(("summary", ""));
    summary_call_args.extend(filter_rpc_args.iter().copied());

    let summary_xml = exec
        .call("get-flow-session-information", &summary_call_args)
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let total_count_reported = parse_summary_total(&summary_xml)?;

    // Blast-radius refusal: decided from the summary count alone (see
    // `plan_walk`) — never from whether a filter happened to be present.
    if let WalkDecision::Refuse(reason) = plan_walk(total_count_reported, cap) {
        let resp = SrxToolResponse::active(FlowSessionQuery {
            nodes: Vec::new(),
            total_count_reported,
            truncated: true,
            refused: Some(reason),
            cap,
        });
        return Ok(if args.include_raw {
            resp.with_raw(compose_refuse_raw(&summary_xml))
        } else {
            resp
        });
    }

    let walk_xml = exec
        .call("get-flow-session-information", &filter_rpc_args)
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let mut parsed = parse_walk(&walk_xml, total_count_reported, cap)?;
    if args.include_raw {
        let truncated = parsed.data.as_ref().is_some_and(|d| d.truncated);
        parsed = parsed.with_raw(compose_walk_raw(&summary_xml, &walk_xml, truncated));
    }
    Ok(parsed)
}

/// Whether `run()` should attempt the full walk RPC, decided purely from the
/// summary count and the cap — never from whether the caller supplied a
/// filter (a filter that doesn't actually narrow anything, e.g. `protocol=
/// tcp` or a `/0` prefix — the latter rejected earlier by `validate_prefix`
/// regardless — must not be able to disable this check).
///
/// `None` (summary schema didn't parse, or the RPC returned no count) is
/// refused, not proceeded: the fail-closed lens says a full-table walk must
/// never run on the strength of an absent safety number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalkDecision {
    Proceed,
    Refuse(RefusalReason),
}

fn plan_walk(summary_total: Option<u64>, cap: u32) -> WalkDecision {
    match summary_total {
        Some(total) if total <= u64::from(cap) => WalkDecision::Proceed,
        Some(_) => WalkDecision::Refuse(RefusalReason::CountExceedsCap),
        None => WalkDecision::Refuse(RefusalReason::CountUnavailable),
    }
}

/// Raw XML to attach when the walk was refused: the summary only, since no
/// walk was ever issued.
fn compose_refuse_raw(summary_xml: &str) -> String {
    format!("<!-- summary -->\n{summary_xml}")
}

/// Raw XML to attach when the walk did run. The walk body is included only
/// when the structured result was *not* truncated — a truncated result means
/// the parsed `sessions` list is already capped, but the raw walk XML is not,
/// so attaching it here would hand the model the full untruncated table
/// through the one field the cap doesn't otherwise touch.
fn compose_walk_raw(summary_xml: &str, walk_xml: &str, truncated: bool) -> String {
    if truncated {
        format!(
            "<!-- summary -->\n{summary_xml}\n<!-- walk raw XML omitted: result was truncated \
             to the cap, and the raw walk body is not cap-bounded -->"
        )
    } else {
        format!("<!-- summary -->\n{summary_xml}\n<!-- walk -->\n{walk_xml}")
    }
}

// ── Parsers ───────────────────────────────────────────────────────────────────

/// Parse the `<summary/>`-flagged reply for the total session count, summed
/// across every routing engine (a cluster's node0/node1 counts must both
/// contribute — reading only the first node undercounts the table the walk
/// would enumerate).
///
/// Two element names are recognised, depending on whether the summary RPC
/// carried filter args: `sessions-in-use` (unfiltered — the whole table) or
/// `displayed-session-count` (filtered — the count matching the filter; see
/// module docs for why a filtered query never reports `sessions-in-use`).
/// Absence of both on a given node is not a hard error — `run()` treats an
/// overall `None` as "refuse the walk", per `plan_walk`'s fail-closed
/// contract.
///
/// A node whose only reply content is a `warning`-severity `rpc-error`
/// still has its count read. A severity-less `rpc-error` (the routine reply
/// from a cluster's secondary node) skips that node, as before. An explicit
/// `error`-severity `rpc-error` on **any** node
/// makes the whole total unavailable (`Ok(None)`, i.e. `CountUnavailable`):
/// summing only the healthy nodes would under-count, and `plan_walk` could
/// then let an unbounded walk proceed for the node that failed its summary
/// (Percy F2, MEC-302 — fail closed).
pub fn parse_summary_total(xml: &str) -> Result<Option<u64>, SrxError> {
    let re_nodes = crate::xml::multi_re_split(xml)?;

    let mut total: u64 = 0;
    let mut any_found = false;
    for re_node in &re_nodes {
        match extract_rpc_error(&re_node.inner_xml) {
            // An explicit error on any node: the total is unknowable.
            Some(e) if e.is_error => return Ok(None),
            // Severity-less (e.g. a cluster secondary node's routine
            // "node is secondary" reply): that node has no usable summary.
            Some(e) if !e.is_warning => continue,
            _ => {}
        }
        let wrapped = ensure_single_root(&re_node.inner_xml);
        let doc = roxmltree::Document::parse(&wrapped)
            .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;
        let count = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "displayed-session-count")
            .and_then(|n| n.text())
            .and_then(|t| t.trim().parse::<u64>().ok())
            .or_else(|| {
                doc.descendants()
                    .find(|n| n.is_element() && n.tag_name().name() == "sessions-in-use")
                    .and_then(|n| n.text())
                    .and_then(|t| t.trim().parse::<u64>().ok())
            });
        if let Some(count) = count {
            total = total.saturating_add(count);
            any_found = true;
        }
    }
    Ok(any_found.then_some(total))
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
        let rpc_error = extract_rpc_error(&re_node.inner_xml);
        if let Some(err) = &rpc_error
            && !err.is_warning
        {
            // A node holding no sessions for this query (e.g. secondary for
            // every relevant RG) is a normal per-node result, not a failure
            // of the whole call — but the message is kept so a genuine
            // per-node failure isn't silently reported as "zero sessions".
            nodes.push(NodeSessions {
                re_name: re_node.re_name.clone(),
                sessions: Vec::new(),
                error: Some(err.message.clone()),
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
            // A warning-severity rpc-error is not a per-node failure, but
            // the message is still surfaced alongside the sessions it came
            // with — it isn't discarded just because parsing continued.
            error: rpc_error.map(|e| e.message),
        });
    }

    Ok(SrxToolResponse::active(FlowSessionQuery {
        nodes,
        total_count_reported,
        truncated,
        refused: None,
        cap,
    }))
}

/// Parse every `<flow-session>` block in one node's fragment.
fn parse_sessions(xml: &str) -> Result<Vec<FlowSession>, SrxError> {
    let wrapped = ensure_single_root(xml);
    let doc = roxmltree::Document::parse(&wrapped)
        .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;

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

/// Wrap `xml` in a synthetic root if it doesn't already parse as one
/// well-formed document.
///
/// `multi_re_split` hands back the concatenation of every child of a
/// `<multi-routing-engine-item>` except `<re-name>` — a single node can
/// carry more than one top-level sibling (e.g. a `flow-session-information`
/// block *and* a `warning`-severity `rpc-error`, the case R3 needs to parse
/// through rather than bail out of), which `roxmltree::Document::parse`
/// rejects outright as multiple document roots. Mirrors `xml::text_of`'s
/// same fallback for the same reason.
fn ensure_single_root(xml: &str) -> std::borrow::Cow<'_, str> {
    if roxmltree::Document::parse(xml).is_ok() {
        std::borrow::Cow::Borrowed(xml)
    } else {
        std::borrow::Cow::Owned(format!("<_>{xml}</_>"))
    }
}

fn child_text(node: &roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == name)
        .and_then(|n| n.text())
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// A node's `<rpc-error>`, if its fragment contains one.
struct RpcErrorInfo {
    message: String,
    /// True when `<error-severity>warning</error-severity>` — a warning is
    /// informational and does not mean the node's reply lacks usable data,
    /// unlike an absent severity or `error` (Junos's default when the
    /// element is omitted).
    is_warning: bool,
    /// `<error-severity>error</error-severity>` explicitly present. A
    /// severity-less rpc-error (e.g. the routine "node is secondary for all
    /// relevant redundancy groups" reply from a cluster's secondary node) is
    /// neither a warning nor an explicit error.
    is_error: bool,
}

/// Extract a node's `<rpc-error>`, if the fragment contains one. `None`
/// means the fragment is a normal (non-error) reply body.
fn extract_rpc_error(xml: &str) -> Option<RpcErrorInfo> {
    let wrapped = ensure_single_root(xml);
    let doc = roxmltree::Document::parse(&wrapped).ok()?;
    let err = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "rpc-error")?;
    let message = err
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "error-message")
        .and_then(|n| n.text())
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "rpc-error (no error-message)".to_string());
    let is_warning = err
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "error-severity")
        .and_then(|n| n.text())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("warning"));
    let is_error = err
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "error-severity")
        .and_then(|n| n.text())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("error"));
    Some(RpcErrorInfo {
        message,
        is_warning,
        is_error,
    })
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

    // ── R1 (Percy re-review): a filtered summary has no `sessions-in-use`
    // at all — the earlier fix only ever looked for that element, so every
    // filtered query parsed `None` and was refused unconditionally, which
    // is the opposite of what the mandatory-filter design is for. ─────────

    #[test]
    fn filtered_summary_total_parses_displayed_session_count() {
        // displayed-session-count=1 is the REAL count captured live against
        // vsrx-ci for a *filtered* query (module docs); the wrapping XML is
        // a hypothesis, same as the unfiltered fixture.
        let xml = fixture("summary_filtered_vsrx_ci.xml");
        let total = parse_summary_total(&xml).unwrap();
        assert_eq!(total, Some(1));
    }

    #[test]
    fn summary_with_one_node_rpc_error_is_unavailable() {
        // Percy F2 (MEC-302): node0 reports a count, node1 fails its summary
        // with an error-severity rpc-error. Summing only node0 would
        // under-count and let plan_walk proceed; the total must be None.
        let xml = r#"<rpc-reply>
  <multi-routing-engine-results>
    <multi-routing-engine-item>
      <re-name>node0</re-name>
      <flow-session-information>
        <sessions-in-use>3</sessions-in-use>
      </flow-session-information>
    </multi-routing-engine-item>
    <multi-routing-engine-item>
      <re-name>node1</re-name>
      <rpc-error>
        <error-severity>error</error-severity>
        <error-message>node1 summary unavailable</error-message>
      </rpc-error>
    </multi-routing-engine-item>
  </multi-routing-engine-results>
</rpc-reply>"#;
        assert_eq!(parse_summary_total(xml).unwrap(), None);
        assert_eq!(
            plan_walk(None, DEFAULT_CAP),
            WalkDecision::Refuse(RefusalReason::CountUnavailable),
            "an unavailable total must refuse the walk"
        );
    }

    #[test]
    fn filtered_summary_under_cap_lets_plan_walk_proceed() {
        let xml = fixture("summary_filtered_vsrx_ci.xml");
        let total = parse_summary_total(&xml).unwrap();
        assert_eq!(
            plan_walk(total, DEFAULT_CAP),
            WalkDecision::Proceed,
            "a filtered, in-cap query must not be refused just because it \
             carries no sessions-in-use element"
        );
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
        assert!(node0.error.is_none());
        assert_eq!(
            node1.error.as_deref(),
            Some("node is secondary for all relevant redundancy groups"),
            "node1's rpc-error must be surfaced, not silently reported as zero sessions"
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
        assert!(node0.error.is_none());
        assert!(node1.error.is_none());
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
    fn walk_not_truncated_when_summary_total_within_cap() {
        let xml = fixture("standalone_with_nat.xml");
        let resp = parse_walk(&xml, Some(2), DEFAULT_CAP).unwrap();
        let data = resp.data.expect("data present");
        assert!(!data.truncated);
    }

    // ── plan_walk: the actual refuse/proceed decision (F2 fix — this used to
    // be exercised only by a test that constructed its own expected output
    // and asserted on it, never calling the decision logic) ─────────────────

    #[test]
    fn plan_walk_refuses_when_count_exceeds_cap() {
        // The bug this closes: plan_walk takes no filter argument at all —
        // a caller-supplied filter (protocol=tcp, a wide prefix, etc.) can no
        // longer disable the refusal, because the decision never looks at
        // whether one was given, only at the reported count vs. the cap.
        assert_eq!(
            plan_walk(Some(10), 5),
            WalkDecision::Refuse(RefusalReason::CountExceedsCap)
        );
    }

    #[test]
    fn plan_walk_refuses_when_summary_count_is_unknown() {
        // Fail closed: an unparseable/missing summary count must never be
        // treated as "safe to walk".
        assert_eq!(
            plan_walk(None, 5),
            WalkDecision::Refuse(RefusalReason::CountUnavailable)
        );
    }

    #[test]
    fn plan_walk_proceeds_when_count_is_within_cap() {
        assert_eq!(plan_walk(Some(5), 5), WalkDecision::Proceed);
        assert_eq!(plan_walk(Some(3), 5), WalkDecision::Proceed);
    }

    // ── R2 (Percy re-review): refusal reason distinguishes "narrow the
    // query" from "the tool couldn't read the device's count" ───────────────

    #[test]
    fn refusal_reason_distinguishes_over_cap_from_unavailable_count() {
        assert_ne!(
            plan_walk(Some(10), 5),
            plan_walk(None, 5),
            "count-exceeds-cap and count-unavailable must be distinguishable, \
             not both collapse to the same refusal"
        );
    }

    // ── compose_walk_raw: include_raw must never carry the walk body past
    // the cap (F1 fix) ────────────────────────────────────────────────────────

    #[test]
    fn raw_walk_body_omitted_when_result_truncated() {
        let raw = compose_walk_raw(
            "<summary/>",
            "<flow-session-information><flow-session><session-identifier>1</session-identifier>\
             </flow-session></flow-session-information>",
            true,
        );
        assert!(
            !raw.contains("flow-session-information"),
            "truncated result must not leak the raw walk body: {raw}"
        );
    }

    #[test]
    fn raw_walk_body_included_when_result_not_truncated() {
        let raw = compose_walk_raw("<summary/>", "<flow-session-information/>", false);
        assert!(raw.contains("flow-session-information"));
    }

    #[test]
    fn raw_refuse_carries_only_the_summary() {
        let raw = compose_refuse_raw("<flow-session-summary-information/>");
        assert!(raw.contains("flow-session-summary-information"));
        assert!(!raw.contains("<flow-session>"));
    }

    // ── summing sessions-in-use across cluster nodes ─────────────────────────

    #[test]
    fn summary_total_sums_across_both_cluster_nodes() {
        let xml = r#"<rpc-reply>
  <multi-routing-engine-results>
    <multi-routing-engine-item>
      <re-name>node0</re-name>
      <flow-session-summary-information>
        <sessions-in-use>4</sessions-in-use>
      </flow-session-summary-information>
    </multi-routing-engine-item>
    <multi-routing-engine-item>
      <re-name>node1</re-name>
      <flow-session-summary-information>
        <sessions-in-use>6</sessions-in-use>
      </flow-session-summary-information>
    </multi-routing-engine-item>
  </multi-routing-engine-results>
</rpc-reply>"#;
        assert_eq!(parse_summary_total(xml).unwrap(), Some(10));
    }

    #[test]
    fn summary_total_ignores_a_node_reporting_rpc_error() {
        let xml = r#"<rpc-reply>
  <multi-routing-engine-results>
    <multi-routing-engine-item>
      <re-name>node0</re-name>
      <flow-session-summary-information>
        <sessions-in-use>4</sessions-in-use>
      </flow-session-summary-information>
    </multi-routing-engine-item>
    <multi-routing-engine-item>
      <re-name>node1</re-name>
      <rpc-error>
        <error-message>node is secondary for all relevant redundancy groups</error-message>
      </rpc-error>
    </multi-routing-engine-item>
  </multi-routing-engine-results>
</rpc-reply>"#;
        assert_eq!(parse_summary_total(xml).unwrap(), Some(4));
    }

    // ── R3 (Percy re-review): a `warning`-severity rpc-error alongside real
    // data must not drop that node's count — only an absent/`error`-severity
    // rpc-error means the node produced no usable reply. ─────────────────────

    #[test]
    fn summary_total_counts_a_node_reporting_only_a_warning() {
        let xml = r#"<rpc-reply>
  <multi-routing-engine-results>
    <multi-routing-engine-item>
      <re-name>node0</re-name>
      <flow-session-summary-information>
        <sessions-in-use>4</sessions-in-use>
      </flow-session-summary-information>
      <rpc-error>
        <error-severity>warning</error-severity>
        <error-message>deprecated command syntax</error-message>
      </rpc-error>
    </multi-routing-engine-item>
    <multi-routing-engine-item>
      <re-name>node1</re-name>
      <rpc-error>
        <error-message>node is secondary for all relevant redundancy groups</error-message>
      </rpc-error>
    </multi-routing-engine-item>
  </multi-routing-engine-results>
</rpc-reply>"#;
        assert_eq!(
            parse_summary_total(xml).unwrap(),
            Some(4),
            "a warning alongside real data must not undercount the summary \
             (fails open on the cap if it does)"
        );
    }

    #[test]
    fn walk_keeps_sessions_from_a_node_reporting_only_a_warning() {
        let xml = r#"<rpc-reply>
  <multi-routing-engine-results>
    <multi-routing-engine-item>
      <re-name>node0</re-name>
      <flow-session-information>
        <flow-session>
          <session-identifier>1001</session-identifier>
          <session-protocol-name>tcp</session-protocol-name>
          <source-address>198.51.100.5</source-address>
          <source-port>443</source-port>
          <destination-address>203.0.113.9</destination-address>
          <destination-port>51000</destination-port>
        </flow-session>
      </flow-session-information>
      <rpc-error>
        <error-severity>warning</error-severity>
        <error-message>deprecated command syntax</error-message>
      </rpc-error>
    </multi-routing-engine-item>
  </multi-routing-engine-results>
</rpc-reply>"#;
        let resp = parse_walk(xml, Some(1), DEFAULT_CAP).unwrap();
        let data = resp.data.expect("data present");
        assert_eq!(
            data.nodes[0].sessions.len(),
            1,
            "a warning-severity rpc-error must not drop this node's sessions"
        );
        assert_eq!(
            data.nodes[0].error.as_deref(),
            Some("deprecated command syntax"),
            "the warning is still surfaced, just not treated as fatal"
        );
    }

    // ── /0 prefix rejection (F1 fix) ──────────────────────────────────────────

    #[test]
    fn slash_zero_ipv4_prefix_rejected_pre_rpc() {
        let mut args = base_args();
        args.destination_prefix = Some("0.0.0.0/0".into());
        assert!(matches!(
            validate_filter(&args),
            Err(SrxError::InvalidInput(_))
        ));
    }

    #[test]
    fn slash_zero_ipv6_prefix_rejected_pre_rpc() {
        let mut args = base_args();
        args.destination_prefix = Some("::/0".into());
        assert!(matches!(
            validate_filter(&args),
            Err(SrxError::InvalidInput(_))
        ));
    }

    // ── session_identifier / application: pre-RPC validation (F6 fix) ────────

    #[test]
    fn non_numeric_session_identifier_rejected_pre_rpc() {
        let mut args = base_args();
        args.session_identifier = Some("not-a-number".into());
        assert!(matches!(
            validate_filter(&args),
            Err(SrxError::InvalidInput(_))
        ));
    }

    #[test]
    fn numeric_session_identifier_accepted() {
        let mut args = base_args();
        args.session_identifier = Some("300001".into());
        let filter = validate_filter(&args).expect("should validate");
        assert_eq!(filter.session_identifier, Some(300_001));
    }

    #[test]
    fn application_with_disallowed_characters_rejected_pre_rpc() {
        let mut args = base_args();
        args.application = Some("junos-https; rm -rf /".into());
        assert!(matches!(
            validate_filter(&args),
            Err(SrxError::InvalidInput(_))
        ));
    }

    #[test]
    fn application_error_message_does_not_echo_the_raw_value() {
        let mut args = base_args();
        args.application = Some("junos-https; rm -rf /".into());
        let err = validate_filter(&args).unwrap_err().to_string();
        assert!(
            !err.contains("rm -rf"),
            "error must not echo raw input: {err}"
        );
    }

    #[test]
    fn well_formed_application_accepted() {
        let mut args = base_args();
        args.application = Some("junos-https".into());
        let filter = validate_filter(&args).expect("should validate");
        assert_eq!(filter.application.as_deref(), Some("junos-https"));
    }
}
