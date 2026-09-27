//! `srx_policy_match` — `show security match-policies` for a 5-tuple.
//!
//! This is the deterministic "would this traffic be allowed" answer (spec:
//! `srx-policy-read-spec`, MEC-53, §6). The tool exists specifically so
//! nothing upstream ever has to infer a match from the policy list itself —
//! the device's own verdict is returned unchanged.
//!
//! # RPC name correction (2026-09-27, live `vsrx-ci` capture)
//!
//! The spec originally hypothesized `get-match-policies-information` with
//! `from-zone-name`/`to-zone-name` args. A live `show security
//! match-policies ... | display xml rpc` capture against `vsrx-ci` (which
//! prints the RPC a CLI command maps to, without needing a raw-RPC-capable
//! tool) confirmed the real RPC is `<match-firewall-policies>`, with flat,
//! unsuffixed args: `from-zone`, `to-zone`, `source-ip`, `destination-ip`,
//! `source-port`, `destination-port`, `protocol`. `srx-policy-read-spec` §11
//! has been corrected; this module implements the corrected name.
//!
//! # Junos XML schema — reply body NOT live-confirmed
//!
//! The MCP tool available for this capture executes CLI text and separately
//! exposes `| display xml rpc` (request shape only); it does not return the
//! executed reply in structured per-element XML for this command. One field
//! mapping IS real: a live `trust`→`untrust` match-policies query against
//! `vsrx-ci` (which has only a global permit-all policy, no explicit
//! zone-pair policy) returned the CLI text:
//!
//! ```text
//! Policy: Default-Policy, action-type: deny-all, State: enabled, Index: 2
//!   Sequence number: 2
//! ```
//!
//! i.e. the device's own default-deny fallthrough, confirming `action-type:
//! deny-all` (not folded into a generic "deny") is the literal signal Junos
//! uses for "no explicit policy matched". This also corroborates spec open
//! question 1: the global any/any policy did **not** apply to this explicit
//! zone-pair query.
//!
//! The fixtures below hand-write the XML element names following this
//! crate's Junos XML conventions (hyphenated tags, `-results` root, a
//! `policy-information` record block) and the confirmed `action-type` /
//! `policy-name` field labels above. Element names beyond those two are a
//! hypothesis, not a live-confirmed schema — flagged here and in the PR
//! description per "parser differentials are an exploit, not a quirk": a
//! future live capture that disagrees should correct this module and the
//! spec, not be silently patched around.
//!
//! # `default-policy permit-all` fix (Percy review, 2026-09-27)
//!
//! An earlier revision mapped only `action-type: deny-all` to `NoMatch`,
//! treating every other unrecognised `action-type` (including `permit-all`,
//! which `set security policies default-policy permit-all` produces) as a
//! parse error. That meant a device configured to permit unmatched traffic
//! answered this deterministic "would this traffic be allowed" tool with an
//! error at exactly the moment the answer matters most — unmatched traffic on
//! such a device is *allowed*, not blocked. `permit-all` is now recognised
//! alongside `deny-all`, and [`PolicyMatchResult::default_action`] records
//! which one applied so a caller can distinguish "no policy matched, and the
//! device denies by default" from "no policy matched, and the device permits
//! by default" — both are `NoMatch`, but they are not the same answer.
//!
//! # Customer-data note (spec §6)
//!
//! The 5-tuple is customer data in the *request* as well as the response.
//! `mecmcp-redact` (H1a / MEC-11) does not exist yet — it is blocked on
//! MEC-9 (GitHub connection). Until it lands, this module does not echo the
//! 5-tuple into any error message or log line above what `tracing`'s normal
//! `SrxError` display already carries (none of the `InvalidInput` messages
//! below include the raw IP/port values), so there is no new unredacted
//! logging path introduced here — but the argument-side redaction pass
//! called for in the spec is still outstanding and belongs to MEC-11/H1c,
//! not this tool.

use crate::protocol::Protocol;
use crate::{SrxError, SrxToolResponse};
use rust_junosmcp_core::device_manager::PooledDevice;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ── Public types ──────────────────────────────────────────────────────────────

/// Arguments for `srx_policy_match`.
///
/// Fields arrive as raw strings/numbers (MCP JSON args have no IP/port/enum
/// types); [`parse_five_tuple`] is the one place that turns them into a
/// [`FiveTuple`] before any RPC is built.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = rust_junosmcp_core::schema_alias::router_name_alias)]
pub struct PolicyMatchArgs {
    /// Device name (aliased as router_name).
    #[serde(alias = "router_name")]
    pub router: String,
    /// Source zone name.
    pub from_zone: String,
    /// Destination zone name.
    pub to_zone: String,
    /// Source IP address (no CIDR — a single host address).
    pub source_ip: String,
    /// Destination IP address (no CIDR — a single host address).
    pub destination_ip: String,
    /// Source port, 0-65535.
    pub source_port: u32,
    /// Destination port, 0-65535.
    pub destination_port: u32,
    /// Protocol: "tcp", "udp", "icmp" (case-insensitive), or a numeric IANA
    /// protocol number.
    pub protocol: String,
    /// Include raw XML from device in response. Default false.
    #[serde(default)]
    pub include_raw: bool,
}

/// A validated, typed 5-tuple. Constructing one is the pre-RPC validation
/// gate — a malformed call is unrepresentable once this type exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiveTuple {
    /// Source zone name.
    pub from_zone: String,
    /// Destination zone name.
    pub to_zone: String,
    /// Source IP address.
    pub source_ip: IpAddr,
    /// Destination IP address.
    pub destination_ip: IpAddr,
    /// Source port.
    pub source_port: u16,
    /// Destination port.
    pub destination_port: u16,
    /// IP protocol.
    pub protocol: Protocol,
}

/// The device's own verdict for a 5-tuple match.
///
/// `NoMatch` (default-policy fallthrough, no explicit policy) is kept
/// distinct from `Deny` (an explicit deny/reject policy matched) — a SOC
/// operator or `firewallintentconverter` needs to tell those apart. `NoMatch`
/// does not by itself say whether unmatched traffic is denied or permitted —
/// see [`PolicyMatchResult::default_action`].
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum MatchVerdict {
    /// An explicit permit policy matched.
    Permit,
    /// An explicit deny policy matched.
    Deny,
    /// An explicit reject policy matched.
    Reject,
    /// No explicit policy matched; the device's default-policy fallthrough
    /// applied. Check `default_action` for whether that means deny or permit.
    NoMatch,
}

/// Which way a device's default-policy fallthrough resolves unmatched
/// traffic. Only meaningful when [`PolicyMatchResult::verdict`] is
/// `MatchVerdict::NoMatch`.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    /// `set security policies default-policy deny-all` (the Junos default).
    Deny,
    /// `set security policies default-policy permit-all`.
    Permit,
}

/// The policy that matched, when `verdict != NoMatch`.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct MatchedPolicy {
    /// From-zone of the matched policy (`"any"` for a global policy).
    pub from_zone: String,
    /// To-zone of the matched policy (`"any"` for a global policy).
    pub to_zone: String,
    /// Policy name.
    pub name: String,
    /// Evaluation sequence number.
    pub sequence: u32,
}

/// Result of a `srx_policy_match` query.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct PolicyMatchResult {
    /// The device's verdict for this 5-tuple.
    pub verdict: MatchVerdict,
    /// The matched policy. `None` only for `NoMatch`.
    pub matched_policy: Option<MatchedPolicy>,
    /// True when the matched policy is a global (zone-independent) policy.
    pub is_global: bool,
    /// Set only when `verdict == NoMatch`: which default-policy action the
    /// device applied to this unmatched traffic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_action: Option<DefaultAction>,
}

// ── Pre-RPC validation ───────────────────────────────────────────────────────

/// Validate a zone-name token before it reaches the RPC. `rustez::build_rpc_xml`
/// escapes the value on the wire, so this is not an injection guard — it's a
/// type/length check (Junos zone names are short, `[A-Za-z0-9._-]+` tokens)
/// so a caller can't hand the device an arbitrarily large or control-character
/// string. Error messages never echo the raw value — zone names are customer
/// data (spec §6).
fn validate_zone_token(field: &'static str, s: &str) -> Result<String, SrxError> {
    if s.is_empty() {
        return Err(SrxError::InvalidInput(format!("{field} must not be empty")));
    }
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

/// Parse and validate a [`PolicyMatchArgs`] into a typed [`FiveTuple`].
///
/// Returns `SrxError::InvalidInput` for anything malformed, before any RPC
/// is built or sent — this is what the MEC-55 "invalid 5-tuple input is
/// rejected pre-RPC" acceptance criterion targets.
pub fn parse_five_tuple(args: &PolicyMatchArgs) -> Result<FiveTuple, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    let from_zone = validate_zone_token("from_zone", args.from_zone.trim())?;
    let to_zone = validate_zone_token("to_zone", args.to_zone.trim())?;
    let source_ip: IpAddr = args
        .source_ip
        .trim()
        .parse()
        .map_err(|_| SrxError::InvalidInput("source_ip is not a valid IP address".into()))?;
    let destination_ip: IpAddr =
        args.destination_ip.trim().parse().map_err(|_| {
            SrxError::InvalidInput("destination_ip is not a valid IP address".into())
        })?;
    let source_port = u16::try_from(args.source_port)
        .map_err(|_| SrxError::InvalidInput("source_port must be 0-65535".into()))?;
    let destination_port = u16::try_from(args.destination_port)
        .map_err(|_| SrxError::InvalidInput("destination_port must be 0-65535".into()))?;
    let protocol = Protocol::parse(&args.protocol)?;

    Ok(FiveTuple {
        from_zone,
        to_zone,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol,
    })
}

// ── `run()` — async entry point ───────────────────────────────────────────────

/// Run `match-firewall-policies` against a pooled device and return a typed
/// `SrxToolResponse<PolicyMatchResult>`.
pub async fn run(
    device: &mut PooledDevice,
    args: PolicyMatchArgs,
) -> Result<SrxToolResponse<PolicyMatchResult>, SrxError> {
    let five_tuple = parse_five_tuple(&args)?;

    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let source_port_s = five_tuple.source_port.to_string();
    let destination_port_s = five_tuple.destination_port.to_string();
    let protocol_s = five_tuple.protocol.rpc_value();
    let source_ip_s = five_tuple.source_ip.to_string();
    let destination_ip_s = five_tuple.destination_ip.to_string();

    let reply = exec
        .call(
            "match-firewall-policies",
            &[
                ("from-zone", five_tuple.from_zone.as_str()),
                ("to-zone", five_tuple.to_zone.as_str()),
                ("source-ip", source_ip_s.as_str()),
                ("destination-ip", destination_ip_s.as_str()),
                ("source-port", source_port_s.as_str()),
                ("destination-port", destination_port_s.as_str()),
                ("protocol", protocol_s.as_str()),
            ],
        )
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let mut parsed = parse(&reply)?;
    if args.include_raw {
        parsed = parsed.with_raw(reply);
    }
    Ok(parsed)
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse a `match-firewall-policies` reply body into a typed
/// `SrxToolResponse<PolicyMatchResult>`.
///
/// Pure, unit-testable entry point; `run()` calls it after obtaining the raw
/// XML from the device. `match-policies` is a config-plane answer (which
/// policy would match), not session-plane, so unlike `srx_flow_sessions` it
/// does not need per-node splitting for correctness — but the reply is still
/// routed through `multi_re_split` defensively, using whichever node
/// responds first without an `<rpc-error>` (both should agree, per spec §6).
pub fn parse(xml: &str) -> Result<SrxToolResponse<PolicyMatchResult>, SrxError> {
    let cleaned = crate::xml::sanitize_rustez_xml(xml);
    let re_nodes = crate::xml::multi_re_split(&cleaned)?;

    let node = re_nodes
        .iter()
        .find(|n| !contains_rpc_error(&n.inner_xml))
        .ok_or_else(|| SrxError::Rpc {
            tag: "rpc-error".into(),
            severity: "error".into(),
            message: "every node returned rpc-error for match-firewall-policies".into(),
        })?;

    let doc = roxmltree::Document::parse(&node.inner_xml)
        .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;

    let policy_node = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "policy-information")
        .ok_or_else(|| {
            SrxError::schema_mismatch("match-firewall-policies", "policy-information")
        })?;

    let policy_name = child_text(&policy_node, "policy-name")
        .ok_or_else(|| SrxError::schema_mismatch("match-firewall-policies", "policy-name"))?;
    let action_type = child_text(&policy_node, "action-type")
        .ok_or_else(|| SrxError::schema_mismatch("match-firewall-policies", "action-type"))?;
    let sequence: u32 = child_text(&policy_node, "policy-sequence-number")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

    let action_lc = action_type.trim().to_ascii_lowercase();

    // "deny-all" / "permit-all" on the synthetic "Default-Policy" are
    // Junos's literal signal for the default-policy fallthrough — "deny-all"
    // confirmed live against vsrx-ci (see module docs); "permit-all" is the
    // documented counterpart for `default-policy permit-all` (fixed after
    // Percy review — see module docs). Keyed on action-type, not the policy
    // name, since the name is a device-chosen label, not a stable contract.
    let default_action = match action_lc.as_str() {
        "deny-all" => Some(DefaultAction::Deny),
        "permit-all" => Some(DefaultAction::Permit),
        _ => None,
    };
    if let Some(default_action) = default_action {
        return Ok(SrxToolResponse::active(PolicyMatchResult {
            verdict: MatchVerdict::NoMatch,
            matched_policy: None,
            is_global: false,
            default_action: Some(default_action),
        }));
    }

    let verdict = match action_lc.as_str() {
        "permit" => MatchVerdict::Permit,
        "deny" => MatchVerdict::Deny,
        "reject" => MatchVerdict::Reject,
        other => {
            return Err(SrxError::Parse(format!(
                "unrecognised match-policies action-type: {other:?}"
            )));
        }
    };

    // Required (not defaulted to ""): an absent zone on an explicit policy
    // match is a schema mismatch, not "unknown zone" — silently defaulting
    // here previously meant a real schema drift could report is_global=false
    // on what was actually a global policy hit, with no error at all.
    let from_zone = child_text(&policy_node, "from-zone-name")
        .ok_or_else(|| SrxError::schema_mismatch("match-firewall-policies", "from-zone-name"))?;
    let to_zone = child_text(&policy_node, "to-zone-name")
        .ok_or_else(|| SrxError::schema_mismatch("match-firewall-policies", "to-zone-name"))?;

    let is_global = from_zone.eq_ignore_ascii_case("any") && to_zone.eq_ignore_ascii_case("any");

    Ok(SrxToolResponse::active(PolicyMatchResult {
        verdict,
        matched_policy: Some(MatchedPolicy {
            from_zone,
            to_zone,
            name: policy_name,
            sequence,
        }),
        is_global,
        default_action: None,
    }))
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
    use crate::SrxState;
    use pretty_assertions::assert_eq;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/policy_match")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()))
    }

    fn valid_args() -> PolicyMatchArgs {
        PolicyMatchArgs {
            router: "vsrx-ci".into(),
            from_zone: "trust".into(),
            to_zone: "untrust".into(),
            source_ip: "10.0.0.5".into(),
            destination_ip: "8.8.8.8".into(),
            source_port: 33000,
            destination_port: 443,
            protocol: "tcp".into(),
            include_raw: false,
        }
    }

    // ── parse_five_tuple: pre-RPC validation ─────────────────────────────────

    #[test]
    fn valid_five_tuple_parses() {
        let ft = parse_five_tuple(&valid_args()).expect("should parse");
        assert_eq!(ft.source_port, 33000);
        assert_eq!(ft.destination_port, 443);
        assert_eq!(ft.protocol, Protocol::Tcp);
    }

    #[test]
    fn empty_router_rejected() {
        let mut args = valid_args();
        args.router = "  ".into();
        assert!(matches!(
            parse_five_tuple(&args),
            Err(SrxError::InvalidInput(_))
        ));
    }

    #[test]
    fn bad_source_ip_rejected_pre_rpc() {
        let mut args = valid_args();
        args.source_ip = "not-an-ip".into();
        assert!(matches!(
            parse_five_tuple(&args),
            Err(SrxError::InvalidInput(_))
        ));
    }

    #[test]
    fn bad_destination_ip_rejected_pre_rpc() {
        let mut args = valid_args();
        args.destination_ip = "999.999.999.999".into();
        assert!(matches!(
            parse_five_tuple(&args),
            Err(SrxError::InvalidInput(_))
        ));
    }

    #[test]
    fn out_of_range_port_rejected_pre_rpc() {
        let mut args = valid_args();
        args.source_port = 70_000;
        assert!(matches!(
            parse_five_tuple(&args),
            Err(SrxError::InvalidInput(_))
        ));
    }

    #[test]
    fn unknown_protocol_token_rejected_pre_rpc() {
        let mut args = valid_args();
        args.protocol = "bogus".into();
        assert!(matches!(
            parse_five_tuple(&args),
            Err(SrxError::InvalidInput(_))
        ));
    }

    #[test]
    fn numeric_protocol_fallback_accepted() {
        let mut args = valid_args();
        args.protocol = "47".into();
        let ft = parse_five_tuple(&args).expect("numeric protocol should parse");
        assert_eq!(ft.protocol, Protocol::Other(47));
    }

    // ── parse(): fixture-driven verdicts ─────────────────────────────────────

    #[test]
    fn no_match_default_deny() {
        // Real CLI text captured live against vsrx-ci (module docs); the
        // wrapping XML tags are the hypothesis under test.
        let xml = fixture("no_match_default_deny.xml");
        let resp = parse(&xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::Active);
        let data = resp.data.expect("data present");
        assert_eq!(data.verdict, MatchVerdict::NoMatch);
        assert!(
            data.matched_policy.is_none(),
            "NoMatch has no matched_policy"
        );
        assert!(!data.is_global);
        assert_eq!(data.default_action, Some(DefaultAction::Deny));
    }

    #[test]
    fn no_match_default_permit_all() {
        // Regression for the bug this review closed: a device with
        // `default-policy permit-all` must not error on unmatched traffic —
        // that's exactly the case where the answer (permit) matters most.
        let xml = fixture("no_match_default_permit.xml");
        let resp = parse(&xml).expect("permit-all must not be treated as an unknown action-type");
        let data = resp.data.expect("data present");
        assert_eq!(data.verdict, MatchVerdict::NoMatch);
        assert!(data.matched_policy.is_none());
        assert_eq!(data.default_action, Some(DefaultAction::Permit));
    }

    #[test]
    fn explicit_permit_policy() {
        let xml = fixture("permit.xml");
        let resp = parse(&xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.verdict, MatchVerdict::Permit);
        let policy = data.matched_policy.expect("matched_policy present");
        assert_eq!(policy.name, "allow-web");
        assert_eq!(policy.from_zone, "trust");
        assert_eq!(policy.to_zone, "untrust");
        assert_eq!(policy.sequence, 1);
        assert!(!data.is_global);
    }

    #[test]
    fn explicit_deny_policy() {
        let xml = fixture("deny.xml");
        let resp = parse(&xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.verdict, MatchVerdict::Deny);
        assert_eq!(
            data.matched_policy.expect("matched_policy present").name,
            "block-telnet"
        );
    }

    #[test]
    fn explicit_reject_policy() {
        let xml = fixture("reject.xml");
        let resp = parse(&xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.verdict, MatchVerdict::Reject);
        assert_eq!(
            data.matched_policy.expect("matched_policy present").name,
            "reject-ftp"
        );
    }

    #[test]
    fn global_policy_hit_sets_is_global() {
        // "vsrx-ci-1" is the real global policy name observed live on
        // vsrx-ci (spec §11); the surrounding match-policies XML is
        // synthetic, following the confirmed field names.
        let xml = fixture("global_permit.xml");
        let resp = parse(&xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.verdict, MatchVerdict::Permit);
        assert!(data.is_global, "any/any policy must set is_global");
        let policy = data.matched_policy.expect("matched_policy present");
        assert_eq!(policy.name, "vsrx-ci-1");
        assert_eq!(policy.from_zone, "any");
        assert_eq!(policy.to_zone, "any");
    }

    #[test]
    fn unrecognised_action_type_is_parse_error() {
        let xml = fixture("unknown_action_type.xml");
        let err = parse(&xml).expect_err("unknown action-type must fail closed");
        assert!(matches!(err, SrxError::Parse(_)));
    }

    #[test]
    fn missing_policy_information_is_schema_mismatch() {
        let xml = "<match-firewall-policies-results/>";
        let err = parse(xml).expect_err("missing policy-information must fail closed");
        assert!(matches!(err, SrxError::SchemaMismatch { .. }));
    }

    #[test]
    fn missing_from_zone_on_an_explicit_match_is_schema_mismatch() {
        // F4 fix: a schema drift that drops from-zone-name must surface as an
        // error, not silently default to "" (which would misreport is_global).
        let xml = r#"<match-firewall-policies-results>
  <policy-information>
    <policy-name>allow-web</policy-name>
    <action-type>permit</action-type>
    <to-zone-name>untrust</to-zone-name>
  </policy-information>
</match-firewall-policies-results>"#;
        let err = parse(xml).expect_err("missing from-zone-name must fail closed");
        assert!(matches!(err, SrxError::SchemaMismatch { .. }));
    }

    // ── from_zone / to_zone: pre-RPC validation (F6 fix) ─────────────────────

    #[test]
    fn from_zone_with_disallowed_characters_rejected_pre_rpc() {
        let mut args = valid_args();
        args.from_zone = "trust; rm -rf /".into();
        let err = parse_five_tuple(&args).unwrap_err();
        assert!(matches!(err, SrxError::InvalidInput(_)));
        assert!(
            !err.to_string().contains("rm -rf"),
            "error must not echo raw input: {err}"
        );
    }

    #[test]
    fn empty_to_zone_rejected_pre_rpc() {
        let mut args = valid_args();
        args.to_zone = "  ".into();
        assert!(matches!(
            parse_five_tuple(&args),
            Err(SrxError::InvalidInput(_))
        ));
    }
}
