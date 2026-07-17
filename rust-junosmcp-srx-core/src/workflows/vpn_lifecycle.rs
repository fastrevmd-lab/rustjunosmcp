//! `vpn_lifecycle_report` — IKE (P1) + IPsec (P2) SA correlation snapshot.
//!
//! Issues two concurrent NETCONF RPCs:
//!   - `<get-ike-security-associations-information><detail/></get-ike-security-associations-information>`
//!   - `<get-security-associations-information/>`
//!
//! # Junos XML schema (vSRX 24.x/25.x — actual, detail style)
//!
//! ## IKE (detail)
//!
//! ```xml
//! <ike-security-associations-information>
//!   <ike-security-associations-block>
//!     <ike-sa-remote-address>192.168.1.161</ike-sa-remote-address>
//!     <ike-sa-index>3128619</ike-sa-index>
//!     <ike-gw-name>lab-ike-gw</ike-gw-name>
//!     <ike-security-associations>
//!       <ike-sa-state>UP</ike-sa-state>
//!       <ike-sa-initiator-cookie>f8e88716124475b0</ike-sa-initiator-cookie>
//!       <ike-sa-responder-cookie>8b2be098e20e317e</ike-sa-responder-cookie>
//!       <ike-sa-exchange-type>IKEv2</ike-sa-exchange-type>
//!       <ike-sa-lifetime>Expires in 27590 seconds</ike-sa-lifetime>
//!       …
//!     </ike-security-associations>
//!   </ike-security-associations-block>
//! </ike-security-associations-information>
//! ```
//!
//! ## IPsec (brief)
//!
//! ```xml
//! <ipsec-security-associations-information>
//!   <total-active-tunnels>1</total-active-tunnels>
//!   <ipsec-security-associations-block>
//!     <sa-block-state>up</sa-block-state>
//!     <ipsec-security-associations>
//!       <sa-direction>&lt;</sa-direction>
//!       <sa-tunnel-index>131073</sa-tunnel-index>
//!       <sa-spi>4ef526a8</sa-spi>
//!       <sa-remote-gateway>192.168.1.161</sa-remote-gateway>
//!       <sa-hard-lifetime>2473</sa-hard-lifetime>
//!       <sa-lifesize-remaining>unlim</sa-lifesize-remaining>
//!       …
//!     </ipsec-security-associations>
//!   </ipsec-security-associations-block>
//! </ipsec-security-associations-information>
//! ```
//!
//! ## Empty / not-configured
//!
//! - Empty: top element present but with no SA children (test16 pattern).
//! - Not configured: `<xnm:error>` with message containing "not configured".
//!
//! Absence rule: `NotConfigured` only when **both** RPCs return an xnm:error.
//! Empty SA lists are valid and result in `Active` with empty vecs.

use crate::{SrxError, SrxToolResponse};
use rust_junosmcp_core::device_manager::PooledDevice;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct VpnLifecycleArgs {
    #[serde(alias = "router_name")]
    pub router: String,
    /// Filter IKE and IPsec SAs to those whose remote address contains this substring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// Filter IPsec SAs to those whose **remote gateway** address contains this
    /// substring. The brief-style IPsec RPC does not surface the st0 interface
    /// name, so this is effectively a second peer-substring filter; it remains
    /// distinct from `peer` so that callers can express tunnel-vs-IKE-only
    /// intent independently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<String>,
    #[serde(default)]
    pub include_raw: bool,
}

/// One IKE Phase-1 security association.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct IkeSa {
    /// IKE SA index. `None` when Junos omits or returns a non-numeric value
    /// — distinguishes "field absent" from a legitimate index of 0.
    pub index: Option<u64>,
    /// Remote peer IP address.
    pub remote_address: String,
    /// SA state: "UP", "DOWN", "INITIATING", etc.
    pub state: String,
    /// Exchange type: "IKEv2", "IKEv1", etc.
    pub mode: String,
    pub initiator_cookie: String,
    pub responder_cookie: String,
    /// Remaining lifetime in seconds, parsed from "Expires in N seconds".
    /// `None` when the field is absent or unparseable (e.g. "Disabled").
    pub lifetime_remaining_seconds: Option<u64>,
    /// IKE gateway name from Junos config (e.g. "lab-ike-gw").
    pub gateway_name: Option<String>,
}

/// One IPsec Phase-2 security association (one direction).
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct IpsecSa {
    /// IPsec tunnel id (one per pair). `None` when Junos omits or returns a
    /// non-numeric value — distinguishes "field absent" from a legitimate id of 0.
    pub tunnel_id: Option<u32>,
    /// Traffic direction: "<" (inbound) or ">" (outbound).
    pub direction: String,
    /// Remote gateway IP address.
    pub gateway: String,
    /// SPI value in hex.
    pub spi: String,
    /// Block state: "up" or "down".
    pub block_state: String,
    /// Remaining lifetime in seconds. `None` when absent or zero.
    pub lifetime_remaining_seconds: Option<u64>,
    /// Remaining lifesize in kilobytes. `None` when "unlim" or absent.
    pub lifetime_remaining_kilobytes: Option<u64>,
}

/// Correlation between one IKE SA and its associated IPsec SAs (by remote address).
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct VpnCorrelation {
    /// IKE SA index. `None` when the source IKE SA's index was absent or
    /// unparseable.
    pub ike_sa_index: Option<u64>,
    /// Tunnel ids of correlated IPsec SAs, deduplicated. Only known
    /// (`Some(u32)`) tunnel ids appear here.
    pub ipsec_sa_tunnel_ids: Vec<u32>,
}

/// Per-node VPN report (one element for standalone devices, two for HA clusters).
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct NodeVpnReport {
    /// Routing-engine name: "" for standalone, "node0"/"node1" for cluster.
    pub re_name: String,
    pub ike_sas: Vec<IkeSa>,
    pub ipsec_sas: Vec<IpsecSa>,
    pub correlations: Vec<VpnCorrelation>,
}

/// Aggregated VPN lifecycle report returned by the tool.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct VpnLifecycleData {
    pub nodes: Vec<NodeVpnReport>,
}

// ── `run()` — async entry point ───────────────────────────────────────────────

/// Run `get-ike-security-associations-information` (detail) and
/// `get-security-associations-information` (brief) against a pooled device.
pub async fn run(
    device: &mut PooledDevice,
    args: VpnLifecycleArgs,
) -> Result<SrxToolResponse<VpnLifecycleData>, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }

    // Issue IKE RPC.
    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let ike_xml = exec
        .call_xml("<get-ike-security-associations-information><detail/></get-ike-security-associations-information>")
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    // Issue IPsec RPC on the same session.
    let ipsec_xml = exec
        .call("get-security-associations-information", &[])
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let mut parsed = parse_combined(
        &ike_xml,
        &ipsec_xml,
        args.peer.as_deref(),
        args.tunnel.as_deref(),
    )?;
    if args.include_raw {
        let raw = format!("<!-- IKE -->\n{ike_xml}\n<!-- IPsec -->\n{ipsec_xml}");
        parsed = parsed.with_raw(raw);
    }
    Ok(parsed)
}

// ── Parsers ───────────────────────────────────────────────────────────────────

/// Parse both RPC replies and produce a `SrxToolResponse<VpnLifecycleData>`.
///
/// Absence rule: `NotConfigured` only when **both** replies are xnm:errors.
/// Empty SA lists → `Active` with empty vecs.
///
/// Peer/tunnel filters are applied before correlation.
pub fn parse_combined(
    ike_xml: &str,
    ipsec_xml: &str,
    peer_filter: Option<&str>,
    tunnel_filter: Option<&str>,
) -> Result<SrxToolResponse<VpnLifecycleData>, SrxError> {
    // Strip undeclared junos: namespace attributes before any XML parsing.
    // rustez strips the <nc:rpc-reply> wrapper (which declared xmlns:junos),
    // leaving orphaned junos:style="…" attributes that roxmltree rejects.
    let ike_clean = crate::xml::sanitize_rustez_xml(ike_xml);
    let ipsec_clean = crate::xml::sanitize_rustez_xml(ipsec_xml);
    let ike_xml = ike_clean.as_ref();
    let ipsec_xml = ipsec_clean.as_ref();

    let ike_not_configured = is_not_configured_xml(ike_xml)?;
    let ipsec_not_configured = is_not_configured_xml(ipsec_xml)?;

    if ike_not_configured && ipsec_not_configured {
        return Ok(SrxToolResponse::not_configured(
            "security ike/ipsec stanza absent",
        ));
    }

    // For standalone devices multi_re_split returns a single node with re_name="".
    let ike_nodes = crate::xml::multi_re_split(ike_xml)?;
    let ipsec_nodes = crate::xml::multi_re_split(ipsec_xml)?;

    // Build the node set: use IKE nodes as the primary key (they're always present
    // even when empty). Pair each IKE node with the matching IPsec node by re_name.
    let mut nodes: Vec<NodeVpnReport> = Vec::new();

    for ike_node in &ike_nodes {
        let ipsec_node = ipsec_nodes.iter().find(|n| n.re_name == ike_node.re_name);
        let ipsec_inner = ipsec_node.map(|n| n.inner_xml.as_str()).unwrap_or("");

        let mut ike_sas = parse_ike(&ike_node.inner_xml)?;
        let mut ipsec_sas = parse_ipsec(ipsec_inner)?;

        // Apply filters before correlation.
        if let Some(peer) = peer_filter {
            ike_sas.retain(|sa| sa.remote_address.contains(peer));
            ipsec_sas.retain(|sa| sa.gateway.contains(peer));
        }
        if let Some(tunnel) = tunnel_filter {
            // Tunnel filter applies to IPsec only (by gateway substring for now; a future
            // revision may use st0 interface name when the detail RPC provides it).
            ipsec_sas.retain(|sa| sa.gateway.contains(tunnel));
        }

        let correlations = correlate(&ike_sas, &ipsec_sas);

        nodes.push(NodeVpnReport {
            re_name: ike_node.re_name.clone(),
            ike_sas,
            ipsec_sas,
            correlations,
        });
    }

    Ok(SrxToolResponse::active(VpnLifecycleData { nodes }))
}

/// Parse an IKE SA reply (detail style) into a vec of `IkeSa`.
///
/// Accepts both the raw NETCONF reply (with `<nc:rpc-reply>` wrapper) and the
/// inner element body returned by `rustez::RpcExecutor::call`.
pub fn parse_ike(xml: &str) -> Result<Vec<IkeSa>, SrxError> {
    if is_not_configured_xml(xml)? {
        return Ok(Vec::new());
    }

    let cleaned = crate::xml::sanitize_rustez_xml(xml);
    let doc = roxmltree::Document::parse(&cleaned)
        .map_err(|e| SrxError::Parse(format!("IKE xml parse: {e}")))?;

    let mut sas: Vec<IkeSa> = Vec::new();

    // Walk all <ike-security-associations-block> elements.
    for block in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "ike-security-associations-block")
    {
        // Remote address and index live directly in the block.
        let remote_address = block
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "ike-sa-remote-address")
            .and_then(|n| n.text())
            .map(|t| t.trim().to_string())
            .unwrap_or_default();

        let index: Option<u64> = block
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "ike-sa-index")
            .and_then(|n| n.text())
            .and_then(|t| t.trim().parse().ok());

        let gateway_name: Option<String> = block
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "ike-gw-name")
            .and_then(|n| n.text())
            .map(|t| t.trim().to_string())
            .filter(|s| !s.is_empty());

        // The actual SA data is inside <ike-security-associations>.
        for sa_node in block
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "ike-security-associations")
        {
            let state = child_text(&sa_node, "ike-sa-state").unwrap_or_default();
            let mode = child_text(&sa_node, "ike-sa-exchange-type").unwrap_or_default();
            let initiator_cookie =
                child_text(&sa_node, "ike-sa-initiator-cookie").unwrap_or_default();
            let responder_cookie =
                child_text(&sa_node, "ike-sa-responder-cookie").unwrap_or_default();

            let lifetime_remaining_seconds = child_text(&sa_node, "ike-sa-lifetime")
                .as_deref()
                .and_then(parse_lifetime_seconds);

            sas.push(IkeSa {
                index,
                remote_address: remote_address.clone(),
                state,
                mode,
                initiator_cookie,
                responder_cookie,
                lifetime_remaining_seconds,
                gateway_name: gateway_name.clone(),
            });
        }
    }

    Ok(sas)
}

/// Parse an IPsec SA reply (brief style) into a vec of `IpsecSa` (one per direction).
pub fn parse_ipsec(xml: &str) -> Result<Vec<IpsecSa>, SrxError> {
    if xml.trim().is_empty() || is_not_configured_xml(xml)? {
        return Ok(Vec::new());
    }

    let cleaned = crate::xml::sanitize_rustez_xml(xml);
    let doc = roxmltree::Document::parse(&cleaned)
        .map_err(|e| SrxError::Parse(format!("IPsec xml parse: {e}")))?;

    let mut sas: Vec<IpsecSa> = Vec::new();

    for block in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "ipsec-security-associations-block")
    {
        let block_state = child_text(&block, "sa-block-state").unwrap_or_default();

        for sa_node in block
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "ipsec-security-associations")
        {
            let direction = child_text(&sa_node, "sa-direction").unwrap_or_default();
            let tunnel_id: Option<u32> = child_text(&sa_node, "sa-tunnel-index")
                .as_deref()
                .and_then(|t| t.parse().ok());
            let spi = child_text(&sa_node, "sa-spi").unwrap_or_default();
            let gateway = child_text(&sa_node, "sa-remote-gateway").unwrap_or_default();

            let lifetime_remaining_seconds = child_text(&sa_node, "sa-hard-lifetime")
                .as_deref()
                .and_then(|t| {
                    let n: u64 = t.parse().ok()?;
                    if n == 0 {
                        None
                    } else {
                        Some(n)
                    }
                });

            let lifetime_remaining_kilobytes = child_text(&sa_node, "sa-lifesize-remaining")
                .as_deref()
                .and_then(|t| {
                    if t == "unlim" || t == "-" {
                        None
                    } else {
                        t.parse().ok()
                    }
                });

            sas.push(IpsecSa {
                tunnel_id,
                direction,
                gateway,
                spi,
                block_state: block_state.clone(),
                lifetime_remaining_seconds,
                lifetime_remaining_kilobytes,
            });
        }
    }

    Ok(sas)
}

/// Build `VpnCorrelation`s by matching IKE SAs to IPsec SAs via `remote_address` == `gateway`.
fn correlate(ike_sas: &[IkeSa], ipsec_sas: &[IpsecSa]) -> Vec<VpnCorrelation> {
    ike_sas
        .iter()
        .map(|ike| {
            let ipsec_ids: Vec<u32> = ipsec_sas
                .iter()
                .filter(|ipc| ipc.gateway == ike.remote_address)
                .filter_map(|ipc| ipc.tunnel_id)
                // Deduplicate tunnel_ids (inbound and outbound share the same id).
                .fold(Vec::<u32>::new(), |mut acc, id| {
                    if !acc.contains(&id) {
                        acc.push(id);
                    }
                    acc
                });
            VpnCorrelation {
                ike_sa_index: ike.index,
                ipsec_sa_tunnel_ids: ipsec_ids,
            }
        })
        .collect()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Return the trimmed text of the first direct child element matching `name`.
fn child_text(node: &roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == name)
        .and_then(|n| n.text())
        .map(|t| t.trim().to_string())
}

/// Parse "Expires in N seconds" → `Some(N)`.
///
/// Junos formats this as exactly "Expires in N seconds" in the `<ike-sa-lifetime>`
/// element. Any other text (e.g. "Disabled") returns `None`.
fn parse_lifetime_seconds(text: &str) -> Option<u64> {
    let text = text.trim();
    // Pattern: "Expires in N seconds"
    let after = text.strip_prefix("Expires in ")?;
    let before = after.strip_suffix(" seconds")?;
    before.trim().parse().ok()
}

/// Check whether a reply XML represents a "not configured" or error condition.
///
/// Conditions that indicate not-configured:
/// 1. A top-level `<xnm:error>` / `<rpc-error>` with `<message>` containing
///    "not configured" or "not enabled" (case-insensitive).
/// 2. A top-level error element with `<error-tag>` equal to `not-configured`
///    or `data-missing`.
/// 3. An error element present with no SA information root element.
///
/// Never inspects raw text — always via roxmltree element traversal.
fn is_not_configured_xml(xml: &str) -> Result<bool, SrxError> {
    let xml = xml.trim();
    if xml.is_empty() {
        return Ok(false);
    }

    let cleaned = crate::xml::sanitize_rustez_xml(xml);
    let doc = roxmltree::Document::parse(&cleaned)
        .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;

    let root = doc.root_element();
    let root_is_error = is_error_element(&root);

    let any_error = root_is_error
        || root
            .children()
            .any(|n| n.is_element() && is_error_element(&n));

    if !any_error {
        return Ok(false);
    }

    // We have an error element. Check whether any SA data root is also present
    // (that would mean the error is incidental, not the whole reply).
    let has_sa_info = doc.descendants().any(|n| {
        n.is_element()
            && matches!(
                n.tag_name().name(),
                "ike-security-associations-information" | "ipsec-security-associations-information"
            )
    });
    if has_sa_info {
        return Ok(false);
    }

    // Inspect error elements for condition 1 & 2.
    let error_nodes: Vec<_> = if root_is_error {
        vec![root]
    } else {
        root.children()
            .filter(|n| n.is_element() && is_error_element(n))
            .collect()
    };

    for err in &error_nodes {
        for child in err.descendants().filter(|n| n.is_element()) {
            if child.tag_name().name() == "error-tag" {
                if let Some(t) = child.text() {
                    let t = t.trim();
                    if t == "not-configured" || t == "data-missing" {
                        return Ok(true);
                    }
                }
            }
            if child.tag_name().name() == "message" {
                if let Some(t) = child.text() {
                    let lower = t.to_ascii_lowercase();
                    if lower.contains("not configured") || lower.contains("not enabled") {
                        return Ok(true);
                    }
                }
            }
        }
    }

    // Error present, no SA info, message didn't match known patterns
    // — conservatively treat as not-configured.
    Ok(true)
}

/// Return true if `node` is an error element (xnm:error or rpc-error).
fn is_error_element(node: &roxmltree::Node<'_, '_>) -> bool {
    matches!(node.tag_name().name(), "error" | "rpc-error")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SrxState;
    use pretty_assertions::assert_eq;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/vpn_lifecycle")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()))
    }

    // ── parse_lifetime_seconds ────────────────────────────────────────────────

    #[test]
    fn lifetime_parse_valid() {
        assert_eq!(
            parse_lifetime_seconds("Expires in 27590 seconds"),
            Some(27590)
        );
        assert_eq!(
            parse_lifetime_seconds("  Expires in 100 seconds  "),
            Some(100)
        );
    }

    #[test]
    fn lifetime_parse_disabled() {
        assert_eq!(parse_lifetime_seconds("Disabled"), None);
        assert_eq!(parse_lifetime_seconds(""), None);
    }

    // ── parse_ike ─────────────────────────────────────────────────────────────

    #[test]
    fn ike_sa_up_parsed() {
        let xml = fixture("ike_sa_up_test10.xml");
        let sas = parse_ike(&xml).expect("parse_ike should succeed");
        assert_eq!(sas.len(), 1, "expected 1 IKE SA");
        let sa = &sas[0];
        assert_eq!(sa.index, Some(3128619));
        assert_eq!(sa.remote_address, "192.168.1.161");
        assert_eq!(sa.state, "UP");
        assert_eq!(sa.mode, "IKEv2");
        assert_eq!(sa.initiator_cookie, "f8e88716124475b0");
        assert_eq!(sa.responder_cookie, "8b2be098e20e317e");
        assert_eq!(sa.lifetime_remaining_seconds, Some(27590));
        assert_eq!(sa.gateway_name.as_deref(), Some("lab-ike-gw"));
    }

    #[test]
    fn ike_sa_empty_returns_empty_vec() {
        let xml = fixture("ike_sa_empty_test16.xml");
        let sas = parse_ike(&xml).expect("parse_ike should succeed for empty");
        assert!(sas.is_empty(), "expected 0 IKE SAs for no-VPN device");
    }

    #[test]
    fn ike_not_configured_returns_empty_vec() {
        let xml = fixture("ike_not_configured.xml");
        let sas = parse_ike(&xml).expect("parse_ike should succeed for not-configured");
        assert!(sas.is_empty(), "expected empty vec for not-configured IKE");
    }

    // ── parse_ipsec ───────────────────────────────────────────────────────────

    #[test]
    fn ipsec_sa_up_parsed() {
        let xml = fixture("ipsec_sa_up_test10.xml");
        let sas = parse_ipsec(&xml).expect("parse_ipsec should succeed");
        assert_eq!(sas.len(), 2, "expected 2 IPsec SAs (inbound + outbound)");

        let inbound = sas.iter().find(|s| s.direction == "<").expect("inbound SA");
        assert_eq!(inbound.tunnel_id, Some(131073));
        assert_eq!(inbound.spi, "4ef526a8");
        assert_eq!(inbound.gateway, "192.168.1.161");
        assert_eq!(inbound.block_state, "up");
        assert_eq!(inbound.lifetime_remaining_seconds, Some(2473));
        assert!(
            inbound.lifetime_remaining_kilobytes.is_none(),
            "unlim → None"
        );

        let outbound = sas
            .iter()
            .find(|s| s.direction == ">")
            .expect("outbound SA");
        assert_eq!(outbound.spi, "cb151b04");
        assert_eq!(outbound.tunnel_id, Some(131073));
    }

    #[test]
    fn ipsec_sa_empty_returns_empty_vec() {
        let xml = fixture("ipsec_sa_empty_test16.xml");
        let sas = parse_ipsec(&xml).expect("parse_ipsec should succeed for empty");
        assert!(sas.is_empty(), "expected 0 IPsec SAs");
    }

    #[test]
    fn ipsec_not_configured_returns_empty_vec() {
        let xml = fixture("ipsec_not_configured.xml");
        let sas = parse_ipsec(&xml).expect("parse_ipsec should succeed for not-configured");
        assert!(sas.is_empty());
    }

    #[test]
    fn ipsec_sa_down_parsed() {
        let xml = fixture("ipsec_sa_down.xml");
        let sas = parse_ipsec(&xml).expect("parse_ipsec should succeed for down state");
        assert_eq!(sas.len(), 1);
        let sa = &sas[0];
        assert_eq!(sa.block_state, "down");
        assert_eq!(sa.lifetime_remaining_seconds, None, "0 lifetime → None");
    }

    // ── parse_combined ────────────────────────────────────────────────────────

    #[test]
    fn combined_active_tunnel_test10() {
        let ike_xml = fixture("ike_sa_up_test10.xml");
        let ipsec_xml = fixture("ipsec_sa_up_test10.xml");
        let resp = parse_combined(&ike_xml, &ipsec_xml, None, None).expect("combined parse");
        assert_eq!(resp.state, SrxState::Active);
        let data = resp.data.expect("data must be present");
        assert_eq!(data.nodes.len(), 1);
        let node = &data.nodes[0];
        assert_eq!(node.re_name, "");
        assert_eq!(node.ike_sas.len(), 1, "1 IKE SA");
        assert_eq!(node.ipsec_sas.len(), 2, "2 IPsec SAs (in + out)");
        assert_eq!(node.correlations.len(), 1, "1 correlation");
        assert_eq!(node.correlations[0].ike_sa_index, Some(3128619));
        assert_eq!(node.correlations[0].ipsec_sa_tunnel_ids, vec![131073]);
    }

    #[test]
    fn combined_empty_sas_is_active_test16() {
        let ike_xml = fixture("ike_sa_empty_test16.xml");
        let ipsec_xml = fixture("ipsec_sa_empty_test16.xml");
        let resp = parse_combined(&ike_xml, &ipsec_xml, None, None).expect("combined parse");
        // Empty SA lists = Active (VPN configured but no current SAs, or no VPN configured
        // at all but RPC succeeded — either way it's not a protocol error).
        assert_eq!(resp.state, SrxState::Active);
        let data = resp.data.expect("data must be present");
        assert_eq!(data.nodes[0].ike_sas.len(), 0);
        assert_eq!(data.nodes[0].ipsec_sas.len(), 0);
        assert_eq!(data.nodes[0].correlations.len(), 0);
    }

    #[test]
    fn combined_both_not_configured_returns_not_configured() {
        let ike_xml = fixture("ike_not_configured.xml");
        let ipsec_xml = fixture("ipsec_not_configured.xml");
        let resp = parse_combined(&ike_xml, &ipsec_xml, None, None).expect("combined parse");
        assert_eq!(resp.state, SrxState::NotConfigured);
        assert!(resp.reason.as_deref().unwrap_or("").contains("absent"));
        assert!(resp.data.is_none());
    }

    #[test]
    fn combined_ike_not_configured_but_ipsec_ok_is_active() {
        // IKE error + IPsec empty = only one side errored → Active.
        let ike_xml = fixture("ike_not_configured.xml");
        let ipsec_xml = fixture("ipsec_sa_empty_test16.xml");
        let resp = parse_combined(&ike_xml, &ipsec_xml, None, None).expect("combined parse");
        assert_eq!(resp.state, SrxState::Active);
    }

    // ── peer filter ───────────────────────────────────────────────────────────

    #[test]
    fn peer_filter_matches() {
        let ike_xml = fixture("ike_sa_up_test10.xml");
        let ipsec_xml = fixture("ipsec_sa_up_test10.xml");
        let resp = parse_combined(&ike_xml, &ipsec_xml, Some("192.168.1.161"), None)
            .expect("filtered parse");
        assert_eq!(resp.state, SrxState::Active);
        let data = resp.data.unwrap();
        assert_eq!(data.nodes[0].ike_sas.len(), 1, "filter kept matching SA");
    }

    #[test]
    fn combined_ike_up_ipsec_empty_correlation_has_no_tunnels() {
        // Phase-1 up, Phase-2 down (rekeying / cleared / never installed).
        // Correlation must still be present so consumers can flag the gap,
        // but its tunnel-id list must be empty.
        let ike_xml = fixture("ike_sa_up_test10.xml");
        let ipsec_xml = fixture("ipsec_sa_empty_test16.xml");
        let resp = parse_combined(&ike_xml, &ipsec_xml, None, None).expect("combined parse");
        assert_eq!(resp.state, SrxState::Active);
        let data = resp.data.unwrap();
        let node = &data.nodes[0];
        assert_eq!(node.ike_sas.len(), 1);
        assert!(node.ipsec_sas.is_empty(), "phase 2 empty");
        assert_eq!(node.correlations.len(), 1);
        assert!(
            node.correlations[0].ipsec_sa_tunnel_ids.is_empty(),
            "no ipsec tunnels to correlate to"
        );
    }

    #[test]
    fn peer_filter_no_match_gives_empty_vecs() {
        let ike_xml = fixture("ike_sa_up_test10.xml");
        let ipsec_xml = fixture("ipsec_sa_up_test10.xml");
        let resp =
            parse_combined(&ike_xml, &ipsec_xml, Some("10.0.0.1"), None).expect("filtered parse");
        assert_eq!(resp.state, SrxState::Active, "still Active, just empty");
        let data = resp.data.unwrap();
        assert!(data.nodes[0].ike_sas.is_empty());
        assert!(data.nodes[0].ipsec_sas.is_empty());
    }
}
