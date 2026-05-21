//! `get_srx_security_services_status` — concurrent sub-RPC health snapshot.
//!
//! # Actual NETCONF RPC names (vSRX 24.4, verified 2026-05-21)
//!
//! | Sub-service | RPC name                          | Notes                               |
//! |-------------|-----------------------------------|-------------------------------------|
//! | IDP         | `get-idp-security-package-information` | Returns `<idp-security-package-information>` |
//! | AppID       | `get-appid-package-version`       | Returns `<appid-package-version>`   |
//! | UTM AV      | `get-anti-virus-status`           | Returns `no-config` engine type when not configured |
//! | SecIntel    | `get-secintel-feed-summary`       | Returns syntax rpc-error on vSRX 24.4 |
//! | ATP/AAMW    | `get-aamw-status`                 | Returns `<aamw-errors>` when no URL configured |
//!
//! # Concurrency note
//!
//! The plan calls for `tokio::try_join!` (strategy A = 5 separate pool
//! acquisitions). However, `DeviceManager::open()` returns a `PooledDevice`
//! which is `&mut`-only; the per-router lock means only one `PooledDevice`
//! can be alive at a time for a given device (they would deadlock waiting on
//! each other). The plan's own `run()` skeleton (Task 4 Step 6) already
//! shows the sequential path: one `exec` handle, five sequential `.call()`s.
//! We follow that pattern (strategy B) and document it here.
//!
//! The await points still keep the executor responsive; the bottleneck is the
//! NETCONF channel serialisation on the device side anyway.

use crate::xml::multi_re_split;
use crate::{SrxError, SrxToolResponse};
use rust_junosmcp_core::device_manager::PooledDevice;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ServicesStatusArgs {
    pub router: String,
    #[serde(default)]
    pub include_raw: bool,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct ServicesStatusData {
    pub nodes: Vec<NodeServicesStatus>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct NodeServicesStatus {
    /// `""` for standalone devices, `"node0"` / `"node1"` for clustered.
    pub re_name: String,
    pub idp: SubServiceStatus<IdpInfo>,
    pub appid: SubServiceStatus<AppIdInfo>,
    pub utm_av: SubServiceStatus<UtmAvInfo>,
    pub secintel: SubServiceStatus<SecIntelInfo>,
    pub atp_cloud: SubServiceStatus<AtpCloudInfo>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct SubServiceStatus<T: JsonSchema + Serialize + PartialEq + Eq> {
    pub state: crate::SrxState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl<T: JsonSchema + Serialize + PartialEq + Eq> SubServiceStatus<T> {
    fn active(data: T) -> Self {
        Self {
            state: crate::SrxState::Active,
            data: Some(data),
            reason: None,
        }
    }

    fn not_configured(reason: impl Into<String>) -> Self {
        Self {
            state: crate::SrxState::NotConfigured,
            data: None,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct IdpInfo {
    /// e.g. `"3714(4.1)"` or `"N/A(N/A)"` when no package loaded.
    pub package_version: String,
    /// Detector engine version, or `"N/A"`.
    pub detector_version: String,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct AppIdInfo {
    /// Application-identification package version. `"0"` when none loaded.
    pub version: String,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct UtmAvInfo {
    /// Anti-virus scan engine type, e.g. `"sophos-engine"`.
    pub engine_type: String,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct SecIntelInfo {
    /// Feed names reported by SecIntel (empty list when all feeds down).
    pub feeds: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct AtpCloudInfo {
    /// The configured AAMW/ATP-Cloud connection URL when present in the
    /// `<aamw-status>` payload, otherwise `None`. Presence of `Active` state
    /// already implies AAMW is enrolled; this field carries the destination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_url: Option<String>,
}

// ── `run()` — async entry point ───────────────────────────────────────────────

/// Run all five sub-RPCs sequentially through a single pooled session and
/// aggregate into a typed `ServicesStatusData`.
///
/// Sub-RPCs run sequentially (strategy B) because the per-router pool lock
/// prevents concurrent pool acquisitions for the same device. The plan's own
/// `run()` skeleton uses this pattern.
pub async fn run(
    device: &mut PooledDevice,
    args: ServicesStatusArgs,
) -> Result<SrxToolResponse<ServicesStatusData>, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }

    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let idp_xml = exec
        .call("get-idp-security-package-information", &[])
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let appid_xml = exec
        .call("get-appid-package-version", &[])
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let utm_xml = exec
        .call("get-anti-virus-status", &[])
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let secintel_xml = exec
        .call("get-secintel-feed-summary", &[])
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let atp_xml = exec
        .call("get-aamw-status", &[])
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    // Split each reply by RE node (standalone → single node with re_name "").
    let idp_nodes = multi_re_split(&idp_xml)?;
    let appid_nodes = multi_re_split(&appid_xml)?;
    let utm_nodes = multi_re_split(&utm_xml)?;
    let secintel_nodes = multi_re_split(&secintel_xml)?;
    let atp_nodes = multi_re_split(&atp_xml)?;

    // Derive the node list from the IDP reply (most likely to have multi-RE).
    let node_names: Vec<String> = idp_nodes.iter().map(|n| n.re_name.clone()).collect();

    let nodes: Vec<NodeServicesStatus> = node_names
        .into_iter()
        .enumerate()
        .map(|(i, re_name)| {
            fn pick(v: &[crate::xml::ReNode], i: usize) -> &str {
                v.get(i).map(|n| n.inner_xml.as_str()).unwrap_or("")
            }
            NodeServicesStatus {
                re_name,
                idp: parse_idp(pick(&idp_nodes, i)),
                appid: parse_appid(pick(&appid_nodes, i)),
                utm_av: parse_utm_av(pick(&utm_nodes, i)),
                secintel: parse_secintel(pick(&secintel_nodes, i)),
                atp_cloud: parse_atp(pick(&atp_nodes, i)),
            }
        })
        .collect();

    let all_absent = nodes.iter().all(|n| {
        matches!(n.idp.state, crate::SrxState::NotConfigured)
            && matches!(n.appid.state, crate::SrxState::NotConfigured)
            && matches!(n.utm_av.state, crate::SrxState::NotConfigured)
            && matches!(n.secintel.state, crate::SrxState::NotConfigured)
            && matches!(n.atp_cloud.state, crate::SrxState::NotConfigured)
    });

    let mut resp = if all_absent {
        SrxToolResponse::<ServicesStatusData>::not_configured(
            "no SRX security services configured on this device",
        )
    } else {
        SrxToolResponse::<ServicesStatusData>::active(ServicesStatusData { nodes })
    };

    if args.include_raw {
        resp = resp.with_raw(format!(
            "<!-- idp -->\n{idp_xml}\n<!-- appid -->\n{appid_xml}\n<!-- utm -->\n{utm_xml}\n<!-- secintel -->\n{secintel_xml}\n<!-- atp -->\n{atp_xml}"
        ));
    }

    Ok(resp)
}

// ── Per-sub-RPC parsers ───────────────────────────────────────────────────────
//
// Each parser receives the inner XML for ONE routing-engine node (already
// multi-RE-split by `run()`). They never fail with `SrxError` — sub-service
// absence is signalled through `SubServiceStatus::not_configured`.

/// Parse `<idp-security-package-information>` reply body.
///
/// Returns `Active` whenever the `<idp-security-package-information>` root
/// element is present, even when versions are `"N/A"`. Returns
/// `NotConfigured` only on `<rpc-error>` or missing root element.
pub fn parse_idp(xml: &str) -> SubServiceStatus<IdpInfo> {
    let doc = match roxmltree::Document::parse(xml) {
        Ok(d) => d,
        Err(e) => return SubServiceStatus::not_configured(format!("xml parse error: {e}")),
    };

    // Check for rpc-error first.
    if let Some(reason) = rpc_error_reason(&doc) {
        return SubServiceStatus::not_configured(reason);
    }

    let root = doc.root_element();
    let el = find_element(&root, "idp-security-package-information");
    let Some(el) = el else {
        return SubServiceStatus::not_configured("idp-security-package-information element absent");
    };

    let package_version = child_text(&el, "security-package-version").unwrap_or_default();
    let detector_version = child_text(&el, "detector-version").unwrap_or_default();

    SubServiceStatus::active(IdpInfo {
        package_version,
        detector_version,
    })
}

/// Parse `<appid-package-version>` reply body.
///
/// Returns `Active` whenever the root element is present. Version `"0"` means
/// no package is loaded but the feature is available.
pub fn parse_appid(xml: &str) -> SubServiceStatus<AppIdInfo> {
    let doc = match roxmltree::Document::parse(xml) {
        Ok(d) => d,
        Err(e) => return SubServiceStatus::not_configured(format!("xml parse error: {e}")),
    };

    if let Some(reason) = rpc_error_reason(&doc) {
        return SubServiceStatus::not_configured(reason);
    }

    let root = doc.root_element();
    let el = find_element(&root, "appid-package-version");
    let Some(el) = el else {
        return SubServiceStatus::not_configured("appid-package-version element absent");
    };

    let version = child_text(&el, "version-detail").unwrap_or_default();

    SubServiceStatus::active(AppIdInfo { version })
}

/// Parse `<anti-virus>` reply body from `get-anti-virus-status`.
///
/// Junos 24.4 returns an `<anti-virus>` wrapper even when no engine is
/// configured; in that case `<anti-virus-scan-engine-type>` is `"no-config"`.
/// We treat `no-config` as `not_configured`.
pub fn parse_utm_av(xml: &str) -> SubServiceStatus<UtmAvInfo> {
    let doc = match roxmltree::Document::parse(xml) {
        Ok(d) => d,
        Err(e) => return SubServiceStatus::not_configured(format!("xml parse error: {e}")),
    };

    if let Some(reason) = rpc_error_reason(&doc) {
        return SubServiceStatus::not_configured(reason);
    }

    // Walk for anti-virus-scan-engine-type anywhere in the document.
    let engine_type = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "anti-virus-scan-engine-type")
        .and_then(|n| n.text())
        .map(|t| t.trim().to_string())
        .unwrap_or_default();

    if engine_type.is_empty() || engine_type == "no-config" {
        return SubServiceStatus::not_configured("UTM anti-virus not configured (no-config)");
    }

    SubServiceStatus::active(UtmAvInfo { engine_type })
}

/// Parse `get-secintel-feed-summary` reply body.
///
/// On vSRX 24.4 this RPC returns a syntax `rpc-error`; we treat any
/// `rpc-error` as `not_configured`. If/when the RPC succeeds, we collect
/// feed names from `<feed-name>` elements inside `<secintel-feed>` items.
pub fn parse_secintel(xml: &str) -> SubServiceStatus<SecIntelInfo> {
    let doc = match roxmltree::Document::parse(xml) {
        Ok(d) => d,
        Err(e) => return SubServiceStatus::not_configured(format!("xml parse error: {e}")),
    };

    if let Some(reason) = rpc_error_reason(&doc) {
        return SubServiceStatus::not_configured(reason);
    }

    // Collect feed names if any are present.
    let feeds: Vec<String> = doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "feed-name")
        .filter_map(|n| n.text())
        .map(|t| t.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // If no root element representing the feed summary is present and no
    // feeds were found, treat as not configured.
    let has_summary = doc
        .descendants()
        .any(|n| n.is_element() && n.tag_name().name() == "secintel-feed-summary");

    if !has_summary && feeds.is_empty() {
        return SubServiceStatus::not_configured("secintel-feed-summary element absent");
    }

    SubServiceStatus::active(SecIntelInfo { feeds })
}

/// Parse `get-aamw-status` reply body.
///
/// If `<aamw-errors>` is present the AAMW/ATP cloud is not enrolled.
/// A successful enrollment would return `<aamw-status>` with connection info.
pub fn parse_atp(xml: &str) -> SubServiceStatus<AtpCloudInfo> {
    let doc = match roxmltree::Document::parse(xml) {
        Ok(d) => d,
        Err(e) => return SubServiceStatus::not_configured(format!("xml parse error: {e}")),
    };

    if let Some(reason) = rpc_error_reason(&doc) {
        return SubServiceStatus::not_configured(reason);
    }

    // <aamw-errors> present → not enrolled.
    let has_errors = doc
        .descendants()
        .any(|n| n.is_element() && n.tag_name().name() == "aamw-errors");

    if has_errors {
        return SubServiceStatus::not_configured(
            "AAMW/ATP Cloud not configured (no connection URL)",
        );
    }

    // Locate <aamw-status>. If absent (empty reply / unexpected schema),
    // treat as NotConfigured — Active without a status block carries no
    // useful information.
    let status_node = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "aamw-status");

    let Some(status_node) = status_node else {
        return SubServiceStatus::not_configured("aamw-status element absent");
    };

    let connection_url = child_text(&status_node, "aamw-connection-url");

    SubServiceStatus::active(AtpCloudInfo { connection_url })
}

// ── XML helpers ───────────────────────────────────────────────────────────────

/// Return an error description if the document's root is an `<rpc-error>` or
/// contains one as a top-level child.
fn rpc_error_reason(doc: &roxmltree::Document<'_>) -> Option<String> {
    let root = doc.root_element();

    // Match only `rpc-error` (the NETCONF standard tag name). A broader
    // `"error"` match risks false positives on benign Junos payloads that
    // include generic <error> elements (e.g. inside <aamw-errors>).
    let is_err = |n: roxmltree::Node<'_, '_>| n.tag_name().name() == "rpc-error";

    let err_node: Option<roxmltree::Node<'_, '_>> = if is_err(root) {
        Some(root)
    } else {
        root.children().find(|n| n.is_element() && is_err(*n))
    };

    let err = err_node?;

    // Prefer <error-message> text; fall back to tag/bad-element.
    let msg = err
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "error-message")
        .and_then(|n| n.text())
        .map(|t| t.trim().to_string());

    let bad = err
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "bad-element")
        .and_then(|n| n.text())
        .map(|t| t.trim().to_string());

    Some(match (msg, bad) {
        (Some(m), Some(b)) => format!("rpc-error: {m} (bad-element: {b})"),
        (Some(m), None) => format!("rpc-error: {m}"),
        (None, Some(b)) => format!("rpc-error: bad-element={b}"),
        (None, None) => "rpc-error (unknown)".into(),
    })
}

/// Find the first descendant element with the given local name.
fn find_element<'a, 'input>(
    node: &roxmltree::Node<'a, 'input>,
    name: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    if node.tag_name().name() == name {
        return Some(*node);
    }
    node.descendants()
        .find(|n| n.is_element() && n.tag_name().name() == name)
}

/// Return the trimmed text of the first child element with the given name.
fn child_text(node: &roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == name)
        .and_then(|n| n.text())
        .map(|t| t.trim().to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SrxState;
    use pretty_assertions::assert_eq;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/services_status")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()))
    }

    // ── IDP ──────────────────────────────────────────────────────────────────

    #[test]
    fn idp_active_parses() {
        let r = parse_idp(&fixture("idp_active.xml"));
        assert_eq!(r.state, SrxState::Active);
        let data = r.data.expect("data must be present");
        assert_eq!(data.package_version, "N/A(N/A)");
        assert_eq!(data.detector_version, "N/A");
    }

    #[test]
    fn idp_clustered_parses_standalone_node() {
        // multi_re_split already handled upstream; fixture is inner XML for one node.
        let raw = fixture("idp_clustered.xml");
        // Parse the multi-RE wrapper manually to get one node's inner XML.
        let nodes = multi_re_split(&raw).expect("multi_re_split");
        assert_eq!(nodes.len(), 2);
        let r = parse_idp(&nodes[0].inner_xml);
        assert_eq!(r.state, SrxState::Active);
        assert_eq!(nodes[0].re_name, "node0");
    }

    // ── AppID ─────────────────────────────────────────────────────────────────

    #[test]
    fn appid_active_parses() {
        let r = parse_appid(&fixture("appid_active.xml"));
        assert_eq!(r.state, SrxState::Active);
        let data = r.data.expect("data must be present");
        assert!(!data.version.is_empty(), "version must not be empty");
        assert_eq!(data.version, "0");
    }

    // ── UTM AV ────────────────────────────────────────────────────────────────

    #[test]
    fn utm_av_not_configured() {
        let r = parse_utm_av(&fixture("utm_av_not_configured.xml"));
        assert_eq!(r.state, SrxState::NotConfigured);
        assert!(
            r.reason.as_deref().unwrap_or("").contains("no-config"),
            "reason: {:?}",
            r.reason
        );
    }

    // ── SecIntel ──────────────────────────────────────────────────────────────

    #[test]
    fn secintel_not_configured() {
        let r = parse_secintel(&fixture("secintel_not_configured.xml"));
        assert_eq!(r.state, SrxState::NotConfigured);
        assert!(r.reason.is_some(), "reason must be set");
    }

    // ── ATP/AAMW ──────────────────────────────────────────────────────────────

    #[test]
    fn atp_not_configured() {
        let r = parse_atp(&fixture("atp_not_configured.xml"));
        assert_eq!(r.state, SrxState::NotConfigured);
        assert!(
            r.reason.as_deref().unwrap_or("").contains("not configured"),
            "reason: {:?}",
            r.reason
        );
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn idp_rpc_error_is_not_configured() {
        let xml = r#"<nc:rpc-error xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
<nc:error-type>application</nc:error-type>
<nc:error-tag>not-configured</nc:error-tag>
<nc:error-severity>error</nc:error-severity>
<nc:error-message>IDP not configured</nc:error-message>
</nc:rpc-error>"#;
        let r = parse_idp(xml);
        assert_eq!(r.state, SrxState::NotConfigured);
    }

    #[test]
    fn appid_rpc_error_is_not_configured() {
        let xml = r#"<nc:rpc-error xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
<nc:error-type>protocol</nc:error-type>
<nc:error-tag>operation-failed</nc:error-tag>
<nc:error-severity>error</nc:error-severity>
<nc:error-message>syntax error</nc:error-message>
<nc:error-info><nc:bad-element>get-appid-package-version</nc:bad-element></nc:error-info>
</nc:rpc-error>"#;
        let r = parse_appid(xml);
        assert_eq!(r.state, SrxState::NotConfigured);
    }

    #[test]
    fn utm_av_with_real_engine_is_active() {
        let xml = r#"<anti-virus xmlns:junos="http://xml.juniper.net/junos/24.4R1.9/junos" junos:style="status">
<anti-virus-status>
<anti-virus-scan-engine-type>sophos-engine</anti-virus-scan-engine-type>
</anti-virus-status>
</anti-virus>"#;
        let r = parse_utm_av(xml);
        assert_eq!(r.state, SrxState::Active);
        assert_eq!(r.data.unwrap().engine_type, "sophos-engine");
    }

    #[test]
    fn atp_enrolled_surfaces_connection_url() {
        let xml = r#"<aamw-status>
<aamw-connection-url>https://atp.example.com</aamw-connection-url>
</aamw-status>"#;
        let r = parse_atp(xml);
        assert_eq!(r.state, SrxState::Active);
        assert_eq!(
            r.data.unwrap().connection_url.as_deref(),
            Some("https://atp.example.com")
        );
    }

    #[test]
    fn atp_empty_reply_is_not_configured() {
        // Empty reply, neither <aamw-status> nor <aamw-errors> present
        // (defensive case — observed when the RPC is filtered out by config).
        let xml = "<rpc-reply/>";
        let r = parse_atp(xml);
        assert_eq!(r.state, SrxState::NotConfigured);
        assert!(
            r.reason
                .as_deref()
                .unwrap_or("")
                .contains("aamw-status element absent"),
            "reason: {:?}",
            r.reason
        );
    }
}
