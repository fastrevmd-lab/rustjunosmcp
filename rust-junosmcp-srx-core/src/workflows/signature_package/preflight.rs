//! Pre-flight helpers shared by signature-package workflows.
//!
//! Two kinds of code live here:
//! * **Offline parsers** — pure functions over Junos XML replies
//!   (`detect_commit_confirmed`).
//! * **Device-touching wrappers** — async functions that fire a Junos RPC
//!   via a [`PooledDevice`] and convert the reply into a pre-flight
//!   verdict (`license_active`, `cluster_topology`).
//!
//! Per design §"Internal helpers are NOT re-entrant MCP calls", the
//! device-touching wrappers re-use the existing workflow parsers
//! (`workflows::license::parse`, `workflows::cluster_status::parse`)
//! directly rather than going through the MCP layer.

use crate::workflows::signature_package::Topology;
use crate::SrxError;
use rust_junosmcp_core::device_manager::PooledDevice;

/// True if the device has an open commit-confirmed rollback window.
///
/// The Junos `<get-commit-information>` RPC returns a `<commit-information>`
/// element with one `<commit-history>` per recent commit. While the
/// commit-confirmed window is open, the most recent history record
/// carries an explicit `<commit-confirmed>rollback pending</commit-confirmed>`
/// child element.
///
/// This helper checks for *any* `<commit-confirmed>` element in the
/// reply. It returns Ok(false) when the XML parses cleanly with no such
/// element, Ok(true) when one is present, and Err(SrxError::Parse) when
/// the XML is malformed.
///
/// Signature-package install is op-mode, not config-mode, so pre-flight
/// does not block on a positive return — callers use this to emit a
/// `tracing::warn!(target = "audit", ...)` and proceed.
pub fn detect_commit_confirmed(commit_info_xml: &str) -> Result<bool, SrxError> {
    let sanitized = crate::xml::sanitize_rustez_xml(commit_info_xml);
    let doc = roxmltree::Document::parse(&sanitized)
        .map_err(|e| SrxError::Parse(format!("roxmltree (commit-information): {e}")))?;
    Ok(doc
        .descendants()
        .any(|n| n.is_element() && n.tag_name().name() == "commit-confirmed"))
}

// ── Device-touching wrappers ──────────────────────────────────────────────────

/// Pre-flight: assert that a Junos license for `feature` is active on the
/// device. Returns `Ok(())` when at least one matching `<feature-summary>`
/// record is installed; otherwise `Err(SignaturePackageLicenseInactive)`.
///
/// Implementation: fires `<get-license-summary-information/>` and runs
/// [`crate::workflows::license::parse`] directly — no re-entrant MCP call.
pub async fn license_active(
    device: &mut PooledDevice,
    router: &str,
    feature: crate::workflows::license::SrxLicensedFeature,
) -> Result<(), SrxError> {
    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let summary_xml = exec
        .call("get-license-summary-information", &[])
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let parsed = crate::workflows::license::parse(feature, &summary_xml)?;
    let active = matches!(parsed.state, crate::SrxState::Active);
    if !active {
        return Err(SrxError::SignaturePackageLicenseInactive {
            router: router.to_string(),
            feature: match feature {
                crate::workflows::license::SrxLicensedFeature::Idp => "idp".into(),
                crate::workflows::license::SrxLicensedFeature::AppId => "app_id".into(),
                other => format!("{other:?}").to_lowercase(),
            },
        });
    }
    // Defence-in-depth: license parsed Active but installed count is 0 →
    // matching record(s) exist but no entitlement. Treat as inactive.
    if let Some(data) = parsed.data {
        if data.counts.installed == 0 {
            return Err(SrxError::SignaturePackageLicenseInactive {
                router: router.to_string(),
                feature: match feature {
                    crate::workflows::license::SrxLicensedFeature::Idp => "idp".into(),
                    crate::workflows::license::SrxLicensedFeature::AppId => "app_id".into(),
                    other => format!("{other:?}").to_lowercase(),
                },
            });
        }
    }
    Ok(())
}

/// Pre-flight: classify the device topology and verify the cluster (if any)
/// is in a synchronized state.
///
/// Returns:
/// * `Ok(Topology::Standalone)` when `<get-chassis-cluster-status/>` returns
///   an `<xnm:error>` of the "not enabled" shape (parser maps to
///   `state: NotConfigured`).
/// * `Ok(Topology::ChassisCluster)` when both nodes report a healthy
///   primary/secondary pairing on every redundancy group.
/// * `Err(SignaturePackageClusterDesynced)` when any redundancy-group member
///   reports a status other than `primary` / `secondary` (e.g.
///   `secondary-hold`, `ineligible`, `disabled`).
pub async fn cluster_topology(
    device: &mut PooledDevice,
    router: &str,
) -> Result<Topology, SrxError> {
    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let reply = exec
        .call("get-chassis-cluster-status", &[])
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let parsed = crate::workflows::cluster_status::parse(&reply)?;
    match parsed.state {
        crate::SrxState::NotConfigured | crate::SrxState::Error => Ok(Topology::Standalone),
        crate::SrxState::Active => {
            if let Some(data) = parsed.data {
                for rg in &data.redundancy_groups {
                    for m in &rg.members {
                        let s = m.status.to_ascii_lowercase();
                        let healthy = matches!(s.as_str(), "primary" | "secondary");
                        if !healthy {
                            return Err(SrxError::SignaturePackageClusterDesynced {
                                router: router.to_string(),
                                state: m.status.clone(),
                            });
                        }
                    }
                }
            }
            Ok(Topology::ChassisCluster)
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/signature_package")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()))
    }

    #[test]
    fn detects_active_commit_confirmed_window() {
        // commit_confirmed_active.xml carries `<commit-confirmed>rollback
        // pending</commit-confirmed>` on the most recent history record —
        // captured live via /tmp/commit-confirmed-probe.sh.
        let xml = fixture("commit_confirmed_active.xml");
        let open = detect_commit_confirmed(&xml).expect("fixture parses");
        assert!(
            open,
            "commit_confirmed_active.xml should report window open"
        );
    }

    #[test]
    fn no_commit_confirmed_element_returns_false() {
        let xml = r#"<commit-information format="xml">
            <commit-history>
                <sequence-number>0</sequence-number>
                <user>netconf</user>
                <client>netconf</client>
                <date-time junos:seconds="1779738168">2026-05-25 19:42:48 UTC</date-time>
                <log>Configuration loaded via MCP</log>
            </commit-history>
        </commit-information>"#;
        let open = detect_commit_confirmed(xml).expect("inline XML parses");
        assert!(!open, "no <commit-confirmed> element should report closed");
    }

    #[test]
    fn empty_history_returns_false() {
        let xml = r#"<commit-information format="xml"></commit-information>"#;
        assert!(!detect_commit_confirmed(xml).unwrap());
    }

    #[test]
    fn malformed_xml_returns_parse_error() {
        let xml = "<commit-information><commit-history>";
        let err = detect_commit_confirmed(xml).expect_err("malformed XML must error");
        match err {
            SrxError::Parse(msg) => assert!(
                msg.contains("commit-information"),
                "parse error should name the RPC: got {msg:?}"
            ),
            other => panic!("expected Parse, got {other:?}"),
        }
    }
}
