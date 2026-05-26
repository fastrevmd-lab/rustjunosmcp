//! Pure XML helpers shared by signature-package pre-flight code.
//!
//! Device-touching wrappers — `license_active(device, feature)`,
//! `cluster_topology(device)`, `signatures_server_reachable(exec)` —
//! land alongside their first consumer (Tasks 4+). Today this module
//! ships only the offline parsers that have stable Junos schemas.

use crate::SrxError;

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
