//! Redaction rules applied when `redact=true` (default) on
//! `collect_jtac_support_bundle`. Strips known-sensitive elements from
//! captured `get-configuration` and per-RPC XML payloads before they're
//! written into the on-device tarball.
//!
//! Locked rule list (Phase 3 design doc § "Redact rules"):
//! * `pre-shared-key` — IKE PSKs (`security ike policy ... pre-shared-key`)
//! * `secret` / `simple-password` / `encrypted-password` — local-user,
//!   RADIUS, TACACS, snmp-v3, IPsec-mfg secrets
//! * `community` under `snmp` — SNMP v1/v2c community strings
//! * `radius-server` `secret` — RADIUS shared-secret
//! * `tacplus-server` `secret` — TACACS+ shared-secret
//! * `hmac-key` — routing-options authentication-key HMAC
//!
//! The redaction is XML-element-name based — every matching element has
//! its text content replaced with `<REDACTED>` while preserving the XML
//! structure so JTAC can still see *where* a secret was configured.

/// Element names whose text content is replaced with `<REDACTED>`.
/// Matching is exact on the local element name (namespace-stripped).
pub const REDACT_ELEMENT_NAMES: &[&str] = &[
    "pre-shared-key",
    "secret",
    "simple-password",
    "encrypted-password",
    "community",
    "hmac-key",
];

/// Replacement string used in redacted element text.
pub const REDACTED_MARKER: &str = "<REDACTED>";

/// Redact known-sensitive element text content from an XML payload.
/// Returns the redacted XML string. If the input cannot be parsed,
/// returns the input unchanged (callers should treat parse failures as
/// non-fatal and log them).
pub fn redact_xml(input: &str) -> String {
    use quick_xml::events::{BytesText, Event};
    use quick_xml::reader::Reader;
    use quick_xml::writer::Writer;

    // Gate on well-formedness first: quick-xml's streaming reader is lenient
    // (it silently tolerates unclosed tags), so use roxmltree as a strict
    // parse check. On any parse failure return the input unchanged — callers
    // treat that as non-fatal.
    if roxmltree::Document::parse(input).is_err() {
        return input.to_string();
    }

    let mut reader = Reader::from_str(input);
    let mut writer = Writer::new(Vec::new());

    // Whether each currently-open element matched a redacted name, and a
    // count of open matched ancestors. While `redact_depth > 0` every text
    // node (the matched element's own text or any descendant's) is replaced
    // with the marker, but all element tags are emitted verbatim so the XML
    // structure is preserved.
    let mut matched_stack: Vec<bool> = Vec::new();
    let mut redact_depth: usize = 0;

    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let matched = REDACT_ELEMENT_NAMES
                    .iter()
                    .any(|name| e.local_name().as_ref() == name.as_bytes());
                if writer.write_event(Event::Start(e)).is_err() {
                    return input.to_string();
                }
                if matched {
                    redact_depth += 1;
                }
                matched_stack.push(matched);
            }
            Ok(Event::End(e)) => {
                if writer.write_event(Event::End(e)).is_err() {
                    return input.to_string();
                }
                if matched_stack.pop().unwrap_or(false) {
                    redact_depth = redact_depth.saturating_sub(1);
                }
            }
            Ok(Event::Text(_)) | Ok(Event::CData(_)) if redact_depth > 0 => {
                if writer
                    .write_event(Event::Text(BytesText::new(REDACTED_MARKER)))
                    .is_err()
                {
                    return input.to_string();
                }
            }
            Ok(event) => {
                if writer.write_event(event).is_err() {
                    return input.to_string();
                }
            }
            Err(_) => return input.to_string(),
        }
    }

    String::from_utf8(writer.into_inner()).unwrap_or_else(|_| input.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // #85: a known-sensitive element's text content is replaced with the
    // redaction marker while the element itself is preserved.
    #[test]
    fn redacts_pre_shared_key_text() {
        let xml = "<ike-policy><pre-shared-key>s3cr3t-psk</pre-shared-key></ike-policy>";
        let out = redact_xml(xml);
        assert!(!out.contains("s3cr3t-psk"), "secret leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
        assert!(
            out.contains("pre-shared-key"),
            "element name dropped: {out}"
        );
    }

    // Every name in the locked list must be redacted.
    #[test]
    fn redacts_every_known_element_name() {
        for name in REDACT_ELEMENT_NAMES {
            let xml = format!("<root><{name}>leak-{name}</{name}></root>");
            let out = redact_xml(&xml);
            assert!(
                !out.contains(&format!("leak-{name}")),
                "secret leaked for <{name}>: {out}"
            );
            assert!(
                out.contains("REDACTED"),
                "marker missing for <{name}>: {out}"
            );
        }
    }

    // Non-sensitive elements are passed through untouched.
    #[test]
    fn leaves_non_sensitive_text_untouched() {
        let xml = "<config><host-name>edge01</host-name></config>";
        let out = redact_xml(xml);
        assert!(out.contains("edge01"), "non-sensitive text mangled: {out}");
        assert!(!out.contains("REDACTED"), "unexpected redaction: {out}");
    }

    // Matching is on the namespace-stripped local name.
    #[test]
    fn matches_namespace_prefixed_local_name() {
        let xml = "<junos:secret xmlns:junos=\"http://x\">topsecret</junos:secret>";
        let out = redact_xml(xml);
        assert!(!out.contains("topsecret"), "secret leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
    }

    // Surrounding structure and sibling text are preserved.
    #[test]
    fn preserves_surrounding_structure() {
        let xml = "<users><user><name>bob</name><secret>pw123</secret></user></users>";
        let out = redact_xml(xml);
        assert!(out.contains("bob"), "sibling text lost: {out}");
        assert!(!out.contains("pw123"), "secret leaked: {out}");
        assert!(out.contains("<name>"), "structure lost: {out}");
        assert!(out.contains("secret"), "redacted element name lost: {out}");
    }

    // Unparseable input is returned unchanged (callers treat as non-fatal).
    #[test]
    fn returns_input_unchanged_on_parse_failure() {
        let bad = "<unclosed><secret>oops";
        assert_eq!(redact_xml(bad), bad);
    }
}
