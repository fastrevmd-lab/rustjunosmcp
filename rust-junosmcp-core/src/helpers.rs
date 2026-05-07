//! Pure helper functions, easily unit-testable without device contact.

use crate::error::JmcpError;
use rustez::ConfigPayload;

/// Map the optional `config_format` string from the MCP tool input to
/// a `rustez::ConfigPayload` constructor closure. Default = "set".
pub fn build_config_payload(text: String, fmt: Option<&str>) -> Result<ConfigPayload, JmcpError> {
    match fmt.unwrap_or("set") {
        "set" => Ok(ConfigPayload::Set(text)),
        "text" => Ok(ConfigPayload::Text(text)),
        "xml" => Ok(ConfigPayload::Xml(text)),
        other => Err(JmcpError::BadFormat(other.into())),
    }
}

/// Truncate `s` to at most 120 chars on a char boundary.
pub fn excerpt(s: &str) -> String {
    if s.len() <= 120 {
        return s.to_string();
    }
    let mut end = 120;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Strip `<configuration-information>` / `<configuration-output>` XML wrapper
/// tags that Junos adds around CLI output delivered over NETCONF.
pub fn strip_config_xml_wrapper(raw: &str) -> String {
    if let Some(start) = raw.find("<configuration-output>") {
        let content_start = start + "<configuration-output>".len();
        if let Some(end) = raw[content_start..].find("</configuration-output>") {
            return raw[content_start..content_start + end].trim().to_string();
        }
    }
    raw.trim().to_string()
}

/// Maximum allowed length for user-supplied text fields (1 MB).
pub const MAX_INPUT_LEN: usize = 1_048_576;

/// Reject text fields that exceed the maximum allowed length.
pub fn validate_input_length(field_name: &str, value: &str) -> Result<(), JmcpError> {
    if value.len() > MAX_INPUT_LEN {
        return Err(JmcpError::InventoryInvalid(format!(
            "{field_name} exceeds maximum length of {} bytes",
            MAX_INPUT_LEN
        )));
    }
    Ok(())
}

/// Clamp an LLM-provided rollback version to the Junos-supported range 1..=49.
pub fn validate_rollback_version(v: i64) -> Result<u32, JmcpError> {
    if (1..=49).contains(&v) {
        Ok(v as u32)
    } else {
        Err(JmcpError::BadRollbackVersion(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_config_payload_defaults_to_set() {
        let p = build_config_payload("set system foo".into(), None).unwrap();
        assert!(matches!(p, ConfigPayload::Set(ref s) if s == "set system foo"));
    }

    #[test]
    fn build_config_payload_accepts_text() {
        let p = build_config_payload("system { foo; }".into(), Some("text")).unwrap();
        assert!(matches!(p, ConfigPayload::Text(_)));
    }

    #[test]
    fn build_config_payload_accepts_xml() {
        let p = build_config_payload("<foo/>".into(), Some("xml")).unwrap();
        assert!(matches!(p, ConfigPayload::Xml(_)));
    }

    #[test]
    fn build_config_payload_rejects_unknown() {
        let r = build_config_payload("x".into(), Some("yaml"));
        assert!(matches!(r, Err(JmcpError::BadFormat(ref s)) if s == "yaml"));
    }

    #[test]
    fn rollback_version_accepts_1_through_49() {
        assert_eq!(validate_rollback_version(1).unwrap(), 1);
        assert_eq!(validate_rollback_version(49).unwrap(), 49);
    }

    #[test]
    fn rollback_version_rejects_zero() {
        let r = validate_rollback_version(0);
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(0))));
    }

    #[test]
    fn rollback_version_rejects_50() {
        let r = validate_rollback_version(50);
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(50))));
    }

    #[test]
    fn rollback_version_rejects_negative() {
        let r = validate_rollback_version(-3);
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(-3))));
    }

    #[test]
    fn excerpt_short_string_unchanged() {
        let s = "show version";
        assert_eq!(excerpt(s), s);
    }

    #[test]
    fn excerpt_truncates_at_120_char_boundary() {
        let s = "a".repeat(200);
        let result = excerpt(&s);
        assert_eq!(result.len(), 120);
    }

    #[test]
    fn strip_config_xml_wrapper_extracts_content() {
        let raw = "<configuration-information><configuration-output>  system { host-name r1; }  </configuration-output></configuration-information>";
        assert_eq!(strip_config_xml_wrapper(raw), "system { host-name r1; }");
    }

    #[test]
    fn strip_config_xml_wrapper_passthrough_when_no_tag() {
        let raw = "  system { host-name r1; }  ";
        assert_eq!(strip_config_xml_wrapper(raw), "system { host-name r1; }");
    }
}
