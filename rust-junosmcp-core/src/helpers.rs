//! Pure helper functions, easily unit-testable without device contact.

use crate::error::JmcpError;
use rustez::{ConfigPayload, Facts};
use serde_json::{json, Value};

/// Map the optional `config_format` string from the MCP tool input to
/// a `rustez::ConfigPayload` constructor closure. Default = "set".
pub fn build_config_payload(
    text: String,
    fmt: Option<&str>,
) -> Result<ConfigPayload, JmcpError> {
    match fmt.unwrap_or("set") {
        "set"  => Ok(ConfigPayload::Set(text)),
        "text" => Ok(ConfigPayload::Text(text)),
        "xml"  => Ok(ConfigPayload::Xml(text)),
        other  => Err(JmcpError::BadFormat(other.into())),
    }
}

/// Clamp an LLM-provided rollback version to the Junos-supported range 1..=49.
pub fn validate_rollback_version(v: i64) -> Result<u32, JmcpError> {
    if (1..=49).contains(&v) {
        Ok(v as u32)
    } else {
        Err(JmcpError::BadRollbackVersion(v))
    }
}

/// Hand-build a JSON object from `rustez::Facts`. rustez::Facts does not
/// derive Serialize today (see followup #1); update this when it does.
pub fn facts_to_json(f: &Facts) -> Value {
    json!({
        "hostname": f.hostname,
        "model": f.model,
        "version": f.version,
        "serial_number": f.serial_number,
        "personality": format!("{:?}", f.personality),
        "domain": f.domain,
        "fqdn": f.fqdn,
        "is_cluster": f.is_cluster,
        "route_engines": f.route_engines.iter().map(|re| json!({
            "status": format!("{:?}", re),
        })).collect::<Vec<_>>(),
        "master_re": f.master_re,
    })
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
}
