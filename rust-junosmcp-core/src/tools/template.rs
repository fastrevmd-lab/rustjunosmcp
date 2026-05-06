//! `render_and_apply_j2_template` — Jinja2 render with optional commit.
//!
//! Vars input is parsed as JSON if it starts with `{` (after whitespace) or
//! YAML otherwise. Both must produce a top-level object.

use crate::error::JmcpError;
use serde_json::Value;

/// Parse `vars_content` as JSON if first non-whitespace char is `{`,
/// otherwise as YAML. Both branches must produce a `Value::Object`.
pub(crate) fn parse_vars(input: &str) -> Result<Value, JmcpError> {
    let trimmed = input.trim_start();
    let parsed = if trimmed.starts_with('{') {
        serde_json::from_str::<Value>(input)
            .map_err(|e| JmcpError::TemplateVars(format!("JSON parse failed: {e}")))?
    } else {
        serde_yml::from_str::<Value>(input)
            .map_err(|e| JmcpError::TemplateVars(format!("YAML parse failed: {e}")))?
    };
    if !parsed.is_object() {
        return Err(JmcpError::TemplateVars(
            "vars_content must deserialize to a top-level object/map".into(),
        ));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vars_sniff_routes_json() {
        let v = parse_vars(r#"{"name":"r1","port":22}"#).unwrap();
        assert_eq!(v["name"], "r1");
        assert_eq!(v["port"], 22);
    }

    #[test]
    fn vars_sniff_routes_yaml() {
        let v = parse_vars("name: r1\nport: 22\n").unwrap();
        assert_eq!(v["name"], "r1");
        assert_eq!(v["port"], 22);
    }

    #[test]
    fn vars_sniff_handles_leading_whitespace_for_json() {
        let v = parse_vars("   \n   {\"x\":1}").unwrap();
        assert_eq!(v["x"], 1);
    }

    #[test]
    fn vars_sniff_rejects_non_object_json_array() {
        let r = parse_vars("[1,2,3]");
        assert!(matches!(r, Err(JmcpError::TemplateVars(_))));
    }

    #[test]
    fn vars_sniff_rejects_non_object_yaml_scalar() {
        let r = parse_vars("just a string");
        assert!(matches!(r, Err(JmcpError::TemplateVars(_))));
    }

    #[test]
    fn vars_sniff_surfaces_yaml_parse_error() {
        // Stray colons + flow indentation will fail YAML parse.
        let r = parse_vars("key: : :\n  - bad: : :\n");
        assert!(matches!(r, Err(JmcpError::TemplateVars(s)) if s.contains("YAML")));
    }
}
