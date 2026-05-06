//! `render_and_apply_j2_template` — Jinja2 render with optional commit.
//!
//! Vars input is parsed as JSON if it starts with `{` (after whitespace) or
//! YAML otherwise. Both must produce a top-level object.

use crate::error::JmcpError;
use minijinja::{Environment, UndefinedBehavior};
use serde_json::Value;

/// Parse `vars_content` as JSON if first non-whitespace char is `{`,
/// otherwise as YAML. Both branches must produce a `Value::Object`.
#[allow(dead_code)]
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

/// Render `template_content` with `vars` (a JSON object). Strict-undefined:
/// missing variables surface as `JmcpError::TemplateRender`, not silently as "".
#[allow(dead_code)]
pub(crate) fn render(template_content: &str, vars: &Value) -> Result<String, JmcpError> {
    let mut env = Environment::new();
    env.set_undefined_behavior(UndefinedBehavior::Strict);
    let tmpl = env
        .template_from_str(template_content)
        .map_err(|e| JmcpError::TemplateSyntax(format!("{e}")))?;
    tmpl.render(vars)
        .map_err(|e| JmcpError::TemplateRender(format!("{e}")))
}

/// Auto-detect Junos config format from the rendered string.
/// Returns "xml" if the first non-whitespace char is `<`, "set" if any line
/// starts with `set ` or `delete `, otherwise "text".
#[allow(dead_code)]
pub(crate) fn detect_format(rendered: &str) -> &'static str {
    let trimmed = rendered.trim_start();
    if trimmed.starts_with('<') {
        return "xml";
    }
    for line in rendered.lines() {
        let line = line.trim_start();
        if line.starts_with("set ") || line.starts_with("delete ") {
            return "set";
        }
    }
    "text"
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

    #[test]
    fn render_substitutes_simple_var() {
        let out = render(
            "set system host-name {{ name }}",
            &parse_vars(r#"{"name":"r1"}"#).unwrap(),
        )
        .unwrap();
        assert_eq!(out, "set system host-name r1");
    }

    #[test]
    fn render_strict_undefined_fails_with_var_name() {
        let r = render(
            "set system host-name {{ missing }}",
            &parse_vars("{}").unwrap(),
        );
        match r {
            Err(JmcpError::TemplateRender(s)) => assert!(s.contains("undefined")),
            other => panic!("expected TemplateRender, got {other:?}"),
        }
    }

    #[test]
    fn render_minijinja_filters_work() {
        let out = render(
            "{{ name | upper }}-{{ ports | length }}",
            &parse_vars(r#"{"name":"r1","ports":[1,2,3,4]}"#).unwrap(),
        )
        .unwrap();
        assert_eq!(out, "R1-4");
    }

    #[test]
    fn render_template_syntax_error_surfaces() {
        let r = render("{{ unterminated", &parse_vars("{}").unwrap());
        assert!(matches!(r, Err(JmcpError::TemplateSyntax(_))));
    }

    #[test]
    fn format_autodetect_xml_for_leading_lt() {
        assert_eq!(detect_format("<configuration>...</configuration>"), "xml");
        assert_eq!(detect_format("\n  <foo/>"), "xml");
    }

    #[test]
    fn format_autodetect_set_for_set_lines() {
        assert_eq!(detect_format("set system host-name r1"), "set");
        assert_eq!(detect_format("delete protocols bgp"), "set");
        // Mixed input, but `set ` line wins:
        assert_eq!(detect_format("set foo\n# comment\nbar"), "set");
    }

    #[test]
    fn format_autodetect_text_otherwise() {
        assert_eq!(detect_format("system {\n  host-name r1;\n}"), "text");
        assert_eq!(detect_format(""), "text");
    }
}
