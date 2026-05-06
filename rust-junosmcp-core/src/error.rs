//! Error type surfaced through the MCP server.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum JmcpError {
    #[error("router '{0}' not found in device mapping")]
    UnknownRouter(String),

    #[error("invalid devices.json: {0}")]
    InventoryInvalid(String),

    #[error("private key file not found: {0}")]
    KeyFileMissing(PathBuf),

    #[error("ssh_config invalid for router '{router}': {source}")]
    SshConfigInvalid {
        router: String,
        #[source]
        source: rustez::SshConfigError,
    },

    #[error("invalid config_format '{0}' (expected set, text, or xml)")]
    BadFormat(String),

    #[error("invalid pfe_command: {0}")]
    BadPfeCommand(String),

    #[error("rollback version {0} out of range (1..=49)")]
    BadRollbackVersion(i64),

    #[error("operation timed out after {0:?}")]
    Timeout(std::time::Duration),

    #[error(transparent)]
    Rustez(Box<rustez::RustEzError>),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error(
        "denied by blocklist: {tool} on '{router}' matched rule '{pattern}' \
             (action=deny, source={rule_source}); input: {input_excerpt}"
    )]
    Denied {
        tool: &'static str,
        router: String,
        pattern: String,
        rule_source: &'static str,
        input_excerpt: String,
        line_number: Option<usize>,
    },

    #[error("config blocklist rules require config_format=set; got '{format}'")]
    ConfigFormatNotAllowedWithRules { format: String },

    #[error("invalid blocklist rule for {scope}: pattern '{pattern}': {source}")]
    BlocklistRuleInvalid {
        scope: String,
        pattern: String,
        #[source]
        source: globset::Error,
    },

    /// Jinja2 template failed to parse (`minijinja::Error` syntax kind).
    /// Inner string carries the line/col-formatted message.
    #[error("template syntax error: {0}")]
    TemplateSyntax(String),

    /// `vars_content` could not be parsed as JSON or YAML.
    /// Inner string mentions which parser was attempted last.
    #[error("template vars parse error: {0}")]
    TemplateVars(String),

    /// Render-time error (most commonly strict-undefined hits).
    #[error("template render error: {0}")]
    TemplateRender(String),

    /// Rendered template uses `text` or `xml` format against a device with
    /// active config blocklist rules. Same restriction as load_and_commit_config.
    #[error("template format `{format}` not allowed: device has config rules; use `set`")]
    TemplateFormatMismatch { format: String },

    #[error("validation error: {0}")]
    Validation(String),

    #[error("inventory is read-only (--inventory-readonly set)")]
    InventoryReadonly,

    #[error("device `{0}` already exists in the inventory")]
    DeviceExists(String),

    #[error("password authentication is not allowed for add_device; use --allow-password-auth-add to enable")]
    PasswordAuthDisabled,

    #[error("invalid device name `{0}`: must match ^[A-Za-z0-9_.-]+$")]
    InvalidDeviceName(String),

    #[error("invalid device IP/hostname `{0}`")]
    InvalidDeviceIp(String),

    #[error("invalid device port `{0}`: must be in 1..=65535")]
    InvalidDevicePort(u32),

    #[error("missing required arguments: {0:?}")]
    MissingArguments(Vec<String>),

    #[error(
        "inventory file changed on disk between read and write; call reload_devices and retry"
    )]
    InventoryDriftedOnDisk,

    #[error("inventory is empty (no devices)")]
    EmptyInventory,

    #[error("inventory file read error: {0}")]
    InventoryRead(String),

    #[error("inventory parse error: {0}")]
    InventoryParse(String),

    #[error("inventory file write error: {0}")]
    InventoryWrite(String),
}

impl From<rustez::RustEzError> for JmcpError {
    fn from(e: rustez::RustEzError) -> Self {
        JmcpError::Rustez(Box::new(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_router_displays_router_name() {
        let e = JmcpError::UnknownRouter("r99".into());
        assert_eq!(e.to_string(), "router 'r99' not found in device mapping");
    }

    #[test]
    fn ssh_config_invalid_mentions_router_and_cause() {
        let e = JmcpError::SshConfigInvalid {
            router: "r1".into(),
            source: rustez::SshConfigError::Io {
                path: std::path::PathBuf::from("/no/such/path"),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
            },
        };
        let s = e.to_string();
        assert!(s.contains("ssh_config"));
        assert!(s.contains("r1"));
    }

    #[test]
    fn bad_format_shows_invalid_value() {
        let e = JmcpError::BadFormat("yaml".into());
        assert_eq!(
            e.to_string(),
            "invalid config_format 'yaml' (expected set, text, or xml)"
        );
    }

    #[test]
    fn bad_rollback_version_shows_value_and_range() {
        let e = JmcpError::BadRollbackVersion(99);
        assert_eq!(e.to_string(), "rollback version 99 out of range (1..=49)");
    }

    #[test]
    fn denied_displays_tool_router_and_rule() {
        let e = JmcpError::Denied {
            tool: "execute_junos_command",
            router: "r1".into(),
            pattern: "request system *".into(),
            rule_source: "defaults",
            input_excerpt: "request system reboot".into(),
            line_number: None,
        };
        let s = e.to_string();
        assert!(s.contains("execute_junos_command"));
        assert!(s.contains("r1"));
        assert!(s.contains("request system *"));
        assert!(s.contains("defaults"));
        assert!(s.contains("request system reboot"));
    }

    #[test]
    fn config_format_not_allowed_with_rules_names_format() {
        let e = JmcpError::ConfigFormatNotAllowedWithRules {
            format: "xml".into(),
        };
        let s = e.to_string();
        assert!(s.contains("xml"));
        assert!(s.contains("set"));
    }

    #[test]
    fn blocklist_rule_invalid_names_scope_and_pattern() {
        let glob_err = globset::Glob::new("[unterminated").unwrap_err();
        let e = JmcpError::BlocklistRuleInvalid {
            scope: "_blocklist_defaults.commands".into(),
            pattern: "[unterminated".into(),
            source: glob_err,
        };
        let s = e.to_string();
        assert!(s.contains("_blocklist_defaults.commands"));
        assert!(s.contains("[unterminated"));
    }

    #[test]
    fn bad_pfe_command_displays_reason() {
        let e = JmcpError::BadPfeCommand("contains literal quote".into());
        let s = e.to_string();
        assert!(s.contains("invalid pfe_command"));
        assert!(s.contains("contains literal quote"));
    }

    #[test]
    fn template_syntax_display() {
        let e = JmcpError::TemplateSyntax("line 3: unexpected end-of-input".into());
        let s = format!("{e}");
        assert!(s.contains("template syntax"));
        assert!(s.contains("line 3"));
    }

    #[test]
    fn inventory_readonly_display_mentions_flag() {
        let s = JmcpError::InventoryReadonly.to_string();
        assert!(s.contains("--inventory-readonly"));
    }

    #[test]
    fn device_exists_display_includes_name() {
        let s = JmcpError::DeviceExists("r1".into()).to_string();
        assert!(s.contains("`r1`"));
        assert!(s.contains("already exists"));
    }

    #[test]
    fn password_auth_disabled_display_mentions_flag() {
        let s = JmcpError::PasswordAuthDisabled.to_string();
        assert!(s.contains("--allow-password-auth-add"));
    }

    #[test]
    fn invalid_device_name_display_includes_regex() {
        let s = JmcpError::InvalidDeviceName("bad name".into()).to_string();
        assert!(s.contains("bad name"));
        assert!(s.contains("^[A-Za-z0-9_.-]+$"));
    }

    #[test]
    fn invalid_device_ip_display_includes_value() {
        let s = JmcpError::InvalidDeviceIp("not-an-ip".into()).to_string();
        assert!(s.contains("not-an-ip"));
    }

    #[test]
    fn invalid_device_port_display_includes_range() {
        let s = JmcpError::InvalidDevicePort(70_000).to_string();
        assert!(s.contains("70000"));
        assert!(s.contains("1..=65535"));
    }

    #[test]
    fn missing_arguments_display_uses_debug_format() {
        let s = JmcpError::MissingArguments(vec!["router_name".into(), "ip".into()]).to_string();
        assert!(s.contains("[\"router_name\", \"ip\"]"));
    }

    #[test]
    fn inventory_drifted_display_recommends_reload() {
        let s = JmcpError::InventoryDriftedOnDisk.to_string();
        assert!(s.contains("reload_devices"));
    }

    #[test]
    fn empty_inventory_display() {
        let s = JmcpError::EmptyInventory.to_string();
        assert!(s.contains("inventory is empty"));
    }

    #[test]
    fn inventory_read_display_includes_cause() {
        let s = JmcpError::InventoryRead("permission denied".into()).to_string();
        assert!(s.contains("read"));
        assert!(s.contains("permission denied"));
    }

    #[test]
    fn inventory_parse_display_includes_cause() {
        let s = JmcpError::InventoryParse("expected `{` at line 1".into()).to_string();
        assert!(s.contains("parse"));
        assert!(s.contains("expected `{`"));
    }

    #[test]
    fn inventory_write_display_includes_cause() {
        let s = JmcpError::InventoryWrite("disk full".into()).to_string();
        assert!(s.contains("write"));
        assert!(s.contains("disk full"));
    }
}
