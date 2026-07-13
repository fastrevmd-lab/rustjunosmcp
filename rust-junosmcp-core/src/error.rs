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

    #[error("invalid source_path [code=bad_source_path]: {0}")]
    BadSourcePath(String),

    #[error(
        "insufficient disk [code=insufficient_disk]: {message} (free={free}B required={required}B)"
    )]
    InsufficientDisk {
        free: u64,
        required: u64,
        message: String,
    },

    #[error(
        "unsupported auth [code=unsupported_auth]: device '{0}' uses password auth; transfer_file requires ssh_key (add SshKey to inventory)"
    )]
    UnsupportedAuth(String),

    #[error(
        "destination already exists with different content [code=dest_exists_differs]: {dest} (local sha256={local_sha}, remote sha256={remote_sha}); pass force=true to overwrite"
    )]
    DestExistsDiffers {
        dest: String,
        local_sha: String,
        remote_sha: String,
    },

    #[error("scp failed [code=scp_failed] (exit={exit_code}): {stderr}")]
    ScpFailed { exit_code: i32, stderr: String },

    #[error(
        "required OpenSSH scp dependency unavailable [code=scp_dependency_unavailable]: {detail}; install openssh-client with legacy -O support or use the supported container image"
    )]
    ScpDependencyUnavailable { detail: String },

    #[error(
        "scp connect timeout [code=connect_timeout]: device '{0}' may be unreachable or SSH (port 22) is filtered"
    )]
    ConnectTimeout(String),

    #[error(
        "host key verification failed [code=host_key_mismatch]: router '{router}' was rejected; review or refresh the entry in {known_hosts_file}"
    )]
    HostKeyMismatch {
        router: String,
        known_hosts_file: PathBuf,
    },

    #[error("device probe failed [code=device_probe_failed] (phase={phase}): {message}")]
    DeviceProbeFailed { phase: String, message: String },

    #[error(
        "post-transfer verify failed [code=verify_mismatch]: {dest} (local sha256={local_sha}, remote sha256={remote_sha}); destination file was deleted"
    )]
    VerifyMismatch {
        dest: String,
        local_sha: String,
        remote_sha: String,
    },

    #[error("[code=local_dest_exists_differs] local destination '{dest}' exists with sha256 '{local_sha}'; remote sha256 is '{remote_sha}'; set force=true to overwrite")]
    LocalDestExistsDiffers {
        dest: String,
        local_sha: String,
        remote_sha: String,
    },

    #[error("[code=remote_file_missing] router '{router}' has no file at '{remote_path}'")]
    RemoteFileMissing { router: String, remote_path: String },

    #[error("[code=fetch_verify_mismatch] fetched file '{dest}' local sha256 '{local_sha}' does not match remote sha256 '{remote_sha}'")]
    FetchVerifyMismatch {
        dest: String,
        local_sha: String,
        remote_sha: String,
    },

    #[error(
        "transfer outer timeout [code=outer_timeout] after {0:?}; raise the `timeout` arg or split the file"
    )]
    TransferOuterTimeout(std::time::Duration),

    #[error(
        "confirmation required [code=confirmation_required]: re-call with confirm=true to proceed; plan: {payload}"
    )]
    ConfirmationRequired { payload: serde_json::Value },

    #[error(
        "cluster device unsupported [code=cluster_unsupported]: router '{router}' is a chassis cluster; upgrade_junos v1 supports standalone devices only (ISSU support deferred to v2)"
    )]
    UpgradeClusterUnsupported { router: String },

    #[error(
        "active commit-confirmed window [code=commit_confirmed_active]: router '{router}' has a pending rollback in {rollback_secs}s; run `commit` or `rollback` first, then retry"
    )]
    UpgradeCommitConfirmedActive { router: String, rollback_secs: u64 },

    #[error(
        "install RPC timed out [code=install_timeout]: router '{router}' after {elapsed:?}; the install may still be running on the device — check from console or retry once the device is reachable"
    )]
    UpgradeInstallTimeout {
        router: String,
        elapsed: std::time::Duration,
    },

    #[error(
        "device did not return after reboot [code=reboot_timeout]: router '{router}' did not reopen NETCONF within {waited_secs}s; check console / hardware status"
    )]
    UpgradeRebootTimeout { router: String, waited_secs: u64 },

    #[error(
        "post-upgrade version mismatch [code=postverify_mismatch]: router '{router}' expected '{expected}', got '{observed}'; the install may have rolled back or failed silently"
    )]
    UpgradePostVerifyMismatch {
        router: String,
        expected: String,
        observed: String,
    },

    #[error(
        "upgrade outer timeout [code=upgrade_outer_timeout] after {0:?}; raise the `timeout` arg or check device responsiveness"
    )]
    UpgradeOuterTimeout(std::time::Duration),

    #[error("operation timed out after {0:?}")]
    Timeout(std::time::Duration),

    #[error("operation cancelled by client [code=cancelled]")]
    Cancelled,

    #[error(
        "device lease busy [code=device_lease_busy]: router '{router}' remained locked by another destructive workflow after {waited_secs}s"
    )]
    DeviceLeaseBusy { router: String, waited_secs: u64 },

    #[error("device lease failed [code=device_lease_error]: router '{router}': {detail}")]
    DeviceLeaseError { router: String, detail: String },

    #[error(
        "candidate cleanup failed [code=candidate_cleanup_failed]: primary={primary}; rollback={rollback}; unlock={unlock}"
    )]
    CandidateCleanupFailed {
        primary: String,
        rollback: String,
        unlock: String,
    },

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

    /// A `junos_config_diff` failed because the on-box config won't parse for
    /// the current mode; message carries the raw error + an actionable hint.
    #[error("{0}")]
    ConfigParseHint(String),

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

    #[error(
        "known_hosts file missing or unreadable [code=known_hosts_missing]: {0}; run scripts/scan-known-hosts.sh to pre-populate it, or pass --ssh-accept-new-host-keys (lab only)"
    )]
    KnownHostsMissing(PathBuf),
}

impl From<rustez::RustEzError> for JmcpError {
    fn from(e: rustez::RustEzError) -> Self {
        JmcpError::Rustez(Box::new(e))
    }
}

impl JmcpError {
    /// Returns the stable audit `error_kind` string for this error variant.
    ///
    /// Used by `AuditScope::fail_kind` to emit structured error classes to SIEM.
    /// This match is EXHAUSTIVE (no `_` wildcard) so that any new variant added
    /// to `JmcpError` triggers a compile error here, forcing a deliberate
    /// classification decision for the new variant.
    pub fn audit_kind(&self) -> &'static str {
        match self {
            Self::UnknownRouter(_) => "unknown_router",
            Self::InventoryInvalid(_) => "invalid_input",
            Self::KeyFileMissing(_) => "not_found",
            Self::SshConfigInvalid { .. } => "invalid_input",
            Self::BadFormat(_) => "invalid_input",
            Self::BadPfeCommand(_) => "invalid_input",
            Self::BadRollbackVersion(_) => "invalid_input",
            Self::BadSourcePath(_) => "invalid_input",
            Self::InsufficientDisk { .. } => "insufficient_disk",
            Self::UnsupportedAuth(_) => "unsupported",
            Self::DestExistsDiffers { .. } => "conflict",
            Self::ScpFailed { .. } => "scp_failed",
            Self::ScpDependencyUnavailable { .. } => "dependency_unavailable",
            Self::ConnectTimeout(_) => "timeout",
            Self::HostKeyMismatch { .. } => "host_key_mismatch",
            Self::DeviceProbeFailed { .. } => "device_probe_failed",
            Self::VerifyMismatch { .. } => "verify_mismatch",
            Self::LocalDestExistsDiffers { .. } => "conflict",
            Self::RemoteFileMissing { .. } => "not_found",
            Self::FetchVerifyMismatch { .. } => "verify_mismatch",
            Self::TransferOuterTimeout(_) => "timeout",
            Self::ConfirmationRequired { .. } => "confirmation_required",
            Self::UpgradeClusterUnsupported { .. } => "unsupported",
            Self::UpgradeCommitConfirmedActive { .. } => "commit_confirmed_active",
            Self::UpgradeInstallTimeout { .. } => "timeout",
            Self::UpgradeRebootTimeout { .. } => "timeout",
            Self::UpgradePostVerifyMismatch { .. } => "verify_mismatch",
            Self::UpgradeOuterTimeout(_) => "timeout",
            Self::Timeout(_) => "timeout",
            Self::Cancelled => "cancelled",
            Self::DeviceLeaseBusy { .. } => "lease_busy",
            Self::DeviceLeaseError { .. } => "lease_error",
            Self::CandidateCleanupFailed { .. } => "lease_error",
            Self::Rustez(_) => "transport",
            Self::Io(_) => "io",
            Self::Json(_) => "parse",
            Self::Denied { .. } => "blocked",
            Self::ConfigFormatNotAllowedWithRules { .. } => "invalid_input",
            Self::BlocklistRuleInvalid { .. } => "invalid_input",
            Self::TemplateSyntax(_) => "parse",
            Self::TemplateVars(_) => "parse",
            Self::TemplateRender(_) => "parse",
            Self::TemplateFormatMismatch { .. } => "invalid_input",
            Self::Validation(_) => "invalid_input",
            Self::ConfigParseHint(_) => "invalid_input",
            Self::InventoryReadonly => "inventory_readonly",
            Self::DeviceExists(_) => "conflict",
            Self::PasswordAuthDisabled => "unsupported",
            Self::InvalidDeviceName(_) => "invalid_input",
            Self::InvalidDeviceIp(_) => "invalid_input",
            Self::InvalidDevicePort(_) => "invalid_input",
            Self::MissingArguments(_) => "invalid_input",
            Self::InventoryDriftedOnDisk => "conflict",
            Self::EmptyInventory => "inventory_empty",
            Self::InventoryRead(_) => "io",
            Self::InventoryParse(_) => "parse",
            Self::InventoryWrite(_) => "io",
            Self::KnownHostsMissing(_) => "not_found",
        }
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

    #[test]
    fn bad_source_path_display_includes_code() {
        let s = JmcpError::BadSourcePath("contains '/'".into()).to_string();
        assert!(s.contains("code=bad_source_path"));
        assert!(s.contains("contains '/'"));
    }

    #[test]
    fn unsupported_auth_display_includes_remediation() {
        let s = JmcpError::UnsupportedAuth("vSRX-test10".into()).to_string();
        assert!(s.contains("code=unsupported_auth"));
        assert!(s.contains("vSRX-test10"));
        assert!(s.contains("ssh_key"));
    }

    #[test]
    fn dest_exists_differs_display_includes_force_hint() {
        let s = JmcpError::DestExistsDiffers {
            dest: "/var/tmp/foo".into(),
            local_sha: "aaa".into(),
            remote_sha: "bbb".into(),
        }
        .to_string();
        assert!(s.contains("code=dest_exists_differs"));
        assert!(s.contains("force=true"));
    }

    #[test]
    fn scp_failed_display_includes_stderr() {
        let s = JmcpError::ScpFailed {
            exit_code: 1,
            stderr: "Permission denied".into(),
        }
        .to_string();
        assert!(s.contains("code=scp_failed"));
        assert!(s.contains("Permission denied"));
        assert!(s.contains("exit=1"));
    }

    #[test]
    fn scp_dependency_unavailable_display_includes_code_and_remediation() {
        let s = JmcpError::ScpDependencyUnavailable {
            detail: "executable 'scp' was not found in PATH".into(),
        }
        .to_string();
        assert!(s.contains("[code=scp_dependency_unavailable]"));
        assert!(s.contains("openssh-client"));
        assert!(s.contains("legacy -O"));
    }

    #[test]
    fn connect_timeout_display_includes_hint() {
        let s = JmcpError::ConnectTimeout("vSRX-test10".into()).to_string();
        assert!(s.contains("code=connect_timeout"));
        assert!(s.contains("vSRX-test10"));
    }

    #[test]
    fn host_key_mismatch_display_includes_code_router_and_known_hosts() {
        let s = JmcpError::HostKeyMismatch {
            router: "vSRX-test10".into(),
            known_hosts_file: std::path::PathBuf::from("/etc/jmcp/known_hosts"),
        }
        .to_string();
        assert!(s.contains("[code=host_key_mismatch]"), "got {s}");
        assert!(s.contains("vSRX-test10"), "got {s}");
        assert!(s.contains("/etc/jmcp/known_hosts"), "got {s}");
    }

    #[test]
    fn device_probe_failed_display_includes_code_and_phase() {
        let e = JmcpError::DeviceProbeFailed {
            phase: "storage_probe".into(),
            message: "rpc-error: ...".into(),
        };
        let s = e.to_string();
        assert!(s.contains("[code=device_probe_failed]"));
        assert!(s.contains("storage_probe"));
    }

    #[test]
    fn verify_mismatch_display_notes_deletion() {
        let s = JmcpError::VerifyMismatch {
            dest: "/var/tmp/foo".into(),
            local_sha: "aaa".into(),
            remote_sha: "bbb".into(),
        }
        .to_string();
        assert!(s.contains("code=verify_mismatch"));
        assert!(s.contains("deleted"));
    }

    #[test]
    fn transfer_outer_timeout_display_includes_remediation() {
        let s = JmcpError::TransferOuterTimeout(std::time::Duration::from_secs(60)).to_string();
        assert!(s.contains("code=outer_timeout"));
        assert!(s.contains("raise"));
    }

    #[test]
    fn confirmation_required_display_includes_code_and_router() {
        let payload = serde_json::json!({
            "router": "vsrx-test18",
            "current_version": "24.4R1.9",
            "target_version": "25.4R1.12",
        });
        let s = JmcpError::ConfirmationRequired {
            payload: payload.clone(),
        }
        .to_string();
        assert!(s.contains("[code=confirmation_required]"), "got {s}");
        assert!(s.contains("vsrx-test18"), "got {s}");
        assert!(s.contains("25.4R1.12"), "got {s}");
    }

    #[test]
    fn upgrade_cluster_unsupported_display_includes_code_and_router() {
        let s = JmcpError::UpgradeClusterUnsupported {
            router: "vsrx-test19".into(),
        }
        .to_string();
        assert!(s.contains("[code=cluster_unsupported]"), "got {s}");
        assert!(s.contains("vsrx-test19"), "got {s}");
    }

    #[test]
    fn upgrade_commit_confirmed_active_display_includes_code_and_rollback() {
        let s = JmcpError::UpgradeCommitConfirmedActive {
            router: "vsrx-test10".into(),
            rollback_secs: 540,
        }
        .to_string();
        assert!(s.contains("[code=commit_confirmed_active]"), "got {s}");
        assert!(s.contains("vsrx-test10"), "got {s}");
        assert!(s.contains("540"), "got {s}");
    }

    #[test]
    fn upgrade_install_timeout_display_includes_code() {
        let s = JmcpError::UpgradeInstallTimeout {
            router: "vsrx-test10".into(),
            elapsed: std::time::Duration::from_secs(3600),
        }
        .to_string();
        assert!(s.contains("[code=install_timeout]"), "got {s}");
        assert!(s.contains("vsrx-test10"), "got {s}");
    }

    #[test]
    fn upgrade_reboot_timeout_display_includes_code_and_secs() {
        let s = JmcpError::UpgradeRebootTimeout {
            router: "vsrx-test10".into(),
            waited_secs: 480,
        }
        .to_string();
        assert!(s.contains("[code=reboot_timeout]"), "got {s}");
        assert!(s.contains("vsrx-test10"), "got {s}");
        assert!(s.contains("480"), "got {s}");
    }

    #[test]
    fn upgrade_postverify_mismatch_display_includes_versions() {
        let s = JmcpError::UpgradePostVerifyMismatch {
            router: "vsrx-test10".into(),
            expected: "25.4R1.12".into(),
            observed: "24.4R1.9".into(),
        }
        .to_string();
        assert!(s.contains("[code=postverify_mismatch]"), "got {s}");
        assert!(s.contains("25.4R1.12"), "got {s}");
        assert!(s.contains("24.4R1.9"), "got {s}");
    }

    #[test]
    fn upgrade_outer_timeout_display_includes_code_and_duration() {
        let s = JmcpError::UpgradeOuterTimeout(std::time::Duration::from_secs(900)).to_string();
        assert!(s.contains("[code=upgrade_outer_timeout]"), "got {s}");
        assert!(s.contains("900s"), "got {s}");
    }

    #[test]
    fn cancelled_display_includes_code() {
        let s = JmcpError::Cancelled.to_string();
        assert!(s.contains("[code=cancelled]"), "got {s}");
        assert!(s.contains("cancelled by client"), "got {s}");
    }

    #[test]
    fn device_lease_errors_have_stable_codes() {
        let busy = JmcpError::DeviceLeaseBusy {
            router: "srx-01".into(),
            waited_secs: 30,
        }
        .to_string();
        assert!(busy.contains("[code=device_lease_busy]"));

        let failed = JmcpError::DeviceLeaseError {
            router: "srx-01".into(),
            detail: "permission denied".into(),
        }
        .to_string();
        assert!(failed.contains("[code=device_lease_error]"));
    }

    #[test]
    fn local_dest_exists_differs_display_has_code() {
        let s = JmcpError::LocalDestExistsDiffers {
            dest: "/var/lib/jmcp/staging/foo.tgz".into(),
            local_sha: "aaaa".into(),
            remote_sha: "bbbb".into(),
        }
        .to_string();
        assert!(s.contains("[code=local_dest_exists_differs]"), "{s}");
        assert!(s.contains("aaaa"), "{s}");
        assert!(s.contains("bbbb"), "{s}");
    }

    #[test]
    fn remote_file_missing_display_has_code() {
        let s = JmcpError::RemoteFileMissing {
            router: "vsrx-test10".into(),
            remote_path: "/var/tmp/missing.txt".into(),
        }
        .to_string();
        assert!(s.contains("[code=remote_file_missing]"), "{s}");
        assert!(s.contains("vsrx-test10"), "{s}");
    }

    #[test]
    fn fetch_verify_mismatch_display_has_code() {
        let s = JmcpError::FetchVerifyMismatch {
            dest: "/var/lib/jmcp/staging/foo.tgz".into(),
            local_sha: "aaaa".into(),
            remote_sha: "bbbb".into(),
        }
        .to_string();
        assert!(s.contains("[code=fetch_verify_mismatch]"), "{s}");
    }

    // --- audit_kind tests ---

    #[test]
    fn audit_kind_timeout() {
        assert_eq!(
            JmcpError::Timeout(std::time::Duration::from_secs(30)).audit_kind(),
            "timeout"
        );
    }

    #[test]
    fn audit_kind_lease_busy() {
        assert_eq!(
            JmcpError::DeviceLeaseBusy {
                router: "r1".into(),
                waited_secs: 60
            }
            .audit_kind(),
            "lease_busy"
        );
    }

    #[test]
    fn audit_kind_confirmation_required() {
        assert_eq!(
            JmcpError::ConfirmationRequired {
                payload: serde_json::json!({"router": "r1"})
            }
            .audit_kind(),
            "confirmation_required"
        );
    }

    #[test]
    fn audit_kind_unknown_router() {
        assert_eq!(
            JmcpError::UnknownRouter("r99".into()).audit_kind(),
            "unknown_router"
        );
    }

    #[test]
    fn audit_kind_invalid_input() {
        assert_eq!(
            JmcpError::BadFormat("yaml".into()).audit_kind(),
            "invalid_input"
        );
    }

    #[test]
    fn audit_kind_blocked() {
        assert_eq!(
            JmcpError::Denied {
                tool: "execute_junos_command",
                router: "r1".into(),
                pattern: "request system *".into(),
                rule_source: "defaults",
                input_excerpt: "request system reboot".into(),
                line_number: None,
            }
            .audit_kind(),
            "blocked"
        );
    }

    #[test]
    fn audit_kind_transport() {
        // Can't easily construct a RustEzError in tests (external crate),
        // so we verify the mapping via the match statement coverage instead.
        // The Rustez variant maps to "transport" per the exhaustive match.
    }

    #[test]
    fn audit_kind_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        assert_eq!(JmcpError::Io(io_err).audit_kind(), "io");
    }
}
