//! MCP tool argument types. Each tool gets a typed input struct that
//! `schemars` derives a JSON schema from for advertisement to the client.

use schemars::JsonSchema;
use serde::Deserialize;

pub mod add_device;
pub mod batch;
pub mod config_diff;
pub mod execute_command;
pub mod facts;
pub mod get_config;
pub mod list_staged_files;
pub mod load_commit;
pub mod pfe;
pub mod reload_devices;
pub mod router_list;
pub mod template;
pub mod transfer_file;
pub mod upgrade_junos;

fn default_timeout() -> u64 {
    360
}
fn default_transfer_timeout() -> u64 {
    600
}
fn default_list_staged_timeout() -> u64 {
    30
}
fn default_upgrade_timeout() -> u64 {
    900
}
fn default_reboot_wait_secs() -> u64 {
    480
}
fn default_verify() -> bool {
    true
}
fn default_version() -> i64 {
    1
}
fn default_set_format() -> String {
    "set".into()
}
fn default_commit_comment() -> String {
    "Configuration loaded via MCP".into()
}
fn default_max_concurrent_routers() -> u32 {
    16
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
pub struct EmptyArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteCommandArgs {
    /// The name of the router.
    pub router_name: String,
    /// The command to execute on the router.
    pub command: String,
    /// Command timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetConfigArgs {
    pub router_name: String,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ConfigDiffArgs {
    pub router_name: String,
    /// Rollback version to compare against (1-49).
    #[serde(default = "default_version")]
    pub version: i64,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GatherFactsArgs {
    pub router_name: String,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LoadCommitArgs {
    pub router_name: String,
    /// The configuration text to load.
    pub config_text: String,
    /// Format: set, text, or xml.
    #[serde(default = "default_set_format")]
    pub config_format: String,
    /// Commit comment recorded in the device commit log.
    #[serde(default = "default_commit_comment")]
    pub commit_comment: String,
    /// If set, uses confirmed commit with auto-rollback after N minutes.
    /// The router will automatically revert if not confirmed within this window.
    #[serde(default)]
    pub confirm_timeout_mins: Option<u32>,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecutePfeArgs {
    /// The name of the router.
    pub router_name: String,
    /// FPC target, e.g. `fpc0`.
    pub fpc_target: String,
    /// PFE command to execute (no surrounding quotes).
    pub pfe_command: String,
    /// Per-command timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteBatchArgs {
    /// Routers to execute against. Must be non-empty.
    pub routers: Vec<String>,
    /// Operational CLI commands to run sequentially per router. Must be non-empty.
    pub commands: Vec<String>,
    /// Per-command timeout in seconds.
    #[serde(default = "default_timeout")]
    pub command_timeout: u64,
    /// Optional whole-batch wall-clock ceiling in seconds.
    #[serde(default)]
    pub batch_timeout: Option<u64>,
    /// Maximum number of routers in flight concurrently.
    #[serde(default = "default_max_concurrent_routers")]
    pub max_concurrent_routers: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TemplateArgs {
    /// Jinja2 template content as a string (inline; no file path).
    pub template_content: String,
    /// Vars as a JSON or YAML string. Sniffed by first non-whitespace char.
    /// Must deserialize to a top-level object/map.
    pub vars_content: String,
    /// Single router to apply to. Mutually exclusive with `router_names`.
    #[serde(default)]
    pub router_name: Option<String>,
    /// Multiple routers to apply to. Mutually exclusive with `router_name`.
    #[serde(default)]
    pub router_names: Option<Vec<String>>,
    /// If false (default), only renders and returns the rendered string.
    #[serde(default)]
    pub apply_config: bool,
    /// Commit comment recorded in the device commit log when applied.
    #[serde(default = "default_commit_comment")]
    pub commit_comment: String,
    /// If true, runs lock + load + diff + rollback (no commit). Implies apply_config=true.
    #[serde(default)]
    pub dry_run: bool,
    /// Override format detection ('set', 'text', 'xml'). Auto-detected if omitted.
    #[serde(default)]
    pub config_format: Option<String>,
    /// Connection timeout in seconds (per-router).
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
pub struct AddDeviceArgs {
    /// Device name/identifier in the inventory map.
    #[serde(default)]
    pub device_name: Option<String>,
    /// Device IP address or hostname.
    #[serde(default)]
    pub device_ip: Option<String>,
    /// SSH port. Default 22.
    #[serde(default)]
    pub device_port: Option<u32>,
    /// Username.
    #[serde(default)]
    pub username: Option<String>,
    /// Auth config (tagged enum: ssh_key | password).
    #[serde(default)]
    pub auth: Option<crate::inventory::AuthConfig>,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
pub struct ReloadDevicesArgs {
    /// Optional path to a different inventory file. If omitted, re-reads
    /// the current --device-mapping.
    #[serde(default)]
    pub file_name: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TransferFileArgs {
    /// Target router name (must exist in inventory and use ssh_key auth).
    pub router_name: String,
    /// Basename of the file under the staging dir. Must not contain '/', '\\', or '..'.
    pub source_path: String,
    /// Overwrite if dest exists with different sha256. Default false.
    #[serde(default)]
    pub force: bool,
    /// Post-transfer sha256 verification. Default true.
    #[serde(default = "default_verify")]
    pub verify: bool,
    /// Per-call timeout in seconds. Default 600.
    #[serde(default = "default_transfer_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListStagedFilesArgs {
    /// Optional router name. If present, also lists the device's /var/tmp/.
    #[serde(default)]
    pub router_name: Option<String>,
    /// Per-call timeout in seconds. Default 30.
    #[serde(default = "default_list_staged_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpgradeJunosArgs {
    /// Target router (must exist in inventory and use ssh_key auth).
    pub router_name: String,
    /// Basename of the staged image under the staging dir. Validated
    /// against the same ASCII allowlist as transfer_file.
    pub source_path: String,
    /// Expected target version string, e.g. "25.4R1.12". Post-install
    /// `show version` must match exactly or the call fails with
    /// UpgradePostVerifyMismatch.
    pub target_version: String,
    /// REQUIRED to perform the destructive upgrade. Defaults to false.
    /// When false the tool runs read-only pre-flight and returns the
    /// upgrade plan as a ConfirmationRequired error.
    #[serde(default)]
    pub confirm: bool,
    /// Per-call outer timeout in seconds. Default 900 (15 min).
    #[serde(default = "default_upgrade_timeout")]
    pub timeout: u64,
    /// Wall-clock budget for NETCONF to reopen after install + reboot.
    /// Default 480 (8 min).
    #[serde(default = "default_reboot_wait_secs")]
    pub reboot_wait_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_command_defaults_timeout() {
        let v = serde_json::json!({"router_name":"r1","command":"show version"});
        let a: ExecuteCommandArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.timeout, 360);
    }

    #[test]
    fn config_diff_defaults_version_to_1() {
        let v = serde_json::json!({"router_name":"r1"});
        let a: ConfigDiffArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.version, 1);
    }

    #[test]
    fn load_commit_defaults_format_and_comment() {
        let v = serde_json::json!({"router_name":"r1","config_text":"set x"});
        let a: LoadCommitArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.config_format, "set");
        assert_eq!(a.commit_comment, "Configuration loaded via MCP");
        assert_eq!(a.timeout, 360);
    }

    #[test]
    fn execute_command_rejects_missing_required() {
        let v = serde_json::json!({"router_name":"r1"});
        let r: Result<ExecuteCommandArgs, _> = serde_json::from_value(v);
        assert!(r.is_err());
    }

    #[test]
    fn execute_pfe_defaults_timeout() {
        let v = serde_json::json!({"router_name":"r1","fpc_target":"fpc0","pfe_command":"show jnh 0 stats"});
        let a: ExecutePfeArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.timeout, 360);
        assert_eq!(a.fpc_target, "fpc0");
    }

    #[test]
    fn execute_pfe_rejects_missing_fpc_target() {
        let v = serde_json::json!({"router_name":"r1","pfe_command":"show jnh 0 stats"});
        let r: Result<ExecutePfeArgs, _> = serde_json::from_value(v);
        assert!(r.is_err());
    }

    #[test]
    fn execute_batch_defaults_concurrency_and_command_timeout() {
        let v = serde_json::json!({"routers":["r1","r2"],"commands":["show version"]});
        let a: ExecuteBatchArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.command_timeout, 360);
        assert_eq!(a.max_concurrent_routers, 16);
        assert!(a.batch_timeout.is_none());
    }

    #[test]
    fn execute_batch_accepts_explicit_batch_timeout() {
        let v = serde_json::json!({
            "routers":["r1"],"commands":["show version"],
            "batch_timeout":600,"max_concurrent_routers":4
        });
        let a: ExecuteBatchArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.batch_timeout, Some(600));
        assert_eq!(a.max_concurrent_routers, 4);
    }

    #[test]
    fn template_args_defaults_apply_and_dry_run_to_false() {
        let v = serde_json::json!({
            "template_content":"set system host-name {{ name }}",
            "vars_content":"{\"name\":\"r1\"}",
            "router_name":"r1"
        });
        let a: TemplateArgs = serde_json::from_value(v).unwrap();
        assert!(!a.apply_config);
        assert!(!a.dry_run);
        assert_eq!(a.commit_comment, "Configuration loaded via MCP");
        assert_eq!(a.router_name.as_deref(), Some("r1"));
        assert!(a.router_names.is_none());
        assert_eq!(a.timeout, 360);
    }

    #[test]
    fn template_args_accepts_router_names_list() {
        let v = serde_json::json!({
            "template_content":"set foo",
            "vars_content":"{}",
            "router_names":["r1","r2"]
        });
        let a: TemplateArgs = serde_json::from_value(v).unwrap();
        assert_eq!(
            a.router_names.as_deref(),
            Some(&["r1".into(), "r2".into()][..])
        );
    }

    #[test]
    fn add_device_args_all_optional() {
        let v = serde_json::json!({});
        let a: AddDeviceArgs = serde_json::from_value(v).unwrap();
        assert!(a.device_name.is_none());
        assert!(a.auth.is_none());
    }

    #[test]
    fn add_device_args_accepts_full_payload() {
        let v = serde_json::json!({
            "device_name": "core-3",
            "device_ip": "10.0.0.3",
            "device_port": 22,
            "username": "automation",
            "auth": {"type":"ssh_key","private_key_path":"/etc/jmcp/keys/id"}
        });
        let a: AddDeviceArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.device_name.as_deref(), Some("core-3"));
        assert_eq!(a.device_port, Some(22));
        assert!(matches!(
            a.auth,
            Some(crate::inventory::AuthConfig::SshKey { .. })
        ));
    }

    #[test]
    fn reload_devices_args_file_name_optional() {
        let v = serde_json::json!({});
        let a: ReloadDevicesArgs = serde_json::from_value(v).unwrap();
        assert!(a.file_name.is_none());
    }

    #[test]
    fn transfer_file_args_defaults() {
        let v = serde_json::json!({"router_name":"r1","source_path":"foo.tgz"});
        let a: TransferFileArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.router_name, "r1");
        assert_eq!(a.source_path, "foo.tgz");
        assert!(!a.force);
        assert!(a.verify);
        assert_eq!(a.timeout, 600);
    }

    #[test]
    fn transfer_file_args_rejects_missing_source() {
        let v = serde_json::json!({"router_name":"r1"});
        let r: Result<TransferFileArgs, _> = serde_json::from_value(v);
        assert!(r.is_err());
    }

    #[test]
    fn list_staged_files_args_router_optional() {
        let v = serde_json::json!({});
        let a: ListStagedFilesArgs = serde_json::from_value(v).unwrap();
        assert!(a.router_name.is_none());
        assert_eq!(a.timeout, 30);
    }

    #[test]
    fn list_staged_files_args_with_router() {
        let v = serde_json::json!({"router_name":"vSRX-test10"});
        let a: ListStagedFilesArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.router_name.as_deref(), Some("vSRX-test10"));
    }

    #[test]
    fn upgrade_junos_args_defaults() {
        let v = serde_json::json!({
            "router_name": "vsrx-test10",
            "source_path": "junos-25.4R1.12.tgz",
            "target_version": "25.4R1.12"
        });
        let a: UpgradeJunosArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.router_name, "vsrx-test10");
        assert_eq!(a.source_path, "junos-25.4R1.12.tgz");
        assert_eq!(a.target_version, "25.4R1.12");
        assert!(!a.confirm);
        assert_eq!(a.timeout, 900);
        assert_eq!(a.reboot_wait_secs, 480);
    }

    #[test]
    fn upgrade_junos_args_rejects_missing_required() {
        for missing in [
            serde_json::json!({"source_path":"x.tgz","target_version":"25.4R1.12"}),
            serde_json::json!({"router_name":"r1","target_version":"25.4R1.12"}),
            serde_json::json!({"router_name":"r1","source_path":"x.tgz"}),
        ] {
            let r: Result<UpgradeJunosArgs, _> = serde_json::from_value(missing);
            assert!(r.is_err(), "should reject missing required");
        }
    }

    #[test]
    fn upgrade_junos_args_accepts_confirm_true() {
        let v = serde_json::json!({
            "router_name": "r1",
            "source_path": "x.tgz",
            "target_version": "25.4R1.12",
            "confirm": true
        });
        let a: UpgradeJunosArgs = serde_json::from_value(v).unwrap();
        assert!(a.confirm);
    }

    #[test]
    fn upgrade_junos_args_accepts_custom_timeouts() {
        let v = serde_json::json!({
            "router_name": "r1",
            "source_path": "x.tgz",
            "target_version": "25.4R1.12",
            "timeout": 1800,
            "reboot_wait_secs": 720
        });
        let a: UpgradeJunosArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.timeout, 1800);
        assert_eq!(a.reboot_wait_secs, 720);
    }
}
