//! `devices.json` parsing and validation.
//!
//! Drop-in compatible with Juniper/junos-mcp-server.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Shared input-validation helpers used by both `Inventory::validate`
/// (load-time) and `add_device::validate` (runtime). Keeping these in one
/// module guarantees the on-disk parser and the live-add API enforce the
/// same character classes (RJMCP-SEC-003).
pub(crate) mod validation {
    use std::path::Path;

    /// Device name: 1..=64 ASCII alnum + `_ . -`, never starting with `-`.
    pub fn is_valid_device_name(s: &str) -> bool {
        if s.is_empty() || s.len() > 64 || s.starts_with('-') {
            return false;
        }
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    }

    /// IPv4/IPv6 literal or RFC 1123 hostname (1..=253 chars; labels 1..=63
    /// of `[A-Za-z0-9-]`, no leading/trailing hyphen).
    pub fn is_valid_ip_or_hostname(s: &str) -> bool {
        if s.parse::<std::net::IpAddr>().is_ok() {
            return true;
        }
        if s.is_empty() || s.len() > 253 {
            return false;
        }
        s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
    }

    /// SSH username: 1..=64 ASCII alnum + `_ . -`, must not start with `-`.
    /// The leading-dash rejection prevents the value from being interpreted
    /// as an SSH option flag (e.g. `-oProxyCommand=...`).
    pub fn is_valid_ssh_username(s: &str) -> bool {
        if s.is_empty() || s.len() > 64 || s.starts_with('-') {
            return false;
        }
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    }

    /// SSH private-key path: non-empty, contains no NUL byte, and the
    /// rendered string form must not begin with `-` (same SSH-flag concern
    /// as usernames). Existence is checked separately by `Inventory::validate`.
    pub fn is_valid_auth_path(p: &Path) -> bool {
        let os = p.as_os_str();
        if os.is_empty() {
            return false;
        }
        // Reject embedded NUL — defends against unusual byte sequences in
        // path-like inputs.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            if os.as_bytes().contains(&0) {
                return false;
            }
        }
        if let Some(s) = p.to_str()
            && s.starts_with('-')
        {
            return false;
        }
        true
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::PathBuf;

        #[test]
        fn device_name_accepts_canonical_forms() {
            for ok in ["r1", "core-3", "user.name", "user_name", "vsrx-test10"] {
                assert!(is_valid_device_name(ok), "should accept: {ok}");
            }
        }

        #[test]
        fn device_name_rejects_bad_forms() {
            for bad in [
                "",
                " ",
                "bad name",
                "evil; rm -rf /",
                "-leading-dash",
                "a/b",
                &"x".repeat(65),
            ] {
                assert!(!is_valid_device_name(bad), "should reject: {bad:?}");
            }
        }

        #[test]
        fn ip_or_hostname_accepts_addr_and_hostname() {
            for ok in [
                "10.0.0.1",
                "127.0.0.1",
                "::1",
                "fe80::1",
                "router-3.example.net",
                "h",
            ] {
                assert!(is_valid_ip_or_hostname(ok), "should accept: {ok}");
            }
        }

        #[test]
        fn ip_or_hostname_rejects_junk() {
            for bad in [
                "",
                "not an ip or host",
                "10.0.0.1; rm -rf /",
                "-bad.example",
                "bad-.example",
                ".",
                "a..b",
            ] {
                assert!(!is_valid_ip_or_hostname(bad), "should reject: {bad:?}");
            }
        }

        #[test]
        fn ssh_username_accepts_typical_names() {
            for ok in ["admin", "netconf", "user.name", "user-name", "user_name"] {
                assert!(is_valid_ssh_username(ok), "should accept: {ok}");
            }
        }

        #[test]
        fn ssh_username_rejects_leading_dash_and_spaces() {
            for bad in [
                "",
                " ",
                "-oProxyCommand=foo",
                "user with space",
                "user/name",
                &"x".repeat(65),
            ] {
                assert!(!is_valid_ssh_username(bad), "should reject: {bad:?}");
            }
        }

        #[test]
        fn auth_path_accepts_typical_paths() {
            assert!(is_valid_auth_path(&PathBuf::from("/etc/jmcp/keys/id")));
            assert!(is_valid_auth_path(&PathBuf::from("./key.pem")));
            assert!(is_valid_auth_path(&PathBuf::from("relative/path")));
        }

        #[test]
        fn auth_path_rejects_empty_or_leading_dash() {
            assert!(!is_valid_auth_path(&PathBuf::from("")));
            assert!(!is_valid_auth_path(&PathBuf::from("-evil")));
            assert!(!is_valid_auth_path(&PathBuf::from("-oProxyCommand=foo")));
        }
    }
}

/// Device authentication method for NETCONF.
// Tagged enum mirroring the Python repo's `auth.type` discriminator for
// drop-in compatibility with Juniper/junos-mcp-server inventories.
// The `Debug` impl is hand-written to redact passwords.
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    /// Authenticate with a plaintext password. Supported for NETCONF; not
    /// supported for SCP-based file transfers.
    Password { password: String },
    /// Authenticate with an SSH private key. Path is validated at inventory
    /// load time; the file must exist.
    SshKey { private_key_path: PathBuf },
}

// Hand-written Debug to redact passwords. Never derive Debug on this enum.
impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password { .. } => f
                .debug_struct("Password")
                .field("password", &"<redacted>")
                .finish(),
            Self::SshKey { private_key_path } => f
                .debug_struct("SshKey")
                .field("private_key_path", private_key_path)
                .finish(),
        }
    }
}

#[cfg(test)]
mod auth_tests {
    use super::*;

    #[test]
    fn password_debug_does_not_leak_secret() {
        let auth = AuthConfig::Password {
            password: "hunter2".into(),
        };
        let s = format!("{auth:?}");
        assert!(
            !s.contains("hunter2"),
            "debug output leaked the password: {s}"
        );
        assert!(s.contains("redacted"));
    }

    #[test]
    fn ssh_key_debug_shows_path() {
        let auth = AuthConfig::SshKey {
            private_key_path: "/tmp/k.pem".into(),
        };
        let s = format!("{auth:?}");
        assert!(s.contains("/tmp/k.pem"));
    }

    #[test]
    fn deserialize_password() {
        let json = r#"{"type":"password","password":"x"}"#;
        let parsed: AuthConfig = serde_json::from_str(json).unwrap();
        match parsed {
            AuthConfig::Password { password } => assert_eq!(password, "x"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn deserialize_ssh_key() {
        let json = r#"{"type":"ssh_key","private_key_path":"/k.pem"}"#;
        let parsed: AuthConfig = serde_json::from_str(json).unwrap();
        match parsed {
            AuthConfig::SshKey { private_key_path } => {
                assert_eq!(private_key_path, std::path::PathBuf::from("/k.pem"))
            }
            _ => panic!("wrong variant"),
        }
    }
}

/// Blocklist rule action.
// Rules are evaluated most-specific-first (literal count tiebreak), then
// device rules win over defaults.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Block the input. Logged as a denied operation.
    Deny,
    /// Permit the input. Overrides a broader `Deny` rule.
    Allow,
}

/// Single blocklist rule as authored in `devices.json`.
// Compiled into a `CompiledRule<Action>` by `policy::build()`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuleSpec {
    /// `deny` or `allow`.
    pub action: Action,
    /// Glob pattern (e.g., `request system *`, `delete interfaces *`).
    pub pattern: String,
}

/// Per-domain blocklist rules for a device or the global defaults.
// `commands` gates `execute_junos_command`, `config` gates
// `load_and_commit_config` (set-format only), and `pfe_commands` gates
// `execute_junos_pfe_command`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlocklistRules {
    /// Rules for operational CLI commands. Defaults to empty.
    #[serde(default)]
    pub commands: Vec<RuleSpec>,
    /// Rules for configuration loads (set-format only). Defaults to empty.
    #[serde(default)]
    pub config: Vec<RuleSpec>,
    /// Rules for PFE commands. Defaults to empty.
    #[serde(default)]
    pub pfe_commands: Vec<RuleSpec>,
}

fn default_port() -> u16 {
    22
}

/// Single device entry from `devices.json`.
///
/// Validated at load time: `ip` must be an IPv4/IPv6 address or RFC 1123
/// hostname; `port` in 1..=65535; `username` is 1-64 ASCII alphanumeric +
/// `_.-`, no leading hyphen; `private_key_path` (if SSH key auth) must exist
/// on disk. Optional `ssh_config` is loaded for ProxyJump/ProxyCommand; all
/// other connection parameters come from this entry.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceEntry {
    /// IPv4/IPv6 address or RFC 1123 hostname.
    pub ip: String,
    /// SSH port. Defaults to 22.
    #[serde(default = "default_port")]
    pub port: u16,
    /// SSH username. 1-64 ASCII alphanumeric + `_.-`, no leading hyphen.
    pub username: String,
    /// Authentication method (password or SSH key).
    pub auth: AuthConfig,
    /// Optional SSH config file for ProxyJump/ProxyCommand. When set, `ip` is
    /// used as the alias to look up proxy settings. Connection parameters
    /// (`ip`, `port`, `username`, `auth`) from this entry override the file.
    #[serde(default)]
    pub ssh_config: Option<PathBuf>,
    /// Per-device blocklist rules. Merged with `_blocklist_defaults` at
    /// policy build time.
    #[serde(default)]
    pub blocklist: Option<BlocklistRules>,
}

#[cfg(test)]
mod entry_tests {
    use super::*;

    #[test]
    fn parses_password_entry_with_default_port() {
        let json = r#"{
            "ip":"10.0.0.1",
            "username":"admin",
            "auth":{"type":"password","password":"x"}
        }"#;
        let e: DeviceEntry = serde_json::from_str(json).unwrap();
        assert_eq!(e.ip, "10.0.0.1");
        assert_eq!(e.port, 22);
        assert_eq!(e.username, "admin");
        assert!(e.ssh_config.is_none());
    }

    #[test]
    fn parses_ssh_key_entry_with_explicit_port_and_ssh_config() {
        let json = r#"{
            "ip":"10.0.0.2",
            "port":830,
            "username":"netconf",
            "ssh_config":"/home/u/.ssh/config_jh",
            "auth":{"type":"ssh_key","private_key_path":"/k.pem"}
        }"#;
        let e: DeviceEntry = serde_json::from_str(json).unwrap();
        assert_eq!(e.port, 830);
        assert_eq!(e.ssh_config, Some(PathBuf::from("/home/u/.ssh/config_jh")));
    }

    #[test]
    fn rejects_missing_required_fields() {
        let json = r#"{"username":"admin","auth":{"type":"password","password":"x"}}"#;
        let r: Result<DeviceEntry, _> = serde_json::from_str(json);
        assert!(r.is_err(), "expected error for missing 'ip'");
    }
}

use crate::error::JmcpError;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

/// Parsed and validated Junos device inventory.
///
/// Wraps `mecmcp-inventory::FileInventory<DeviceEntry, BlocklistRules>` and
/// adds Junos-specific validation (SSH username/key-path character classes,
/// port range, key-file existence). The flat-map schema with
/// `_blocklist_defaults` is parsed by the shared crate; the validators here
/// encode SSH and Junos rules the shared crate does not know.
#[derive(Debug, Clone)]
pub struct Inventory {
    devices: HashMap<String, DeviceEntry>,
    blocklist_defaults: Option<BlocklistRules>,
    source_path: PathBuf,
}

impl Inventory {
    /// Empty inventory with no devices. For tests that do not need real devices.
    pub fn empty() -> Self {
        Self {
            devices: Default::default(),
            blocklist_defaults: None,
            source_path: PathBuf::new(),
        }
    }

    /// Load and validate `devices.json` from disk.
    ///
    /// Parsing is delegated to `mecmcp-inventory::FileInventory`, which handles
    /// the flat-map schema (top-level keys are device names, plus the special
    /// `_blocklist_defaults` policy key). Junos-specific validators then check
    /// SSH username/key-path character classes, port ranges, and key-file
    /// existence. Returns `InventoryInvalid` if parsing fails or any device
    /// entry is malformed.
    pub fn load(path: &Path) -> Result<Self, JmcpError> {
        use mecmcp_inventory::Inventory as _;

        let shared = mecmcp_inventory::FileInventory::<DeviceEntry, BlocklistRules>::load(path)
            .map_err(|error| JmcpError::InventoryInvalid(error.to_string()))?;

        let devices: HashMap<String, DeviceEntry> = shared
            .names()
            .into_iter()
            .map(|name| {
                let entry = shared
                    .get(&name)
                    .map_err(|error| JmcpError::InventoryInvalid(error.to_string()))?;
                Ok((name, entry))
            })
            .collect::<Result<_, JmcpError>>()?;

        Self::validate(&devices)?;

        Ok(Self {
            devices,
            blocklist_defaults: shared.policy(),
            source_path: path.to_path_buf(),
        })
    }

    fn validate(devices: &HashMap<String, DeviceEntry>) -> Result<(), JmcpError> {
        use validation::*;
        for (name, entry) in devices {
            if !is_valid_device_name(name) {
                return Err(JmcpError::InventoryInvalid(format!(
                    "router '{name}': name is invalid (must match ^[A-Za-z0-9_.-]{{1,64}}$, no leading '-')"
                )));
            }
            if !is_valid_ip_or_hostname(&entry.ip) {
                return Err(JmcpError::InventoryInvalid(format!(
                    "router '{name}': ip/hostname is invalid"
                )));
            }
            if entry.port == 0 {
                return Err(JmcpError::InventoryInvalid(format!(
                    "router '{name}': port must be non-zero"
                )));
            }
            if !is_valid_ssh_username(&entry.username) {
                return Err(JmcpError::InventoryInvalid(format!(
                    "router '{name}': username is invalid (must match ^[A-Za-z0-9_.-]{{1,64}}$, no leading '-')"
                )));
            }
            if let AuthConfig::SshKey { private_key_path } = &entry.auth {
                if !is_valid_auth_path(private_key_path) {
                    return Err(JmcpError::InventoryInvalid(format!(
                        "router '{name}': private_key_path is invalid (empty, contains NUL, or starts with '-')"
                    )));
                }
                if !private_key_path.exists() {
                    return Err(JmcpError::KeyFileMissing(private_key_path.clone()));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod load_tests {
    use super::*;
    use std::io::Write;

    fn write(name: &str, json: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new()
            .prefix(name)
            .suffix(".json")
            .tempfile()
            .unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f
    }

    #[test]
    fn loads_valid_password_only_inventory() {
        let f = write(
            "ok",
            r#"{
            "r1":{"ip":"1.2.3.4","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let inv = Inventory::load(f.path()).unwrap();
        assert_eq!(inv.devices.len(), 1);
    }

    #[test]
    fn rejects_zero_port() {
        let f = write(
            "p0",
            r#"{
            "r1":{"ip":"1.2.3.4","port":0,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn rejects_empty_ip() {
        let f = write(
            "ip",
            r#"{
            "r1":{"ip":"","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn rejects_device_name_with_space() {
        let f = write(
            "badname",
            r#"{
            "bad name":{"ip":"1.2.3.4","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn rejects_ip_with_shell_metacharacters() {
        let f = write(
            "shellip",
            r#"{
            "r1":{"ip":"10.0.0.1; rm -rf /","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn rejects_username_starting_with_dash() {
        let f = write(
            "badusr",
            r#"{
            "r1":{"ip":"1.2.3.4","username":"-oProxyCommand=foo","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn rejects_username_with_space() {
        let f = write(
            "spcusr",
            r#"{
            "r1":{"ip":"1.2.3.4","username":"user with space","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn rejects_private_key_path_starting_with_dash() {
        // A `private_key_path` whose rendered string starts with `-` could be
        // mis-parsed by ssh/scp as a CLI flag (e.g. `-oProxyCommand=...`).
        // Validation must reject before any existence check.
        let json = r#"{
            "r1":{"ip":"1.2.3.4","username":"u",
                   "auth":{"type":"ssh_key","private_key_path":"-oProxyCommand=foo"}}
        }"#;
        let f = write("dashkey", json);
        let r = Inventory::load(f.path());
        assert!(
            matches!(r, Err(JmcpError::InventoryInvalid(ref s)) if s.contains("private_key_path")),
            "expected InventoryInvalid for leading-dash path, got {r:?}"
        );
    }

    #[test]
    fn accepts_typical_usernames() {
        for name in ["admin", "netconf", "user.name", "user-name", "user_name"] {
            let json = format!(
                r#"{{"r1":{{"ip":"1.2.3.4","username":"{name}","auth":{{"type":"password","password":"x"}}}}}}"#,
            );
            let f = write("u", &json);
            let inv = Inventory::load(f.path());
            assert!(inv.is_ok(), "expected '{name}' accepted, got {inv:?}");
        }
    }

    #[test]
    fn rejects_missing_key_file() {
        let f = write(
            "missing",
            r#"{
            "r1":{"ip":"1.2.3.4","username":"u",
                  "auth":{"type":"ssh_key","private_key_path":"/nope/missing.pem"}}
        }"#,
        );
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::KeyFileMissing(_))));
    }

    #[test]
    fn accepts_existing_key_file() {
        let key = tempfile::NamedTempFile::new().unwrap();
        let json = format!(
            r#"{{
            "r1":{{"ip":"1.2.3.4","username":"u",
                   "auth":{{"type":"ssh_key","private_key_path":"{}"}}}}
        }}"#,
            key.path().display()
        );
        let f = write("withkey", &json);
        let inv = Inventory::load(f.path()).unwrap();
        assert_eq!(inv.devices.len(), 1);
    }

    #[test]
    fn rejects_invalid_json() {
        let f = write("bad", "{not json");
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn loads_inventory_with_blocklist_defaults_and_per_device_blocklist() {
        let f = write(
            "bl",
            r#"{
                "_blocklist_defaults": {
                    "commands": [
                        {"action":"deny","pattern":"request system *"}
                    ],
                    "config": [
                        {"action":"deny","pattern":"delete *"}
                    ]
                },
                "r1": {
                    "ip":"1.2.3.4","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {
                        "commands": [
                            {"action":"allow","pattern":"request system reboot"}
                        ]
                    }
                }
            }"#,
        );
        let inv = Inventory::load(f.path()).unwrap();
        let defaults = inv.blocklist_defaults().expect("defaults present");
        assert_eq!(defaults.commands.len(), 1);
        assert_eq!(defaults.config.len(), 1);
        let r1 = inv.get("r1").unwrap();
        let r1_bl = r1.blocklist.as_ref().expect("r1 has blocklist");
        assert_eq!(r1_bl.commands.len(), 1);
        assert!(r1_bl.config.is_empty());
    }

    #[test]
    fn v0_1_inventory_without_blocklist_loads_unchanged() {
        let f = write(
            "v01",
            r#"{
                "r1":{"ip":"1.2.3.4","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let inv = Inventory::load(f.path()).unwrap();
        assert!(inv.blocklist_defaults().is_none());
        assert!(inv.get("r1").unwrap().blocklist.is_none());
    }

    #[test]
    fn missing_blocklist_subkeys_default_to_empty() {
        let f = write(
            "empty",
            r#"{
                "_blocklist_defaults": {},
                "r1":{
                    "ip":"1.2.3.4","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {}
                }
            }"#,
        );
        let inv = Inventory::load(f.path()).unwrap();
        let d = inv.blocklist_defaults().unwrap();
        assert!(d.commands.is_empty() && d.config.is_empty());
        let r1bl = inv.get("r1").unwrap().blocklist.as_ref().unwrap();
        assert!(r1bl.commands.is_empty() && r1bl.config.is_empty());
    }

    #[test]
    fn loads_inventory_with_pfe_commands() {
        let f = write(
            "pfe",
            r#"{
                "_blocklist_defaults": {
                    "pfe_commands": [{"action":"deny","pattern":"set *"}]
                },
                "r1": {
                    "ip":"1.2.3.4","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {
                        "pfe_commands": [{"action":"allow","pattern":"set debug *"}]
                    }
                }
            }"#,
        );
        let inv = Inventory::load(f.path()).unwrap();
        let d = inv.blocklist_defaults().expect("defaults present");
        assert_eq!(d.pfe_commands.len(), 1);
        assert_eq!(d.pfe_commands[0].pattern, "set *");
        let r1bl = inv.get("r1").unwrap().blocklist.as_ref().unwrap();
        assert_eq!(r1bl.pfe_commands.len(), 1);
        assert_eq!(r1bl.pfe_commands[0].pattern, "set debug *");
    }

    #[test]
    fn missing_pfe_commands_defaults_to_empty() {
        let f = write(
            "no_pfe",
            r#"{
                "_blocklist_defaults": {"commands":[{"action":"deny","pattern":"x"}]},
                "r1":{"ip":"1.2.3.4","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let inv = Inventory::load(f.path()).unwrap();
        assert!(inv.blocklist_defaults().unwrap().pfe_commands.is_empty());
    }
}

impl Inventory {
    /// Look up a device by name. Returns `UnknownRouter` if not found.
    pub fn get(&self, name: &str) -> Result<&DeviceEntry, JmcpError> {
        self.devices
            .get(name)
            .ok_or_else(|| JmcpError::UnknownRouter(name.to_string()))
    }

    /// Alphabetically sorted list of device names. Used by `get_router_list`.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.devices.keys().cloned().collect();
        names.sort();
        names
    }

    /// Path from which this inventory was loaded. Used by `reload_devices` and
    /// `add_device` for CAS checks.
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    /// Global blocklist rules from `_blocklist_defaults`, if present. Merged
    /// with each device's per-device rules at policy build time.
    pub fn blocklist_defaults(&self) -> Option<&BlocklistRules> {
        self.blocklist_defaults.as_ref()
    }

    /// Number of devices in this inventory.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// True if this inventory contains no devices.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// True if the named device exists in this inventory. Used server-side to
    /// classify tool errors (unknown device vs. out-of-scope) for observability
    /// logging without leaking inventory to the caller.
    pub fn contains_router(&self, name: &str) -> bool {
        self.devices.contains_key(name)
    }
}

#[cfg(test)]
mod accessor_tests {
    use super::*;
    use std::io::Write;

    fn build(json: &str) -> Inventory {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Inventory::load(f.path()).unwrap()
    }

    #[test]
    fn get_returns_known_router() {
        let inv = build(
            r#"{
            "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        assert_eq!(inv.get("r1").unwrap().ip, "1.1.1.1");
    }

    #[test]
    fn get_returns_unknown_router_error() {
        let inv = build(
            r#"{
            "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let r = inv.get("nope");
        assert!(matches!(r, Err(JmcpError::UnknownRouter(ref s)) if s == "nope"));
    }

    #[test]
    fn names_returns_sorted() {
        let inv = build(
            r#"{
            "z":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}},
            "a":{"ip":"1.1.1.2","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        assert_eq!(inv.names(), vec!["a".to_string(), "z".to_string()]);
    }

    #[test]
    fn contains_router_returns_true_for_present() {
        let inv = build(
            r#"{
            "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        assert!(inv.contains_router("r1"));
    }

    #[test]
    fn contains_router_returns_false_for_absent() {
        let inv = build(
            r#"{
            "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        assert!(!inv.contains_router("nope"));
    }
}

#[cfg(test)]
mod rule_type_tests {
    use super::*;

    #[test]
    fn rule_spec_parses_deny() {
        let json = r#"{"action":"deny","pattern":"request system *"}"#;
        let r: RuleSpec = serde_json::from_str(json).unwrap();
        assert_eq!(r.pattern, "request system *");
        assert!(matches!(r.action, Action::Deny));
    }

    #[test]
    fn rule_spec_parses_allow() {
        let json = r#"{"action":"allow","pattern":"show *"}"#;
        let r: RuleSpec = serde_json::from_str(json).unwrap();
        assert!(matches!(r.action, Action::Allow));
    }

    #[test]
    fn rule_spec_rejects_unknown_action() {
        let json = r#"{"action":"audit","pattern":"x"}"#;
        let r: Result<RuleSpec, _> = serde_json::from_str(json);
        assert!(r.is_err());
    }

    #[test]
    fn blocklist_rules_default_to_empty_lists() {
        let json = r#"{}"#;
        let b: BlocklistRules = serde_json::from_str(json).unwrap();
        assert!(b.commands.is_empty());
        assert!(b.config.is_empty());
        assert!(b.pfe_commands.is_empty());
    }
}

/// Insert a device into a JSON-shaped inventory, preserving key order.
///
/// Used by `add_device` to build the updated inventory before writing it back
/// to disk. Returns the modified `Value`. Fails with `DeviceExists` if `name`
/// is already a top-level key.
pub fn insert_device(
    inv: &serde_json::Value,
    name: &str,
    ip: &str,
    port: u32,
    username: &str,
    auth: &AuthConfig,
) -> Result<serde_json::Value, JmcpError> {
    let mut out = inv.clone();
    let entry = serde_json::json!({
        "ip": ip,
        "port": port,
        "username": username,
        "auth": auth,
    });

    let inserted = if let Some(obj) = out.as_object_mut() {
        if obj.contains_key(name) {
            return Err(JmcpError::DeviceExists(name.to_string()));
        }
        obj.insert(name.to_string(), entry);
        true
    } else {
        false
    };

    if !inserted {
        return Err(JmcpError::InventoryParse(
            "top-level inventory is not a JSON object".into(),
        ));
    }
    Ok(out)
}

/// SHA-256 digest of the file at `path`, or all-zeros if it does not exist.
///
/// Used by `add_device` and `reload_devices` for CAS checks. The all-zero
/// sentinel cannot collide with a real SHA-256 digest (statistically
/// infeasible), so callers can treat it as "no last-known content" and detect
/// TOCTOU races.
pub fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let digest = Sha256::digest(&bytes);
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            Ok(out)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok([0u8; 32]),
        Err(e) => Err(e),
    }
}

/// Atomically write JSON to disk via same-filesystem rename.
///
/// Writes `value` (pretty-printed + trailing newline) to a temp file in the
/// same directory as `path`, syncs it, then renames over `path`. Preserves
/// existing file mode bits on Unix. Accepts an arbitrary `serde_json::Value`
/// rather than a typed struct so callers can preserve unknown top-level keys
/// (`_blocklist_defaults`, future extensions). Used by `add_device`.
pub fn write_atomic(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "inventory path has no parent directory",
        )
    })?;
    if !parent.as_os_str().is_empty() && !parent.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("parent directory does not exist: {}", parent.display()),
        ));
    }
    let resolved_parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };

    let mut tmp = tempfile::NamedTempFile::new_in(resolved_parent)?;
    let pretty = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    tmp.write_all(pretty.as_bytes())?;
    tmp.write_all(b"\n")?;
    tmp.as_file().sync_all()?;

    // Preserve mode bits if the target already exists.
    #[cfg(unix)]
    if let Ok(meta) = std::fs::metadata(path) {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode))?;
    }

    // Surface the underlying io::Error from rename(2) (EXDEV, EACCES, ENOSPC,
    // …) untouched rather than stringifying through PersistError.
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod write_tests {
    use super::*;

    fn fixture(json: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn atomic_write_replaces_file_in_place() {
        let f = fixture(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let new_content = serde_json::json!({
            "r2": {"ip":"10.0.0.2","username":"u","auth":{"type":"password","password":"x"}}
        });
        write_atomic(f.path(), &new_content).unwrap();
        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(f.path()).unwrap()).unwrap();
        assert!(on_disk.get("r2").is_some());
        assert!(on_disk.get("r1").is_none());
    }

    #[test]
    fn atomic_write_preserves_blocklist_defaults() {
        let original = serde_json::json!({
            "_blocklist_defaults": {"commands":[{"action":"deny","pattern":"request system reboot"}]},
            "r1": {"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        });
        let f = fixture(&serde_json::to_string(&original).unwrap());

        let mut updated = original.clone();
        updated["r2"] = serde_json::json!({
            "ip":"10.0.0.2","username":"u","auth":{"type":"password","password":"x"}
        });

        write_atomic(f.path(), &updated).unwrap();

        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(f.path()).unwrap()).unwrap();
        assert!(on_disk.get("_blocklist_defaults").is_some());
        assert!(on_disk.get("r1").is_some());
        assert!(on_disk.get("r2").is_some());
    }

    #[test]
    fn atomic_write_preserves_key_order() {
        // Requires serde_json's `preserve_order` feature; verify by building
        // the input map in insertion order and checking on-disk byte order.
        let mut map = serde_json::Map::new();
        map.insert("first".into(), serde_json::json!({"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}));
        map.insert("second".into(), serde_json::json!({"ip":"127.0.0.2","username":"u","auth":{"type":"password","password":"x"}}));
        let val = serde_json::Value::Object(map);
        let f = tempfile::NamedTempFile::new().unwrap();
        write_atomic(f.path(), &val).unwrap();
        let bytes = std::fs::read(f.path()).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.find("\"first\"").unwrap() < s.find("\"second\"").unwrap());
    }
}
