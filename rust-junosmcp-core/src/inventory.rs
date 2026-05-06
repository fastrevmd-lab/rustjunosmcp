//! `devices.json` parsing and validation.
//!
//! Drop-in compatible with Juniper/junos-mcp-server.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Authentication config for a Junos device. Tagged enum mirrors the Python
/// repo's `auth.type` discriminator.
#[derive(Clone, Deserialize, JsonSchema, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    Password { password: String },
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

/// `deny` blocks the tool call; `allow` overrides a broader deny.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Deny,
    Allow,
}

/// One author-side rule: an action and a glob pattern.
#[derive(Clone, Debug, Deserialize)]
pub struct RuleSpec {
    pub action: Action,
    pub pattern: String,
}

/// Per-domain rule lists (commands → execute_junos_command,
/// config → load_and_commit_config).
#[derive(Clone, Debug, Default, Deserialize)]
pub struct BlocklistRules {
    #[serde(default)]
    pub commands: Vec<RuleSpec>,
    #[serde(default)]
    pub config: Vec<RuleSpec>,
    #[serde(default)]
    pub pfe_commands: Vec<RuleSpec>,
}

fn default_port() -> u16 {
    22
}

/// One entry in `devices.json`.
#[derive(Clone, Debug, Deserialize)]
pub struct DeviceEntry {
    pub ip: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: String,
    pub auth: AuthConfig,
    /// Optional path to an OpenSSH `ssh_config(5)` file. When set, the file
    /// is loaded and `ip` is used as the alias to look up `ProxyJump` /
    /// `ProxyCommand` settings. The entry's explicit `ip`, `port`,
    /// `username`, and `auth` remain authoritative; only proxy settings are
    /// pulled from the config file. Mirrors PyEZ semantics.
    #[serde(default)]
    pub ssh_config: Option<PathBuf>,
    /// Optional per-device blocklist rules. Merged with `_blocklist_defaults`
    /// at policy build time. See [`BlocklistRules`].
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

#[derive(Debug, Clone)]
pub struct Inventory {
    devices: HashMap<String, DeviceEntry>,
    blocklist_defaults: Option<BlocklistRules>,
    source_path: PathBuf,
}

#[derive(Deserialize)]
struct InventoryFile {
    #[serde(default, rename = "_blocklist_defaults")]
    blocklist_defaults: Option<BlocklistRules>,
    #[serde(flatten)]
    devices: HashMap<String, DeviceEntry>,
}

impl Inventory {
    /// Construct an empty inventory. Useful for tests that don't need real devices.
    pub fn empty() -> Self {
        Self {
            devices: Default::default(),
            blocklist_defaults: None,
            source_path: PathBuf::new(),
        }
    }

    /// Load and validate a `devices.json` file.
    pub fn load(path: &Path) -> Result<Self, JmcpError> {
        let bytes = std::fs::read(path)?;
        let file: InventoryFile = serde_json::from_slice(&bytes)
            .map_err(|e| JmcpError::InventoryInvalid(e.to_string()))?;
        Self::validate(&file.devices)?;
        Ok(Self {
            devices: file.devices,
            blocklist_defaults: file.blocklist_defaults,
            source_path: path.to_path_buf(),
        })
    }

    fn validate(devices: &HashMap<String, DeviceEntry>) -> Result<(), JmcpError> {
        for (name, entry) in devices {
            if entry.ip.trim().is_empty() {
                return Err(JmcpError::InventoryInvalid(format!(
                    "router '{name}': ip is empty"
                )));
            }
            if entry.port == 0 {
                return Err(JmcpError::InventoryInvalid(format!(
                    "router '{name}': port must be non-zero"
                )));
            }
            if entry.username.trim().is_empty() {
                return Err(JmcpError::InventoryInvalid(format!(
                    "router '{name}': username is empty"
                )));
            }
            if let AuthConfig::SshKey { private_key_path } = &entry.auth {
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
    /// Look up a device by name.
    pub fn get(&self, name: &str) -> Result<&DeviceEntry, JmcpError> {
        self.devices
            .get(name)
            .ok_or_else(|| JmcpError::UnknownRouter(name.to_string()))
    }

    /// Sorted list of router names. Used by `get_router_list`.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.devices.keys().cloned().collect();
        names.sort();
        names
    }

    /// Source path the inventory was loaded from. Used by v0.2 `reload_devices`.
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    /// Top-level blocklist defaults merged into every device's effective rule
    /// set. `None` if the file has no `_blocklist_defaults` key.
    pub fn blocklist_defaults(&self) -> Option<&BlocklistRules> {
        self.blocklist_defaults.as_ref()
    }

    /// Number of devices currently in this inventory.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// True if the inventory has no devices.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
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

/// Insert a new device into a `serde_json::Value`-shaped inventory.
/// Preserves all existing top-level keys and key order. Returns the updated
/// value. Errors if `name` already exists at top-level.
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

/// SHA-256 of the file at `path`. Returns zeros if the file doesn't exist
/// (callers treat zeros as "no last-known content"). The all-zero output
/// cannot collide with a real SHA-256 digest, so callers can rely on this
/// sentinel for TOCTOU CAS checks.
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

/// Atomically replace `path` with the JSON serialization of `value`.
/// Same-filesystem rename via tempfile. Preserves existing file mode bits
/// (Unix only). Round-trips an arbitrary `serde_json::Value` rather than the
/// typed `InventoryFile` so callers can preserve unknown top-level keys
/// (e.g. `_blocklist_defaults`, future extensions).
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
