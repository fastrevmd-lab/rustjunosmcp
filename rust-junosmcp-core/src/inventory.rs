//! `devices.json` parsing and validation.
//!
//! Drop-in compatible with Juniper/junos-mcp-server.

use serde::Deserialize;
use std::path::PathBuf;

/// Authentication config for a Junos device. Tagged enum mirrors the Python
/// repo's `auth.type` discriminator.
#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    Password { password: String },
    SshKey { private_key_path: PathBuf },
}

// Hand-written Debug to redact passwords. Never derive Debug on this enum.
impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password { .. } => f.debug_struct("Password")
                .field("password", &"<redacted>")
                .finish(),
            Self::SshKey { private_key_path } => f.debug_struct("SshKey")
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
        let auth = AuthConfig::Password { password: "hunter2".into() };
        let s = format!("{auth:?}");
        assert!(!s.contains("hunter2"), "debug output leaked the password: {s}");
        assert!(s.contains("redacted"));
    }

    #[test]
    fn ssh_key_debug_shows_path() {
        let auth = AuthConfig::SshKey { private_key_path: "/tmp/k.pem".into() };
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
            AuthConfig::SshKey { private_key_path } =>
                assert_eq!(private_key_path, std::path::PathBuf::from("/k.pem")),
            _ => panic!("wrong variant"),
        }
    }
}

fn default_port() -> u16 { 22 }

/// One entry in `devices.json`.
#[derive(Clone, Debug, Deserialize)]
pub struct DeviceEntry {
    pub ip: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: String,
    pub auth: AuthConfig,
    /// Optional path to OpenSSH config file (jumphost). Parsed but not yet
    /// honored — see [`crate::error::JmcpError::SshConfigUnsupported`].
    #[serde(default)]
    pub ssh_config: Option<PathBuf>,
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
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Inventory {
    devices: HashMap<String, DeviceEntry>,
    source_path: PathBuf,
}

impl Inventory {
    /// Load and validate a `devices.json` file.
    pub fn load(path: &Path) -> Result<Self, JmcpError> {
        let bytes = std::fs::read(path)?;
        let devices: HashMap<String, DeviceEntry> = serde_json::from_slice(&bytes)
            .map_err(|e| JmcpError::InventoryInvalid(e.to_string()))?;
        Self::validate(&devices)?;
        Ok(Self {
            devices,
            source_path: path.to_path_buf(),
        })
    }

    fn validate(devices: &HashMap<String, DeviceEntry>) -> Result<(), JmcpError> {
        for (name, entry) in devices {
            if entry.ip.trim().is_empty() {
                return Err(JmcpError::InventoryInvalid(
                    format!("router '{name}': ip is empty"),
                ));
            }
            if entry.port == 0 {
                return Err(JmcpError::InventoryInvalid(
                    format!("router '{name}': port must be non-zero"),
                ));
            }
            if entry.username.trim().is_empty() {
                return Err(JmcpError::InventoryInvalid(
                    format!("router '{name}': username is empty"),
                ));
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
        let f = write("ok", r#"{
            "r1":{"ip":"1.2.3.4","username":"u","auth":{"type":"password","password":"x"}}
        }"#);
        let inv = Inventory::load(f.path()).unwrap();
        assert_eq!(inv.devices.len(), 1);
    }

    #[test]
    fn rejects_zero_port() {
        let f = write("p0", r#"{
            "r1":{"ip":"1.2.3.4","port":0,"username":"u","auth":{"type":"password","password":"x"}}
        }"#);
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn rejects_empty_ip() {
        let f = write("ip", r#"{
            "r1":{"ip":"","username":"u","auth":{"type":"password","password":"x"}}
        }"#);
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn rejects_missing_key_file() {
        let f = write("missing", r#"{
            "r1":{"ip":"1.2.3.4","username":"u",
                  "auth":{"type":"ssh_key","private_key_path":"/nope/missing.pem"}}
        }"#);
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::KeyFileMissing(_))));
    }

    #[test]
    fn accepts_existing_key_file() {
        let key = tempfile::NamedTempFile::new().unwrap();
        let json = format!(r#"{{
            "r1":{{"ip":"1.2.3.4","username":"u",
                   "auth":{{"type":"ssh_key","private_key_path":"{}"}}}}
        }}"#, key.path().display());
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
}
