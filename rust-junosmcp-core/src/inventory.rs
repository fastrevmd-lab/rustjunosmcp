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
