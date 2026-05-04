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
}
