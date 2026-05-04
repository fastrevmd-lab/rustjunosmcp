//! Connection lifecycle management. Open-per-call — every tool invocation
//! opens a fresh `rustez::Device`, runs its operation, and closes it.

use crate::error::JmcpError;
use crate::inventory::{AuthConfig, Inventory};
use rustez::{Device, SshConfigFile};
use std::sync::Arc;

#[derive(Clone)]
pub struct DeviceManager {
    inventory: Arc<Inventory>,
}

impl DeviceManager {
    pub fn new(inventory: Arc<Inventory>) -> Self {
        Self { inventory }
    }

    /// Open a fresh `rustez::Device` for the named router. Caller is
    /// responsible for `close()`.
    ///
    /// When `ssh_config` is set on the entry, the file is loaded and the
    /// entry's `ip` is used as the alias to obtain `ProxyJump` and
    /// `ProxyCommand` settings (mirroring PyEZ). The entry's explicit
    /// `ip`, `port`, `username`, and `auth` remain authoritative.
    pub async fn open(&self, router_name: &str) -> Result<Device, JmcpError> {
        let entry = self.inventory.get(router_name)?;

        let mut builder = Device::connect(&entry.ip)
            .port(entry.port)
            .username(&entry.username);

        if let Some(ssh_config_path) = &entry.ssh_config {
            let cfg = SshConfigFile::load(ssh_config_path).map_err(|source| {
                JmcpError::SshConfigInvalid {
                    router: router_name.to_string(),
                    source,
                }
            })?;
            let resolved = cfg.resolve(&entry.ip);
            if !resolved.jump_hosts.is_empty() {
                builder = builder.jump_hosts(resolved.jump_hosts);
            }
            if let Some(command) = resolved.proxy_command {
                builder = builder.proxy_command(&command);
            }
        }

        builder = match &entry.auth {
            AuthConfig::Password { password } => builder.password(password),
            AuthConfig::SshKey { private_key_path } => {
                let path_str = private_key_path.to_str().ok_or_else(|| {
                    JmcpError::InventoryInvalid(format!(
                        "private_key_path is not valid UTF-8: {}",
                        private_key_path.display()
                    ))
                })?;
                builder.key_file(path_str)
            }
        };

        Ok(builder.open().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn build_inventory(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    #[tokio::test]
    async fn unknown_router_returns_unknown_router_error() {
        let inv = build_inventory(
            r#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let dm = DeviceManager::new(inv);
        let r = dm.open("nope").await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(ref s)) if s == "nope"));
    }

    #[tokio::test]
    async fn ssh_config_missing_file_returns_invalid_error() {
        let inv = build_inventory(
            r#"{
            "r1":{"ip":"127.0.0.1","username":"u",
                  "ssh_config":"/nonexistent/ssh/config",
                  "auth":{"type":"password","password":"x"}}
        }"#,
        );
        let dm = DeviceManager::new(inv);
        let r = dm.open("r1").await;
        assert!(matches!(
            r,
            Err(JmcpError::SshConfigInvalid { ref router, .. }) if router == "r1"
        ));
    }
}
