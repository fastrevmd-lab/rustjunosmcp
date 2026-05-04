//! Connection lifecycle management. Open-per-call — every tool invocation
//! opens a fresh `rustez::Device`, runs its operation, and closes it.

use crate::error::JmcpError;
use crate::inventory::{AuthConfig, Inventory};
use rustez::Device;
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
    pub async fn open(&self, router_name: &str) -> Result<Device, JmcpError> {
        let entry = self.inventory.get(router_name)?;

        // ssh_config jumphost is v0.2 work — fail loudly so the LLM
        // doesn't think it silently used the jumphost.
        if entry.ssh_config.is_some() {
            return Err(JmcpError::SshConfigUnsupported(router_name.into()));
        }

        let mut builder = Device::connect(&entry.ip)
            .port(entry.port)
            .username(&entry.username);

        builder = match &entry.auth {
            AuthConfig::Password { password } => builder.password(password),
            AuthConfig::SshKey { private_key_path } => {
                let path_str = private_key_path
                    .to_str()
                    .ok_or_else(|| JmcpError::InventoryInvalid(
                        format!("private_key_path is not valid UTF-8: {}",
                                private_key_path.display())
                    ))?;
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
        let inv = build_inventory(r#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#);
        let dm = DeviceManager::new(inv);
        let r = dm.open("nope").await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(ref s)) if s == "nope"));
    }

    #[tokio::test]
    async fn ssh_config_set_returns_unsupported_error() {
        let inv = build_inventory(r#"{
            "r1":{"ip":"127.0.0.1","username":"u",
                  "ssh_config":"/tmp/never-used",
                  "auth":{"type":"password","password":"x"}}
        }"#);
        let dm = DeviceManager::new(inv);
        let r = dm.open("r1").await;
        assert!(matches!(r, Err(JmcpError::SshConfigUnsupported(ref s)) if s == "r1"));
    }
}
