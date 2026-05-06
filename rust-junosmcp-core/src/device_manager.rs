//! Connection lifecycle management. Open-per-call — every tool invocation
//! opens a fresh `rustez::Device`, runs its operation, and closes it.

use crate::error::JmcpError;
use crate::inventory::{AuthConfig, Inventory};
use arc_swap::ArcSwap;
use rustez::{Device, SshConfigFile};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct DeviceManager {
    inventory: Arc<ArcSwap<Inventory>>,
    inventory_path: Arc<ArcSwap<PathBuf>>,
    inventory_hash: Arc<ArcSwap<[u8; 32]>>,
    inventory_write_lock: Arc<Mutex<()>>,
    inventory_readonly: bool,
    allow_password_auth_add: bool,
}

impl DeviceManager {
    pub fn new(inventory: Arc<Inventory>) -> Self {
        Self::with_path(inventory, PathBuf::new(), [0u8; 32], false, false)
    }

    pub fn with_path(
        inventory: Arc<Inventory>,
        path: PathBuf,
        hash: [u8; 32],
        inventory_readonly: bool,
        allow_password_auth_add: bool,
    ) -> Self {
        Self {
            inventory: Arc::new(ArcSwap::from(inventory)),
            inventory_path: Arc::new(ArcSwap::from_pointee(path)),
            inventory_hash: Arc::new(ArcSwap::from_pointee(hash)),
            inventory_write_lock: Arc::new(Mutex::new(())),
            inventory_readonly,
            allow_password_auth_add,
        }
    }

    /// Returns an owned snapshot of the current inventory. Cheap (Arc clone);
    /// readers never block writers, and the snapshot stays valid even if the
    /// inventory is hot-swapped after this call.
    pub fn inventory(&self) -> Arc<Inventory> {
        self.inventory.load_full()
    }

    pub fn inventory_path(&self) -> PathBuf {
        (**self.inventory_path.load()).clone()
    }

    pub fn inventory_hash(&self) -> [u8; 32] {
        **self.inventory_hash.load()
    }

    pub fn inventory_readonly(&self) -> bool {
        self.inventory_readonly
    }

    pub fn allow_password_auth_add(&self) -> bool {
        self.allow_password_auth_add
    }

    pub fn write_lock(&self) -> Arc<Mutex<()>> {
        self.inventory_write_lock.clone()
    }

    /// Atomically swap inventory + path + hash. Caller must hold `write_lock`.
    ///
    /// Readers that need a coherent `(inventory, path, hash)` triple must also
    /// hold `write_lock`; outside the lock these three swaps are observed in
    /// arbitrary order.
    pub fn store_inventory(&self, inv: Arc<Inventory>, path: PathBuf, hash: [u8; 32]) {
        self.inventory.store(inv);
        self.inventory_path.store(Arc::new(path));
        self.inventory_hash.store(Arc::new(hash));
    }

    /// Open a fresh `rustez::Device` for the named router. Caller is
    /// responsible for `close()`.
    ///
    /// When `ssh_config` is set on the entry, the file is loaded and the
    /// entry's `ip` is used as the alias to obtain `ProxyJump` and
    /// `ProxyCommand` settings (mirroring PyEZ). The entry's explicit
    /// `ip`, `port`, `username`, and `auth` remain authoritative.
    pub async fn open(&self, router_name: &str) -> Result<Device, JmcpError> {
        let inventory = self.inventory.load();
        let entry = inventory.get(router_name)?;

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
