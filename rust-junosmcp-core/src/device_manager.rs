//! Connection lifecycle management with per-router session pooling.
//!
//! `DeviceManager::open()` returns a `PooledDevice` RAII guard. When the guard
//! is dropped, the underlying `rustez::Device` is returned to a single-slot
//! pool (keyed by router name) for reuse by the next caller — unless the
//! config-db was left open, in which case the session is closed instead.

use crate::error::JmcpError;
use crate::inventory::{AuthConfig, Inventory};
use arc_swap::ArcSwap;
use rustez::{Device, SshConfigFile};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// ── Pool constants ──────────────────────────────────────────────────────

const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const POOL_REAPER_INTERVAL: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// Per-RPC timeout pushed into `rustez::Device` at connect time. Set high so
/// the MCP per-call `tokio::time::timeout(args.timeout, ...)` is the
/// user-visible bound. Without this, `rustez` defaults to 30 s and silently
/// truncates any long-running operational command (e.g. `request system
/// software add ...`) regardless of the MCP-side timeout.
const POOL_RPC_TIMEOUT: Duration = Duration::from_secs(3600);

// ── Session pool ────────────────────────────────────────────────────────

struct PoolEntry {
    device: Device,
    returned_at: Instant,
}

struct SessionPool {
    slots: Mutex<HashMap<String, PoolEntry>>,
    idle_timeout: Duration,
}

impl SessionPool {
    fn new() -> Arc<Self> {
        let pool = Arc::new(Self {
            slots: Mutex::new(HashMap::new()),
            idle_timeout: POOL_IDLE_TIMEOUT,
        });
        // Spawn the reaper only if we're inside a tokio runtime
        // (unit tests using #[test] don't have one).
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let weak = Arc::downgrade(&pool);
            handle.spawn(async move {
                let mut interval = tokio::time::interval(POOL_REAPER_INTERVAL);
                loop {
                    interval.tick().await;
                    let pool = match weak.upgrade() {
                        Some(p) => p,
                        None => return,
                    };
                    pool.evict_expired().await;
                }
            });
        }
        pool
    }

    async fn evict_expired(&self) {
        let mut slots = self.slots.lock().await;
        let now = Instant::now();
        let expired: Vec<String> = slots
            .iter()
            .filter(|(_, e)| now.duration_since(e.returned_at) > self.idle_timeout)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            if let Some(entry) = slots.remove(&key) {
                tokio::spawn(async move {
                    let mut d = entry.device;
                    let _ = d.close().await;
                });
            }
        }
    }

    async fn try_checkout(&self, name: &str) -> Option<Device> {
        let mut slots = self.slots.lock().await;
        let entry = slots.remove(name)?;
        let now = Instant::now();
        if now.duration_since(entry.returned_at) > self.idle_timeout {
            tokio::spawn(async move {
                let mut d = entry.device;
                let _ = d.close().await;
            });
            return None;
        }
        if !entry.device.session_alive() {
            tokio::spawn(async move {
                let mut d = entry.device;
                let _ = d.close().await;
            });
            return None;
        }
        Some(entry.device)
    }

    async fn return_session(&self, name: String, dev: Device) {
        if !dev.session_alive() {
            let mut d = dev;
            let _ = d.close().await;
            return;
        }
        let mut slots = self.slots.lock().await;
        if let Some(old) = slots.insert(
            name,
            PoolEntry {
                device: dev,
                returned_at: Instant::now(),
            },
        ) {
            tokio::spawn(async move {
                let mut d = old.device;
                let _ = d.close().await;
            });
        }
    }

    async fn invalidate(&self, names: &[String]) {
        let mut slots = self.slots.lock().await;
        for name in names {
            if let Some(entry) = slots.remove(name) {
                tokio::spawn(async move {
                    let mut d = entry.device;
                    let _ = d.close().await;
                });
            }
        }
    }
}

// ── PooledDevice RAII guard ─────────────────────────────────────────────

/// RAII wrapper around `Device` that returns the session to the pool on drop.
///
/// If the config-db is left open (e.g. tool crashed between lock and unlock),
/// the session is closed instead of pooled.
pub struct PooledDevice {
    dev: Option<Device>,
    router_name: String,
    pool: Arc<SessionPool>,
}

impl Deref for PooledDevice {
    type Target = Device;
    fn deref(&self) -> &Device {
        self.dev.as_ref().expect("PooledDevice used after drop")
    }
}

impl DerefMut for PooledDevice {
    fn deref_mut(&mut self) -> &mut Device {
        self.dev.as_mut().expect("PooledDevice used after drop")
    }
}

impl Drop for PooledDevice {
    fn drop(&mut self) {
        if let Some(dev) = self.dev.take() {
            let Ok(handle) = tokio::runtime::Handle::try_current() else {
                return; // No runtime — session leaks but process doesn't crash
            };
            if dev.is_config_db_open() {
                // Config DB left open — cannot reuse, must close.
                handle.spawn(async move {
                    let mut d = dev;
                    let _ = d.close().await;
                });
            } else {
                // Return to pool for reuse.
                let pool = self.pool.clone();
                let name = self.router_name.clone();
                handle.spawn(async move {
                    pool.return_session(name, dev).await;
                });
            }
        }
    }
}

// ── DeviceManager ───────────────────────────────────────────────────────

#[derive(Clone)]
pub struct DeviceManager {
    inventory: Arc<ArcSwap<Inventory>>,
    inventory_path: Arc<ArcSwap<PathBuf>>,
    inventory_hash: Arc<ArcSwap<[u8; 32]>>,
    inventory_write_lock: Arc<Mutex<()>>,
    inventory_readonly: bool,
    allow_password_auth_add: bool,
    pool: Arc<SessionPool>,
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
            pool: SessionPool::new(),
        }
    }

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

    pub fn store_inventory(&self, inv: Arc<Inventory>, path: PathBuf, hash: [u8; 32]) {
        self.inventory.store(inv);
        self.inventory_path.store(Arc::new(path));
        self.inventory_hash.store(Arc::new(hash));
    }

    /// Drain pool entries for routers that were removed or whose config changed.
    pub async fn invalidate_pool(&self, names: &[String]) {
        self.pool.invalidate(names).await;
    }

    /// Open a `Device` for the named router, reusing a pooled session if one
    /// is available and healthy. Returns a `PooledDevice` guard that
    /// automatically returns the session to the pool on drop.
    pub async fn open(&self, router_name: &str) -> Result<PooledDevice, JmcpError> {
        let inventory = self.inventory.load();
        let entry = inventory.get(router_name)?;

        // Try the pool first.
        if let Some(dev) = self.pool.try_checkout(router_name).await {
            tracing::debug!(router = %router_name, "reusing pooled NETCONF session");
            return Ok(PooledDevice {
                dev: Some(dev),
                router_name: router_name.to_string(),
                pool: self.pool.clone(),
            });
        }

        // No pooled session — open fresh.
        let mut builder = Device::connect(&entry.ip)
            .port(entry.port)
            .username(&entry.username)
            .keepalive_interval(KEEPALIVE_INTERVAL)
            .rpc_timeout(POOL_RPC_TIMEOUT);

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

        let dev = builder.open().await?;
        Ok(PooledDevice {
            dev: Some(dev),
            router_name: router_name.to_string(),
            pool: self.pool.clone(),
        })
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

    #[test]
    fn pool_rpc_timeout_is_at_least_one_hour() {
        // POOL_RPC_TIMEOUT must comfortably exceed any plausible per-call
        // MCP timeout so that the MCP-side `tokio::time::timeout` is the
        // user-visible bound, not rustez's internal cap.
        assert!(
            POOL_RPC_TIMEOUT >= Duration::from_secs(3600),
            "POOL_RPC_TIMEOUT must be >= 1h to cover long-running ops; got {:?}",
            POOL_RPC_TIMEOUT
        );
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
