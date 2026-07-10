//! Connection lifecycle management with per-router session pooling.
//!
//! `DeviceManager::open()` returns a `PooledDevice` RAII guard. When the guard
//! is dropped, the underlying `rustez::Device` is returned to a single-slot
//! pool (keyed by router name) for reuse by the next caller — unless the
//! config-db was left open, in which case the session is closed instead.

use crate::error::JmcpError;
use crate::inventory::{AuthConfig, Inventory};
use arc_swap::ArcSwap;
use rustez::{Device, HostKeyVerification, SshConfigFile};
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

/// Max connect attempts on the fresh-connect path before giving up. Covers a
/// brief reboot/transport flap (issue #83) where the device accepted us a
/// moment ago but a follow-up `open()` lands mid-blip with "No route to host"
/// / "connection refused". Long reboot waits are handled separately by
/// `upgrade_junos::wait_for_netconf`; this only absorbs short transients.
const CONNECT_MAX_ATTEMPTS: u32 = 3;

/// Fixed backoff between fresh-connect retry attempts.
const CONNECT_RETRY_BACKOFF: Duration = Duration::from_secs(3);

// ── Transient-error classification ──────────────────────────────────────

/// Classify whether an error string indicates a transient/stale condition
/// (peer rebooted, transport dropped, keepalive probe failed, connect blip)
/// such that the operation is worth retrying on a fresh session (issue #83).
///
/// Must NOT match genuine command/RPC/auth errors (syntax error, rpc-error,
/// permission denied, host-key mismatch, unknown router) — those are real and
/// must propagate without retry. This is the single canonical classifier;
/// `upgrade_junos::error_indicates_stale_session` delegates here.
pub(crate) fn error_is_transient(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    [
        "session expired",
        "keepalive probe failed",
        "connection closed",
        "connection reset",
        "connection refused",
        "connection failed",
        "broken pipe",
        "unexpected eof",
        "early eof",
        "channel closed",
        "session closed",
        "no route to host",
        "transport error",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Retry an async operation on transient errors with bounded attempts and a
/// fixed backoff. The op closure receives the 1-based attempt number. Returns
/// the first `Ok`, or the last `Err`. Non-transient errors short-circuit
/// immediately (no retry), so genuine failures (auth, unknown router, RPC
/// errors) still fail fast.
async fn retry_transient<F, Fut, T>(
    max_attempts: u32,
    backoff: Duration,
    mut op: F,
) -> Result<T, JmcpError>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<T, JmcpError>>,
{
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match op(attempt).await {
            Ok(value) => return Ok(value),
            Err(err) if attempt < max_attempts && error_is_transient(&err.to_string()) => {
                tracing::warn!(
                    attempt,
                    max_attempts,
                    error = %err,
                    "transient error; retrying after backoff"
                );
                tokio::time::sleep(backoff).await;
            }
            Err(err) => return Err(err),
        }
    }
}

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
/// If candidate state is uncertain or the config DB is left open, the session
/// is closed instead of pooled.
pub struct PooledDevice {
    dev: Option<Device>,
    router_name: String,
    pool: Arc<SessionPool>,
    reuse_allowed: bool,
}

impl PooledDevice {
    /// Keep a session with uncertain candidate state out of the pool.
    pub(crate) fn prevent_reuse(&mut self) {
        self.reuse_allowed = false;
    }

    /// Re-enable pooling only after candidate cleanup completed successfully.
    pub(crate) fn allow_reuse(&mut self) {
        self.reuse_allowed = true;
    }
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
            if !self.reuse_allowed || dev.is_config_db_open() {
                // Candidate state is uncertain or a config DB was left open.
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
    /// SSH host-key verification policy applied to every NETCONF connect.
    /// Defaults to `AcceptAll` for unit-test ergonomics; production callers
    /// (`main.rs`) override via [`Self::with_host_key_policy`].
    host_key_policy: HostKeyVerification,
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
            host_key_policy: HostKeyVerification::AcceptAll,
            pool: SessionPool::new(),
        }
    }

    /// Override the SSH host-key verification policy applied to every
    /// NETCONF connect. Production callers should set this to either
    /// `HostKeyVerification::KnownHosts(<path>)` (strict, recommended) or
    /// `HostKeyVerification::AcceptAll` (lab/TOFU mode).
    pub fn with_host_key_policy(mut self, policy: HostKeyVerification) -> Self {
        self.host_key_policy = policy;
        self
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
        // Try the pool first.
        if let Some(dev) = self.pool.try_checkout(router_name).await {
            tracing::debug!(router = %router_name, "reusing pooled NETCONF session");
            return Ok(PooledDevice {
                dev: Some(dev),
                router_name: router_name.to_string(),
                pool: self.pool.clone(),
                reuse_allowed: true,
            });
        }

        // No pooled session — open fresh.
        self.connect_fresh(router_name).await
    }

    /// Open a guaranteed-fresh `Device`, bypassing the pool. Any existing
    /// pooled entry for this router is invalidated (closed) first so a dead
    /// session left behind by a transient blip or a reboot can't linger and
    /// be handed to the next caller (issue #83). Use this on the reconnect
    /// path after a pooled RPC fails with a stale-session error.
    pub async fn open_fresh(&self, router_name: &str) -> Result<PooledDevice, JmcpError> {
        self.pool.invalidate(&[router_name.to_string()]).await;
        self.connect_fresh(router_name).await
    }

    /// Open a session and run an operational CLI command, transparently
    /// reconnecting on a guaranteed-fresh session and retrying once if the
    /// first attempt fails with a transient/stale-session error (issue #83).
    ///
    /// The pooled [`Self::open`] may hand back a session that was alive at
    /// checkout but whose peer rebooted between checkout and the first RPC; the
    /// keepalive probe then fails with "session expired" / "keepalive probe
    /// failed". Rather than surface that as a hard error to the caller, the
    /// dead session is dropped, a fresh one is opened (which itself retries
    /// connect-time transients via [`Self::connect_fresh`]), and the command is
    /// run again. Genuine command/RPC errors are non-transient and propagate
    /// without a retry.
    pub async fn run_cli(&self, router_name: &str, command: &str) -> Result<String, JmcpError> {
        let mut dev = self.open(router_name).await?;
        match dev.cli(command).await {
            Ok(output) => Ok(output),
            Err(err) if error_is_transient(&err.to_string()) => {
                tracing::warn!(
                    router = %router_name,
                    error = %err,
                    "pooled session stale on cli; reconnecting fresh and retrying once"
                );
                drop(dev);
                let mut fresh = self.open_fresh(router_name).await?;
                Ok(fresh.cli(command).await?)
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Establish a brand-new NETCONF connection for `router_name` (no pool
    /// checkout). Shared by [`Self::open`]'s cache-miss path and
    /// [`Self::open_fresh`].
    async fn connect_fresh(&self, router_name: &str) -> Result<PooledDevice, JmcpError> {
        // Snapshot the inventory entry up front so the retry closure owns its
        // connection parameters (the ArcSwap guard must not be held across the
        // retry/backoff awaits).
        let entry = {
            let inventory = self.inventory.load();
            inventory.get(router_name)?.clone()
        };
        let policy = self.host_key_policy.clone();

        // Retry the fresh connect on transient transport errors (issue #83):
        // a reboot/transport flap can make an `open()` land mid-blip with
        // "No route to host" / "connection refused" even though the device is
        // coming back. Genuine errors (auth, ssh_config, host-key) are
        // non-transient and fail fast on the first attempt.
        let dev = retry_transient(CONNECT_MAX_ATTEMPTS, CONNECT_RETRY_BACKOFF, |_attempt| {
            let entry = entry.clone();
            let policy = policy.clone();
            async move {
                let mut builder = Device::connect(&entry.ip)
                    .port(entry.port)
                    .username(&entry.username)
                    .keepalive_interval(KEEPALIVE_INTERVAL)
                    .rpc_timeout(POOL_RPC_TIMEOUT)
                    .host_key_verification(policy);

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
        })
        .await?;

        Ok(PooledDevice {
            dev: Some(dev),
            router_name: router_name.to_string(),
            pool: self.pool.clone(),
            reuse_allowed: true,
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

    use std::sync::atomic::{AtomicU32, Ordering};

    // ── error_is_transient classifier (issue #83) ───────────────────────

    #[test]
    fn transient_detects_no_route_to_host() {
        assert!(error_is_transient(
            "netconf error: transport error: connection failed: SSH connect to 192.168.1.233:22 failed: No route to host (os error 113)"
        ));
    }

    #[test]
    fn transient_detects_keepalive_probe_failed() {
        assert!(error_is_transient(
            "netconf error: protocol error: session expired: keepalive probe failed"
        ));
    }

    #[test]
    fn transient_detects_connection_reset_and_refused() {
        assert!(error_is_transient("Connection reset by peer"));
        assert!(error_is_transient("connect: Connection refused"));
    }

    #[test]
    fn transient_does_not_match_syntax_or_auth_errors() {
        assert!(!error_is_transient("error: syntax error, expecting <name>"));
        assert!(!error_is_transient("rpc-error: package not found"));
        assert!(!error_is_transient("Permission denied (publickey)"));
        assert!(!error_is_transient(
            "router 'r99' not found in device mapping"
        ));
        assert!(!error_is_transient(""));
    }

    // ── retry_transient bounded-backoff helper (issue #83) ───────────────

    #[tokio::test]
    async fn retry_transient_succeeds_after_two_transient_failures() {
        let calls = AtomicU32::new(0);
        let out = retry_transient(5, Duration::ZERO, |_attempt| {
            let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                if n < 3 {
                    Err(JmcpError::Validation("connection refused".into()))
                } else {
                    Ok::<u32, JmcpError>(n)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(out, 3);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_transient_returns_immediately_on_non_transient() {
        let calls = AtomicU32::new(0);
        let res: Result<u32, JmcpError> = retry_transient(5, Duration::ZERO, |_attempt| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { Err(JmcpError::UnknownRouter("r1".into())) }
        })
        .await;
        assert!(matches!(res, Err(JmcpError::UnknownRouter(_))));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "must not retry non-transient"
        );
    }

    #[tokio::test]
    async fn retry_transient_exhausts_attempts_on_persistent_transient() {
        let calls = AtomicU32::new(0);
        let res: Result<u32, JmcpError> = retry_transient(3, Duration::ZERO, |_attempt| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { Err(JmcpError::Validation("no route to host".into())) }
        })
        .await;
        assert!(res.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3, "must stop at max_attempts");
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

    // #83: open_fresh bypasses the pool but still validates inventory; an
    // unknown router must surface UnknownRouter rather than attempting a
    // connection.
    #[tokio::test]
    async fn open_fresh_unknown_router_returns_unknown_router_error() {
        let inv = build_inventory(
            r#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let dm = DeviceManager::new(inv);
        let r = dm.open_fresh("nope").await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(ref s)) if s == "nope"));
    }

    #[test]
    fn default_host_key_policy_is_accept_all() {
        // Backward-compat: `DeviceManager::new` and `with_path` default to
        // AcceptAll so the ~40 unit-test call sites don't have to plumb a
        // policy through. Production wiring (`main.rs`) overrides via
        // `.with_host_key_policy(...)`.
        let inv = build_inventory(r#"{}"#);
        let dm = DeviceManager::new(inv);
        assert!(matches!(dm.host_key_policy, HostKeyVerification::AcceptAll));
    }

    #[test]
    fn with_host_key_policy_overrides_default() {
        let inv = build_inventory(r#"{}"#);
        let dm = DeviceManager::new(inv).with_host_key_policy(HostKeyVerification::KnownHosts(
            PathBuf::from("/etc/jmcp/known_hosts"),
        ));
        match &dm.host_key_policy {
            HostKeyVerification::KnownHosts(p) => {
                assert_eq!(p, &PathBuf::from("/etc/jmcp/known_hosts"))
            }
            other => panic!("expected KnownHosts, got {:?}", other),
        }
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
