//! Cross-process per-device leases for destructive workflows.
//!
//! The open file descriptor and kernel lock are authoritative. There is no
//! time-based lease that can expire during a valid long-running upgrade. File
//! descriptors close on normal return, cancellation, panic unwind, or process
//! death, so the kernel provides crash recovery without stale-lock deletion.

use crate::JmcpError;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;

pub const DEFAULT_DEVICE_LEASE_DIR: &str = "/var/lib/jmcp/device-leases";
const DEFAULT_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Debug)]
pub struct DeviceLeaseManager {
    directory: Arc<PathBuf>,
    wait_timeout: Duration,
    poll_interval: Duration,
}

impl DeviceLeaseManager {
    pub fn for_directory(directory: impl Into<PathBuf>) -> Result<Self, JmcpError> {
        Self::with_timing(directory, DEFAULT_WAIT_TIMEOUT, DEFAULT_POLL_INTERVAL)
    }

    pub fn with_timing(
        directory: impl Into<PathBuf>,
        wait_timeout: Duration,
        poll_interval: Duration,
    ) -> Result<Self, JmcpError> {
        let directory = directory.into();
        prepare_directory(&directory)?;
        Ok(Self {
            directory: Arc::new(directory),
            wait_timeout,
            poll_interval: poll_interval.max(Duration::from_millis(1)),
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub async fn acquire(
        &self,
        router: &str,
        operation: &str,
        correlation_id: &str,
    ) -> Result<DeviceLeaseGuard, JmcpError> {
        self.acquire_cancellable(router, operation, correlation_id, &CancellationToken::new())
            .await
    }

    pub async fn acquire_cancellable(
        &self,
        router: &str,
        operation: &str,
        correlation_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<DeviceLeaseGuard, JmcpError> {
        let path = self.lock_path(router);
        let mut file = open_lock_file(&path, router)?;
        let started = Instant::now();
        let deadline = started
            .checked_add(self.wait_timeout)
            .ok_or_else(|| lease_error(router, "lease wait deadline overflow"))?;
        let mut wait_logged = false;

        loop {
            if cancellation.is_cancelled() {
                return Err(JmcpError::Cancelled);
            }
            match file.try_lock() {
                Ok(()) => {
                    let waited = started.elapsed();
                    write_metadata(&mut file, router, operation, correlation_id, "held").map_err(
                        |error| {
                            lease_error(
                                router,
                                format!("writing lease ownership metadata: {error}"),
                            )
                        },
                    )?;
                    tracing::info!(
                        event = "device_lease_acquired",
                        router,
                        operation,
                        correlation_id,
                        waited_ms = waited.as_millis() as u64,
                        lock_path = %path.display(),
                        "acquired cross-process device lease"
                    );
                    return Ok(DeviceLeaseGuard {
                        file: Some(file),
                        path,
                        router: router.to_string(),
                        operation: operation.to_string(),
                        correlation_id: correlation_id.to_string(),
                        acquired_at: Instant::now(),
                    });
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    if !wait_logged {
                        tracing::info!(
                            event = "device_lease_wait",
                            router,
                            operation,
                            correlation_id,
                            wait_timeout_ms = self.wait_timeout.as_millis() as u64,
                            "waiting for cross-process device lease"
                        );
                        wait_logged = true;
                    }
                    if Instant::now() >= deadline {
                        tracing::warn!(
                            event = "device_lease_busy",
                            router,
                            operation,
                            correlation_id,
                            waited_ms = started.elapsed().as_millis() as u64,
                            "cross-process device lease remained busy"
                        );
                        return Err(JmcpError::DeviceLeaseBusy {
                            router: router.to_string(),
                            waited_secs: self.wait_timeout.as_secs(),
                        });
                    }
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(lease_error(
                        router,
                        format!("locking {}: {error}", path.display()),
                    ));
                }
            }

            tokio::select! {
                _ = cancellation.cancelled() => return Err(JmcpError::Cancelled),
                _ = tokio::time::sleep(self.poll_interval) => {}
            }
        }
    }

    fn lock_path(&self, router: &str) -> PathBuf {
        let digest: [u8; 32] = Sha256::digest(router.as_bytes()).into();
        let mut filename = String::with_capacity(64 + ".lock".len());
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut filename, "{byte:02x}").expect("writing to String cannot fail");
        }
        filename.push_str(".lock");
        self.directory.join(filename)
    }
}

#[derive(Debug)]
pub struct DeviceLeaseGuard {
    file: Option<File>,
    path: PathBuf,
    router: String,
    operation: String,
    correlation_id: String,
    acquired_at: Instant,
}

impl Drop for DeviceLeaseGuard {
    fn drop(&mut self) {
        let Some(mut file) = self.file.take() else {
            return;
        };
        if let Err(error) = write_metadata(
            &mut file,
            &self.router,
            &self.operation,
            &self.correlation_id,
            "released",
        ) {
            tracing::warn!(
                event = "device_lease_metadata_failed",
                router = %self.router,
                operation = %self.operation,
                correlation_id = %self.correlation_id,
                error = %error,
                "failed to update device lease release metadata"
            );
        }
        if let Err(error) = file.unlock() {
            tracing::error!(
                event = "device_lease_release_failed",
                router = %self.router,
                operation = %self.operation,
                correlation_id = %self.correlation_id,
                error = %error,
                lock_path = %self.path.display(),
                "failed to release cross-process device lease"
            );
            return;
        }
        tracing::info!(
            event = "device_lease_released",
            router = %self.router,
            operation = %self.operation,
            correlation_id = %self.correlation_id,
            held_ms = self.acquired_at.elapsed().as_millis() as u64,
            "released cross-process device lease"
        );
    }
}

fn prepare_directory(directory: &Path) -> Result<(), JmcpError> {
    if let Ok(metadata) = std::fs::symlink_metadata(directory) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(lease_error(
                "startup",
                format!(
                    "device lease path {} must be a real directory",
                    directory.display()
                ),
            ));
        }
        secure_directory_permissions(directory)?;
        return Ok(());
    }

    std::fs::create_dir_all(directory).map_err(|error| {
        lease_error(
            "startup",
            format!(
                "creating device lease directory {}: {error}",
                directory.display()
            ),
        )
    })?;
    let metadata = std::fs::symlink_metadata(directory).map_err(|error| {
        lease_error(
            "startup",
            format!(
                "checking device lease directory {}: {error}",
                directory.display()
            ),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(lease_error(
            "startup",
            format!(
                "device lease path {} must be a real directory",
                directory.display()
            ),
        ));
    }
    secure_directory_permissions(directory)?;
    Ok(())
}

fn secure_directory_permissions(directory: &Path) -> Result<(), JmcpError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                lease_error(
                    "startup",
                    format!(
                        "setting device lease directory permissions on {}: {error}",
                        directory.display()
                    ),
                )
            },
        )?;
    }
    Ok(())
}

fn open_lock_file(path: &Path, router: &str) -> Result<File, JmcpError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|error| {
        lease_error(
            router,
            format!("opening lease file {}: {error}", path.display()),
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        lease_error(
            router,
            format!("checking lease file {}: {error}", path.display()),
        )
    })?;
    if !metadata.is_file() {
        return Err(lease_error(
            router,
            format!("lease path {} is not a regular file", path.display()),
        ));
    }
    Ok(file)
}

fn write_metadata(
    file: &mut File,
    router: &str,
    operation: &str,
    correlation_id: &str,
    state: &str,
) -> Result<(), JmcpError> {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let metadata = serde_json::json!({
        "state": state,
        "router": router,
        "operation": operation,
        "correlation_id": correlation_id,
        "pid": std::process::id(),
        "timestamp_unix_ms": timestamp_ms,
    });
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    serde_json::to_writer(&mut *file, &metadata)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn lease_error(router: impl Into<String>, detail: impl Into<String>) -> JmcpError {
    JmcpError::DeviceLeaseError {
        router: router.into(),
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn separate_managers_serialize_upgrade_and_srx_workflows() {
        let directory = tempfile::tempdir().unwrap();
        let upgrade = DeviceLeaseManager::with_timing(
            directory.path(),
            Duration::from_millis(50),
            Duration::from_millis(5),
        )
        .unwrap();
        let srx = upgrade.clone();
        let guard = upgrade
            .acquire("srx-01", "upgrade_junos", "upgrade-1")
            .await
            .unwrap();
        let error = srx
            .acquire("srx-01", "manage_idp_security_package", "sigpkg-1")
            .await
            .unwrap_err();
        assert!(matches!(error, JmcpError::DeviceLeaseBusy { .. }));
        drop(guard);
        srx.acquire("srx-01", "manage_idp_security_package", "sigpkg-1")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn different_routers_do_not_block_each_other() {
        let directory = tempfile::tempdir().unwrap();
        let leases = DeviceLeaseManager::with_timing(
            directory.path(),
            Duration::from_millis(50),
            Duration::from_millis(5),
        )
        .unwrap();
        let _first = leases.acquire("srx-01", "idp", "one").await.unwrap();
        let _second = leases.acquire("srx-02", "appid", "two").await.unwrap();
    }

    #[tokio::test]
    async fn cancellation_stops_lease_wait() {
        let directory = tempfile::tempdir().unwrap();
        let leases = DeviceLeaseManager::with_timing(
            directory.path(),
            Duration::from_secs(10),
            Duration::from_millis(5),
        )
        .unwrap();
        let _guard = leases.acquire("srx-01", "idp", "one").await.unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let error = leases
            .acquire_cancellable("srx-01", "upgrade", "two", &cancellation)
            .await
            .unwrap_err();
        assert!(matches!(error, JmcpError::Cancelled));
    }

    #[test]
    fn symlink_directory_is_rejected() {
        #[cfg(unix)]
        {
            let root = tempfile::tempdir().unwrap();
            let target = root.path().join("target");
            let link = root.path().join("link");
            std::fs::create_dir(&target).unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(DeviceLeaseManager::for_directory(link).is_err());
        }
    }
}
