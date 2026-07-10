//! Process-boundary and crash-recovery tests for destructive device leases.

#![cfg(unix)]

use rust_junosmcp_core::{DeviceLeaseManager, JmcpError};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const CHILD_MODE: &str = "JMCP_DEVICE_LEASE_CHILD";
const LEASE_DIR: &str = "JMCP_DEVICE_LEASE_TEST_DIR";
const READY_FILE: &str = "JMCP_DEVICE_LEASE_READY_FILE";

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn child_holds_device_lease() {
    if std::env::var_os(CHILD_MODE).is_none() {
        return;
    }

    let directory = std::env::var_os(LEASE_DIR).expect("child lease directory");
    let ready = std::env::var_os(READY_FILE).expect("child ready file");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let leases = DeviceLeaseManager::for_directory(directory).unwrap();
        let _guard = leases
            .acquire("srx-01", "manage_idp_security_package", "child-idp")
            .await
            .unwrap();
        std::fs::write(ready, b"ready").unwrap();
        std::future::pending::<()>().await;
    });
}

#[tokio::test(flavor = "current_thread")]
async fn another_process_is_blocked_and_kernel_releases_lease_after_crash() {
    let directory = tempfile::tempdir().unwrap();
    let ready = directory.path().join("child.ready");
    let executable = std::env::current_exe().unwrap();
    let child = Command::new(executable)
        .args(["--exact", "child_holds_device_lease", "--nocapture"])
        .env(CHILD_MODE, "1")
        .env(LEASE_DIR, directory.path())
        .env(READY_FILE, &ready)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut child = ChildGuard(child);
    wait_for_file(&ready, &mut child.0);

    let contender = DeviceLeaseManager::with_timing(
        directory.path(),
        Duration::from_millis(100),
        Duration::from_millis(5),
    )
    .unwrap();
    let busy = contender
        .acquire("srx-01", "upgrade_junos", "parent-upgrade")
        .await
        .unwrap_err();
    assert!(matches!(busy, JmcpError::DeviceLeaseBusy { .. }));

    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    assert!(!status.success(), "child should have been terminated");

    contender
        .acquire("srx-01", "upgrade_junos", "parent-after-crash")
        .await
        .expect("kernel must release the file lease when the child exits");
}

fn wait_for_file(path: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("lease child exited before becoming ready: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for lease child"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
