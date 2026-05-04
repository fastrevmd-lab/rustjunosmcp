//! `junos_config_diff` — `show | compare rollback N` for N in 1..=49.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::validate_rollback_version;
use crate::tools::ConfigDiffArgs;
use serde_json::{json, Value};
use std::sync::Arc;

pub async fn handle(
    args: ConfigDiffArgs,
    dm: Arc<DeviceManager>,
) -> Result<Value, JmcpError> {
    let version = validate_rollback_version(args.version)?;
    let mut dev = dm.open(&args.router_name).await?;
    let cmd = format!("show | compare rollback {version}");
    let diff = dev.cli(&cmd).await?;
    let _ = dev.close().await;
    Ok(json!(diff))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    fn dm() -> Arc<DeviceManager> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(br#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#).unwrap();
        Arc::new(DeviceManager::new(Arc::new(Inventory::load(f.path()).unwrap())))
    }

    #[tokio::test]
    async fn rejects_version_zero_before_connecting() {
        let r = handle(
            ConfigDiffArgs { router_name: "r1".into(), version: 0 },
            dm(),
        ).await;
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(0))));
    }

    #[tokio::test]
    async fn rejects_version_50_before_connecting() {
        let r = handle(
            ConfigDiffArgs { router_name: "r1".into(), version: 50 },
            dm(),
        ).await;
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(50))));
    }
}
