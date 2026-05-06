//! `junos_config_diff` — compare running config against rollback N (1..=49).

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::validate_rollback_version;
use crate::tools::ConfigDiffArgs;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

/// Strip `<configuration-information>` / `<configuration-output>` XML wrapper
/// tags that Junos adds around CLI output delivered over NETCONF.
fn strip_config_xml_wrapper(raw: &str) -> String {
    if let Some(start) = raw.find("<configuration-output>") {
        let content_start = start + "<configuration-output>".len();
        if let Some(end) = raw[content_start..].find("</configuration-output>") {
            return raw[content_start..content_start + end].trim().to_string();
        }
    }
    raw.trim().to_string()
}

pub async fn handle(args: ConfigDiffArgs, dm: Arc<DeviceManager>) -> Result<Value, JmcpError> {
    let version = validate_rollback_version(args.version)?;
    let timeout = Duration::from_secs(args.timeout);
    let result = tokio::time::timeout(timeout, async {
        let mut dev = dm.open(&args.router_name).await?;
        let cmd = format!("show configuration | compare rollback {version}");
        let diff = dev.cli(&cmd).await?;
        Ok::<_, JmcpError>(diff)
    })
    .await
    .map_err(|_| JmcpError::Timeout(timeout))??;
    Ok(json!(strip_config_xml_wrapper(&result)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    fn dm() -> Arc<DeviceManager> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        )
        .unwrap();
        Arc::new(DeviceManager::new(Arc::new(
            Inventory::load(f.path()).unwrap(),
        )))
    }

    #[tokio::test]
    async fn rejects_version_zero_before_connecting() {
        let r = handle(
            ConfigDiffArgs {
                router_name: "r1".into(),
                version: 0,
                timeout: 5,
            },
            dm(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(0))));
    }

    #[tokio::test]
    async fn rejects_version_50_before_connecting() {
        let r = handle(
            ConfigDiffArgs {
                router_name: "r1".into(),
                version: 50,
                timeout: 5,
            },
            dm(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(50))));
    }
}
