//! `execute_junos_command` — run an operational CLI command on one router.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::tools::ExecuteCommandArgs;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

pub async fn handle(
    args: ExecuteCommandArgs,
    dm: Arc<DeviceManager>,
) -> Result<Value, JmcpError> {
    let timeout = Duration::from_secs(args.timeout);
    let mut dev = dm.open(&args.router_name).await?;

    let result = tokio::time::timeout(timeout, dev.cli(&args.command))
        .await
        .map_err(|_| JmcpError::Timeout(timeout))?;

    let _ = dev.close().await; // best-effort
    Ok(json!(result?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    #[tokio::test]
    async fn unknown_router_propagates_error() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(br#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#).unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let dm  = Arc::new(DeviceManager::new(inv));
        let r = handle(
            ExecuteCommandArgs {
                router_name: "nope".into(),
                command: "show version".into(),
                timeout: 5,
            },
            dm,
        ).await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }
}
