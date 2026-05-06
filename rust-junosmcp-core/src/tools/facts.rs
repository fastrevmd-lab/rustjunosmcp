//! `gather_device_facts` — return device facts as a JSON object.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::tools::GatherFactsArgs;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

pub async fn handle(args: GatherFactsArgs, dm: Arc<DeviceManager>) -> Result<Value, JmcpError> {
    let timeout = Duration::from_secs(args.timeout);
    let result = tokio::time::timeout(timeout, async {
        let mut dev = dm.open(&args.router_name).await?;
        let facts = dev.facts().await?;
        let value = serde_json::to_value(facts)?;
        let _ = dev.close().await;
        Ok::<_, JmcpError>(value)
    })
    .await
    .map_err(|_| JmcpError::Timeout(timeout))??;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    #[tokio::test]
    async fn unknown_router_propagates_error() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        )
        .unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            GatherFactsArgs {
                router_name: "nope".into(),
                timeout: 5,
            },
            dm,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }
}
