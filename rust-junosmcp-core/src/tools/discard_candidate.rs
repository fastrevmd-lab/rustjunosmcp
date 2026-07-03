//! `discard_candidate` — discard uncommitted candidate config (rollback 0),
//! returning the candidate to the running config. Never changes the running
//! config. Recovers a candidate left dirty ("configuration database modified").

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::tools::DiscardCandidateArgs;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

pub async fn handle(
    args: DiscardCandidateArgs,
    dm: Arc<DeviceManager>,
) -> Result<Value, JmcpError> {
    // Confirm the router exists before connecting.
    let _ = dm.inventory().get(&args.router_name)?;
    let timeout_dur = Duration::from_secs(args.timeout);

    let result = tokio::time::timeout(timeout_dur, async {
        let mut dev = dm.open(&args.router_name).await?;
        let mut cfg = dev.config()?;
        cfg.lock().await?;
        // Discard any uncommitted candidate changes; always unlock afterward.
        let rolled_back = cfg.rollback(0).await;
        let _ = cfg.unlock().await;
        rolled_back?;
        Ok::<_, JmcpError>(json!({
            "success": true,
            "message": "candidate configuration discarded (rolled back to running)"
        }))
    })
    .await
    .map_err(|_| JmcpError::Timeout(timeout_dur))??;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    fn inv_with(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    #[tokio::test]
    async fn unknown_router_propagates_error() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            DiscardCandidateArgs {
                router_name: "nope".into(),
                timeout: 5,
            },
            dm,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }
}
