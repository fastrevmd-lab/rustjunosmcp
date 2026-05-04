//! `load_and_commit_config` — lock candidate, load, diff, commit (with comment),
//! unlock. Rollback on commit failure. Returns `{success, diff, error?}`.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::build_config_payload;
use crate::tools::LoadCommitArgs;
use serde_json::{json, Value};
use std::sync::Arc;

pub async fn handle(args: LoadCommitArgs, dm: Arc<DeviceManager>) -> Result<Value, JmcpError> {
    let payload = build_config_payload(args.config_text, Some(&args.config_format))?;

    let mut dev = dm.open(&args.router_name).await?;
    let mut cfg = dev.config()?;

    cfg.lock().await?;
    if let Err(e) = cfg.load(payload).await {
        let _ = cfg.unlock().await;
        let _ = dev.close().await;
        return Err(JmcpError::from(e));
    }
    let diff = cfg.diff().await?.unwrap_or_default();

    let commit_result = cfg.commit_with_comment(&args.commit_comment).await;

    let result = match commit_result {
        Ok(_) => json!({ "success": true, "diff": diff }),
        Err(e) => {
            // Discard the candidate so the next session starts clean.
            // rollback(0) discards uncommitted changes.
            let _ = cfg.rollback(0).await;
            json!({ "success": false, "diff": diff, "error": e.to_string() })
        }
    };

    // Best-effort unlock + close.
    let _ = cfg.unlock().await;
    let _ = dev.close().await;
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
            LoadCommitArgs {
                router_name: "nope".into(),
                config_text: "set system foo".into(),
                config_format: "set".into(),
                commit_comment: "test".into(),
            },
            dm,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn invalid_format_rejected_before_connect() {
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
            LoadCommitArgs {
                router_name: "r1".into(),
                config_text: "x".into(),
                config_format: "yaml".into(),
                commit_comment: "test".into(),
            },
            dm,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadFormat(ref s)) if s == "yaml"));
    }
}
