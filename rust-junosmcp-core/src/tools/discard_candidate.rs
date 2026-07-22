//! `discard_candidate` — discard uncommitted candidate config (rollback 0),
//! returning the candidate to the running config. Never changes the running
//! config. Operates lock-free on the shared candidate to recover a candidate
//! left dirty ("configuration database modified").

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::tools::candidate_transaction::{self, CandidateMode, CandidateRequest, CandidateResult};
use crate::tools::DiscardCandidateArgs;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub async fn handle(
    args: DiscardCandidateArgs,
    dm: Arc<DeviceManager>,
) -> Result<Value, JmcpError> {
    handle_with_cancel(args, dm, CancellationToken::new()).await
}

pub async fn handle_with_cancel(
    args: DiscardCandidateArgs,
    dm: Arc<DeviceManager>,
    ct: CancellationToken,
) -> Result<Value, JmcpError> {
    // Confirm the router exists before connecting.
    let _ = dm.inventory().get(&args.router_name)?;
    let timeout_dur = Duration::from_secs(args.timeout);

    match candidate_transaction::run(
        &dm,
        &args.router_name,
        CandidateRequest {
            payload: None,
            mode: CandidateMode::Discard,
        },
        timeout_dur,
        &ct,
    )
    .await?
    {
        CandidateResult::Discarded => Ok(json!({
            "success": true,
            "message": "candidate configuration discarded (rolled back to running)"
        })),
        _ => unreachable!("discard transaction returned the wrong result kind"),
    }
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
