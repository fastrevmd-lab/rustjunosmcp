//! `confirm_commit` — send the confirming commit for a Junos commit-confirmed
//! window opened by `load_and_commit_config`, `rollback_config`, or
//! `render_and_apply_j2_template`.
//!
//! These three tools commit directly against the device candidate (no
//! change-set operation record), so they cannot use `confirm_junos_change_set`,
//! which is keyed by an `operation_id` the coordinator tracks. Junos itself
//! does not care which tool opened the window: any commit against the
//! candidate before the deadline cancels the scheduled rollback, so this tool
//! sends a plain commit the same way `confirm_junos_change_set` does for the
//! change-set path (MEC-45).
//!
//! There is no server-side record of "is a window actually open" for this
//! path — Junos is the source of truth. Calling this with no window open is a
//! harmless no-op commit, mirroring `upgrade_junos`'s own device-side check
//! (`commit_confirmed_active`) rather than a second, possibly-stale copy of
//! the same state.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::junos_transaction::JunosTransaction;
use crate::tools::ConfirmCommitArgs;
use mecmcp_audit::Attribution;
use mecmcp_changeset::{CommitOutcome, DeviceTransaction as _};
use serde_json::{Value, json};
use std::sync::Arc;

/// Send the confirming commit to `args.device`, cancelling any pending
/// commit-confirmed auto-rollback.
pub async fn handle(
    args: ConfirmCommitArgs,
    dm: Arc<DeviceManager>,
    attribution: Attribution,
) -> Result<Value, JmcpError> {
    // Confirm the device exists before touching it.
    dm.inventory().get(&args.device)?;

    let transaction = JunosTransaction::new(dm, args.device.clone());
    let outcome = transaction
        .confirm_commit("confirm_commit", &attribution)
        .await?;

    match outcome {
        CommitOutcome::Reconciled {
            succeeded: true,
            details,
            ..
        } => Ok(json!({
            "device": args.device,
            "confirmed": true,
            "details": details,
            "message": "confirming commit accepted; any pending automatic rollback is cancelled"
        })),
        CommitOutcome::Reconciled {
            succeeded: false,
            details,
            ..
        } => Err(JmcpError::Validation(format!(
            "confirming commit failed: {}",
            details.as_deref().unwrap_or("no details")
        ))),
        other => Ok(json!({
            "device": args.device,
            "confirmed": false,
            "commit_outcome": format!("{other:?}"),
            "message": "the confirming commit did not report a definite outcome; if a \
                        rollback window is open on the device it may still be running"
        })),
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
            ConfirmCommitArgs {
                device: "nope".into(),
                timeout: 5,
            },
            dm,
            Attribution::stdio(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }
}
