//! `rollback_config` — load a Junos rollback archive (rollback N) into the
//! candidate and optionally commit it.
//!
//! - **Preview mode** (commit=false, default): loads rollback N, computes the
//!   diff, then discards the candidate (stateless). Returns the diff without
//!   committing.
//! - **Commit mode** (commit=true): loads rollback N and commits. Supports
//!   confirmed-commit with auto-rollback after N minutes.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::{confirm_timeout_to_secs, validate_rollback_version};
use crate::tools::candidate_transaction::{self, CandidateMode, CandidateRequest, CandidateResult};
use crate::tools::RollbackConfigArgs;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub async fn handle(args: RollbackConfigArgs, dm: Arc<DeviceManager>) -> Result<Value, JmcpError> {
    handle_with_cancel(args, dm, CancellationToken::new()).await
}

pub async fn handle_with_cancel(
    args: RollbackConfigArgs,
    dm: Arc<DeviceManager>,
    ct: CancellationToken,
) -> Result<Value, JmcpError> {
    // Confirm the router exists before connecting.
    let _ = dm.inventory().get(&args.router_name)?;

    // Validate rollback version 0..=49.
    let version = validate_rollback_version(args.version)?;

    // NOTE: Config blocklist is NOT applied. Rollback restores an archived,
    // already-committed configuration (not caller-authored text). Granting
    // rollback_config scope is equivalent to full config-change authority.

    let timeout_dur = Duration::from_secs(args.timeout);

    let has_commit_comment = args.commit_comment.is_some();
    let mode = if !args.commit {
        // Preview: load rollback N, diff, discard.
        CandidateMode::DryRun
    } else if let Some(mins) = args.confirm_timeout_mins {
        // Confirmed commit: auto-rollback after N minutes if not confirmed.
        let secs = confirm_timeout_to_secs(mins)?;
        CandidateMode::CommitConfirmed(secs)
    } else {
        // Normal commit with comment.
        let comment = args
            .commit_comment
            .unwrap_or_else(|| format!("rollback to {} via rollback_config", version));
        CandidateMode::CommitWithComment(comment)
    };

    match candidate_transaction::run(
        &dm,
        &args.router_name,
        CandidateRequest {
            payload: None,
            rollback_source: Some(version),
            mode,
        },
        timeout_dur,
        &ct,
    )
    .await?
    {
        CandidateResult::DryRun { diff } => {
            // Preview mode: config loaded and diffed, then discarded.
            Ok(json!({
                "committed": false,
                "diff": diff,
                "version": version
            }))
        }
        CandidateResult::Committed { diff } => {
            // Commit succeeded (normal or confirmed).
            let mut result = json!({
                "committed": true,
                "diff": diff,
                "version": version
            });
            if let Some(mins) = args.confirm_timeout_mins {
                result["confirmed"] = json!(true);
                result["rollback_in_minutes"] = json!(mins);
                result["message"] = json!(format!(
                    "Commit confirmed: auto-rollback in {} minutes unless confirmed. \
                     Send another commit to confirm.",
                    mins
                ));
                if has_commit_comment {
                    result["note"] = json!(
                        "commit_comment is ignored during confirmed commits \
                         (rustez API limitation)"
                    );
                }
            }
            Ok(result)
        }
        CandidateResult::CommitFailed { diff, error } => {
            // Commit was attempted but device rejected it.
            Ok(json!({
                "committed": false,
                "diff": diff,
                "version": version,
                "error": error
            }))
        }
        _ => unreachable!("rollback transaction returned unexpected result kind"),
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
            RollbackConfigArgs {
                router_name: "nope".into(),
                version: 1,
                commit: false,
                confirm_timeout_mins: None,
                commit_comment: None,
                timeout: 5,
            },
            dm,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn version_out_of_range_rejected() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            RollbackConfigArgs {
                router_name: "r1".into(),
                version: 50,
                commit: false,
                confirm_timeout_mins: None,
                commit_comment: None,
                timeout: 5,
            },
            dm,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(50))));
    }
}
