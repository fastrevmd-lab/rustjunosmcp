//! Offline recovery on the persisted change-set state file.
//!
//! One non-terminal operation blocks every later change on its device, and the
//! tool surface cannot clear it: a failed discard leaves the operation behind,
//! and `cancel_junos_change_set` refuses a change set that is already terminal.
//! Until this command existed the only way out was editing the JSON by hand
//! (#313).

use crate::cli::{StateAction, StateDisposition};
use anyhow::{Result, anyhow};
use mecmcp_changeset::{OperationLimits, RecoveryDisposition, resolve_persisted_operation};

/// Run one `state` subcommand.
///
/// # Errors
///
/// Returns an error if the state file cannot be read, the operation is unknown
/// or already terminal, or the confirmation string does not match exactly.
pub fn run(action: StateAction) -> Result<()> {
    let StateAction::Resolve {
        state_file,
        operation_id,
        disposition,
        confirmation,
    } = action;

    let disposition = match disposition {
        StateDisposition::Committed => RecoveryDisposition::Committed,
        StateDisposition::Discarded => RecoveryDisposition::Discarded,
    };

    // The shared resolver does the work: it refuses a terminal record, checks
    // the confirmation string exactly, re-signs nothing, clears the held-lock
    // flag, and records which state was forced. Same function rust-panosmcp
    // exposes as `state resolve`.
    let output = resolve_persisted_operation(
        &state_file,
        &operation_id,
        disposition,
        &confirmation,
        OperationLimits::default(),
    )
    .map_err(|error| anyhow!("{error}"))?;

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mecmcp_changeset::{
        ChangesetCoordinator, LifecycleState, OperationLimits, OperationRecord,
    };
    use serde_json::json;
    use std::sync::Arc;
    use std::time::Duration;

    const OPERATION: &str = "99c21bcdbc0ad34940cfdb6ed561dbdb971589534c14cad6a77c66b954b524cb";
    const DEVICE: &str = "vsrx-ci";
    const OWNER: &str = "claude-test";

    /// The record a failed apply leaves behind: `Failed`, and not terminal.
    fn stuck_operation() -> OperationRecord {
        OperationRecord {
            id: OPERATION.to_owned(),
            owner: OWNER.to_owned(),
            device: DEVICE.to_owned(),
            endpoint: format!("junos://{DEVICE}:830"),
            action: json!("merge"),
            xpath: None,
            actions: vec![json!({"op": "set"})],
            change_set_id: None,
            current: format!("sha256:{}", "a".repeat(64)),
            state: LifecycleState::Failed,
            job_id: None,
            details: None,
            config_lock_held: true,
            policy_signature: String::new(),
            attribution: None,
            rollback_deadline_unix: None,
            config_authority: None,
        }
    }

    async fn state_file_with_stuck_operation() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("changeset-state.json");
        let coordinator = ChangesetCoordinator::load(
            Some(&path),
            OperationLimits::default(),
            Duration::from_secs(900),
            false,
        )
        .expect("coordinator");
        Arc::new(coordinator)
            .insert(stuck_operation())
            .await
            .expect("insert");
        (dir, path)
    }

    /// The whole point: after resolving, the record is terminal, so the device
    /// accepts a new operation instead of refusing every one.
    #[tokio::test]
    async fn resolving_a_stuck_operation_makes_it_terminal() {
        let (_dir, path) = state_file_with_stuck_operation().await;

        run(StateAction::Resolve {
            state_file: path.clone(),
            operation_id: OPERATION.to_owned(),
            disposition: StateDisposition::Discarded,
            confirmation: format!("RESOLVED {OPERATION} AS DISCARDED"),
        })
        .expect("resolve");

        let reloaded = ChangesetCoordinator::load(
            Some(&path),
            OperationLimits::default(),
            Duration::from_secs(900),
            false,
        )
        .expect("reload");
        let record = reloaded
            .record(OPERATION, OWNER, DEVICE)
            .await
            .expect("record");
        assert_eq!(
            record.state,
            LifecycleState::Discarded,
            "a non-terminal record still blocks every later apply on the device"
        );
    }

    /// The confirmation string is the whole safety of the command: it is the
    /// operator asserting they looked at the device. A mismatch must refuse.
    #[tokio::test]
    async fn a_wrong_confirmation_refuses_and_changes_nothing() {
        let (_dir, path) = state_file_with_stuck_operation().await;

        let result = run(StateAction::Resolve {
            state_file: path.clone(),
            operation_id: OPERATION.to_owned(),
            disposition: StateDisposition::Discarded,
            confirmation: "RESOLVED some-other-operation AS DISCARDED".to_owned(),
        });

        assert!(result.is_err(), "a mismatched confirmation must be refused");
        let reloaded = ChangesetCoordinator::load(
            Some(&path),
            OperationLimits::default(),
            Duration::from_secs(900),
            false,
        )
        .expect("reload");
        let record = reloaded
            .record(OPERATION, OWNER, DEVICE)
            .await
            .expect("record");
        assert_eq!(
            record.state,
            LifecycleState::Failed,
            "a refused resolve must leave the record exactly as it found it"
        );
    }
}
