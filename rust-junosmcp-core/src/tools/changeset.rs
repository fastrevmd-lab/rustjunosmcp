//! Junos change-set lifecycle tools — two-person approval for multi-action plans.
//!
//! This module provides the MCP tool implementations for the change-set flow:
//! create → approve (by a second principal) → apply. It wraps the coordinator
//! from `mecmcp-changeset` and uses `JunosTransaction` as the device backend.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::excerpt;
use crate::junos_transaction::{JunosAction, JunosTransaction};
use crate::policy::{Decision, Policy};
use mecmcp_audit::Attribution;
use mecmcp_changeset::{ChangesetCoordinator, CommitOptions, DeviceTransaction as _};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Arguments for `create_junos_change_set`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateChangeSetArgs {
    /// Target device name.
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// Expected device fingerprint before applying. If the device state
    /// changes after planning, application will be rejected.
    pub expected_fingerprint: String,
    /// List of actions to stage. Each action is either a payload or a
    /// rollback archive reference.
    pub actions: Vec<JunosAction>,
}

/// Arguments for `approve_junos_change_set`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ApproveChangeSetArgs {
    /// Change-set ID returned by create.
    pub change_set_id: String,
    /// Device name. Required because change sets are indexed by (id, device).
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// Expected plan digest. The approver must compute or be shown the exact
    /// digest and confirm it matches what they reviewed.
    pub expected_digest: String,
}

/// Arguments for `apply_junos_change_set`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ApplyChangeSetArgs {
    /// Change-set ID to apply.
    pub change_set_id: String,
    /// Expected plan digest. Prevents applying a plan that was tampered with
    /// after approval.
    pub expected_digest: String,
    /// Expected device fingerprint at apply time. If the device changed after
    /// the plan was created, the apply is rejected.
    pub expected_fingerprint: String,
    /// Target device endpoint (device name from inventory).
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// Optional confirmed-commit window, in whole minutes.
    ///
    /// When set, the device commits the change and schedules an automatic
    /// rollback after this many minutes unless `confirm_junos_change_set` is
    /// called first. Minutes, not seconds — that is what Junos schedules, and
    /// it matches `rollback_config`'s existing `confirm_timeout_mins`.
    ///
    /// Omit for an ordinary commit with no rollback timer.
    pub confirm_timeout_mins: Option<u32>,
}

/// Arguments for `confirm_junos_change_set`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ConfirmChangeSetArgs {
    /// Operation ID returned by `apply_junos_change_set`.
    pub operation_id: String,
    /// Device name. Change sets are indexed by (id, device).
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
}

/// Arguments for `get_junos_change_set_status`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetChangeSetStatusArgs {
    /// Change-set ID to query.
    pub change_set_id: String,
    /// Device name. Required because change sets are indexed by (id, device).
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
}

/// Create a change set (plan).
pub async fn create_change_set(
    args: CreateChangeSetArgs,
    dm: Arc<DeviceManager>,
    coordinator: Arc<ChangesetCoordinator>,
    policy: Arc<Policy>,
    attribution: Attribution,
) -> Result<Value, JmcpError> {
    create_change_set_with_cancel(
        args,
        dm,
        coordinator,
        policy,
        attribution,
        CancellationToken::new(),
    )
    .await
}

pub async fn create_change_set_with_cancel(
    args: CreateChangeSetArgs,
    dm: Arc<DeviceManager>,
    coordinator: Arc<ChangesetCoordinator>,
    policy: Arc<Policy>,
    attribution: Attribution,
    _ct: CancellationToken,
) -> Result<Value, JmcpError> {
    // Validate the device exists.
    let _ = dm.inventory().get(&args.device)?;

    // Derive the owner from the authenticated caller's principal.
    let owner = attribution.principal.to_string();

    // Check every action against the device's configuration policy.
    for action in &args.actions {
        if let Some(payload) = &action.payload {
            let format = payload.format.as_deref().unwrap_or("set");
            match policy.check_config(&args.device, format, &payload.text)? {
                Decision::Allow => {}
                Decision::Deny {
                    rule,
                    source,
                    line_number,
                } => {
                    let pattern = rule.pattern.clone();
                    let source_str = source.as_str();
                    let denied_excerpt = excerpt(&payload.text);
                    return Err(JmcpError::Denied {
                        tool: "create_junos_change_set",
                        router: args.device.clone(),
                        pattern,
                        rule_source: source_str,
                        input_excerpt: denied_excerpt,
                        line_number,
                    });
                }
            }
        }
        // Rollback actions do not need policy checks - they reference pre-existing config.
    }

    // The coordinator's create_change_set computes the digest over
    // (owner, device, expected_fingerprint, actions). It persists the plan
    // and returns the change_set_id and plan_digest.
    // Policy signature: we don't have a meaningful signature for Junos policy yet.
    // The check_config above enforces the policy, so the coordinator knows the
    // actions passed validation. For now, use a static marker.
    let policy_signature = "junos-default-v1".to_string();

    let result = coordinator
        .create_change_set(
            args.device,
            args.actions,
            owner,
            args.expected_fingerprint,
            policy_signature,
        )
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    Ok(json!({
        "change_set_id": result.change_set_id,
        "plan_digest": result.digest,
        "state": format!("{:?}", result.state),
        "message": "change set created; awaiting approval by a second principal"
    }))
}

/// Approve a change set (second principal).
pub async fn approve_change_set(
    args: ApproveChangeSetArgs,
    coordinator: Arc<ChangesetCoordinator>,
    dm: Arc<DeviceManager>,
    attribution: Attribution,
) -> Result<Value, JmcpError> {
    approve_change_set_with_cancel(args, coordinator, dm, attribution, CancellationToken::new())
        .await
}

pub async fn approve_change_set_with_cancel(
    args: ApproveChangeSetArgs,
    coordinator: Arc<ChangesetCoordinator>,
    dm: Arc<DeviceManager>,
    attribution: Attribution,
    _ct: CancellationToken,
) -> Result<Value, JmcpError> {
    // Validate the device exists and is within scope.
    let _ = dm.inventory().get(&args.device)?;

    // Derive the approver from the authenticated caller's principal.
    let approver = attribution.principal.to_string();

    let result = coordinator
        .approve_change_set(
            args.change_set_id.clone(),
            args.device,
            approver,
            args.expected_digest,
        )
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    Ok(json!({
        "change_set_id": args.change_set_id,
        "state": format!("{:?}", result.state),
        "digest": result.digest,
        "message": "change set approved; ready to apply"
    }))
}

/// Apply an approved change set.
pub async fn apply_change_set(
    args: ApplyChangeSetArgs,
    dm: Arc<DeviceManager>,
    coordinator: Arc<ChangesetCoordinator>,
    policy: Arc<Policy>,
    attribution: Attribution,
) -> Result<Value, JmcpError> {
    apply_change_set_with_cancel(
        args,
        dm,
        coordinator,
        policy,
        attribution,
        CancellationToken::new(),
    )
    .await
}

pub async fn apply_change_set_with_cancel(
    args: ApplyChangeSetArgs,
    dm: Arc<DeviceManager>,
    coordinator: Arc<ChangesetCoordinator>,
    policy: Arc<Policy>,
    attribution: Attribution,
    ct: CancellationToken,
) -> Result<Value, JmcpError> {
    // Validate the device exists and capture endpoint components.
    let inventory = dm.inventory();
    let device_entry = inventory.get(&args.device)?;
    let device_ip = device_entry.ip.clone();
    let device_port = device_entry.port;

    // Derive the principal from the authenticated caller.
    let principal = attribution.principal.to_string();

    // Retrieve the full change set record to validate actions against policy before staging.
    let change_set_record = coordinator
        .change_set(&args.change_set_id, &args.device)
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    // Deserialize the actions from the stored JSON and validate each against policy.
    for action_value in &change_set_record.actions {
        let action: JunosAction = serde_json::from_value(action_value.clone())
            .map_err(|e| JmcpError::Validation(format!("failed to deserialize action: {e}")))?;

        if let Some(payload) = &action.payload {
            let format = payload.format.as_deref().unwrap_or("set");
            match policy.check_config(&args.device, format, &payload.text)? {
                Decision::Allow => {}
                Decision::Deny {
                    rule,
                    source,
                    line_number,
                } => {
                    let pattern = rule.pattern.clone();
                    let source_str = source.as_str();
                    let denied_excerpt = excerpt(&payload.text);
                    return Err(JmcpError::Denied {
                        tool: "apply_junos_change_set",
                        router: args.device.clone(),
                        pattern,
                        rule_source: source_str,
                        input_excerpt: denied_excerpt,
                        line_number,
                    });
                }
            }
        }
        // Rollback actions do not need policy checks.
    }

    // Build the transaction backend.
    let transaction = JunosTransaction::new(dm.clone(), args.device.clone());

    // For Junos, there is no XPath equivalent, so the primary target is None.
    // The primary action discriminator: we use "merge" as the default for
    // Junos config load operations (cfg.load() merges by default).
    let primary_action = "merge";
    let primary_target: Option<&str> = None;

    // Construct a stable canonical endpoint URL for the coordinator's guard.
    // Junos has no management URL in the PAN-OS sense, so we synthesize one
    // from the device inventory entry: junos://<ip>:<port>. This is stable
    // and deterministic for a given device entry.
    let endpoint = format!("junos://{device_ip}:{device_port}");

    let result = coordinator
        .apply_change_set(
            args.change_set_id.clone(),
            args.device.clone(),
            endpoint,
            principal.clone(),
            args.expected_digest,
            args.expected_fingerprint.clone(),
            &transaction,
            primary_action,
            primary_target,
            &attribution,
            &ct,
        )
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    // The apply_change_set call stages all actions and returns the staged
    // handle. The caller (this tool) must then diff, validate, and commit.
    // Policy signature for commit - same as what we use for staging.
    let policy_signature = "junos-default-v1";

    // Run diff to get the configuration difference.
    let _diff = coordinator
        .diff_operation(
            &result.operation_id,
            &args.device,
            &principal,
            &result.after_fingerprint,
            &transaction,
            &result.staged,
            &ct,
        )
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    // Run validation before committing.
    let validation = coordinator
        .validate_operation(
            &result.operation_id,
            &args.device,
            &principal,
            &result.after_fingerprint,
            &transaction,
            &result.staged,
            &ct,
        )
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    // A confirmed-commit window is expressed in whole minutes because that is
    // what Junos schedules; the transaction layer refuses anything it cannot
    // honour rather than rounding it.
    let commit_options = CommitOptions {
        confirm_timeout: args
            .confirm_timeout_mins
            .map(|mins| std::time::Duration::from_secs(u64::from(mins) * 60)),
    };

    // Check if validation succeeded. If it failed, refuse to commit.
    if !validation.valid {
        return Err(JmcpError::Validation(format!(
            "configuration validation failed: {}",
            validation.details.as_deref().unwrap_or("no details")
        )));
    }

    let commit_result = coordinator
        .commit_operation(
            &result.operation_id,
            &args.device,
            &principal,
            &result.after_fingerprint,
            policy_signature,
            &transaction,
            &result.staged,
            &attribution,
            &commit_options,
            &ct,
        )
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    // Branch on the commit outcome and report honestly.
    use mecmcp_changeset::CommitOutcome;
    match commit_result {
        CommitOutcome::Reconciled {
            succeeded: true,
            details,
            ..
        } => Ok(json!({
            "change_set_id": args.change_set_id,
            "operation_id": result.operation_id,
            "state": "Applied",
            "commit_outcome": "Reconciled",
            "details": details,
            "message": "change set applied and committed successfully"
        })),
        CommitOutcome::Reconciled {
            succeeded: false,
            details,
            ..
        } => Err(JmcpError::Validation(format!(
            "commit failed: {}",
            details.as_deref().unwrap_or("no details")
        ))),
        CommitOutcome::Indeterminate { reason } => Err(JmcpError::Validation(format!(
            "commit outcome indeterminate, manual reconciliation required: {reason}"
        ))),
        CommitOutcome::Detached { job_id } => Ok(json!({
            "change_set_id": args.change_set_id,
            "operation_id": result.operation_id,
            "state": "Committing",
            "commit_outcome": "Detached",
            "job_id": job_id,
            "message": "commit detached, poll for completion"
        })),
        CommitOutcome::AwaitingConfirmation {
            rollback_deadline_unix,
            details,
            ..
        } => Ok(json!({
            "change_set_id": args.change_set_id,
            "operation_id": result.operation_id,
            "state": "AwaitingConfirmation",
            "commit_outcome": "AwaitingConfirmation",
            "rollback_deadline_unix": rollback_deadline_unix,
            "details": details,
            "message": "commit awaiting confirmation; auto-rollback pending"
        })),
    }
}

/// Confirm a provisional commit before the device rolls it back.
///
/// # Who may confirm
///
/// The **owner** — the principal that applied the change set — not the
/// approver. Authorization already happened at approval: a second principal
/// signed off on this exact plan, and `apply` executed it. Confirming does not
/// change what was approved; it stops the safety timer on a change that is
/// already live. That is execution, and execution is the owner's half of the
/// two-person split throughout this server (the approver's token cannot apply
/// either).
///
/// Requiring the approver here would also mean a change silently reverting
/// because the reviewer had gone home, which turns a safety feature into an
/// outage.
pub async fn confirm_change_set(
    args: ConfirmChangeSetArgs,
    dm: Arc<DeviceManager>,
    coordinator: Arc<ChangesetCoordinator>,
    attribution: Attribution,
) -> Result<Value, JmcpError> {
    let inventory = dm.inventory();
    inventory.get(&args.device)?;

    let principal = attribution.principal.to_string();

    // Scoped to (operation, principal, device), so one caller cannot confirm
    // another's provisional commit.
    let record = coordinator
        .record(&args.operation_id, &principal, &args.device)
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    let Some(deadline) = record.rollback_deadline_unix else {
        return Err(JmcpError::Validation(format!(
            "operation {} has no pending confirmation; it was not committed with a \
             confirm window",
            args.operation_id
        )));
    };

    // Report an expired window rather than issuing a confirming commit that
    // would land on whatever the device rolled back to. The operator needs to
    // know the change is already gone.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
    if now >= deadline {
        return Err(JmcpError::Validation(format!(
            "the confirmation window for operation {} closed at {deadline}; the device \
             has already rolled the change back",
            args.operation_id
        )));
    }

    let transaction = JunosTransaction::new(dm.clone(), args.device.clone());
    let outcome = transaction
        .confirm_commit(&args.operation_id, &attribution)
        .await?;

    use mecmcp_changeset::CommitOutcome;
    match outcome {
        CommitOutcome::Reconciled {
            succeeded: true,
            details,
            ..
        } => {
            let mut confirmed = record;
            confirmed.state = mecmcp_changeset::LifecycleState::Committed;
            confirmed.rollback_deadline_unix = None;
            confirmed.details = details.clone();
            coordinator
                .update(confirmed)
                .await
                .map_err(|e| JmcpError::Validation(e.to_string()))?;

            Ok(json!({
                "operation_id": args.operation_id,
                "device": args.device,
                "state": "Committed",
                "details": details,
                "message": "confirming commit accepted; the automatic rollback is cancelled"
            }))
        }
        other => Ok(json!({
            "operation_id": args.operation_id,
            "device": args.device,
            "state": "Committing",
            "commit_outcome": format!("{other:?}"),
            "rollback_deadline_unix": deadline,
            "message": "the confirming commit did not report success; the rollback timer is still running"
        })),
    }
}

/// Get the status of a change set.
pub async fn get_change_set_status(
    args: GetChangeSetStatusArgs,
    coordinator: Arc<ChangesetCoordinator>,
) -> Result<Value, JmcpError> {
    let status = coordinator
        .change_set_status(args.change_set_id, args.device)
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    // Serialize the full status structure.
    serde_json::to_value(status).map_err(|e| JmcpError::Validation(e.to_string()))
}

/// Arguments for `get_junos_candidate_fingerprint`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CandidateFingerprintArgs {
    /// Target device name.
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
}

/// Read the device's candidate fingerprint.
///
/// This seeds the change-set flow. `create_junos_change_set` requires an
/// `expected_fingerprint` so the plan is bound to the exact candidate it was
/// reviewed against — and without this tool there was no way to obtain one, so
/// the whole workflow was unreachable from MCP (#231).
///
/// The value comes from `DeviceTransaction::fingerprint`, the same code the
/// coordinator compares against at apply time, so it round-trips unchanged.
/// It is a read: no lock is taken and the candidate is not modified.
pub async fn get_candidate_fingerprint(
    args: CandidateFingerprintArgs,
    dm: Arc<DeviceManager>,
) -> Result<Value, JmcpError> {
    let transaction = JunosTransaction::new(dm, args.device.clone());
    let fingerprint = transaction
        .fingerprint()
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    Ok(json!({
        "device": args.device,
        "candidate_fingerprint": fingerprint,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use crate::junos_transaction::ConfigPayloadSpec;
    use mecmcp_audit::{ActorType, Attribution, Principal};
    use std::io::Write;
    use tempfile::TempDir;

    fn inv_with(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    fn test_attribution(principal: &str) -> Attribution {
        Attribution {
            principal: Principal::Token(principal.into()),
            actor_type: ActorType::Human,
            agent: None,
            on_behalf_of: None,
            change_ref: Some("TEST-001".into()),
            request_id: uuid::Uuid::new_v4(),
            token_verified_fields: mecmcp_audit::TokenVerifiedFields::none(),
        }
    }

    fn test_policy(inv: Arc<Inventory>) -> Arc<Policy> {
        Arc::new(Policy::build(&inv).unwrap())
    }

    #[tokio::test]
    async fn create_change_set_unknown_device_fails() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = Arc::new(
            ChangesetCoordinator::load(
                Some(&state_dir.path().join("changeset-state.json")),
                mecmcp_changeset::OperationLimits::default(),
                std::time::Duration::from_secs(300),
                false,
            )
            .unwrap(),
        );

        let r =
            create_change_set(
                CreateChangeSetArgs {
                    device: "nope".into(),
                    expected_fingerprint:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .into(),
                    actions: vec![],
                },
                dm.clone(),
                coordinator,
                policy,
                test_attribution("alice"),
            )
            .await;

        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn approve_change_set_by_same_principal_fails() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = Arc::new(
            ChangesetCoordinator::load(
                Some(&state_dir.path().join("changeset-state.json")),
                mecmcp_changeset::OperationLimits::default(),
                std::time::Duration::from_secs(300),
                false,
            )
            .unwrap(),
        );

        // Create a change set as alice.
        let action = JunosAction {
            payload: Some(ConfigPayloadSpec {
                text: "set system host-name test".into(),
                format: Some("set".into()),
            }),
            rollback_source: None,
        };
        let create_result =
            create_change_set(
                CreateChangeSetArgs {
                    device: "r1".into(),
                    expected_fingerprint:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .into(),
                    actions: vec![action],
                },
                dm.clone(),
                coordinator.clone(),
                policy,
                test_attribution("alice"),
            )
            .await
            .unwrap();

        let change_set_id = create_result["change_set_id"].as_str().unwrap();
        let plan_digest = create_result["plan_digest"].as_str().unwrap();

        // Try to approve as alice (the owner). Should fail.
        let r = approve_change_set(
            ApproveChangeSetArgs {
                change_set_id: change_set_id.into(),
                device: "r1".into(),
                expected_digest: plan_digest.into(),
            },
            coordinator.clone(),
            dm.clone(),
            test_attribution("alice"),
        )
        .await;

        assert!(r.is_err());
        let err_str = r.unwrap_err().to_string();
        // The coordinator enforces separation of duties; assert on what it
        // actually says so this test fails if that check is ever removed.
        assert!(
            err_str.contains("owner cannot approve their own plan"),
            "self-approval must be refused, got: {err_str}"
        );
    }

    #[tokio::test]
    async fn create_approve_status_flow() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = Arc::new(
            ChangesetCoordinator::load(
                Some(&state_dir.path().join("changeset-state.json")),
                mecmcp_changeset::OperationLimits::default(),
                std::time::Duration::from_secs(300),
                false,
            )
            .unwrap(),
        );

        // Create.
        let action = JunosAction {
            payload: Some(ConfigPayloadSpec {
                text: "set system host-name test".into(),
                format: Some("set".into()),
            }),
            rollback_source: None,
        };
        let create_result =
            create_change_set(
                CreateChangeSetArgs {
                    device: "r1".into(),
                    expected_fingerprint:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .into(),
                    actions: vec![action],
                },
                dm.clone(),
                coordinator.clone(),
                policy,
                test_attribution("alice"),
            )
            .await
            .unwrap();

        let change_set_id = create_result["change_set_id"].as_str().unwrap();
        let plan_digest = create_result["plan_digest"].as_str().unwrap();
        assert_eq!(create_result["state"].as_str().unwrap(), "Planned");

        // Approve by a second principal.
        let approve_result = approve_change_set(
            ApproveChangeSetArgs {
                change_set_id: change_set_id.into(),
                device: "r1".into(),
                expected_digest: plan_digest.into(),
            },
            coordinator.clone(),
            dm.clone(),
            test_attribution("bob"),
        )
        .await
        .unwrap();

        assert_eq!(approve_result["state"].as_str().unwrap(), "Approved");

        // Get status.
        let status_result = get_change_set_status(
            GetChangeSetStatusArgs {
                change_set_id: change_set_id.into(),
                device: "r1".into(),
            },
            coordinator.clone(),
        )
        .await
        .unwrap();

        // The lifecycle state serializes lowercase.
        assert_eq!(status_result["state"].as_str().unwrap(), "approved");
        assert_eq!(status_result["owner"].as_str().unwrap(), "alice");
    }
}
