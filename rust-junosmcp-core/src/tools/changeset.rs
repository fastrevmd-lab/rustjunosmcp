//! Junos change-set lifecycle tools — two-person approval for multi-action plans.
//!
//! This module provides the MCP tool implementations for the change-set flow:
//! create → approve (by a second principal) → apply. It wraps the coordinator
//! from `mecmcp-changeset` and uses `JunosTransaction` as the device backend.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::junos_transaction::{JunosAction, JunosTransaction};
use mecmcp_audit::Attribution;
use mecmcp_changeset::{ChangesetCoordinator, CommitOptions};
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
    /// The principal creating this change set. Usually extracted from the
    /// bearer token context. Required for approval enforcement.
    pub owner: String,
    /// Expected device fingerprint before applying. If the device state
    /// changes after planning, application will be rejected.
    pub expected_fingerprint: String,
    /// List of actions to stage. Each action is either a payload or a
    /// rollback archive reference.
    pub actions: Vec<JunosAction>,
    /// Optional approval window in seconds. Defaults to coordinator's
    /// configured window if omitted.
    #[serde(default)]
    pub approval_timeout_secs: Option<u64>,
}

/// Arguments for `approve_junos_change_set`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ApproveChangeSetArgs {
    /// Change-set ID returned by create.
    pub change_set_id: String,
    /// The principal approving this change set. Must be different from the
    /// owner. Usually extracted from the bearer token context.
    pub approver: String,
    /// Expected plan digest. The approver must compute or be shown the exact
    /// digest and confirm it matches what they reviewed.
    pub expected_digest: String,
}

/// Arguments for `apply_junos_change_set`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ApplyChangeSetArgs {
    /// Change-set ID to apply.
    pub change_set_id: String,
    /// The principal applying. Should match the original owner.
    pub principal: String,
    /// Expected plan digest. Prevents applying a plan that was tampered with
    /// after approval.
    pub expected_digest: String,
    /// Expected device fingerprint at apply time. If the device changed after
    /// the plan was created, the apply is rejected.
    pub expected_fingerprint: String,
    /// Target device endpoint (device name from inventory).
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
    attribution: Attribution,
) -> Result<Value, JmcpError> {
    create_change_set_with_cancel(args, dm, coordinator, attribution, CancellationToken::new())
        .await
}

pub async fn create_change_set_with_cancel(
    args: CreateChangeSetArgs,
    dm: Arc<DeviceManager>,
    coordinator: Arc<ChangesetCoordinator>,
    _attribution: Attribution,
    _ct: CancellationToken,
) -> Result<Value, JmcpError> {
    // Validate the device exists.
    let _ = dm.inventory().get(&args.device)?;

    // The coordinator's create_change_set computes the digest over
    // (owner, device, expected_fingerprint, actions). It persists the plan
    // and returns the change_set_id and plan_digest.
    // Policy signature placeholder - Junos doesn't have a policy signature
    // concept exposed in this crate yet.
    let policy_signature = "junos-default-v1".to_string();

    let result = coordinator
        .create_change_set(
            args.device,
            args.actions,
            args.owner,
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
    _attribution: Attribution,
    _ct: CancellationToken,
) -> Result<Value, JmcpError> {
    // We need the device name to look up the change set. In the current API, we have to
    // try all devices or require the caller to provide it. For now, let's add device
    // to ApproveChangeSetArgs.
    // TEMPORARY: Since we need to add device to args anyway, let's do that.
    // Actually, looking at the API, the approver needs to know which device they're
    // approving a change for. So adding device to args makes sense.
    // But that's a breaking change to the tool signature. For now, let's try each device
    // in the inventory until we find the changeset.
    let mut found_device = None;
    for device_name in dm.inventory().names() {
        if let Ok(_status) = coordinator
            .change_set_status(args.change_set_id.clone(), device_name.clone())
            .await
        {
            found_device = Some(device_name.clone());
            break;
        }
    }

    let device = found_device.ok_or_else(|| {
        JmcpError::Validation(format!(
            "change set {} not found on any device",
            args.change_set_id
        ))
    })?;

    let result = coordinator
        .approve_change_set(
            args.change_set_id.clone(),
            device,
            args.approver,
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
    attribution: Attribution,
) -> Result<Value, JmcpError> {
    apply_change_set_with_cancel(args, dm, coordinator, attribution, CancellationToken::new()).await
}

pub async fn apply_change_set_with_cancel(
    args: ApplyChangeSetArgs,
    dm: Arc<DeviceManager>,
    coordinator: Arc<ChangesetCoordinator>,
    attribution: Attribution,
    ct: CancellationToken,
) -> Result<Value, JmcpError> {
    // Validate the device exists.
    let _ = dm.inventory().get(&args.device)?;

    // Build the transaction backend.
    let transaction = JunosTransaction::new(dm.clone(), args.device.clone());

    // For Junos, there is no XPath equivalent, so the primary target is None.
    // The primary action discriminator: we use "merge" as the default for
    // Junos config load operations (cfg.load() merges by default).
    let primary_action = "merge";
    let primary_target: Option<&str> = None;

    // The endpoint is the device name for Junos (used for guard locking).
    let endpoint = args.device.clone();

    let result = coordinator
        .apply_change_set(
            args.change_set_id.clone(),
            args.device.clone(),
            endpoint,
            args.principal.clone(),
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
    // handle. The caller (this tool) must then commit.
    // Policy signature for commit - same as what we use for staging.
    let policy_signature = "junos-default-v1";

    let commit_result = coordinator
        .commit_operation(
            &result.operation_id,
            &args.device,
            &args.principal,
            &result.after_fingerprint,
            policy_signature,
            &transaction,
            &result.staged,
            &attribution,
            &CommitOptions::default(),
            &ct,
        )
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    Ok(json!({
        "change_set_id": args.change_set_id,
        "operation_id": result.operation_id,
        "state": "Applied",
        "commit_outcome": format!("{:?}", commit_result),
        "message": "change set applied and committed"
    }))
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

    #[tokio::test]
    async fn create_change_set_unknown_device_fails() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
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
                    owner: "alice".into(),
                    expected_fingerprint:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .into(),
                    actions: vec![],
                    approval_timeout_secs: None,
                },
                dm.clone(),
                coordinator,
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
        let dm = Arc::new(DeviceManager::new(inv));
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
                    owner: "alice".into(),
                    expected_fingerprint:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .into(),
                    actions: vec![action],
                    approval_timeout_secs: None,
                },
                dm.clone(),
                coordinator.clone(),
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
                approver: "alice".into(),
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
        let dm = Arc::new(DeviceManager::new(inv));
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
                    owner: "alice".into(),
                    expected_fingerprint:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .into(),
                    actions: vec![action],
                    approval_timeout_secs: None,
                },
                dm.clone(),
                coordinator.clone(),
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
                approver: "bob".into(),
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
