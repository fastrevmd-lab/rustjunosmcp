//! `get_junos_config` — return full or scoped text-format running config.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::{
    excerpt, strip_config_xml_wrapper, validate_config_path, validate_input_length,
};
use crate::policy::{Decision, Policy};
use crate::tools::GetConfigArgs;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

pub async fn handle(
    args: GetConfigArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
) -> Result<Value, JmcpError> {
    // Validate config_path if provided
    if let Some(ref path) = args.config_path {
        validate_input_length("config_path", path)?;
        validate_config_path(path)?;
    }

    // Fail fast on unknown devices so the policy check has a valid target.
    let _ = dm.inventory().get(&args.device)?;

    // Build command: "show configuration" or "show configuration <path>"
    let command = match &args.config_path {
        Some(path) if !path.trim().is_empty() => {
            format!("show configuration {}", path.trim())
        }
        _ => "show configuration".to_string(),
    };

    // Check command against policy (same as execute_junos_command)
    if let Decision::Deny { rule, source, .. } = policy.check_command(&args.device, &command) {
        let pattern = rule.pattern.clone();
        let source_str = source.as_str();
        tracing::warn!(
            tool = "get_junos_config",
            router = %args.device,
            matched_rule = %pattern,
            rule_source = %source_str,
            input_excerpt = %excerpt(&command),
            "blocklist denied request",
        );
        return Err(JmcpError::Denied {
            tool: "get_junos_config",
            router: args.device.clone(),
            pattern,
            rule_source: source_str,
            input_excerpt: excerpt(&command),
            line_number: None,
        });
    }

    let timeout = Duration::from_secs(args.timeout);
    let result = tokio::time::timeout(timeout, async {
        let mut dev = dm.open(&args.device).await?;
        let cfg_text = dev.cli(&command).await?;
        Ok::<_, JmcpError>(cfg_text)
    })
    .await
    .map_err(|_| JmcpError::Timeout(timeout))??;
    Ok(json!(strip_config_xml_wrapper(&result)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use crate::policy::Policy;
    use std::io::Write;

    fn test_inventory() -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        )
        .unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    fn test_policy() -> Arc<Policy> {
        let inv = test_inventory();
        Arc::new(Policy::build(&inv).unwrap())
    }

    #[tokio::test]
    async fn unknown_router_propagates_error() {
        let inv = test_inventory();
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            GetConfigArgs {
                device: "nope".into(),
                timeout: 5,
                config_path: None,
            },
            dm,
            policy,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[test]
    fn config_path_none_is_backward_compatible() {
        // Existing callers that omit config_path must get identical behavior.
        // This test verifies that GetConfigArgs can be deserialized without the field.
        let json = r#"{"device": "r1", "timeout": 30}"#;
        let args: GetConfigArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.device, "r1");
        assert_eq!(args.timeout, 30);
        assert!(args.config_path.is_none());
    }

    #[test]
    fn config_path_with_value_is_preserved() {
        let json = r#"{"device": "r1", "timeout": 30, "config_path": "system services"}"#;
        let args: GetConfigArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.config_path, Some("system services".to_string()));
    }

    #[tokio::test]
    async fn config_path_exceeding_max_length_is_rejected() {
        // config_path over MAX_INPUT_LEN (1 MB) should fail validation
        let huge_path = "a".repeat(1_048_577); // 1 byte over limit
        let inv = test_inventory();
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy();

        let result = handle(
            GetConfigArgs {
                device: "r1".into(),
                timeout: 5,
                config_path: Some(huge_path),
            },
            dm,
            policy,
        )
        .await;

        assert!(matches!(result, Err(JmcpError::InventoryInvalid(_))));
    }

    #[tokio::test]
    async fn injection_pipe_to_save_is_rejected() {
        let inv = test_inventory();
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy();

        let result = handle(
            GetConfigArgs {
                device: "r1".into(),
                timeout: 5,
                config_path: Some("system services | save /tmp/x".to_string()),
            },
            dm,
            policy,
        )
        .await;

        match result {
            Err(JmcpError::Validation(msg)) => {
                assert!(
                    msg.contains("pipe operator"),
                    "expected pipe rejection, got: {msg}"
                );
            }
            other => panic!("expected Validation error for pipe, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn injection_semicolon_is_rejected() {
        let inv = test_inventory();
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy();

        let result = handle(
            GetConfigArgs {
                device: "r1".into(),
                timeout: 5,
                config_path: Some("foo; bar".to_string()),
            },
            dm,
            policy,
        )
        .await;

        match result {
            Err(JmcpError::Validation(msg)) => {
                assert!(
                    msg.contains("semicolon"),
                    "expected semicolon rejection, got: {msg}"
                );
            }
            other => panic!("expected Validation error for semicolon, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn injection_embedded_newline_is_rejected() {
        let inv = test_inventory();
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy();

        let result = handle(
            GetConfigArgs {
                device: "r1".into(),
                timeout: 5,
                config_path: Some("system\nservices".to_string()),
            },
            dm,
            policy,
        )
        .await;

        match result {
            Err(JmcpError::Validation(msg)) => {
                assert!(
                    msg.contains("newline"),
                    "expected newline rejection, got: {msg}"
                );
            }
            other => panic!("expected Validation error for newline, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn injection_leading_newline_is_rejected() {
        let inv = test_inventory();
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy();

        let result = handle(
            GetConfigArgs {
                device: "r1".into(),
                timeout: 5,
                config_path: Some("\nsystem services".to_string()),
            },
            dm,
            policy,
        )
        .await;

        match result {
            Err(JmcpError::Validation(msg)) => {
                assert!(
                    msg.contains("newline"),
                    "expected newline rejection, got: {msg}"
                );
            }
            other => panic!(
                "expected Validation error for leading newline, got {:?}",
                other
            ),
        }
    }

    /// The policy check at the top of `handle` is the second half of the fix for
    /// the injection defect: the allowlist stops shell metacharacters, and this
    /// stops a *syntactically valid* path that a site has chosen to deny.
    ///
    /// Without a test the wiring can be deleted and every other test still
    /// passes — the default blocklist cannot deny anything reachable from a
    /// `show configuration ` prefix, so only a per-device rule exercises it.
    #[tokio::test]
    async fn config_path_forming_a_blocklisted_command_is_denied_by_policy() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"},
                  "blocklist":{"commands":[{"action":"deny","pattern":"show configuration secret*"}]}}
        }"#,
        )
        .unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = Arc::new(Policy::build(&inv).unwrap());

        let result = handle(
            GetConfigArgs {
                device: "r1".into(),
                timeout: 5,
                // Passes the allowlist cleanly — no metacharacters at all.
                config_path: Some("secrets".to_string()),
            },
            dm,
            policy,
        )
        .await;

        match result {
            Err(JmcpError::Denied { .. }) => {}
            other => panic!(
                "a denied config_path must be rejected by the policy, not sent \
                 to the device. got: {other:?}"
            ),
        }
    }
}
