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

    // Apply the same output caps the operational-command tools honour. Without
    // them a caller that asks for a bounded response has no way to get one, and
    // a full `show configuration` is large enough to matter (#253). Caps are
    // applied after the XML wrapper is stripped so a line budget counts
    // configuration lines, not markup.
    let stripped = strip_config_xml_wrapper(&result);
    let capped = crate::output::process_output(
        &command,
        stripped,
        args.max_lines,
        args.max_bytes,
        args.tail,
    );
    Ok(json!(capped))
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
                max_lines: None,
                max_bytes: None,
                tail: false,
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

    /// #253: `filter` is the name callers reach for. It used to be dropped
    /// silently, and the caller got the whole configuration — `## SECRET-DATA`
    /// included — in place of the one stanza they asked for.
    #[test]
    fn filter_is_accepted_as_an_alias_for_config_path() {
        let args: GetConfigArgs =
            serde_json::from_str(r#"{"device": "r1", "filter": "routing-options"}"#).unwrap();
        assert_eq!(args.config_path, Some("routing-options".to_string()));
    }

    /// The general form of #253: an argument this tool does not understand must
    /// be an error, because the fallback is "return everything", and everything
    /// includes credential material the caller did not ask for. Failing closed
    /// is the whole point.
    #[test]
    fn an_unknown_argument_is_rejected_rather_than_ignored() {
        let err = serde_json::from_str::<GetConfigArgs>(
            r#"{"device": "r1", "stanza": "routing-options"}"#,
        )
        .expect_err("an unrecognised argument must not be silently dropped");

        assert!(
            err.to_string().contains("stanza"),
            "the error must name the field the caller got wrong, got: {err}"
        );
    }

    #[test]
    fn output_caps_are_accepted() {
        let args: GetConfigArgs = serde_json::from_str(
            r#"{"device": "r1", "max_lines": 25, "max_bytes": 4096, "tail": true}"#,
        )
        .unwrap();
        assert_eq!(args.max_lines, Some(25));
        assert_eq!(args.max_bytes, Some(4096));
        assert!(args.tail);
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
                max_lines: None,
                max_bytes: None,
                tail: false,
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
                max_lines: None,
                max_bytes: None,
                tail: false,
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
                max_lines: None,
                max_bytes: None,
                tail: false,
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
                max_lines: None,
                max_bytes: None,
                tail: false,
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
                max_lines: None,
                max_bytes: None,
                tail: false,
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
                max_lines: None,
                max_bytes: None,
                tail: false,
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
