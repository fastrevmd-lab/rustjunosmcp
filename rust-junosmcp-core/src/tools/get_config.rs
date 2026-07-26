//! `get_junos_config` — return full or scoped text-format running config.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::{strip_config_xml_wrapper, validate_input_length};
use crate::tools::GetConfigArgs;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

pub async fn handle(args: GetConfigArgs, dm: Arc<DeviceManager>) -> Result<Value, JmcpError> {
    // Validate config_path length if provided
    if let Some(ref path) = args.config_path {
        validate_input_length("config_path", path)?;
    }

    let timeout = Duration::from_secs(args.timeout);
    let result = tokio::time::timeout(timeout, async {
        let mut dev = dm.open(&args.router_name).await?;

        // Build command: "show configuration" or "show configuration <path>"
        let command = match &args.config_path {
            Some(path) if !path.trim().is_empty() => {
                format!("show configuration {}", path.trim())
            }
            _ => "show configuration".to_string(),
        };

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
            GetConfigArgs {
                router_name: "nope".into(),
                timeout: 5,
                config_path: None,
            },
            dm,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[test]
    fn config_path_none_is_backward_compatible() {
        // Existing callers that omit config_path must get identical behavior.
        // This test verifies that GetConfigArgs can be deserialized without the field.
        let json = r#"{"router_name": "r1", "timeout": 30}"#;
        let args: GetConfigArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.router_name, "r1");
        assert_eq!(args.timeout, 30);
        assert!(args.config_path.is_none());
    }

    #[test]
    fn config_path_empty_string_treated_as_none() {
        let json = r#"{"router_name": "r1", "timeout": 30, "config_path": ""}"#;
        let args: GetConfigArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.config_path, Some("".to_string()));
        // The handle function will trim and use full config for empty strings
    }

    #[test]
    fn config_path_with_value_is_preserved() {
        let json = r#"{"router_name": "r1", "timeout": 30, "config_path": "system services"}"#;
        let args: GetConfigArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.config_path, Some("system services".to_string()));
    }

    #[test]
    fn config_path_exceeding_max_length_is_rejected() {
        // config_path over MAX_INPUT_LEN (1 MB) should fail validation
        let huge_path = "a".repeat(1_048_577); // 1 byte over limit
        let inv = Arc::new(Inventory::empty());
        let dm = Arc::new(DeviceManager::new(inv));

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(handle(
            GetConfigArgs {
                router_name: "r1".into(),
                timeout: 5,
                config_path: Some(huge_path),
            },
            dm,
        ));

        assert!(matches!(result, Err(JmcpError::InventoryInvalid(_))));
    }
}
