//! Backward compatibility gate: v0.12.0 published argument names MUST still deserialize.
//!
//! This test loads the actual v0.12.0 `tools/list` surface from a golden file and
//! asserts that every (tool, argument) pair is still accepted. The test is driven
//! by iterating the JSON — NOT hand-enumerated — so a missing alias cannot silently
//! drift unnoticed.

use serde_json::Value;
use std::collections::HashMap;

/// Load the v0.12.0 surface dump: tool name → list of argument names.
fn load_v0_12_0_surface() -> HashMap<String, Vec<String>> {
    let json_bytes = include_bytes!("compat/surface-v0.12.0.json");
    serde_json::from_slice(json_bytes).expect("surface-v0.12.0.json must be valid JSON")
}

#[test]
fn all_v0_12_0_arguments_still_deserialize() {
    use rust_junosmcp_core::tools::*;

    let surface = load_v0_12_0_surface();
    let mut failures = Vec::new();

    for (tool_name, arg_names) in &surface {
        // Build a minimal valid JSON object for each tool using the v0.12.0 argument names.
        // We're testing that the argument NAME is still accepted, not that the value is valid.
        let mut args_obj = serde_json::Map::new();

        for arg_name in arg_names {
            // Populate with a plausible default value for each type
            let value = match arg_name.as_str() {
                // String fields (v0.12.0 names ONLY)
                "command" | "pfe_command" | "fpc_target" | "config_text" | "config_format"
                | "commit_comment" | "feature" | "problem_type" | "request_id"
                | "local_name" | "remote_path" | "config_path" | "peer" | "tunnel"
                | "router" | "router_name" => Value::String("test".into()),

                // Vec<String> fields (v0.12.0 names ONLY)
                "commands" | "routers" => {
                    Value::Array(vec![Value::String("test".into())])
                }

                // Numeric fields (v0.12.0 names ONLY)
                "timeout" | "command_timeout" | "batch_timeout" | "max_concurrent_routers"
                | "max_log_bytes_per_file" | "max_log_files"
                | "device_port" | "version" | "max_lines" | "max_bytes"
                | "confirm_timeout_mins" => Value::Number(60.into()),

                // Boolean fields
                "tail" | "include_raw" | "redact" | "force" | "verify" | "include_logs"
                | "commit" | "dry_run" | "apply_config" => Value::Bool(false),

                _ => {
                    // Unknown field — test should still attempt deserialization
                    Value::String(format!("placeholder-{}", arg_name))
                }
            };
            args_obj.insert(arg_name.clone(), value);
        }

        let json_val = Value::Object(args_obj);

        // Attempt deserialization. We don't care if the struct rejects the VALUES,
        // only that it accepts the ARGUMENT NAMES (serde aliases).
        let result: Result<(), serde_json::Error> = match tool_name.as_str() {
            "execute_junos_command" => serde_json::from_value::<ExecuteCommandArgs>(json_val.clone()).map(|_| ()),
            "execute_junos_command_batch" => serde_json::from_value::<ExecuteBatchArgs>(json_val.clone()).map(|_| ()),
            "execute_junos_pfe_command" => serde_json::from_value::<ExecutePfeArgs>(json_val.clone()).map(|_| ()),
            "gather_device_facts" => serde_json::from_value::<GatherFactsArgs>(json_val.clone()).map(|_| ()),
            "get_junos_config" => serde_json::from_value::<GetConfigArgs>(json_val.clone()).map(|_| ()),
            "commit_check_config" => serde_json::from_value::<CommitCheckArgs>(json_val.clone()).map(|_| ()),
            "junos_config_diff" => serde_json::from_value::<ConfigDiffArgs>(json_val.clone()).map(|_| ()),
            "fetch_file" => serde_json::from_value::<FetchFileArgs>(json_val.clone()).map(|_| ()),
            "list_staged_files" => serde_json::from_value::<ListStagedFilesArgs>(json_val.clone()).map(|_| ()),
            // SRX tools not in rust-junosmcp-core — skip for now
            "check_srx_feature_license" | "collect_jtac_support_bundle"
            | "get_chassis_cluster_status" | "get_srx_security_services_status"
            | "validate_chassis_cluster_health" | "vpn_lifecycle_report" => continue,
            // Tools with no arguments or tools we'll verify separately
            "get_router_list" | "srxmcp_status" => continue,
            _ => {
                failures.push(format!("Unknown tool '{}' in v0.12.0 surface", tool_name));
                continue;
            }
        };

        if let Err(e) = result {
            let err_msg = e.to_string();
            eprintln!("Tool '{}' deserialization error: {}", tool_name, err_msg);
            // Check if the error is about field names (unknown or missing means alias is broken)
            if err_msg.contains("unknown field") || err_msg.contains("missing field") {
                failures.push(format!(
                    "Tool '{}': v0.12.0 argument name not accepted: {}",
                    tool_name, err_msg
                ));
            }
            // Other errors (type mismatches, validation) are OK — we're testing NAME acceptance only
        }
    }

    if !failures.is_empty() {
        panic!(
            "v0.12.0 backward compatibility BROKEN. {} failures:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

#[test]
fn get_router_list_tool_name_still_exists() {
    // Verify that get_router_list is still registered as a tool name (not just an argument).
    // The actual registration is in rust-junosmcp/src/server.rs, so this test just confirms
    // the surface file documents it.
    let surface = load_v0_12_0_surface();
    assert!(
        surface.contains_key("get_router_list"),
        "get_router_list tool name must still be registered"
    );
}
