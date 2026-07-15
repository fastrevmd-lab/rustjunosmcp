//! Router-target extraction and per-router concurrency primitives.

use serde_json::Value;
use std::collections::BTreeSet;

const ROUTER_KEYS: [&str; 4] = ["router", "router_name", "routers", "router_names"];

/// Return sorted, unique, exact router names from top-level `tools/call`
/// arguments. Invalid protocol input is left for rmcp to diagnose.
pub(crate) fn extract_router_targets(body: &[u8]) -> Vec<String> {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };

    let mut targets = BTreeSet::new();
    match &value {
        Value::Array(requests) => {
            for request in requests {
                collect_request_targets(request, &mut targets);
            }
        }
        request => collect_request_targets(request, &mut targets),
    }
    targets.into_iter().collect()
}

fn collect_request_targets(request: &Value, targets: &mut BTreeSet<String>) {
    let Some(request) = request.as_object() else {
        return;
    };
    if request.get("method").and_then(Value::as_str) != Some("tools/call") {
        return;
    }
    let Some(arguments) = request
        .get("params")
        .and_then(Value::as_object)
        .and_then(|params| params.get("arguments"))
        .and_then(Value::as_object)
    else {
        return;
    };

    for key in ROUTER_KEYS {
        if let Some(value) = arguments.get(key) {
            collect_field_targets(value, targets);
        }
    }
}

fn collect_field_targets(value: &Value, targets: &mut BTreeSet<String>) {
    match value {
        Value::String(router) => {
            targets.insert(router.clone());
        }
        Value::Array(routers) => {
            targets.extend(routers.iter().filter_map(Value::as_str).map(str::to_owned));
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::extract_router_targets;

    #[test]
    fn extracts_supported_keys_from_single_and_batched_calls() {
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"one","arguments":{"router":"r4"}}},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"two","arguments":{"router_name":"r3"}}},
            {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"three","arguments":{"routers":["r2","r1"]}}},
            {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"four","arguments":{"router_names":"r5"}}}
        ]"#;

        assert_eq!(
            extract_router_targets(body),
            vec!["r1", "r2", "r3", "r4", "r5"]
        );
    }

    #[test]
    fn deduplicates_exact_names_and_sorts_them() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"batch","arguments":{"router":"b","router_name":"a","routers":["b","a","c"]}}}"#;
        assert_eq!(extract_router_targets(body), vec!["a", "b", "c"]);
    }

    #[test]
    fn ignores_non_tools_calls_nested_keys_invalid_types_and_malformed_json() {
        let non_tool = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"arguments":{"router":"r1"}}}"#;
        let nested = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"payload":{"router":"nested"},"router":17,"routers":[false,42]}}}"#;

        assert!(extract_router_targets(non_tool).is_empty());
        assert!(extract_router_targets(nested).is_empty());
        assert!(extract_router_targets(b"not-json").is_empty());
    }

    #[test]
    fn preserves_exact_case_and_whitespace() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"routers":["SRX-1","srx-1"," srx-1 "]}}}"#;
        assert_eq!(
            extract_router_targets(body),
            vec![" srx-1 ", "SRX-1", "srx-1"]
        );
    }
}
