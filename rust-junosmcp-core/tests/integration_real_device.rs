//! Real-device integration tests. `#[ignore]`'d by default; run with:
//!
//! ```text
//! JMCP_TEST_HOST=10.0.0.1 JMCP_TEST_USER=admin JMCP_TEST_PASS=secret \
//!   cargo test -p rust-junosmcp-core --test integration_real_device -- --ignored
//! ```

use rust_junosmcp_core::{
    DeviceManager, Inventory,
    tools::{
        ConfigDiffArgs, ExecuteCommandArgs, GatherFactsArgs, GetConfigArgs,
        config_diff, execute_command, facts, get_config, router_list,
    },
};
use std::io::Write;
use std::sync::Arc;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing env var {name}"))
}

fn build_dm() -> Arc<DeviceManager> {
    let host = env("JMCP_TEST_HOST");
    let user = env("JMCP_TEST_USER");
    let pass = env("JMCP_TEST_PASS");
    let json = format!(r#"{{
        "lab":{{"ip":"{host}","username":"{user}",
                "auth":{{"type":"password","password":"{pass}"}}}}
    }}"#);
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(json.as_bytes()).unwrap();
    let inv = Arc::new(Inventory::load(f.path()).unwrap());
    Arc::new(DeviceManager::new(inv))
}

#[tokio::test]
#[ignore]
async fn router_list_returns_lab() {
    // Inventory was built above; we exercise the handler against it.
    let inv = {
        let host = env("JMCP_TEST_HOST");
        let user = env("JMCP_TEST_USER");
        let pass = env("JMCP_TEST_PASS");
        let json = format!(r#"{{
            "lab":{{"ip":"{host}","username":"{user}",
                    "auth":{{"type":"password","password":"{pass}"}}}}
        }}"#);
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    };
    let v = router_list::handle(inv).await.unwrap();
    assert_eq!(v, serde_json::json!(["lab"]));
}

#[tokio::test]
#[ignore]
async fn execute_show_version() {
    let dm = build_dm();
    let v = execute_command::handle(
        ExecuteCommandArgs {
            router_name: "lab".into(),
            command: "show version".into(),
            timeout: 30,
        },
        dm,
    ).await.unwrap();
    assert!(v.as_str().unwrap().contains("Junos") || v.as_str().unwrap().contains("Hostname"));
}

#[tokio::test]
#[ignore]
async fn get_running_config() {
    let dm = build_dm();
    let v = get_config::handle(
        GetConfigArgs { router_name: "lab".into() },
        dm,
    ).await.unwrap();
    let body = v.as_str().unwrap();
    assert!(!body.is_empty());
    assert!(body.contains("system") || body.contains("version"));
}

#[tokio::test]
#[ignore]
async fn diff_against_rollback_1() {
    let dm = build_dm();
    let v = config_diff::handle(
        ConfigDiffArgs { router_name: "lab".into(), version: 1 },
        dm,
    ).await.unwrap();
    assert!(v.is_string());
}

#[tokio::test]
#[ignore]
async fn gather_facts() {
    let dm = build_dm();
    let v = facts::handle(
        GatherFactsArgs { router_name: "lab".into(), timeout: 30 },
        dm,
    ).await.unwrap();
    assert!(v.get("hostname").is_some());
    assert!(v.get("version").is_some());
}
