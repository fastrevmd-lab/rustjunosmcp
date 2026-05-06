//! Real-device integration tests. `#[ignore]`'d by default; run with:
//!
//! ```text
//! JMCP_TEST_HOST=10.0.0.1 JMCP_TEST_USER=admin JMCP_TEST_PASS=secret \
//!   cargo test -p rust-junosmcp-core --test integration_real_device -- --ignored
//! ```

use rust_junosmcp_core::{
    policy::Policy,
    tools::{
        batch, config_diff, execute_command, facts, get_config, pfe, router_list, ConfigDiffArgs,
        ExecuteBatchArgs, ExecuteCommandArgs, ExecutePfeArgs, GatherFactsArgs, GetConfigArgs,
    },
    DeviceManager, Inventory,
};
use std::io::Write;
use std::sync::Arc;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing env var {name}"))
}

fn build_inv() -> Arc<Inventory> {
    let host = env("JMCP_TEST_HOST");
    let user = env("JMCP_TEST_USER");
    let pass = env("JMCP_TEST_PASS");
    let json = format!(
        r#"{{
        "lab":{{"ip":"{host}","username":"{user}",
                "auth":{{"type":"password","password":"{pass}"}}}}
    }}"#
    );
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(json.as_bytes()).unwrap();
    Arc::new(Inventory::load(f.path()).unwrap())
}

fn build_dm() -> Arc<DeviceManager> {
    Arc::new(DeviceManager::new(build_inv()))
}

#[tokio::test]
#[ignore]
async fn router_list_returns_lab() {
    // Inventory was built above; we exercise the handler against it.
    let inv = {
        let host = env("JMCP_TEST_HOST");
        let user = env("JMCP_TEST_USER");
        let pass = env("JMCP_TEST_PASS");
        let json = format!(
            r#"{{
            "lab":{{"ip":"{host}","username":"{user}",
                    "auth":{{"type":"password","password":"{pass}"}}}}
        }}"#
        );
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
    let inv = build_inv();
    let dm = Arc::new(DeviceManager::new(inv.clone()));
    let pol = Arc::new(Policy::build(&inv).unwrap());
    let v = execute_command::handle(
        ExecuteCommandArgs {
            router_name: "lab".into(),
            command: "show version".into(),
            timeout: 30,
        },
        dm,
        pol,
    )
    .await
    .unwrap();
    assert!(v.as_str().unwrap().contains("Junos") || v.as_str().unwrap().contains("Hostname"));
}

#[tokio::test]
#[ignore]
async fn get_running_config() {
    let dm = build_dm();
    let v = get_config::handle(
        GetConfigArgs {
            router_name: "lab".into(),
        },
        dm,
    )
    .await
    .unwrap();
    let body = v.as_str().unwrap();
    assert!(!body.is_empty());
    assert!(body.contains("system") || body.contains("version"));
}

#[tokio::test]
#[ignore]
async fn diff_against_rollback_1() {
    let dm = build_dm();
    let v = config_diff::handle(
        ConfigDiffArgs {
            router_name: "lab".into(),
            version: 1,
        },
        dm,
    )
    .await
    .unwrap();
    assert!(v.is_string());
}

#[tokio::test]
#[ignore]
async fn gather_facts() {
    let dm = build_dm();
    let v = facts::handle(
        GatherFactsArgs {
            router_name: "lab".into(),
            timeout: 30,
        },
        dm,
    )
    .await
    .unwrap();
    assert!(v.get("hostname").is_some());
    assert!(v.get("version").is_some());
}

// --- Sub-project #3: PFE + batch ----------------------------------------

fn live_inv() -> Option<Arc<Inventory>> {
    let host = std::env::var("JMCP_TEST_HOST").ok()?;
    let user = std::env::var("JMCP_TEST_USER").ok()?;
    let pass = std::env::var("JMCP_TEST_PASS").ok()?;
    let json = format!(
        r#"{{"r1":{{"ip":"{host}","username":"{user}","auth":{{"type":"password","password":"{pass}"}}}}}}"#
    );
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(json.as_bytes()).unwrap();
    Some(Arc::new(Inventory::load(f.path()).unwrap()))
}

#[tokio::test]
#[ignore]
async fn live_batch_show_version_one_router_one_command() {
    let inv = match live_inv() {
        Some(i) => i,
        None => {
            eprintln!("skipped: JMCP_TEST_HOST/USER/PASS not set");
            return;
        }
    };
    let dm = Arc::new(DeviceManager::new(inv.clone()));
    let pol = Arc::new(Policy::build(&inv).unwrap());
    let args = ExecuteBatchArgs {
        routers: vec!["r1".into()],
        commands: vec!["show version".into()],
        command_timeout: 30,
        batch_timeout: Some(60),
        max_concurrent_routers: 1,
    };
    let v = batch::handle(args, dm, pol).await.unwrap();
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    let cmds = arr[0].pointer("/commands").unwrap().as_array().unwrap();
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0].get("ok"), Some(&serde_json::json!(true)));
    let value = cmds[0].get("value").and_then(|v| v.as_str()).unwrap();
    assert!(!value.trim().is_empty(), "expected non-empty CLI output");
}

#[tokio::test]
#[ignore]
async fn live_pfe_show_jnh_stats_packet() {
    let inv = match live_inv() {
        Some(i) => i,
        None => {
            eprintln!("skipped: JMCP_TEST_HOST/USER/PASS not set");
            return;
        }
    };
    let dm = Arc::new(DeviceManager::new(inv.clone()));
    let pol = Arc::new(Policy::build(&inv).unwrap());
    let args = ExecutePfeArgs {
        router_name: "r1".into(),
        fpc_target: std::env::var("JMCP_TEST_FPC").unwrap_or_else(|_| "fpc0".into()),
        pfe_command: "show jnh 0 stats packet".into(),
        timeout: 30,
    };
    let v = pfe::handle(args, dm, pol).await.unwrap();
    let output = v.get("output").and_then(|x| x.as_str()).unwrap();
    assert!(!output.trim().is_empty(), "expected non-empty PFE output");
}

#[tokio::test]
#[ignore]
async fn live_render_show_version_template_dry_run() {
    let host = std::env::var("JMCP_TEST_HOST").expect("JMCP_TEST_HOST set");
    let user = std::env::var("JMCP_TEST_USER").expect("JMCP_TEST_USER set");
    let pass = std::env::var("JMCP_TEST_PASS").expect("JMCP_TEST_PASS set");

    let inv_json = format!(
        r#"{{"r1":{{"ip":{host:?},"username":{user:?},"auth":{{"type":"password","password":{pass:?}}}}}}}"#
    );

    // Use tempfile + Inventory::load to be explicit about the path requirement.
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(inv_json.as_bytes()).unwrap();
    let inv = Arc::new(rust_junosmcp_core::inventory::Inventory::load(f.path()).unwrap());
    let dm = Arc::new(rust_junosmcp_core::device_manager::DeviceManager::new(
        inv.clone(),
    ));
    let pol = Arc::new(rust_junosmcp_core::policy::Policy::build(&inv).unwrap());

    let args = rust_junosmcp_core::tools::TemplateArgs {
        template_content: "set system host-name {{ name }}".into(),
        vars_content: r#"{"name":"jmcp-test"}"#.into(),
        router_name: Some("r1".into()),
        router_names: None,
        apply_config: true,
        commit_comment: "rust-junosmcp template smoke".into(),
        dry_run: true,
        config_format: None,
    };

    let r = rust_junosmcp_core::tools::template::handle(args, dm, pol)
        .await
        .expect("handle ok");
    let row = &r["results"][0];
    assert_eq!(row["router"], "r1");
    assert!(row.get("diff").is_some(), "expected dry-run diff field");
    assert!(
        row.get("commit_id").is_none(),
        "expected no commit_id in dry-run"
    );
}
