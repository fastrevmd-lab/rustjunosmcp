//! `execute_junos_command_batch` — N routers x M commands, parallel across routers.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait RouterSession: Send {
    async fn cli(&mut self, command: &str) -> Result<String, JmcpError>;
    async fn close(&mut self) -> Result<(), JmcpError>;
}

#[async_trait]
pub trait BatchRunner: Send + Sync {
    async fn open(&self, router: &str) -> Result<Box<dyn RouterSession>, JmcpError>;
}

struct RustEzSession(rustez::Device);

#[async_trait]
impl RouterSession for RustEzSession {
    async fn cli(&mut self, command: &str) -> Result<String, JmcpError> {
        Ok(self.0.cli(command).await?)
    }
    async fn close(&mut self) -> Result<(), JmcpError> {
        Ok(self.0.close().await?)
    }
}

pub struct DeviceManagerRunner(pub Arc<DeviceManager>);

#[async_trait]
impl BatchRunner for DeviceManagerRunner {
    async fn open(&self, router: &str) -> Result<Box<dyn RouterSession>, JmcpError> {
        let dev = self.0.open(router).await?;
        Ok(Box::new(RustEzSession(dev)))
    }
}

use crate::policy::{Decision, Policy};
use crate::tools::ExecuteBatchArgs;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize, Clone)]
pub struct CommandOutcome {
    pub command: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct RouterResult {
    pub router: String,
    pub commands: Vec<CommandOutcome>,
}

fn excerpt(s: &str) -> String {
    if s.len() <= 120 {
        return s.to_string();
    }
    let mut end = 120;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

pub async fn handle(
    args: ExecuteBatchArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
) -> Result<Value, JmcpError> {
    let runner: Arc<dyn BatchRunner> = Arc::new(DeviceManagerRunner(dm.clone()));
    handle_with_runner(args, dm, policy, runner).await
}

pub async fn handle_with_runner(
    args: ExecuteBatchArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
    _runner: Arc<dyn BatchRunner>,
) -> Result<Value, JmcpError> {
    if args.routers.is_empty() {
        return Err(JmcpError::InventoryInvalid(
            "execute_junos_command_batch: routers must be non-empty".into(),
        ));
    }
    if args.commands.is_empty() {
        return Err(JmcpError::InventoryInvalid(
            "execute_junos_command_batch: commands must be non-empty".into(),
        ));
    }

    // Pre-flight 1: every router must exist in inventory.
    for r in &args.routers {
        let _ = dm.inventory().get(r)?;
    }

    // Pre-flight 2: blocklist check on every (router, command) pair.
    for r in &args.routers {
        for c in &args.commands {
            if let Decision::Deny { rule, source, .. } = policy.check_command(r, c) {
                let pattern = rule.pattern.clone();
                let source_str = source.as_str();
                tracing::warn!(
                    tool = "execute_junos_command_batch",
                    router = %r,
                    matched_rule = %pattern,
                    rule_source = %source_str,
                    input_excerpt = %excerpt(c),
                    "blocklist denied request",
                );
                return Err(JmcpError::Denied {
                    tool: "execute_junos_command_batch",
                    router: r.clone(),
                    pattern,
                    rule_source: source_str,
                    input_excerpt: excerpt(c),
                    line_number: None,
                });
            }
        }
    }

    // Fan-out lands in Task 10. For now, return an empty array so pre-flight
    // tests exercise the right code path.
    let empty: Vec<RouterResult> = Vec::new();
    Ok(serde_json::to_value(empty)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    use crate::policy::Policy;
    use crate::tools::ExecuteBatchArgs;

    fn inv_with(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    #[tokio::test]
    async fn unknown_router_in_list_aborts_preflight() {
        let inv = inv_with(
            r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let args = ExecuteBatchArgs {
            routers: vec!["r1".into(), "ghost".into()],
            commands: vec!["show version".into()],
            command_timeout: 1,
            batch_timeout: None,
            max_concurrent_routers: 4,
        };
        let r = super::handle(args, dm, pol).await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(ref s)) if s == "ghost"));
    }

    #[tokio::test]
    async fn denied_command_anywhere_aborts_preflight() {
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"commands":[{"action":"deny","pattern":"request system *"}]},
                "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}},
                "r2":{"ip":"203.0.113.2","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let args = ExecuteBatchArgs {
            routers: vec!["r1".into(), "r2".into()],
            commands: vec!["show version".into(), "request system reboot".into()],
            command_timeout: 1,
            batch_timeout: None,
            max_concurrent_routers: 4,
        };
        match super::handle(args, dm, pol).await {
            Err(JmcpError::Denied { tool, pattern, .. }) => {
                assert_eq!(tool, "execute_junos_command_batch");
                assert_eq!(pattern, "request system *");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_routers_or_commands_is_rejected() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let args = ExecuteBatchArgs {
            routers: vec![],
            commands: vec!["show version".into()],
            command_timeout: 1,
            batch_timeout: None,
            max_concurrent_routers: 4,
        };
        assert!(super::handle(args, dm.clone(), pol.clone()).await.is_err());

        let args = ExecuteBatchArgs {
            routers: vec!["r1".into()],
            commands: vec![],
            command_timeout: 1,
            batch_timeout: None,
            max_concurrent_routers: 4,
        };
        assert!(super::handle(args, dm, pol).await.is_err());
    }

    #[tokio::test]
    async fn device_manager_runner_propagates_unknown_router() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        )
        .unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let runner = DeviceManagerRunner(Arc::new(DeviceManager::new(inv)));
        let r = runner.open("ghost").await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }
}
