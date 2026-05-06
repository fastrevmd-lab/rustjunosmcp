//! `execute_junos_command` — run an operational CLI command on one router.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::policy::{Decision, Policy};
use crate::tools::ExecuteCommandArgs;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

/// Truncate `s` to at most 120 chars on a char boundary.
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
    args: ExecuteCommandArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
) -> Result<Value, JmcpError> {
    // Fail fast on unknown routers so the policy check has a valid target.
    let _ = dm.inventory().get(&args.router_name)?;

    if let Decision::Deny { rule, source, .. } =
        policy.check_command(&args.router_name, &args.command)
    {
        let pattern = rule.pattern.clone();
        let source_str = source.as_str();
        tracing::warn!(
            tool = "execute_junos_command",
            router = %args.router_name,
            matched_rule = %pattern,
            rule_source = %source_str,
            input_excerpt = %excerpt(&args.command),
            "blocklist denied request",
        );
        return Err(JmcpError::Denied {
            tool: "execute_junos_command",
            router: args.router_name.clone(),
            pattern,
            rule_source: source_str,
            input_excerpt: excerpt(&args.command),
            line_number: None,
        });
    }

    let timeout = Duration::from_secs(args.timeout);
    let result = tokio::time::timeout(timeout, async {
        let mut dev = dm.open(&args.router_name).await?;
        let output = dev.cli(&args.command).await?;
        Ok::<_, JmcpError>(output)
    })
    .await
    .map_err(|_| JmcpError::Timeout(timeout))??;
    Ok(json!(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use crate::policy::Policy;
    use std::io::Write;

    fn inv_with(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    #[tokio::test]
    async fn unknown_router_propagates_error() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            ExecuteCommandArgs {
                router_name: "nope".into(),
                command: "show version".into(),
                timeout: 5,
            },
            dm,
            pol,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn denied_command_short_circuits_before_connect() {
        // ip:port is intentionally unreachable; the test asserts we never
        // reach the connect path by looking at the error variant — connect
        // failure would be a Rustez/Timeout error, not Denied.
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"commands":[{"action":"deny","pattern":"request system *"}]},
                "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            ExecuteCommandArgs {
                router_name: "r1".into(),
                command: "request system reboot".into(),
                timeout: 1,
            },
            dm,
            pol,
        )
        .await;
        match r {
            Err(JmcpError::Denied {
                tool,
                router,
                pattern,
                ..
            }) => {
                assert_eq!(tool, "execute_junos_command");
                assert_eq!(router, "r1");
                assert_eq!(pattern, "request system *");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }
}
