//! `execute_junos_pfe_command` — single PFE call against an explicit FPC target.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::policy::{Decision, Policy};
use crate::tools::ExecutePfeArgs;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

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
    args: ExecutePfeArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
) -> Result<Value, JmcpError> {
    // Reject quote-injection inputs before we build the wrapper.
    if args.pfe_command.contains('"') {
        return Err(JmcpError::BadPfeCommand(
            "literal '\"' is not allowed (would break the wrapper command)".into(),
        ));
    }

    // Fail fast on unknown routers so the policy check has a valid target.
    let _ = dm.inventory().get(&args.router_name)?;

    if let Decision::Deny { rule, source, .. } =
        policy.check_pfe_command(&args.router_name, &args.pfe_command)
    {
        let pattern = rule.pattern.clone();
        let source_str = source.as_str();
        tracing::warn!(
            tool = "execute_junos_pfe_command",
            router = %args.router_name,
            matched_rule = %pattern,
            rule_source = %source_str,
            input_excerpt = %excerpt(&args.pfe_command),
            "blocklist denied request",
        );
        return Err(JmcpError::Denied {
            tool: "execute_junos_pfe_command",
            router: args.router_name.clone(),
            pattern,
            rule_source: source_str,
            input_excerpt: excerpt(&args.pfe_command),
            line_number: None,
        });
    }

    let timeout = Duration::from_secs(args.timeout);
    let mut dev = dm.open(&args.router_name).await?;

    let wrapper = format!(
        "request pfe execute target {} command \"{}\"",
        args.fpc_target, args.pfe_command
    );
    let result = tokio::time::timeout(timeout, dev.cli(&wrapper))
        .await
        .map_err(|_| JmcpError::Timeout(timeout))?;

    let _ = dev.close().await;
    Ok(json!({
        "fpc_target": args.fpc_target,
        "output": result?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
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
            ExecutePfeArgs {
                router_name: "nope".into(),
                fpc_target: "fpc0".into(),
                pfe_command: "show jnh 0 stats".into(),
                timeout: 5,
            },
            dm,
            pol,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn denied_pfe_command_short_circuits_before_connect() {
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"pfe_commands":[{"action":"deny","pattern":"set *"}]},
                "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            ExecutePfeArgs {
                router_name: "r1".into(),
                fpc_target: "fpc0".into(),
                pfe_command: "set jnh 0 debug".into(),
                timeout: 1,
            },
            dm,
            pol,
        )
        .await;
        match r {
            Err(JmcpError::Denied { tool, router, pattern, .. }) => {
                assert_eq!(tool, "execute_junos_pfe_command");
                assert_eq!(router, "r1");
                assert_eq!(pattern, "set *");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_pfe_command_with_literal_quote() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            ExecutePfeArgs {
                router_name: "r1".into(),
                fpc_target: "fpc0".into(),
                pfe_command: r#"show "evil""#.into(),
                timeout: 5,
            },
            dm,
            pol,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadPfeCommand(_))));
    }
}
