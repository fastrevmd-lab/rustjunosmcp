//! `commit_check_config` — lock candidate, load, diff, run commit-check
//! (validate only), roll back the candidate, unlock. NEVER commits.
//! Returns `{success, diff, error?}` (+ `checked_only: true` on success).

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::{build_config_payload, excerpt, validate_input_length};
use crate::policy::{Decision, Policy};
use crate::tools::CommitCheckArgs;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

pub async fn handle(
    args: CommitCheckArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
) -> Result<Value, JmcpError> {
    validate_input_length("config_text", &args.config_text)?;
    // Confirm the router exists before consulting the policy.
    let _ = dm.inventory().get(&args.router_name)?;

    // Same blocklist gate as load_and_commit_config: a denied pattern stays
    // denied even for validate-only (defense-in-depth).
    match policy.check_config(&args.router_name, &args.config_format, &args.config_text)? {
        Decision::Allow => {}
        Decision::Deny {
            rule,
            source,
            line_number,
        } => {
            let pattern = rule.pattern.clone();
            let source_str = source.as_str();
            let denied_excerpt = excerpt(&args.config_text);
            tracing::warn!(
                tool = "commit_check_config",
                router = %args.router_name,
                matched_rule = %pattern,
                rule_source = %source_str,
                line_number = ?line_number,
                input_excerpt = %denied_excerpt,
                "blocklist denied request",
            );
            return Err(JmcpError::Denied {
                tool: "commit_check_config",
                router: args.router_name.clone(),
                pattern,
                rule_source: source_str,
                input_excerpt: denied_excerpt,
                line_number,
            });
        }
    }

    let payload = build_config_payload(args.config_text, Some(&args.config_format))?;
    let timeout_dur = Duration::from_secs(args.timeout);

    let result = tokio::time::timeout(timeout_dur, async {
        let mut dev = dm.open(&args.router_name).await?;
        let mut cfg = dev.config()?;

        cfg.lock().await?;

        // After a successful lock, cleanup MUST run on every exit path:
        // discard the candidate (rollback) and release the lock, so a pooled
        // session is never left loaded-and-locked. Run load/diff/check in an
        // inner block, then clean up unconditionally regardless of outcome.
        let outcome: Result<(String, Result<(), rustez::RustEzError>), JmcpError> = async {
            cfg.load(payload).await?;
            let diff = cfg.diff().await?.unwrap_or_default();
            let check = cfg.commit_check().await;
            Ok((diff, check))
        }
        .await;

        let _ = cfg.rollback(0).await;
        let _ = cfg.unlock().await;

        let (diff, check_result) = outcome?;
        let result = match check_result {
            Ok(_) => json!({ "success": true, "diff": diff, "checked_only": true }),
            Err(e) => json!({ "success": false, "diff": diff, "error": e.to_string() }),
        };
        Ok::<_, JmcpError>(result)
    })
    .await
    .map_err(|_| JmcpError::Timeout(timeout_dur))??;

    Ok(result)
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
            CommitCheckArgs {
                router_name: "nope".into(),
                config_text: "set system foo".into(),
                config_format: "set".into(),
                timeout: 5,
            },
            dm,
            pol,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn invalid_format_rejected_before_connect() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            CommitCheckArgs {
                router_name: "r1".into(),
                config_text: "x".into(),
                config_format: "yaml".into(),
                timeout: 5,
            },
            dm,
            pol,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadFormat(ref s)) if s == "yaml"));
    }

    #[tokio::test]
    async fn non_set_format_with_rules_present_returns_format_error() {
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            CommitCheckArgs {
                router_name: "r1".into(),
                config_text: "<x/>".into(),
                config_format: "xml".into(),
                timeout: 5,
            },
            dm,
            pol,
        )
        .await;
        match r {
            Err(JmcpError::ConfigFormatNotAllowedWithRules { format }) => {
                assert_eq!(format, "xml");
            }
            other => panic!("expected ConfigFormatNotAllowedWithRules, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn denied_payload_short_circuits_before_connect() {
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            CommitCheckArgs {
                router_name: "r1".into(),
                config_text: "set foo\ndelete protocols bgp".into(),
                config_format: "set".into(),
                timeout: 5,
            },
            dm,
            pol,
        )
        .await;
        match r {
            Err(JmcpError::Denied {
                tool,
                line_number,
                pattern,
                ..
            }) => {
                assert_eq!(tool, "commit_check_config");
                assert_eq!(line_number, Some(2));
                assert_eq!(pattern, "delete *");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }
}
