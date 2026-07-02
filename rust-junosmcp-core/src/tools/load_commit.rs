//! `load_and_commit_config` — lock candidate, load, diff, commit (with comment),
//! unlock. Rollback on commit failure. Returns `{success, diff, error?}`.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::{build_config_payload, excerpt, validate_input_length};
use crate::policy::{Decision, Policy};
use crate::tools::LoadCommitArgs;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

pub async fn handle(
    args: LoadCommitArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
) -> Result<Value, JmcpError> {
    validate_input_length("config_text", &args.config_text)?;
    // Confirm the router exists before consulting the policy.
    let _ = dm.inventory().get(&args.router_name)?;

    // The format gate is part of the policy check; downstream
    // build_config_payload still validates the value separately.
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
                tool = "load_and_commit_config",
                router = %args.router_name,
                matched_rule = %pattern,
                rule_source = %source_str,
                line_number = ?line_number,
                input_excerpt = %denied_excerpt,
                "blocklist denied request",
            );
            return Err(JmcpError::Denied {
                tool: "load_and_commit_config",
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
    let confirmed = args.confirm_timeout_mins.is_some();
    let confirm_timeout_mins = args.confirm_timeout_mins;
    let commit_comment = args.commit_comment.clone();

    let result = tokio::time::timeout(timeout_dur, async {
        let mut dev = dm.open(&args.router_name).await?;
        let mut cfg = dev.config()?;

        cfg.lock().await?;

        // Run load -> diff -> commit in an inner block so cleanup runs on every
        // exit after a successful lock. Previously a `cfg.diff().await?` (or
        // `load`) failure propagated out before the unlock/rollback, leaving a
        // loaded, LOCKED candidate on the pooled session that poisoned the next
        // request. Now: always unlock, and roll back the candidate on any
        // pre-commit error (load/diff). A *successful* commit is NOT rolled back.
        let outcome: Result<Value, JmcpError> = async {
            cfg.load(payload).await?;
            let diff = cfg.diff().await?.unwrap_or_default();

            let commit_result = if let Some(mins) = confirm_timeout_mins {
                let seconds = mins * 60;
                // rustez's commit_confirmed API does not accept a log comment;
                // the comment is noted in the response but not sent to the device.
                cfg.commit_confirmed(seconds).await
            } else {
                cfg.commit_with_comment(&commit_comment).await
            };

            match commit_result {
                Ok(_) => {
                    let mut obj = json!({ "success": true, "diff": diff });
                    if confirmed {
                        let mins = confirm_timeout_mins.unwrap();
                        obj["confirmed"] = json!(true);
                        obj["rollback_in_minutes"] = json!(mins);
                        obj["message"] = json!(format!(
                            "Commit confirmed: auto-rollback in {} minutes unless confirmed. \
                             Send another commit to confirm.",
                            mins
                        ));
                        if !commit_comment.is_empty() {
                            obj["note"] = json!(
                                "commit_comment is not applied during confirmed commits \
                                 (rustez API limitation)"
                            );
                        }
                    }
                    Ok(obj)
                }
                Err(e) => {
                    // Commit failed: discard the candidate, report the error.
                    let _ = cfg.rollback(0).await;
                    Ok(json!({ "success": false, "diff": diff, "error": e.to_string() }))
                }
            }
        }
        .await;

        // Cleanup on every post-lock exit. Roll back only on a pre-commit error
        // (load/diff) — a committed change is left in place, and the
        // commit-failure branch above already rolled back.
        if outcome.is_err() {
            let _ = cfg.rollback(0).await;
        }
        let _ = cfg.unlock().await;

        outcome
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
            LoadCommitArgs {
                router_name: "nope".into(),
                config_text: "set system foo".into(),
                config_format: "set".into(),
                commit_comment: "test".into(),
                confirm_timeout_mins: None,
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
            LoadCommitArgs {
                router_name: "r1".into(),
                config_text: "x".into(),
                config_format: "yaml".into(),
                commit_comment: "test".into(),
                confirm_timeout_mins: None,
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
            LoadCommitArgs {
                router_name: "r1".into(),
                config_text: "<x/>".into(),
                config_format: "xml".into(),
                commit_comment: "test".into(),
                confirm_timeout_mins: None,
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
            LoadCommitArgs {
                router_name: "r1".into(),
                config_text: "set foo\ndelete protocols bgp".into(),
                config_format: "set".into(),
                commit_comment: "test".into(),
                confirm_timeout_mins: None,
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
                assert_eq!(tool, "load_and_commit_config");
                assert_eq!(line_number, Some(2));
                assert_eq!(pattern, "delete *");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }
}
