//! RAII audit guard: emits exactly one `target="audit"` event on Drop.

use crate::schema::{bounded_error, AuditOutcome, AuditValue};
use rust_junosmcp_auth::caller::CallerCtx;
use std::fmt::Display;
use std::time::Instant;

fn mint_correlation_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("req-{nanos}")
}

/// One audited tool call. Construct at the top of a handler, set an outcome,
/// and let it drop — the drop emits the audit event.
pub struct AuditScope {
    correlation_id: String,
    caller: String,
    tool: &'static str,
    routers: Vec<String>,
    action: &'static str,
    started: Instant,
    outcome: AuditOutcome,
    metadata: Vec<(&'static str, AuditValue)>,
}

impl AuditScope {
    /// Build for a call. `caller` is the token name, or `"stdio"` when absent.
    pub fn new(
        ctx: Option<&CallerCtx>,
        tool: &'static str,
        action: &'static str,
        routers: Vec<String>,
    ) -> Self {
        Self {
            correlation_id: mint_correlation_id(),
            caller: ctx
                .map(|c| c.token_name.clone())
                .unwrap_or_else(|| "stdio".into()),
            tool,
            routers,
            action,
            started: Instant::now(),
            outcome: AuditOutcome::Unsettled,
            metadata: Vec::new(),
        }
    }

    /// Attach a safe metadata field (never secrets).
    pub fn meta(&mut self, key: &'static str, val: impl Into<AuditValue>) {
        self.metadata.push((key, val.into()));
    }

    /// Mark success.
    pub fn succeed(&mut self) {
        self.outcome = AuditOutcome::Succeeded;
    }

    /// Mark failure with a generic kind (`"error"`).
    pub fn fail(&mut self, error: impl Display) {
        self.outcome = AuditOutcome::Failed {
            kind: "error",
            msg: bounded_error(error),
        };
    }

    /// Mark failure with a specific stable kind (e.g. `"timeout"`, `"lease_busy"`).
    pub fn fail_kind(&mut self, kind: &'static str, error: impl Display) {
        self.outcome = AuditOutcome::Failed {
            kind,
            msg: bounded_error(error),
        };
    }

    /// Mark an authorization denial with a reason.
    pub fn deny(&mut self, reason: &'static str) {
        self.outcome = AuditOutcome::Denied { reason };
    }
}

impl Drop for AuditScope {
    fn drop(&mut self) {
        let duration_ms = self.started.elapsed().as_millis() as u64;
        let router_count = self.routers.len() as u64;
        let (routers, metadata) =
            crate::redact::render(crate::redact::active(), &self.routers, &self.metadata);

        // `caller` is emitted directly and is NEVER redactable; only `routers` and
        // `metadata` pass through redact::render above.
        let authorization = match &self.outcome {
            AuditOutcome::Denied { .. } => "denied",
            _ if self.caller == "stdio" => "no_auth",
            _ => "allowed",
        };
        let (result, error_kind, error, reason) = match &self.outcome {
            AuditOutcome::Succeeded => ("ok", "", String::new(), ""),
            AuditOutcome::Failed { kind, msg } => ("error", *kind, msg.clone(), ""),
            AuditOutcome::Denied { reason } => ("denied", "", String::new(), *reason),
            AuditOutcome::Unsettled => ("unsettled", "", String::new(), ""),
        };

        tracing::info!(
            target: "audit",
            correlation_id = %self.correlation_id,
            caller = %self.caller,
            tool = %self.tool,
            routers = %routers,
            router_count = router_count,
            action = %self.action,
            authorization = %authorization,
            result = %result,
            duration_ms = duration_ms,
            error_kind = %error_kind,
            error = %error,
            reason = %reason,
            metadata = %metadata,
            "audit"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::run_with_capture;
    use rust_junosmcp_auth::caller::CallerCtx;
    use rust_junosmcp_auth::ScopeSet;

    fn ctx(name: &str) -> CallerCtx {
        CallerCtx {
            token_name: name.into(),
            routers: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
        }
    }

    #[test]
    fn success_emits_ok_with_duration_and_meta() {
        let out = run_with_capture(|| {
            let mut a = AuditScope::new(
                Some(&ctx("ci")),
                "load_and_commit_config",
                "commit",
                vec!["r1".into()],
            );
            a.meta("config_bytes", 1234u64);
            a.succeed();
        });
        assert!(out.contains("audit"));
        assert!(out.contains("tool=load_and_commit_config"));
        assert!(out.contains("caller=ci"));
        assert!(out.contains("authorization=allowed"));
        assert!(out.contains("result=ok"));
        assert!(out.contains("config_bytes=1234"));
        assert!(out.contains("duration_ms="));
    }

    #[test]
    fn unsettled_when_dropped_without_outcome() {
        let out = run_with_capture(|| {
            let _a = AuditScope::new(
                Some(&ctx("ci")),
                "upgrade_junos",
                "upgrade",
                vec!["r1".into()],
            );
        });
        assert!(out.contains("result=unsettled"));
    }

    #[test]
    fn deny_emits_denied_authorization() {
        let out = run_with_capture(|| {
            let mut a = AuditScope::new(Some(&ctx("ci")), "add_device", "add-device", vec![]);
            a.deny("tool_scope");
        });
        assert!(out.contains("authorization=denied"));
        assert!(out.contains("result=denied"));
        assert!(out.contains("reason=tool_scope"));
    }

    #[test]
    fn stdio_caller_is_no_auth() {
        let out = run_with_capture(|| {
            let mut a = AuditScope::new(None, "get_router_list", "read", vec![]);
            a.succeed();
        });
        assert!(out.contains("caller=stdio"));
        assert!(out.contains("authorization=no_auth"));
    }

    #[test]
    fn drop_applies_installed_redaction() {
        use crate::redact::{self, AuditRedaction};
        // Install a drop policy for `host`. OnceLock is process-global, so this is
        // the only scope test that installs redaction; other tests rely on None.
        redact::install(AuditRedaction::parse("host=drop", None).unwrap());
        let out = run_with_capture(|| {
            let mut a = AuditScope::new(None, "add_device", "add-device", vec!["r1".into()]);
            a.meta("host", "10.0.0.5");
            a.meta("name", "r1");
            a.succeed();
        });
        assert!(
            !out.contains("10.0.0.5"),
            "dropped host value must be absent: {out}"
        );
        assert!(
            out.contains("name=r1"),
            "non-dropped field must survive: {out}"
        );
    }
}
