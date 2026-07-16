//! SRX-specific rmcp adapters composed into the unified [`JmcpHandler`].

use super::{caller_ctx, mint_request_id, JmcpHandler};

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Extensions};
use rmcp::{tool, tool_router};
use rust_junosmcp_audit::AuditScope;
#[cfg(test)]
use rust_junosmcp_core::{DeviceLeaseManager, DeviceManager};
use rust_junosmcp_srx_core::workflows::signature_package::{
    confirmation_token_for_request, ConfirmationBinding,
};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::sync::Arc;
use tokio::time::Instant;

#[derive(Debug, thiserror::Error)]
enum ScopeError {
    #[error(
        "[code=authorization_context_missing] authenticated request is missing authorization context"
    )]
    MissingCallerContext,
    #[error("[code=tool_scope_denied] token '{token}' is not authorized for tool '{tool}'")]
    ToolNotInScope { token: String, tool: &'static str },
    #[error(
        "[code=router_scope_denied] token '{token}' is not authorized for the requested router (tool '{tool}')"
    )]
    RouterNotInScope { token: String, tool: &'static str },
}

impl JmcpHandler {
    /// Pure tool body used by the rmcp adapter below and unit tests.
    fn srxmcp_status_body(&self, _args: SrxmcpStatusArgs) -> SrxmcpStatusResponse {
        let uptime_seconds = Instant::now()
            .saturating_duration_since(*self.started)
            .as_secs();
        SrxmcpStatusResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            endpoint: "srxmcp".to_string(),
            uptime_seconds,
        }
    }

    fn srx_scope_to_call_result(e: ScopeError) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(CallToolResult::error(vec![ContentBlock::text(
            e.to_string(),
        )]))
    }

    fn check_srx_tool_scope(
        &self,
        ctx: Option<&rust_junosmcp_auth::caller::CallerCtx>,
        tool: &'static str,
    ) -> Result<(), ScopeError> {
        if let Some(ctx) = ctx {
            if !ctx.tools.allows(tool) {
                return Err(ScopeError::ToolNotInScope {
                    token: ctx.token_name.clone(),
                    tool,
                });
            }
        }
        Ok(())
    }

    fn check_srx_router_scope(
        &self,
        ctx: Option<&rust_junosmcp_auth::caller::CallerCtx>,
        tool: &'static str,
        router: &str,
    ) -> Result<(), ScopeError> {
        if let Some(ctx) = ctx {
            if !ctx.routers.allows(router) {
                return Err(ScopeError::RouterNotInScope {
                    token: ctx.token_name.clone(),
                    tool,
                });
            }
        }
        Ok(())
    }

    /// Authorize a tool call before any device lookup or workflow work. A
    /// missing caller is accepted only when the handler was constructed for
    /// the explicit no-auth path.
    fn authorize_call<'a>(
        &self,
        extensions: &'a Extensions,
        tool: &'static str,
        router: Option<&str>,
    ) -> Result<Option<&'a rust_junosmcp_auth::caller::CallerCtx>, ScopeError> {
        let ctx = caller_ctx(extensions);
        if self.authorization_required && ctx.is_none() {
            return Err(ScopeError::MissingCallerContext);
        }
        self.check_srx_tool_scope(ctx, tool)?;
        if let Some(router) = router {
            self.check_srx_router_scope(ctx, tool, router)?;
        }
        Ok(ctx)
    }

    fn device_identity(&self, router: &str) -> Result<String, rust_junosmcp_core::JmcpError> {
        let inventory = self.dm.inventory();
        let entry = inventory.get(router)?;
        Ok(format!(
            "{}|{}|{}|{}",
            router, entry.ip, entry.port, entry.username
        ))
    }

    fn signature_error_to_rmcp(e: rust_junosmcp_srx_core::SrxError) -> rmcp::ErrorData {
        match e {
            rust_junosmcp_srx_core::SrxError::InvalidInput(_) => {
                rmcp::ErrorData::invalid_params(e.to_string(), None)
            }
            rust_junosmcp_srx_core::SrxError::SignaturePackageConfirmationRequired { .. }
            | rust_junosmcp_srx_core::SrxError::SignaturePackageConfirmationTokenRequired {
                ..
            }
            | rust_junosmcp_srx_core::SrxError::SignaturePackageConfirmationTokenInvalid {
                ..
            }
            | rust_junosmcp_srx_core::SrxError::SignaturePackageConfirmationPlanDrift { .. }
            | rust_junosmcp_srx_core::SrxError::SignaturePackageConfirmationCapacityExceeded {
                ..
            } => rmcp::ErrorData::invalid_request(e.to_string(), None),
            rust_junosmcp_srx_core::SrxError::Transport(
                rust_junosmcp_core::JmcpError::DeviceLeaseBusy { .. },
            ) => rmcp::ErrorData::invalid_request(e.to_string(), None),
            _ => rmcp::ErrorData::internal_error(e.to_string(), None),
        }
    }

    fn validate_confirmation_request(
        &self,
        confirm: bool,
        token: Option<&str>,
        caller: Option<&str>,
        router: &str,
        device_identity: &str,
    ) -> Result<(), rust_junosmcp_srx_core::SrxError> {
        if let Some(token) = confirmation_token_for_request(confirm, token, router)? {
            let binding = ConfirmationBinding::new(caller, router, device_identity);
            self.confirmation_store
                .validate_binding(token, &binding)
                .map_err(|e| e.into_srx_error(router))?;
        }
        Ok(())
    }
}

/// Source-declaration-order mirror of this server's `#[tool]` surface. The
/// tests below compare it to the shared auth crate's SRX registry.
#[cfg(test)]
const SRX_SERVER_TOOLS: &[&str] = &[
    "srxmcp_status",
    "get_chassis_cluster_status",
    "get_srx_security_services_status",
    "check_srx_feature_license",
    "vpn_lifecycle_report",
    "manage_idp_security_package",
    "manage_appid_signature_package",
    "validate_chassis_cluster_health",
    "collect_jtac_support_bundle",
];

#[cfg(test)]
mod server_tools_const_tests {
    use super::SRX_SERVER_TOOLS;
    use rust_junosmcp_auth::file::SRX_TOOLS;
    use std::collections::HashSet;

    #[test]
    fn server_tools_len_is_nine() {
        assert_eq!(SRX_SERVER_TOOLS.len(), 9);
    }

    #[test]
    fn server_tools_has_no_duplicates() {
        let mut seen = HashSet::new();
        for tool in SRX_SERVER_TOOLS {
            assert!(seen.insert(*tool), "duplicate SRX tool name: {tool}");
        }
    }

    #[test]
    fn server_tools_matches_auth_registry() {
        let server: HashSet<&str> = SRX_SERVER_TOOLS.iter().copied().collect();
        let known: HashSet<&str> = SRX_TOOLS.iter().copied().collect();
        assert_eq!(
            server,
            known,
            "SRX_SERVER_TOOLS / SRX_TOOLS drift: only-in-server={:?}, only-in-known={:?}",
            server.difference(&known).collect::<Vec<_>>(),
            known.difference(&server).collect::<Vec<_>>(),
        );
    }
}

#[tool_router(router = srx_tool_router, vis = "pub(crate)")]
impl JmcpHandler {
    #[tool(
        name = "srxmcp_status",
        description = "Diagnostic — returns this server's version, endpoint name, and uptime in seconds."
    )]
    async fn srxmcp_status(
        &self,
        Parameters(args): Parameters<SrxmcpStatusArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(ctx, "srxmcp_status", "read", vec![]);

        if let Err(e) = self.authorize_call(&extensions, "srxmcp_status", None) {
            audit.deny(match e {
                ScopeError::MissingCallerContext => "missing_caller_context",
                ScopeError::RouterNotInScope { .. } => "router_scope",
                ScopeError::ToolNotInScope { .. } => "tool_scope",
            });
            return Self::srx_scope_to_call_result(e);
        }
        let resp = self.srxmcp_status_body(args);
        let result = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing SrxmcpStatusResponse: {e}"), None)
        });
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind("serialize", e),
        }
        result.map(|body| CallToolResult::success(vec![ContentBlock::text(body)]))
    }

    #[tool(
        name = "get_chassis_cluster_status",
        description = "Chassis-cluster topology + health snapshot. Returns \
                       state=not_configured for standalone SRX devices."
    )]
    async fn get_chassis_cluster_status(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::ClusterStatusArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(
            ctx,
            "get_chassis_cluster_status",
            "read",
            vec![args.router.clone()],
        );

        if let Err(e) = self.authorize_call(
            &extensions,
            "get_chassis_cluster_status",
            Some(&args.router),
        ) {
            audit.deny(match e {
                ScopeError::MissingCallerContext => "missing_caller_context",
                ScopeError::RouterNotInScope { .. } => "router_scope",
                ScopeError::ToolNotInScope { .. } => "tool_scope",
            });
            return Self::srx_scope_to_call_result(e);
        }
        let mut device =
            self.dm.open(&args.router).await.map_err(|e| {
                rmcp::ErrorData::internal_error(format!("opening device: {e}"), None)
            })?;
        let resp = rust_junosmcp_srx_core::workflows::cluster_status::run(&mut device, args)
            .await
            .map_err(|e| match e {
                rust_junosmcp_srx_core::SrxError::InvalidInput(_) => {
                    rmcp::ErrorData::invalid_params(e.to_string(), None)
                }
                _ => rmcp::ErrorData::internal_error(e.to_string(), None),
            })?;
        let result = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing ClusterStatusData: {e}"), None)
        });
        match &result {
            Ok(body) => {
                audit.meta("output_bytes", body.len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail_kind("serialize", e),
        }
        result.map(|body| CallToolResult::success(vec![ContentBlock::text(body)]))
    }

    #[tool(
        name = "get_srx_security_services_status",
        description = "Reports the health and version of up to five SRX security services \
                       (IDP, AppID, UTM Anti-Virus, SecIntel, ATP/AAMW) in a single call. \
                       Each sub-service is independently classified as active or not_configured. \
                       The overall state is not_configured only when all five sub-services are absent."
    )]
    async fn get_srx_security_services_status(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::ServicesStatusArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(
            ctx,
            "get_srx_security_services_status",
            "read",
            vec![args.router.clone()],
        );

        if let Err(e) = self.authorize_call(
            &extensions,
            "get_srx_security_services_status",
            Some(&args.router),
        ) {
            audit.deny(match e {
                ScopeError::MissingCallerContext => "missing_caller_context",
                ScopeError::RouterNotInScope { .. } => "router_scope",
                ScopeError::ToolNotInScope { .. } => "tool_scope",
            });
            return Self::srx_scope_to_call_result(e);
        }
        let mut device =
            self.dm.open(&args.router).await.map_err(|e| {
                rmcp::ErrorData::internal_error(format!("opening device: {e}"), None)
            })?;
        let resp = rust_junosmcp_srx_core::workflows::services_status::run(&mut device, args)
            .await
            .map_err(|e| match e {
                rust_junosmcp_srx_core::SrxError::InvalidInput(_) => {
                    rmcp::ErrorData::invalid_params(e.to_string(), None)
                }
                _ => rmcp::ErrorData::internal_error(e.to_string(), None),
            })?;
        let result = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing ServicesStatusData: {e}"), None)
        });
        match &result {
            Ok(body) => {
                audit.meta("output_bytes", body.len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail_kind("serialize", e),
        }
        result.map(|body| CallToolResult::success(vec![ContentBlock::text(body)]))
    }

    #[tool(
        name = "check_srx_feature_license",
        description = "Check whether a named SRX security feature (IDP, AppID, UTM Antivirus, \
                       Web Filtering, Anti-Spam, SecIntel, ATP Cloud, SSL Proxy) has a valid \
                       license installed on the device. Returns state=not_configured when no \
                       matching license record is present (including the expected lab case where \
                       only eval/trial licenses are installed)."
    )]
    async fn check_srx_feature_license(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::LicenseArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(
            ctx,
            "check_srx_feature_license",
            "read",
            vec![args.router.clone()],
        );

        audit.meta("feature", format!("{:?}", args.feature));

        if let Err(e) =
            self.authorize_call(&extensions, "check_srx_feature_license", Some(&args.router))
        {
            audit.deny(match e {
                ScopeError::MissingCallerContext => "missing_caller_context",
                ScopeError::RouterNotInScope { .. } => "router_scope",
                ScopeError::ToolNotInScope { .. } => "tool_scope",
            });
            return Self::srx_scope_to_call_result(e);
        }
        let mut device =
            self.dm.open(&args.router).await.map_err(|e| {
                rmcp::ErrorData::internal_error(format!("opening device: {e}"), None)
            })?;
        let resp = rust_junosmcp_srx_core::workflows::license::run(&mut device, args)
            .await
            .map_err(|e| match e {
                rust_junosmcp_srx_core::SrxError::InvalidInput(_) => {
                    rmcp::ErrorData::invalid_params(e.to_string(), None)
                }
                _ => rmcp::ErrorData::internal_error(e.to_string(), None),
            })?;
        let result = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing LicenseData: {e}"), None)
        });
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind("serialize", e),
        }
        result.map(|body| CallToolResult::success(vec![ContentBlock::text(body)]))
    }

    #[tool(
        name = "vpn_lifecycle_report",
        description = "Correlates IKE (Phase-1) and IPsec (Phase-2) security associations for \
                       VPN troubleshooting. Returns state=active with IKE SA list, IPsec SA list, \
                       and correlations when VPN is configured (even if no SAs are currently up). \
                       Returns state=not_configured only when both IKE and IPsec RPCs report that \
                       the security stanza is absent. Optionally filter by `peer` (substring \
                       match against both IKE remote address and IPsec gateway) and/or `tunnel` \
                       (substring match against IPsec remote gateway — the brief-style IPsec \
                       RPC does not surface the st0 interface name)."
    )]
    async fn vpn_lifecycle_report(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::VpnLifecycleArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(
            ctx,
            "vpn_lifecycle_report",
            "read",
            vec![args.router.clone()],
        );

        if let Err(e) = self.authorize_call(&extensions, "vpn_lifecycle_report", Some(&args.router))
        {
            audit.deny(match e {
                ScopeError::MissingCallerContext => "missing_caller_context",
                ScopeError::RouterNotInScope { .. } => "router_scope",
                ScopeError::ToolNotInScope { .. } => "tool_scope",
            });
            return Self::srx_scope_to_call_result(e);
        }
        let mut device =
            self.dm.open(&args.router).await.map_err(|e| {
                rmcp::ErrorData::internal_error(format!("opening device: {e}"), None)
            })?;
        let resp = rust_junosmcp_srx_core::workflows::vpn_lifecycle::run(&mut device, args)
            .await
            .map_err(|e| match e {
                rust_junosmcp_srx_core::SrxError::InvalidInput(_) => {
                    rmcp::ErrorData::invalid_params(e.to_string(), None)
                }
                _ => rmcp::ErrorData::internal_error(e.to_string(), None),
            })?;
        let result = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing VpnLifecycleData: {e}"), None)
        });
        match &result {
            Ok(body) => {
                audit.meta("output_bytes", body.len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail_kind("serialize", e),
        }
        result.map(|body| CallToolResult::success(vec![ContentBlock::text(body)]))
    }

    #[tool(
        name = "manage_idp_security_package",
        description = "DESTRUCTIVE on the `download_and_install` and `rollback` actions: \
                       updates / reverts the IDP signature package on an SRX device. \
                       Three actions: `check_server` (read-only — returns installed + latest \
                       version from signatures.juniper.net), `download_and_install` (downloads \
                       and installs the latest or a pinned `version`), and `rollback` \
                       (reverts to the device's preserved previous package). Destructive \
                       verbs use a two-call confirmation protocol: call 1 with `confirm=false` \
                       returns `[code=confirmation_required]` carrying a `plan` and short-lived \
                       `confirmation_token`; call 2 supplies both `confirm=true` and that token. \
                       Tokens are caller-bound and one-time. `download_and_install` \
                       short-circuits with `status=already_at_target` when every node already \
                       runs the requested version."
    )]
    async fn manage_idp_security_package(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::IdpPackageArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx_opt = caller_ctx(&extensions);
        let mut audit = AuditScope::new(
            ctx_opt,
            "manage_idp_security_package",
            "idp-package",
            vec![args.router.clone()],
        );

        audit.meta("action", format!("{:?}", args.action));
        if let Some(ref version) = args.version {
            audit.meta("target_version", version.clone());
        }

        let ctx = match self.authorize_call(
            &extensions,
            "manage_idp_security_package",
            Some(&args.router),
        ) {
            Ok(ctx) => ctx,
            Err(e) => {
                audit.deny(match e {
                    ScopeError::MissingCallerContext => "missing_caller_context",
                    ScopeError::RouterNotInScope { .. } => "router_scope",
                    ScopeError::ToolNotInScope { .. } => "tool_scope",
                });
                return Self::srx_scope_to_call_result(e);
            }
        };
        let caller = ctx.map(|c| c.token_name.as_str());
        let request_id = mint_request_id();
        let device_identity = self.device_identity(&args.router).map_err(|e| {
            rmcp::ErrorData::invalid_params(format!("resolving device identity: {e}"), None)
        })?;
        if args.action != rust_junosmcp_srx_core::IdpAction::CheckServer {
            self.validate_confirmation_request(
                args.confirm,
                args.confirmation_token.as_deref(),
                caller,
                &args.router,
                &device_identity,
            )
            .map_err(Self::signature_error_to_rmcp)?;
        }

        let mut device =
            self.dm.open(&args.router).await.map_err(|e| {
                rmcp::ErrorData::internal_error(format!("opening device: {e}"), None)
            })?;
        let result = rust_junosmcp_srx_core::workflows::idp_package::run(
            &mut device,
            &self.device_leases,
            &self.confirmation_store,
            &args,
            caller,
            &device_identity,
            &request_id,
        )
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        let resp = result.map_err(Self::signature_error_to_rmcp)?;
        let body = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing IdpPackageResponse: {e}"), None)
        })?;
        Ok(CallToolResult::success(vec![ContentBlock::text(body)]))
    }

    #[tool(
        name = "manage_appid_signature_package",
        description = "DESTRUCTIVE on the `download_and_install` and `uninstall` actions: \
                       updates or removes the AppID application signature package on an SRX \
                       device. Three actions: `check_server` (read-only — returns installed \
                       + latest version from signatures.juniper.net), `download_and_install` \
                       (downloads and installs the latest or a pinned `version`), and \
                       `uninstall` (removes the currently-installed application package and \
                       protocol bundle). Destructive verbs use a two-call confirmation \
                       protocol: call 1 with `confirm=false` returns \
                       `[code=confirmation_required]` carrying a `plan` and short-lived \
                       `confirmation_token`; call 2 supplies both `confirm=true` and that \
                       caller-bound, one-time token. \
                       `download_and_install` short-circuits with `status=already_at_target` \
                       when every node already runs the requested version."
    )]
    async fn manage_appid_signature_package(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::AppidPackageArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx_opt = caller_ctx(&extensions);
        let mut audit = AuditScope::new(
            ctx_opt,
            "manage_appid_signature_package",
            "appid-package",
            vec![args.router.clone()],
        );

        audit.meta("action", format!("{:?}", args.action));

        let ctx = match self.authorize_call(
            &extensions,
            "manage_appid_signature_package",
            Some(&args.router),
        ) {
            Ok(ctx) => ctx,
            Err(e) => {
                audit.deny(match e {
                    ScopeError::MissingCallerContext => "missing_caller_context",
                    ScopeError::RouterNotInScope { .. } => "router_scope",
                    ScopeError::ToolNotInScope { .. } => "tool_scope",
                });
                return Self::srx_scope_to_call_result(e);
            }
        };
        let caller = ctx.map(|c| c.token_name.as_str());
        let request_id = mint_request_id();
        let device_identity = self.device_identity(&args.router).map_err(|e| {
            rmcp::ErrorData::invalid_params(format!("resolving device identity: {e}"), None)
        })?;
        if args.action != rust_junosmcp_srx_core::AppidAction::CheckServer {
            self.validate_confirmation_request(
                args.confirm,
                args.confirmation_token.as_deref(),
                caller,
                &args.router,
                &device_identity,
            )
            .map_err(Self::signature_error_to_rmcp)?;
        }

        let mut device =
            self.dm.open(&args.router).await.map_err(|e| {
                rmcp::ErrorData::internal_error(format!("opening device: {e}"), None)
            })?;
        let result = rust_junosmcp_srx_core::workflows::appid_package::run(
            &mut device,
            &self.device_leases,
            &self.confirmation_store,
            &args,
            caller,
            &device_identity,
            &request_id,
        )
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        let resp = result.map_err(Self::signature_error_to_rmcp)?;
        let body = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing AppidPackageResponse: {e}"), None)
        })?;
        Ok(CallToolResult::success(vec![ContentBlock::text(body)]))
    }

    #[tool(
        name = "validate_chassis_cluster_health",
        description = "Runs 8 chassis-cluster diagnostic RPCs (cluster status, interfaces, \
                       information, data-plane / control-plane statistics, per-RE software, \
                       alarms, uptime) and emits an ordered findings list with a rolled-up \
                       verdict (pass / warn / fail). Standalone SRX devices short-circuit to \
                       state=not_configured. Each Finding has check_id (red_led, \
                       disabled_secondary, control_link_failure, major_alarm, minor_alarm, \
                       recent_reboot, version_skew), severity, message, and optional \
                       structured detail. Verdict precedence: fail > warn > pass. \
                       Pass-through cluster_status snapshot is included when the cluster \
                       RPC succeeded. include_raw=true appends concatenated raw RPC XML."
    )]
    async fn validate_chassis_cluster_health(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::ClusterHealthArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(
            ctx,
            "validate_chassis_cluster_health",
            "read",
            vec![args.router.clone()],
        );

        if let Err(e) = self.authorize_call(
            &extensions,
            "validate_chassis_cluster_health",
            Some(&args.router),
        ) {
            audit.deny(match e {
                ScopeError::MissingCallerContext => "missing_caller_context",
                ScopeError::RouterNotInScope { .. } => "router_scope",
                ScopeError::ToolNotInScope { .. } => "tool_scope",
            });
            return Self::srx_scope_to_call_result(e);
        }
        let mut device =
            self.dm.open(&args.router).await.map_err(|e| {
                rmcp::ErrorData::internal_error(format!("opening device: {e}"), None)
            })?;
        let resp = rust_junosmcp_srx_core::workflows::cluster_health::run(&mut device, args)
            .await
            .map_err(|e| match e {
                rust_junosmcp_srx_core::SrxError::InvalidInput(_) => {
                    rmcp::ErrorData::invalid_params(e.to_string(), None)
                }
                _ => rmcp::ErrorData::internal_error(e.to_string(), None),
            })?;
        let result = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing ClusterHealthData: {e}"), None)
        });
        match &result {
            Ok(body) => {
                audit.meta("output_bytes", body.len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail_kind("serialize", e),
        }
        result.map(|body| CallToolResult::success(vec![ContentBlock::text(body)]))
    }

    #[tool(
        name = "collect_jtac_support_bundle",
        description = "Collects a JTAC-ready diagnostic bundle for the named router. \
                       problem_type accepts a closed enum value (chassis_cluster, vpn, \
                       traffic_loss, idp_appid, routing, generic) OR an array of values \
                       for multi-symptom cases. The 'generic' value short-circuits and \
                       runs `request support information | save /var/tmp/srxmcp-<rid>.tgz` \
                       on the device — fetch via the rust-junosmcp `fetch_file` tool. \
                       Per-type values capture the universal baseline (get-configuration, \
                       get-software-information, get-system-uptime-information, \
                       get-system-alarm-information) plus type-specific RPCs, and assemble \
                       the tarball on the MCP host under JMCP_SRX_STAGING_DIR (default \
                       /var/lib/jmcp/srx-staging/bundles/<router>/srxmcp-<rid>.tgz). \
                       The response's bundle.location field is 'device' or 'lxc_staging'. \
                       Caller-supplied request_id is a validated correlation label used only \
                       in response metadata and audit logs. Filesystem paths always use a \
                       separate server-minted srxmcp-<uuid> returned as filesystem_id. \
                       Concurrent calls against the same router serialize on an in-process \
                       per-router semaphore and surface contention as \
                       [code=bundle_per_router_contention]."
    )]
    async fn collect_jtac_support_bundle(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::SupportBundleArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(
            ctx,
            "collect_jtac_support_bundle",
            "collect",
            vec![args.router.clone()],
        );

        if let Err(e) = self.authorize_call(
            &extensions,
            "collect_jtac_support_bundle",
            Some(&args.router),
        ) {
            audit.deny(match e {
                ScopeError::MissingCallerContext => "missing_caller_context",
                ScopeError::RouterNotInScope { .. } => "router_scope",
                ScopeError::ToolNotInScope { .. } => "tool_scope",
            });
            return Self::srx_scope_to_call_result(e);
        }
        rust_junosmcp_srx_core::workflows::support_bundle::validate_path_inputs(&args)
            .map_err(|e| rmcp::ErrorData::invalid_params(e.to_string(), None))?;
        let mut device =
            self.dm.open(&args.router).await.map_err(|e| {
                rmcp::ErrorData::internal_error(format!("opening device: {e}"), None)
            })?;
        let result = rust_junosmcp_srx_core::workflows::support_bundle::run(
            &mut device,
            args,
            &self.support_bundle_staging,
        )
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        let resp = result.map_err(|e| match e {
            rust_junosmcp_srx_core::SrxError::InvalidInput(_) => {
                rmcp::ErrorData::invalid_params(e.to_string(), None)
            }
            rust_junosmcp_srx_core::SrxError::BundlePerRouterContention { .. } => {
                rmcp::ErrorData::invalid_request(e.to_string(), None)
            }
            _ => rmcp::ErrorData::internal_error(e.to_string(), None),
        })?;
        let body = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing SupportBundleData: {e}"), None)
        })?;
        Ok(CallToolResult::success(vec![ContentBlock::text(body)]))
    }
}

#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct SrxmcpStatusArgs {}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct SrxmcpStatusResponse {
    pub version: String,
    pub endpoint: String,
    pub uptime_seconds: u64,
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    use rust_junosmcp_auth::caller::CallerCtx;
    use rust_junosmcp_auth::ScopeSet;

    fn make_handler(authorization_required: bool) -> JmcpHandler {
        let inventory = Arc::new(rust_junosmcp_core::Inventory::empty());
        let dm = Arc::new(DeviceManager::new(inventory.clone()));
        let policy = Arc::new(rust_junosmcp_core::Policy::build(&inventory).unwrap());
        let transfer_cfg = rust_junosmcp_core::TransferConfig {
            staging_dir: std::path::PathBuf::from("/tmp/staging"),
            known_hosts_file: std::path::PathBuf::from("/tmp/known_hosts"),
            scp_runner: Arc::new(rust_junosmcp_core::OpenSshScpRunner),
            transfer_locks: Arc::new(
                rust_junosmcp_core::tools::transfer_file::TransferLocks::default(),
            ),
            accept_new_host_keys: false,
        };
        let lease_dir = tempfile::tempdir().unwrap();
        let device_leases = Arc::new(DeviceLeaseManager::for_directory(lease_dir.path()).unwrap());
        let upgrade_cfg = rust_junosmcp_core::UpgradeConfig {
            transfer_cfg: transfer_cfg.clone(),
            device_leases,
        };
        JmcpHandler::new(dm, policy, transfer_cfg, upgrade_cfg)
            .with_srx_runtime(authorization_required, Default::default())
    }

    #[tokio::test]
    async fn srxmcp_status_preserves_shape() {
        let handler = make_handler(false);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let response = handler.srxmcp_status_body(SrxmcpStatusArgs::default());
        assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(response.endpoint, "srxmcp");
        assert!(response.uptime_seconds < 60);
    }

    #[test]
    fn missing_caller_context_preserves_explicit_no_auth_mode() {
        let handler = make_handler(false);
        assert!(handler
            .authorize_call(
                &Extensions::new(),
                "manage_idp_security_package",
                Some("srx-01"),
            )
            .is_ok());
    }

    #[test]
    fn missing_caller_context_fails_closed_when_authentication_is_required() {
        let handler = make_handler(true);
        assert!(matches!(
            handler.authorize_call(
                &Extensions::new(),
                "manage_idp_security_package",
                Some("srx-01"),
            ),
            Err(ScopeError::MissingCallerContext)
        ));
    }

    #[test]
    fn wildcard_scopes_allow_every_srx_tool_and_router() {
        let handler = make_handler(true);
        let ctx = CallerCtx {
            token_name: "srx-admin".into(),
            routers: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
        };

        for tool in SRX_SERVER_TOOLS {
            assert!(handler.check_srx_tool_scope(Some(&ctx), tool).is_ok());
            assert!(handler
                .check_srx_router_scope(Some(&ctx), tool, "srx-01")
                .is_ok());
        }
    }

    #[test]
    fn destructive_confirmation_is_checked_before_device_open() {
        let handler = make_handler(true);
        let missing = handler.validate_confirmation_request(
            true,
            None,
            Some("alice"),
            "srx-01",
            "srx-01|192.0.2.1|830|netconf",
        );
        assert!(matches!(
            missing,
            Err(rust_junosmcp_srx_core::SrxError::SignaturePackageConfirmationTokenRequired { .. })
        ));

        let binding =
            ConfirmationBinding::new(Some("alice"), "srx-01", "srx-01|192.0.2.1|830|netconf");
        let plan = handler
            .confirmation_store
            .issue(
                serde_json::json!({
                    "code": "confirmation_required",
                    "router": "srx-01",
                    "action": "rollback"
                }),
                binding,
                "req-precheck",
            )
            .unwrap();
        let token = plan["confirmation_token"].as_str().unwrap();
        let cloned_handler = handler.clone();
        assert!(cloned_handler
            .validate_confirmation_request(
                true,
                Some(token),
                Some("alice"),
                "srx-01",
                "srx-01|192.0.2.1|830|netconf",
            )
            .is_ok());
    }
}
