//! SRX-specific rmcp adapters composed into the unified [`JmcpHandler`].
//!
//! Unlike the Junos tool surface in `server.rs`, these adapters do not share
//! a single `to_call_result`-style choke point — each `#[tool]` method
//! serializes its own typed response body and wraps it directly in
//! `ContentBlock::text`. Every one of those `body` values is passed through
//! [`mecmcp_redact::redact_text`] immediately before wrapping, so device
//! secrets pulled in by workflows (chassis-cluster status, VPN lifecycle
//! reports, policy/NAT listings, ...) get the same last-mile redaction pass
//! the Junos tools get from `to_call_result`. `collect_jtac_support_bundle`
//! additionally has its own dedicated, more precise redaction pass
//! (`workflows::support_bundle::redact`) applied earlier, before the tarball
//! is built; the blanket `redact_text` pass here is a second, cheap safety
//! net on its summary response, not a replacement for that pass.

use super::{JmcpHandler, audit_scope, caller_ctx, mint_request_id};

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Extensions};
use rmcp::{tool, tool_router};
#[cfg(test)]
use rust_junosmcp_core::{DeviceLeaseManager, DeviceManager};
use rust_junosmcp_srx_core::workflows::signature_package::{
    ConfirmationBinding, confirmation_token_for_request,
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
        ctx: Option<&rust_junosmcp_auth::CallerCtx>,
        tool: &'static str,
    ) -> Result<(), ScopeError> {
        if let Some(ctx) = ctx
            && !ctx.tools.allows_tool(tool, rust_junosmcp_auth::WRITE_TOOLS)
        {
            return Err(ScopeError::ToolNotInScope {
                token: ctx.token_name.clone(),
                tool,
            });
        }
        Ok(())
    }

    fn check_srx_router_scope(
        &self,
        ctx: Option<&rust_junosmcp_auth::CallerCtx>,
        tool: &'static str,
        router: &str,
    ) -> Result<(), ScopeError> {
        let in_inventory = self.dm.inventory().contains_router(router);
        let allows = ctx.map(|c| c.devices.allows(router)).unwrap_or(true);
        let token = ctx.map(|c| c.token_name.as_str()).unwrap_or("<none>");
        match super::classify_router_access(allows, in_inventory) {
            super::RouterAccess::Allowed => {}
            super::RouterAccess::AllowedUnknown => {
                tracing::info!(
                    token,
                    router,
                    tool,
                    "router request for name absent from devices.json (unknown router)"
                );
            }
            super::RouterAccess::DeniedInScopePresent => {
                tracing::warn!(token, router, tool, "router request denied by token scope");
            }
            super::RouterAccess::DeniedUnknown => {
                tracing::warn!(
                    token,
                    router,
                    tool,
                    "router request denied: name absent from devices.json and out of token scope"
                );
            }
        }
        if let Some(ctx) = ctx
            && !ctx.devices.allows(router)
        {
            return Err(ScopeError::RouterNotInScope {
                token: ctx.token_name.clone(),
                tool,
            });
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
    ) -> Result<Option<&'a rust_junosmcp_auth::CallerCtx>, ScopeError> {
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
    "srx_list_policies",
    "srx_resolve_address",
    "srx_resolve_application",
    "srx_list_nat_rules",
    "manage_idp_security_package",
    "manage_appid_signature_package",
    "validate_chassis_cluster_health",
    "collect_jtac_support_bundle",
    "srx_flow_sessions",
    "srx_policy_match",
];

#[cfg(test)]
mod server_tools_const_tests {
    use super::SRX_SERVER_TOOLS;
    use rust_junosmcp_auth::SRX_TOOLS;
    use std::collections::HashSet;

    #[test]
    fn server_tools_len_is_fifteen() {
        assert_eq!(SRX_SERVER_TOOLS.len(), 15);
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

/// Redaction coverage for the SRX tool surface.
///
/// Unlike the Junos side (`server.rs`'s `to_call_result`), these adapters
/// have no single shared choke point — each `#[tool]` method builds its own
/// `body: String` and passes it through `ContentBlock::text`. Every one of
/// those 15 sites was changed to wrap `body` in
/// `mecmcp_redact::redact_text(&body)` before constructing the
/// `ContentBlock`. There is no fake device/transport in this test tree
/// (`DeviceManager` opens a real `rustez::Device` over real SSH), so these
/// tools' handlers cannot be driven end-to-end here; the functional proof
/// that `redact_text` actually strips the fixture secret shapes
/// (`$9$...`, pre-shared-key, RADIUS/TACACS secret, SNMP community,
/// password) lives in `server.rs`'s `redaction_coverage_tests`, which
/// exercises the identical primitive both call sites share. What this test
/// adds is the completeness check: every tool in `SRX_SERVER_TOOLS` is
/// either covered (wraps `body` the same way) or explicitly excluded with a
/// reason, so a newly added SRX tool is forced to be classified.
#[cfg(test)]
mod redaction_coverage_tests {
    use super::SRX_SERVER_TOOLS;

    /// Names, with reasons, of `SRX_SERVER_TOOLS` entries that return no
    /// device-derived text at all — everything else is expected to route
    /// its `body` through `mecmcp_redact::redact_text` the same way the 15
    /// `ContentBlock::text(mecmcp_redact::redact_text(&body))` call sites in
    /// this file do.
    fn excluded_reason(tool: &str) -> Option<&'static str> {
        match tool {
            "srxmcp_status" => {
                Some("returns this server's own version/endpoint/uptime; no device I/O")
            }
            _ => None,
        }
    }

    #[test]
    fn every_srx_tool_is_covered_or_explicitly_excluded() {
        assert!(
            !SRX_SERVER_TOOLS.is_empty(),
            "SRX_SERVER_TOOLS must not be empty"
        );

        let must_be_covered = [
            "get_chassis_cluster_status",
            "get_srx_security_services_status",
            "check_srx_feature_license",
            "vpn_lifecycle_report",
            "srx_list_policies",
            "srx_resolve_address",
            "srx_resolve_application",
            "srx_list_nat_rules",
            "validate_chassis_cluster_health",
            "collect_jtac_support_bundle",
            "srx_flow_sessions",
            "srx_policy_match",
        ];
        for tool in must_be_covered {
            assert!(
                SRX_SERVER_TOOLS.contains(&tool),
                "test fixture drift: {tool} is not in SRX_SERVER_TOOLS anymore"
            );
            assert!(
                excluded_reason(tool).is_none(),
                "{tool} can return device-derived output and must not be in the exclusion list"
            );
        }

        for tool in SRX_SERVER_TOOLS {
            let _ = excluded_reason(tool);
        }
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
        let mut audit = audit_scope(ctx, "srxmcp_status", "read", vec![]);

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
        result.map(|body| {
            CallToolResult::success(vec![ContentBlock::text(mecmcp_redact::redact_text(&body))])
        })
    }

    #[tool(
        name = "get_chassis_cluster_status",
        description = "Chassis-cluster topology + health snapshot. Returns \
                       state=not_configured for standalone SRX devices. Output is redacted: config/device values matching known secret patterns are replaced before being returned; structure and non-secret values are preserved."
    )]
    async fn get_chassis_cluster_status(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::ClusterStatusArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
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
        result.map(|body| {
            CallToolResult::success(vec![ContentBlock::text(mecmcp_redact::redact_text(&body))])
        })
    }

    #[tool(
        name = "get_srx_security_services_status",
        description = "Reports the health and version of up to five SRX security services \
                       (IDP, AppID, UTM Anti-Virus, SecIntel, ATP/AAMW) in a single call. \
                       Each sub-service is independently classified as active or not_configured. \
                       The overall state is not_configured only when all five sub-services are absent. Output is redacted: config/device values matching known secret patterns are replaced before being returned; structure and non-secret values are preserved."
    )]
    async fn get_srx_security_services_status(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::ServicesStatusArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
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
        result.map(|body| {
            CallToolResult::success(vec![ContentBlock::text(mecmcp_redact::redact_text(&body))])
        })
    }

    #[tool(
        name = "check_srx_feature_license",
        description = "Check whether a named SRX security feature (IDP, AppID, UTM Antivirus, \
                       Web Filtering, Anti-Spam, SecIntel, ATP Cloud, SSL Proxy) has a valid \
                       license installed on the device. Returns state=not_configured when no \
                       matching license record is present (including the expected lab case where \
                       only eval/trial licenses are installed). Output is redacted: config/device values matching known secret patterns are replaced before being returned; structure and non-secret values are preserved."
    )]
    async fn check_srx_feature_license(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::LicenseArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
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
        result.map(|body| {
            CallToolResult::success(vec![ContentBlock::text(mecmcp_redact::redact_text(&body))])
        })
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
                       RPC does not surface the st0 interface name). Output is redacted: config/device values matching known secret patterns are replaced before being returned; structure and non-secret values are preserved."
    )]
    async fn vpn_lifecycle_report(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::VpnLifecycleArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
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
        result.map(|body| {
            CallToolResult::success(vec![ContentBlock::text(mecmcp_redact::redact_text(&body))])
        })
    }

    #[tool(
        name = "srx_list_policies",
        description = "Lists security policies by from-zone/to-zone context, including global \
                       policies (zone `\"any\"`) and, optionally, per-policy hit counts. Names on \
                       each policy (addresses, applications) are returned unresolved — use \
                       srx_resolve_address / srx_resolve_application to expand them. Paginated via \
                       `limit`/`offset` (default limit 500); `truncated` and `total_count` in the \
                       response make any cutoff explicit rather than silent. Output is redacted: config/device values matching known secret patterns are replaced before being returned; structure and non-secret values are preserved."
    )]
    async fn srx_list_policies(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::PolicyListArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(ctx, "srx_list_policies", "read", vec![args.router.clone()]);

        if let Err(e) = self.authorize_call(&extensions, "srx_list_policies", Some(&args.router)) {
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
        let resp = rust_junosmcp_srx_core::workflows::list_policies::run(&mut device, args)
            .await
            .map_err(|e| match e {
                rust_junosmcp_srx_core::SrxError::InvalidInput(_) => {
                    rmcp::ErrorData::invalid_params(e.to_string(), None)
                }
                _ => rmcp::ErrorData::internal_error(e.to_string(), None),
            })?;
        let result = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing PolicyListData: {e}"), None)
        });
        match &result {
            Ok(body) => {
                audit.meta("output_bytes", body.len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail_kind("serialize", e),
        }
        result.map(|body| {
            CallToolResult::success(vec![ContentBlock::text(mecmcp_redact::redact_text(&body))])
        })
    }

    #[tool(
        name = "srx_resolve_address",
        description = "Resolves a Junos address or address-set name (global, or scoped to a \
                       zone's own address-book) to its flattened, deduplicated concrete leaves — \
                       prefixes, ranges, wildcards, or DNS names. Nested sets are walked \
                       recursively in this tool, never on the device; reference cycles are \
                       rejected rather than looped. DNS-name leaves are returned as-is — this tool \
                       never performs its own DNS resolution. `truncated` is set if the flattened \
                       member count exceeds the cap. Output is redacted: config/device values matching known secret patterns are replaced before being returned; structure and non-secret values are preserved."
    )]
    async fn srx_resolve_address(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::AddressResolveArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "srx_resolve_address",
            "read",
            vec![args.router.clone()],
        );

        if let Err(e) = self.authorize_call(&extensions, "srx_resolve_address", Some(&args.router))
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
        let resp = rust_junosmcp_srx_core::workflows::resolve_address::run(&mut device, args)
            .await
            .map_err(|e| match e {
                rust_junosmcp_srx_core::SrxError::InvalidInput(_)
                | rust_junosmcp_srx_core::SrxError::ResolutionNameNotFound { .. } => {
                    rmcp::ErrorData::invalid_params(e.to_string(), None)
                }
                _ => rmcp::ErrorData::internal_error(e.to_string(), None),
            })?;
        let result = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing AddressResolution: {e}"), None)
        });
        match &result {
            Ok(body) => {
                audit.meta("output_bytes", body.len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail_kind("serialize", e),
        }
        result.map(|body| {
            CallToolResult::success(vec![ContentBlock::text(mecmcp_redact::redact_text(&body))])
        })
    }

    #[tool(
        name = "srx_resolve_application",
        description = "Resolves a Junos application or application-set name — including \
                       `junos-*` predefined defaults — to its flattened, deduplicated concrete \
                       protocol/port leaves. Nested sets are walked recursively in this tool, \
                       never on the device; reference cycles are rejected rather than looped. \
                       `junos-*` defaults are served from a compiled-in static table when the \
                       device does not expose its `junos-defaults` group over NETCONF (a live \
                       device definition always takes precedence over the static table). \
                       `truncated` is set if the flattened member count exceeds the cap. \
                       Output is redacted: config/device values matching known secret patterns \
                       are replaced before being returned; structure and non-secret values are \
                       preserved."
    )]
    async fn srx_resolve_application(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::ApplicationResolveArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "srx_resolve_application",
            "read",
            vec![args.router.clone()],
        );

        if let Err(e) =
            self.authorize_call(&extensions, "srx_resolve_application", Some(&args.router))
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
        let resp = rust_junosmcp_srx_core::workflows::resolve_application::run(&mut device, args)
            .await
            .map_err(|e| match e {
                rust_junosmcp_srx_core::SrxError::InvalidInput(_)
                | rust_junosmcp_srx_core::SrxError::ResolutionNameNotFound { .. } => {
                    rmcp::ErrorData::invalid_params(e.to_string(), None)
                }
                _ => rmcp::ErrorData::internal_error(e.to_string(), None),
            })?;
        let result = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing ApplicationResolution: {e}"), None)
        });
        match &result {
            Ok(body) => {
                audit.meta("output_bytes", body.len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail_kind("serialize", e),
        }
        result.map(|body| {
            CallToolResult::success(vec![ContentBlock::text(mecmcp_redact::redact_text(&body))])
        })
    }

    #[tool(
        name = "srx_list_nat_rules",
        description = "Lists source, destination, and static NAT rules, independently per kind. \
                       Match criteria carry unresolved address/address-set names, same as \
                       srx_list_policies — use srx_resolve_address to expand them. Optionally \
                       fetch and join per-rule hit counts (`include_hit_counts`, three extra RPC \
                       round trips; a failed or unparsable join degrades to hit_count=None rather \
                       than failing the call). `limit` caps rules per kind (default 500); \
                       `truncated` is set if any kind was cut short. Output is redacted: config/device values matching known secret patterns are replaced before being returned; structure and non-secret values are preserved."
    )]
    async fn srx_list_nat_rules(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::NatRulesArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(ctx, "srx_list_nat_rules", "read", vec![args.router.clone()]);

        if let Err(e) = self.authorize_call(&extensions, "srx_list_nat_rules", Some(&args.router)) {
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
        let resp = rust_junosmcp_srx_core::workflows::list_nat_rules::run(&mut device, args)
            .await
            .map_err(|e| match e {
                rust_junosmcp_srx_core::SrxError::InvalidInput(_) => {
                    rmcp::ErrorData::invalid_params(e.to_string(), None)
                }
                _ => rmcp::ErrorData::internal_error(e.to_string(), None),
            })?;
        let result = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing NatRules: {e}"), None)
        });
        match &result {
            Ok(body) => {
                audit.meta("output_bytes", body.len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail_kind("serialize", e),
        }
        result.map(|body| {
            CallToolResult::success(vec![ContentBlock::text(mecmcp_redact::redact_text(&body))])
        })
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
        let mut audit = audit_scope(
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
        Ok(CallToolResult::success(vec![ContentBlock::text(
            mecmcp_redact::redact_text(&body),
        )]))
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
        let mut audit = audit_scope(
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
        Ok(CallToolResult::success(vec![ContentBlock::text(
            mecmcp_redact::redact_text(&body),
        )]))
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
                       RPC succeeded. include_raw=true appends concatenated raw RPC XML. Output is redacted: config/device values matching known secret patterns are replaced before being returned; structure and non-secret values are preserved."
    )]
    async fn validate_chassis_cluster_health(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::ClusterHealthArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
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
        result.map(|body| {
            CallToolResult::success(vec![ContentBlock::text(mecmcp_redact::redact_text(&body))])
        })
    }

    // Keep the legacy staging alias in this description for exact v0.3.6 SRX
    // schema compatibility. It remains functional during the 0.8.0 migration
    // window; operator documentation names the canonical JMCP_* replacement.
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
                       [code=bundle_per_router_contention]. Captured artefacts are additionally redacted by a dedicated, more precise pass (locked element/key-name and Junos-hash rules) before they are written into the tarball."
    )]
    async fn collect_jtac_support_bundle(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::SupportBundleArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
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
        Ok(CallToolResult::success(vec![ContentBlock::text(
            mecmcp_redact::redact_text(&body),
        )]))
    }

    #[tool(
        name = "srx_flow_sessions",
        description = "Filtered, hard-capped flow-session query (`show security flow session`). \
                       At least one filter (source_prefix, destination_prefix, source_port + \
                       protocol, destination_port + protocol, protocol, application, or \
                       session_identifier) is required unless acknowledge_unfiltered=true, in \
                       which case the query is still capped (default 200, hard ceiling 2000) \
                       and reported as truncated rather than silently returning everything that \
                       fit. Chassis-cluster session ownership is not synced across nodes, so \
                       sessions are grouped per node (re_name) and never merged into one table. \
                       Before any full walk, the device's own session-count summary is queried \
                       (with the same filters applied); when that count exceeds the cap, or \
                       can't be determined, the full walk is refused outright (never issued) — \
                       regardless of whether a filter was supplied — and the response reports \
                       total_count_reported with truncated=true. Output is redacted: config/device values matching known secret patterns are replaced before being returned; structure and non-secret values are preserved."
    )]
    async fn srx_flow_sessions(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::FlowSessionsArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(ctx, "srx_flow_sessions", "read", vec![args.router.clone()]);

        if let Err(e) = self.authorize_call(&extensions, "srx_flow_sessions", Some(&args.router)) {
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
        let resp = rust_junosmcp_srx_core::workflows::flow_sessions::run(&mut device, args)
            .await
            .map_err(|e| match e {
                rust_junosmcp_srx_core::SrxError::InvalidInput(_) => {
                    rmcp::ErrorData::invalid_params(e.to_string(), None)
                }
                _ => rmcp::ErrorData::internal_error(e.to_string(), None),
            })?;
        let result = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing FlowSessionQuery: {e}"), None)
        });
        match &result {
            Ok(body) => {
                audit.meta("output_bytes", body.len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail_kind("serialize", e),
        }
        result.map(|body| {
            CallToolResult::success(vec![ContentBlock::text(mecmcp_redact::redact_text(&body))])
        })
    }

    #[tool(
        name = "srx_policy_match",
        description = "Deterministic \"would this traffic be allowed\" answer for a 5-tuple \
                       (`show security match-policies`) — the device's own verdict, never a \
                       model's inference from the policy list. verdict is one of permit / deny / \
                       reject / no_match; no_match (device default-policy fallthrough, no explicit \
                       policy matched) is distinct from an explicit deny/reject policy match, and \
                       carries default_action (deny or permit) for whichever default-policy the \
                       device applies. is_global marks a matched zone-independent (any/any) \
                       policy. The 5-tuple (source_ip, \
                       destination_ip, source_port, destination_port, protocol) is parsed into \
                       typed values and rejected with a typed error before any RPC is sent if \
                       malformed. Output is redacted: config/device values matching known secret patterns are replaced before being returned; structure and non-secret values are preserved."
    )]
    async fn srx_policy_match(
        &self,
        Parameters(args): Parameters<rust_junosmcp_srx_core::PolicyMatchArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(ctx, "srx_policy_match", "read", vec![args.router.clone()]);

        if let Err(e) = self.authorize_call(&extensions, "srx_policy_match", Some(&args.router)) {
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
        let resp = rust_junosmcp_srx_core::workflows::policy_match::run(&mut device, args)
            .await
            .map_err(|e| match e {
                rust_junosmcp_srx_core::SrxError::InvalidInput(_) => {
                    rmcp::ErrorData::invalid_params(e.to_string(), None)
                }
                _ => rmcp::ErrorData::internal_error(e.to_string(), None),
            })?;
        let result = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing PolicyMatchResult: {e}"), None)
        });
        match &result {
            Ok(body) => {
                audit.meta("output_bytes", body.len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail_kind("serialize", e),
        }
        result.map(|body| {
            CallToolResult::success(vec![ContentBlock::text(mecmcp_redact::redact_text(&body))])
        })
    }
}

#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
    use rust_junosmcp_auth::{CallerCtx, ScopeSet};

    fn make_handler(authorization_required: bool) -> JmcpHandler {
        let inventory = Arc::new(rust_junosmcp_core::Inventory::empty());
        let dm = Arc::new(DeviceManager::new(inventory.clone()));
        let policy = Arc::new(rust_junosmcp_core::Policy::build(&inventory).unwrap());
        let transfer_cfg = rust_junosmcp_core::TransferConfig {
            staging_dir: std::path::PathBuf::from("/tmp/staging"),
            known_hosts_file: std::path::PathBuf::from("/tmp/known_hosts"),
            scp_runner: rust_junosmcp_core::MockScpRunner::ok(),
            transfer_locks: Arc::new(
                rust_junosmcp_core::tools::transfer_file::TransferLocks::default(),
            ),
            host_key_mode: rust_junosmcp_core::bootstrap::SshHostKeyMode::Strict,
        };
        let lease_dir = tempfile::tempdir().unwrap();
        let device_leases = Arc::new(DeviceLeaseManager::for_directory(lease_dir.path()).unwrap());
        let upgrade_cfg = rust_junosmcp_core::UpgradeConfig {
            transfer_cfg: transfer_cfg.clone(),
            device_leases,
        };
        // In-memory coordinator: these SRX tests never exercise the change-set
        // flow, and giving it no state path keeps them from touching disk.
        let coordinator = Arc::new(
            mecmcp_changeset::ChangesetCoordinator::load(
                None,
                mecmcp_changeset::OperationLimits::default(),
                std::time::Duration::from_secs(900),
                false,
            )
            .expect("in-memory changeset coordinator"),
        );
        JmcpHandler::new(
            dm,
            policy,
            transfer_cfg,
            upgrade_cfg,
            coordinator,
            false,
            false,
            mecmcp_audit::DirectCommitPolicy::new(false),
        )
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
        assert!(
            handler
                .authorize_call(
                    &Extensions::new(),
                    "manage_idp_security_package",
                    Some("srx-01"),
                )
                .is_ok()
        );
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
        let wildcard_ctx = CallerCtx {
            token_name: "srx-admin".into(),
            client_name: None,
            model_id: None,
            session_id: None,
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: Default::default(),
            request_id: uuid::Uuid::new_v4(),
        };

        // Wildcard tool scope now excludes write tools (manage_idp_security_package, manage_appid_signature_package)
        for tool in SRX_SERVER_TOOLS {
            if rust_junosmcp_auth::WRITE_TOOLS.contains(tool) {
                assert!(
                    handler
                        .check_srx_tool_scope(Some(&wildcard_ctx), tool)
                        .is_err(),
                    "wildcard tool scope should deny write tool: {tool}"
                );
            } else {
                assert!(
                    handler
                        .check_srx_tool_scope(Some(&wildcard_ctx), tool)
                        .is_ok(),
                    "wildcard tool scope should allow non-write tool: {tool}"
                );
                assert!(
                    handler
                        .check_srx_router_scope(Some(&wildcard_ctx), tool, "srx-01")
                        .is_ok()
                );
            }
        }

        // Explicit allowlist should still grant write tools
        let explicit_ctx = CallerCtx {
            token_name: "srx-write".into(),
            client_name: None,
            model_id: None,
            session_id: None,
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Allowlist(SRX_SERVER_TOOLS.iter().map(|s| (*s).to_string()).collect()),
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: Default::default(),
            request_id: uuid::Uuid::new_v4(),
        };
        for tool in SRX_SERVER_TOOLS {
            assert!(
                handler
                    .check_srx_tool_scope(Some(&explicit_ctx), tool)
                    .is_ok(),
                "explicit tool allowlist should grant all SRX tools including write tools: {tool}"
            );
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
        assert!(
            cloned_handler
                .validate_confirmation_request(
                    true,
                    Some(token),
                    Some("alice"),
                    "srx-01",
                    "srx-01|192.0.2.1|830|netconf",
                )
                .is_ok()
        );
    }
}
