//! `JmcpSrxHandler` — rmcp `#[tool]` registry root for `rust-srxmcp`.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, Content, Extensions, Implementation, ServerCapabilities, ServerInfo,
};
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use rust_junosmcp_core::tools::transfer_file::TransferLocks;
use rust_junosmcp_core::DeviceManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::Instant;

/// Resolve the authenticated bearer token's `token_name` for audit
/// attribution. Walks the same `Parts` → `Extensions` chain documented in
/// `rust-junosmcp/src/server.rs::caller_ctx` — rmcp 0.8 inserts the whole
/// `http::request::Parts` into the per-request `Extensions`, and our auth
/// layer attaches `CallerCtx` to `Parts.extensions`. Returns `None` under
/// stdio (no HTTP frame) so audit lines still emit with `caller="unknown"`.
fn caller_ctx(extensions: &Extensions) -> Option<&rust_junosmcp_auth::caller::CallerCtx> {
    extensions.get::<http::request::Parts>().and_then(|parts| {
        parts
            .extensions
            .get::<rust_junosmcp_auth::caller::CallerCtx>()
    })
}

/// Mint a short per-request id used in audit lines. Format
/// `req-<nanos>` — nanosecond resolution since UNIX epoch is enough to keep
/// concurrent calls distinct in the same log stream.
fn mint_request_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("req-{nanos}")
}

#[derive(Clone)]
pub struct JmcpSrxHandler {
    started: Arc<Instant>,
    device_manager: Arc<DeviceManager>,
    /// Per-router semaphore shared across destructive workflows. Mirrors the
    /// pattern in `rust-junosmcp/src/server.rs` so a srxmcp `rollback` and a
    /// junos `upgrade_junos` can never race against the same device.
    transfer_locks: Arc<TransferLocks>,
}

impl JmcpSrxHandler {
    pub fn new(
        started: Arc<Instant>,
        device_manager: Arc<DeviceManager>,
        transfer_locks: Arc<TransferLocks>,
    ) -> Self {
        Self {
            started,
            device_manager,
            transfer_locks,
        }
    }

    /// Pure tool body — used by the rmcp adapter below and by integration
    /// tests via `srxmcp_status_test`.
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

    /// Test-only entry point so integration tests can drive the tool body
    /// without constructing an rmcp request envelope.
    pub fn srxmcp_status_test(&self, args: SrxmcpStatusArgs) -> SrxmcpStatusResponse {
        self.srxmcp_status_body(args)
    }
}

#[tool_router]
impl JmcpSrxHandler {
    #[tool(
        name = "srxmcp_status",
        description = "Diagnostic — returns this server's version, endpoint name, and uptime in seconds."
    )]
    async fn srxmcp_status(
        &self,
        Parameters(args): Parameters<SrxmcpStatusArgs>,
        _extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let resp = self.srxmcp_status_body(args);
        let body = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing SrxmcpStatusResponse: {e}"), None)
        })?;
        Ok(CallToolResult::success(vec![Content::text(body)]))
    }

    #[tool(
        name = "get_chassis_cluster_status",
        description = "Chassis-cluster topology + health snapshot. Returns \
                       state=not_configured for standalone SRX devices."
    )]
    async fn get_chassis_cluster_status(
        &self,
        Parameters(args): Parameters<rust_srxmcp_core::ClusterStatusArgs>,
        _extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut device =
            self.device_manager.open(&args.router).await.map_err(|e| {
                rmcp::ErrorData::internal_error(format!("opening device: {e}"), None)
            })?;
        let resp = rust_srxmcp_core::workflows::cluster_status::run(&mut device, args)
            .await
            .map_err(|e| match e {
                rust_srxmcp_core::SrxError::InvalidInput(_) => {
                    rmcp::ErrorData::invalid_params(e.to_string(), None)
                }
                _ => rmcp::ErrorData::internal_error(e.to_string(), None),
            })?;
        let body = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing ClusterStatusData: {e}"), None)
        })?;
        Ok(CallToolResult::success(vec![Content::text(body)]))
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
        Parameters(args): Parameters<rust_srxmcp_core::ServicesStatusArgs>,
        _extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut device =
            self.device_manager.open(&args.router).await.map_err(|e| {
                rmcp::ErrorData::internal_error(format!("opening device: {e}"), None)
            })?;
        let resp = rust_srxmcp_core::workflows::services_status::run(&mut device, args)
            .await
            .map_err(|e| match e {
                rust_srxmcp_core::SrxError::InvalidInput(_) => {
                    rmcp::ErrorData::invalid_params(e.to_string(), None)
                }
                _ => rmcp::ErrorData::internal_error(e.to_string(), None),
            })?;
        let body = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing ServicesStatusData: {e}"), None)
        })?;
        Ok(CallToolResult::success(vec![Content::text(body)]))
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
        Parameters(args): Parameters<rust_srxmcp_core::LicenseArgs>,
        _extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut device =
            self.device_manager.open(&args.router).await.map_err(|e| {
                rmcp::ErrorData::internal_error(format!("opening device: {e}"), None)
            })?;
        let resp = rust_srxmcp_core::workflows::license::run(&mut device, args)
            .await
            .map_err(|e| match e {
                rust_srxmcp_core::SrxError::InvalidInput(_) => {
                    rmcp::ErrorData::invalid_params(e.to_string(), None)
                }
                _ => rmcp::ErrorData::internal_error(e.to_string(), None),
            })?;
        let body = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing LicenseData: {e}"), None)
        })?;
        Ok(CallToolResult::success(vec![Content::text(body)]))
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
        Parameters(args): Parameters<rust_srxmcp_core::VpnLifecycleArgs>,
        _extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut device =
            self.device_manager.open(&args.router).await.map_err(|e| {
                rmcp::ErrorData::internal_error(format!("opening device: {e}"), None)
            })?;
        let resp = rust_srxmcp_core::workflows::vpn_lifecycle::run(&mut device, args)
            .await
            .map_err(|e| match e {
                rust_srxmcp_core::SrxError::InvalidInput(_) => {
                    rmcp::ErrorData::invalid_params(e.to_string(), None)
                }
                _ => rmcp::ErrorData::internal_error(e.to_string(), None),
            })?;
        let body = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing VpnLifecycleData: {e}"), None)
        })?;
        Ok(CallToolResult::success(vec![Content::text(body)]))
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
                       returns `[code=confirmation_required]` carrying a `plan` describing the \
                       intended change; call 2 with `confirm=true` executes. `download_and_install` \
                       short-circuits with `status=already_at_target` when every node already \
                       runs the requested version."
    )]
    async fn manage_idp_security_package(
        &self,
        Parameters(args): Parameters<rust_srxmcp_core::IdpPackageArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let caller = ctx.map(|c| c.token_name.as_str());
        let request_id = mint_request_id();

        let mut device =
            self.device_manager.open(&args.router).await.map_err(|e| {
                rmcp::ErrorData::internal_error(format!("opening device: {e}"), None)
            })?;
        let resp = rust_srxmcp_core::workflows::idp_package::run(
            &mut device,
            &self.transfer_locks,
            &args,
            caller,
            &request_id,
        )
        .await
        .map_err(|e| match e {
            rust_srxmcp_core::SrxError::InvalidInput(_) => {
                rmcp::ErrorData::invalid_params(e.to_string(), None)
            }
            // The two-call confirmation protocol surfaces as a bracketed
            // `[code=confirmation_required]` error string — InvalidRequest
            // is the closest JSON-RPC code (caller needs to re-call with
            // different args).
            rust_srxmcp_core::SrxError::SignaturePackageConfirmationRequired { .. } => {
                rmcp::ErrorData::invalid_request(e.to_string(), None)
            }
            _ => rmcp::ErrorData::internal_error(e.to_string(), None),
        })?;
        let body = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing IdpPackageResponse: {e}"), None)
        })?;
        Ok(CallToolResult::success(vec![Content::text(body)]))
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
                       `[code=confirmation_required]` carrying a `plan` describing the \
                       intended change; call 2 with `confirm=true` executes. \
                       `download_and_install` short-circuits with `status=already_at_target` \
                       when every node already runs the requested version."
    )]
    async fn manage_appid_signature_package(
        &self,
        Parameters(args): Parameters<rust_srxmcp_core::AppidPackageArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let caller = ctx.map(|c| c.token_name.as_str());
        let request_id = mint_request_id();

        let mut device =
            self.device_manager.open(&args.router).await.map_err(|e| {
                rmcp::ErrorData::internal_error(format!("opening device: {e}"), None)
            })?;
        let resp = rust_srxmcp_core::workflows::appid_package::run(
            &mut device,
            &self.transfer_locks,
            &args,
            caller,
            &request_id,
        )
        .await
        .map_err(|e| match e {
            rust_srxmcp_core::SrxError::InvalidInput(_) => {
                rmcp::ErrorData::invalid_params(e.to_string(), None)
            }
            rust_srxmcp_core::SrxError::SignaturePackageConfirmationRequired { .. } => {
                rmcp::ErrorData::invalid_request(e.to_string(), None)
            }
            _ => rmcp::ErrorData::internal_error(e.to_string(), None),
        })?;
        let body = serde_json::to_string_pretty(&resp).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("serializing AppidPackageResponse: {e}"), None)
        })?;
        Ok(CallToolResult::success(vec![Content::text(body)]))
    }
}

#[tool_handler(router = Self::tool_router())]
impl ServerHandler for JmcpSrxHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "srxmcp-server".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                ..Default::default()
            },
            instructions: Some(
                "Juniper SRX-specific MCP server. Phase 1B tools: \
                 srxmcp_status, get_chassis_cluster_status, check_srx_feature_license, \
                 get_srx_security_services_status, vpn_lifecycle_report. \
                 Phase 2 destructive tools: manage_idp_security_package, \
                 manage_appid_signature_package."
                    .into(),
            ),
            ..Default::default()
        }
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
