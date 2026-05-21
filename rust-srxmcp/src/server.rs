//! `JmcpSrxHandler` — rmcp `#[tool]` registry root for `rust-srxmcp`.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, Content, Extensions, Implementation, ServerCapabilities, ServerInfo,
};
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use rust_junosmcp_core::DeviceManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::Instant;

#[derive(Clone)]
pub struct JmcpSrxHandler {
    started: Arc<Instant>,
    device_manager: Arc<DeviceManager>,
}

impl JmcpSrxHandler {
    pub fn new(started: Arc<Instant>, device_manager: Arc<DeviceManager>) -> Self {
        Self {
            started,
            device_manager,
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
                 get_srx_security_services_status."
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
