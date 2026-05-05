//! rmcp `ServerHandler` wrapping the core tool functions.
//!
//! Each `#[tool]` method is a thin adapter: it takes the typed `Parameters<T>`
//! struct, calls into `rust_junosmcp_core::tools::<name>::handle`, and converts
//! the `Result<serde_json::Value, JmcpError>` into the appropriate rmcp content.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, Implementation, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use rust_junosmcp_core::{
    tools::{
        config_diff, execute_command, facts, get_config, load_commit, router_list, ConfigDiffArgs,
        ExecuteCommandArgs, GatherFactsArgs, GetConfigArgs, LoadCommitArgs,
    },
    DeviceManager, Inventory, Policy,
};
use serde_json::Value;
use std::sync::Arc;

#[derive(Clone)]
pub struct JmcpHandler {
    inv: Arc<Inventory>,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
}

impl JmcpHandler {
    pub fn new(inv: Arc<Inventory>, dm: Arc<DeviceManager>, policy: Arc<Policy>) -> Self {
        Self { inv, dm, policy }
    }

    fn to_call_result(
        r: Result<Value, rust_junosmcp_core::JmcpError>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(match r {
            Ok(Value::String(s)) => CallToolResult::success(vec![Content::text(s)]),
            Ok(other) => CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&other).unwrap_or_else(|e| e.to_string()),
            )]),
            Err(e) => CallToolResult::error(vec![Content::text(e.to_string())]),
        })
    }
}

#[tool_router]
impl JmcpHandler {
    #[tool(
        name = "get_router_list",
        description = "Get list of available Junos routers"
    )]
    async fn get_router_list(
        &self,
        Parameters(_): Parameters<rust_junosmcp_core::tools::EmptyArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Self::to_call_result(router_list::handle(self.inv.clone()).await)
    }

    #[tool(
        name = "gather_device_facts",
        description = "Gather Junos device facts from the router"
    )]
    async fn gather_device_facts(
        &self,
        Parameters(args): Parameters<GatherFactsArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Self::to_call_result(facts::handle(args, self.dm.clone()).await)
    }

    #[tool(
        name = "execute_junos_command",
        description = "Execute a Junos command on the router"
    )]
    async fn execute_junos_command(
        &self,
        Parameters(args): Parameters<ExecuteCommandArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Self::to_call_result(
            execute_command::handle(args, self.dm.clone(), self.policy.clone()).await,
        )
    }

    #[tool(
        name = "get_junos_config",
        description = "Get the configuration of the router"
    )]
    async fn get_junos_config(
        &self,
        Parameters(args): Parameters<GetConfigArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Self::to_call_result(get_config::handle(args, self.dm.clone()).await)
    }

    #[tool(
        name = "junos_config_diff",
        description = "Get the configuration diff against a rollback version"
    )]
    async fn junos_config_diff(
        &self,
        Parameters(args): Parameters<ConfigDiffArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Self::to_call_result(config_diff::handle(args, self.dm.clone()).await)
    }

    #[tool(
        name = "load_and_commit_config",
        description = "Load and commit configuration on a Junos router"
    )]
    async fn load_and_commit_config(
        &self,
        Parameters(args): Parameters<LoadCommitArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Self::to_call_result(
            load_commit::handle(args, self.dm.clone(), self.policy.clone()).await,
        )
    }
}

#[tool_handler(router = Self::tool_router())]
impl ServerHandler for JmcpHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "jmcp-server".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                ..Default::default()
            },
            instructions: Some(
                "Junos MCP server (Rust port). Use get_router_list to enumerate \
                 available routers, then run operational commands or load config."
                    .into(),
            ),
            ..Default::default()
        }
    }
}
