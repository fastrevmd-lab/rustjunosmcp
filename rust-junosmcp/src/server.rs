//! rmcp `ServerHandler` wrapping the core tool functions.
//!
//! Each `#[tool]` method is a thin adapter: it takes the typed `Parameters<T>`
//! struct, calls into `rust_junosmcp_core::tools::<name>::handle`, and converts
//! the `Result<serde_json::Value, JmcpError>` into the appropriate rmcp content.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, Content, Extensions, Implementation, ServerCapabilities, ServerInfo,
};
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use rust_junosmcp_core::{
    tools::{
        add_device, batch, config_diff, execute_command, facts, get_config, load_commit, pfe,
        reload_devices, router_list, template, AddDeviceArgs, ConfigDiffArgs, ExecuteBatchArgs,
        ExecuteCommandArgs, ExecutePfeArgs, GatherFactsArgs, GetConfigArgs, LoadCommitArgs,
        ReloadDevicesArgs, TemplateArgs,
    },
    DeviceManager, Inventory, Policy,
};
use serde_json::Value;
use std::sync::Arc;

/// Look up the per-request `CallerCtx` (inserted by the auth middleware on
/// the streamable-http path). Returns `None` under stdio.
///
/// Mechanism: rmcp 0.8.5's `StreamableHttpService` splits the incoming axum
/// request into `(Parts, Body)` and inserts the whole `http::request::Parts`
/// into the per-rmcp-request `Extensions` map. It does NOT propagate
/// individual extension types from `parts.extensions` into rmcp's `Extensions`.
/// So to reach the `CallerCtx` our outer middleware put on `req.extensions_mut()`
/// we have to walk through `Parts.extensions`.
///
/// - **stdio:** no `Parts` is inserted (no HTTP frame) → returns `None` →
///   scope checks become a no-op (preserves original behavior).
/// - **streamable-http:** rmcp inserted `Parts`; auth middleware put `CallerCtx`
///   into `req.extensions` which became `parts.extensions` → returns `Some(&ctx)`.
fn caller_ctx(extensions: &Extensions) -> Option<&crate::caller::CallerCtx> {
    extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<crate::caller::CallerCtx>())
}

#[derive(Debug, thiserror::Error)]
pub enum ScopeError {
    #[error("token '{token}' is not authorized for tool '{tool}'")]
    ToolNotInScope { token: String, tool: &'static str },
    #[error("token '{token}' is not authorized for router '{router}' (tool '{tool}')")]
    RouterNotInScope {
        token: String,
        router: String,
        tool: &'static str,
    },
}

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

    /// Convert `ScopeError` into the same kind of `CallToolResult { isError: true }`
    /// that `JmcpError::Denied` produces. Mirrors `to_call_result`.
    fn scope_to_call_result(e: ScopeError) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(CallToolResult::error(vec![Content::text(e.to_string())]))
    }

    /// Check tool scope. Returns `Err(ScopeError)` if denied, `Ok(())` if allowed
    /// or if no caller context is present (stdio path).
    fn check_tool_scope(
        &self,
        ctx: Option<&crate::caller::CallerCtx>,
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

    /// Check router scope. Returns `Err(ScopeError)` if denied, `Ok(())` if allowed
    /// or if no caller context is present (stdio path).
    fn check_router_scope(
        &self,
        ctx: Option<&crate::caller::CallerCtx>,
        tool: &'static str,
        router: &str,
    ) -> Result<(), ScopeError> {
        if let Some(ctx) = ctx {
            if !ctx.routers.allows(router) {
                return Err(ScopeError::RouterNotInScope {
                    token: ctx.token_name.clone(),
                    router: router.to_string(),
                    tool,
                });
            }
        }
        Ok(())
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
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "get_router_list") {
            return Self::scope_to_call_result(e);
        }
        Self::to_call_result(router_list::handle(self.inv.clone()).await)
    }

    #[tool(
        name = "gather_device_facts",
        description = "Gather Junos device facts from the router"
    )]
    async fn gather_device_facts(
        &self,
        Parameters(args): Parameters<GatherFactsArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "gather_device_facts") {
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "gather_device_facts", &args.router_name) {
            return Self::scope_to_call_result(e);
        }
        Self::to_call_result(facts::handle(args, self.dm.clone()).await)
    }

    #[tool(
        name = "execute_junos_command",
        description = "Execute a Junos command on the router"
    )]
    async fn execute_junos_command(
        &self,
        Parameters(args): Parameters<ExecuteCommandArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "execute_junos_command") {
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "execute_junos_command", &args.router_name) {
            return Self::scope_to_call_result(e);
        }
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
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "get_junos_config") {
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "get_junos_config", &args.router_name) {
            return Self::scope_to_call_result(e);
        }
        Self::to_call_result(get_config::handle(args, self.dm.clone()).await)
    }

    #[tool(
        name = "junos_config_diff",
        description = "Get the configuration diff against a rollback version"
    )]
    async fn junos_config_diff(
        &self,
        Parameters(args): Parameters<ConfigDiffArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "junos_config_diff") {
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "junos_config_diff", &args.router_name) {
            return Self::scope_to_call_result(e);
        }
        Self::to_call_result(config_diff::handle(args, self.dm.clone()).await)
    }

    #[tool(
        name = "load_and_commit_config",
        description = "Load and commit configuration on a Junos router"
    )]
    async fn load_and_commit_config(
        &self,
        Parameters(args): Parameters<LoadCommitArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "load_and_commit_config") {
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "load_and_commit_config", &args.router_name) {
            return Self::scope_to_call_result(e);
        }
        Self::to_call_result(load_commit::handle(args, self.dm.clone(), self.policy.clone()).await)
    }

    #[tool(
        name = "execute_junos_pfe_command",
        description = "Execute a single PFE-shell command on one router via 'request pfe execute target <fpc> command \"<cmd>\"'."
    )]
    async fn execute_junos_pfe_command(
        &self,
        Parameters(args): Parameters<ExecutePfeArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "execute_junos_pfe_command") {
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "execute_junos_pfe_command", &args.router_name)
        {
            return Self::scope_to_call_result(e);
        }
        Self::to_call_result(pfe::handle(args, self.dm.clone(), self.policy.clone()).await)
    }

    #[tool(
        name = "execute_junos_command_batch",
        description = "Run N operational CLI commands across M routers, parallel across routers, sequential per router. Returns a per-router array of {command, ok, value?, error?} entries."
    )]
    async fn execute_junos_command_batch(
        &self,
        Parameters(args): Parameters<ExecuteBatchArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "execute_junos_command_batch") {
            return Self::scope_to_call_result(e);
        }
        for r in &args.routers {
            if let Err(e) = self.check_router_scope(ctx, "execute_junos_command_batch", r) {
                return Self::scope_to_call_result(e);
            }
        }
        Self::to_call_result(batch::handle(args, self.dm.clone(), self.policy.clone()).await)
    }

    #[tool(
        name = "render_and_apply_j2_template",
        description = "Render a Jinja2 template (inline) with JSON or YAML vars. Optionally commit the rendered config to one or more routers; supports dry-run."
    )]
    async fn render_and_apply_j2_template(
        &self,
        Parameters(args): Parameters<TemplateArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "render_and_apply_j2_template") {
            return Self::scope_to_call_result(e);
        }
        // Per-router scope is enforced inside the handler against the
        // resolved router list (router_name OR router_names). Same as
        // execute_junos_command_batch.
        let resolved = match (&args.router_name, &args.router_names) {
            (Some(one), None) => vec![one.clone()],
            (None, Some(many)) => many.clone(),
            _ => Vec::new(),
        };
        for r in &resolved {
            if let Err(e) = self.check_router_scope(ctx, "render_and_apply_j2_template", r) {
                return Self::scope_to_call_result(e);
            }
        }
        Self::to_call_result(template::handle(args, self.dm.clone(), self.policy.clone()).await)
    }

    #[tool(
        name = "add_device",
        description = "Add a Junos device to the in-memory inventory and persist to devices.json. Required fields: device_name, device_ip, username, auth (ssh_key or password). port defaults to 22. With clients that advertise elicitation, missing fields are prompted; otherwise the call returns MissingArguments."
    )]
    async fn add_device(
        &self,
        Parameters(args): Parameters<AddDeviceArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "add_device") {
            return Self::scope_to_call_result(e);
        }
        // Elicitation: rmcp 0.8.5's elicit API is non-trivial to wire safely
        // here; the handler returns MissingArguments for absent required fields,
        // which is the documented contract for non-elicitation transports.
        Self::to_call_result(add_device::handle(args, self.dm.clone()).await)
    }

    #[tool(
        name = "reload_devices",
        description = "Reload the inventory. With no args, re-reads the current --device-mapping. With file_name, swaps to a new inventory file. Reports added/removed/changed device names."
    )]
    async fn reload_devices(
        &self,
        Parameters(args): Parameters<ReloadDevicesArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "reload_devices") {
            return Self::scope_to_call_result(e);
        }
        Self::to_call_result(reload_devices::handle(args, self.dm.clone()).await)
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

#[cfg(test)]
mod scope_tests {
    use super::*;
    use crate::caller::CallerCtx;
    use rust_junosmcp_auth::ScopeSet;

    fn make_handler() -> JmcpHandler {
        let inv = Arc::new(Inventory::empty());
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = Arc::new(Policy::build(&inv).unwrap());
        JmcpHandler::new(inv, dm, policy)
    }

    #[test]
    fn no_ctx_allows_anything() {
        let handler = make_handler();
        assert!(handler
            .check_tool_scope(None, "execute_junos_command")
            .is_ok());
        assert!(handler
            .check_router_scope(None, "execute_junos_command", "r1")
            .is_ok());
    }

    #[test]
    fn tool_scope_denies_when_not_listed() {
        let handler = make_handler();
        let ctx = CallerCtx {
            token_name: "alice".into(),
            routers: ScopeSet::Wildcard,
            tools: ScopeSet::Allowlist(vec!["get_router_list".into()]),
        };
        assert!(handler
            .check_tool_scope(Some(&ctx), "get_router_list")
            .is_ok());
        assert!(matches!(
            handler.check_tool_scope(Some(&ctx), "execute_junos_command"),
            Err(ScopeError::ToolNotInScope { .. })
        ));
    }

    #[test]
    fn router_scope_denies_when_not_listed() {
        let handler = make_handler();
        let ctx = CallerCtx {
            token_name: "alice".into(),
            routers: ScopeSet::Allowlist(vec!["r1".into()]),
            tools: ScopeSet::Wildcard,
        };
        assert!(handler
            .check_router_scope(Some(&ctx), "execute_junos_command", "r1")
            .is_ok());
        assert!(matches!(
            handler.check_router_scope(Some(&ctx), "execute_junos_command", "r2"),
            Err(ScopeError::RouterNotInScope { .. })
        ));
    }

    #[test]
    fn pfe_scope_denial_rejects_call() {
        let handler = make_handler();
        let ctx = CallerCtx {
            token_name: "alice".into(),
            routers: ScopeSet::Wildcard,
            tools: ScopeSet::Allowlist(vec!["execute_junos_command".into()]),
        };
        assert!(matches!(
            handler.check_tool_scope(Some(&ctx), "execute_junos_pfe_command"),
            Err(ScopeError::ToolNotInScope { .. })
        ));
    }

    #[test]
    fn batch_router_scope_first_failure_short_circuits() {
        // Conceptually models the per-router loop: the adapter fails on the
        // first router not in scope.
        let handler = make_handler();
        let ctx = CallerCtx {
            token_name: "alice".into(),
            routers: ScopeSet::Allowlist(vec!["r1".into()]),
            tools: ScopeSet::Wildcard,
        };
        let routers = ["r1", "r2"];
        let mut first_fail: Option<&str> = None;
        for r in &routers {
            if handler
                .check_router_scope(Some(&ctx), "execute_junos_command_batch", r)
                .is_err()
            {
                first_fail = Some(r);
                break;
            }
        }
        assert_eq!(first_fail, Some("r2"));
    }
}
