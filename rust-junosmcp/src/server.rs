//! rmcp `ServerHandler` wrapping the core tool functions.
//!
//! Each `#[tool]` method is a thin adapter: it takes the typed `Parameters<T>`
//! struct, calls into `rust_junosmcp_core::tools::<name>::handle`, and converts
//! the `Result<serde_json::Value, JmcpError>` into the appropriate rmcp content.

use rmcp::handler::server::wrapper::Parameters;
use rust_junosmcp_audit::AuditScope;
use sha2::{Digest, Sha256};
use rmcp::model::{
    CallToolResult, ContentBlock, Extensions, Implementation, ServerCapabilities, ServerInfo,
};
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use rust_junosmcp_core::{
    tools::{
        add_device, batch, commit_check, config_diff, discard_candidate, execute_command, facts,
        fetch_file, get_config, list_staged_files, load_commit, pfe, reload_devices, router_list,
        template, transfer_file, upgrade_junos, AddDeviceArgs, CommitCheckArgs, ConfigDiffArgs,
        DiscardCandidateArgs, ExecuteBatchArgs, ExecuteCommandArgs, ExecutePfeArgs, FetchFileArgs,
        GatherFactsArgs, GetConfigArgs, ListStagedFilesArgs, LoadCommitArgs, ReloadDevicesArgs,
        TemplateArgs, TransferFileArgs, UpgradeJunosArgs,
    },
    DeviceManager, Policy,
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
fn caller_ctx(extensions: &Extensions) -> Option<&rust_junosmcp_auth::caller::CallerCtx> {
    extensions.get::<http::request::Parts>().and_then(|parts| {
        parts
            .extensions
            .get::<rust_junosmcp_auth::caller::CallerCtx>()
    })
}

fn mint_request_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("req-{nanos}")
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
    dm: Arc<DeviceManager>,
    policy: Arc<arc_swap::ArcSwap<Policy>>,
    transfer_cfg: rust_junosmcp_core::TransferConfig,
    upgrade_cfg: rust_junosmcp_core::UpgradeConfig,
}

impl JmcpHandler {
    pub fn new(
        dm: Arc<DeviceManager>,
        policy: Arc<Policy>,
        transfer_cfg: rust_junosmcp_core::TransferConfig,
        upgrade_cfg: rust_junosmcp_core::UpgradeConfig,
    ) -> Self {
        Self {
            dm,
            policy: Arc::new(arc_swap::ArcSwap::from(policy)),
            transfer_cfg,
            upgrade_cfg,
        }
    }

    pub fn transfer_config(&self) -> &rust_junosmcp_core::TransferConfig {
        &self.transfer_cfg
    }

    /// Rebuild the blocklist policy from the current inventory and store it.
    /// Called after inventory mutations (add_device, reload_devices, SIGHUP).
    pub fn rebuild_policy(&self) {
        if let Ok(new_policy) = Policy::build(&self.dm.inventory()) {
            self.policy.store(Arc::new(new_policy));
        }
    }

    fn to_call_result(
        r: Result<Value, rust_junosmcp_core::JmcpError>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(match r {
            Ok(Value::String(s)) => CallToolResult::success(vec![ContentBlock::text(s)]),
            Ok(other) => CallToolResult::success(vec![ContentBlock::text(
                serde_json::to_string_pretty(&other).unwrap_or_else(|e| e.to_string()),
            )]),
            Err(e) => CallToolResult::error(vec![ContentBlock::text(e.to_string())]),
        })
    }

    /// Convert `ScopeError` into the same kind of `CallToolResult { isError: true }`
    /// that `JmcpError::Denied` produces. Mirrors `to_call_result`.
    fn scope_to_call_result(e: ScopeError) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(CallToolResult::error(vec![ContentBlock::text(
            e.to_string(),
        )]))
    }

    /// Check tool scope. Returns `Err(ScopeError)` if denied, `Ok(())` if allowed
    /// or if no caller context is present (stdio path).
    fn check_tool_scope(
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

    /// Check router scope. Returns `Err(ScopeError)` if denied, `Ok(())` if allowed
    /// or if no caller context is present (stdio path).
    fn check_router_scope(
        &self,
        ctx: Option<&rust_junosmcp_auth::caller::CallerCtx>,
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

/// Single source of truth for the MCP tool names this server exposes.
///
/// Listed in source-declaration order below. Must stay in sync with
/// `rust_junosmcp_auth::file::JUNOS_TOOLS`; the
/// `server_tools_matches_known_tools_as_set` unit test enforces this.
/// Drift here silently denies operators least-privilege token scopes for new
/// tools (see RJMCP-SEC-001). This is a binary-crate tripwire consumed only
/// by the inline test module, hence `allow(dead_code)`.
#[allow(dead_code)]
const SERVER_TOOLS: &[&str] = &[
    "get_router_list",
    "gather_device_facts",
    "execute_junos_command",
    "get_junos_config",
    "junos_config_diff",
    "load_and_commit_config",
    "commit_check_config",
    "discard_candidate",
    "execute_junos_pfe_command",
    "execute_junos_command_batch",
    "render_and_apply_j2_template",
    "add_device",
    "reload_devices",
    "transfer_file",
    "fetch_file",
    "upgrade_junos",
    "list_staged_files",
];

#[cfg(test)]
mod server_tools_const_tests {
    use super::SERVER_TOOLS;
    use rust_junosmcp_auth::file::JUNOS_TOOLS;
    use std::collections::HashSet;

    /// Tripwire: changing tool count without updating `SERVER_TOOLS` breaks
    /// the build. Bump this number deliberately when adding/removing tools.
    #[test]
    fn server_tools_len_is_17() {
        assert_eq!(SERVER_TOOLS.len(), 17);
    }

    #[test]
    fn server_tools_has_no_duplicates() {
        let mut seen = HashSet::new();
        for t in SERVER_TOOLS {
            assert!(seen.insert(*t), "duplicate tool name in SERVER_TOOLS: {t}");
        }
    }

    /// RJMCP-SEC-001: prevent `JUNOS_TOOLS` (auth crate) drifting from
    /// `SERVER_TOOLS` (this crate). If a new `#[tool(name = "x")]` is added
    /// without updating both, this test fails and the operator cannot mint a
    /// scoped token for "x" — and would be tempted to fall back to wildcard.
    #[test]
    fn server_tools_matches_known_tools_as_set() {
        let server: HashSet<&str> = SERVER_TOOLS.iter().copied().collect();
        let known: HashSet<&str> = JUNOS_TOOLS.iter().copied().collect();
        assert_eq!(
            server,
            known,
            "SERVER_TOOLS / JUNOS_TOOLS drift: only-in-server={:?}, only-in-known={:?}",
            server.difference(&known).collect::<Vec<_>>(),
            known.difference(&server).collect::<Vec<_>>(),
        );
    }
}

#[tool_router]
impl JmcpHandler {
    #[tool(
        name = "get_router_list",
        description = "Get the Junos routers visible to this caller. Returns [] when the caller's router scope has no current inventory matches."
    )]
    async fn get_router_list(
        &self,
        Parameters(_): Parameters<rust_junosmcp_core::tools::EmptyArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(ctx, "get_router_list", "read", vec![]);

        if let Err(e) = self.check_tool_scope(ctx, "get_router_list") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        let names =
            rust_junosmcp_auth::caller::filter_router_names(ctx, self.dm.inventory().names());
        let result = router_list::handle_names(names).await;
        match &result {
            Ok(v) => {
                if let Some(arr) = v.as_object().and_then(|o| o.get("names")).and_then(|n| n.as_array()) {
                    audit.meta("count", arr.len() as u64);
                }
                audit.succeed();
            }
            Err(e) => audit.fail(e),
        }
        Self::to_call_result(result)
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
        let mut audit = AuditScope::new(ctx, "gather_device_facts", "read", vec![args.router_name.clone()]);

        if let Err(e) = self.check_tool_scope(ctx, "gather_device_facts") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "gather_device_facts", &args.router_name) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        let result = facts::handle(args, self.dm.clone()).await;
        match &result {
            Ok(v) => {
                audit.meta("output_bytes", v.to_string().len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail(e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "execute_junos_command",
        description = "Execute a Junos command on the router. Supports optional max_lines/max_bytes/tail output caps, and honors trailing '| last N' / '| count'."
    )]
    async fn execute_junos_command(
        &self,
        Parameters(args): Parameters<ExecuteCommandArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(ctx, "execute_junos_command", "execute", vec![args.router_name.clone()]);

        if let Err(e) = self.check_tool_scope(ctx, "execute_junos_command") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "execute_junos_command", &args.router_name) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }
        audit.meta("command", args.command.clone());

        let result = execute_command::handle(args, self.dm.clone(), self.policy.load_full()).await;
        match &result {
            Ok(v) => {
                audit.meta("output_bytes", v.to_string().len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail(e),
        }
        Self::to_call_result(result)
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
        let mut audit = AuditScope::new(ctx, "get_junos_config", "read", vec![args.router_name.clone()]);

        if let Err(e) = self.check_tool_scope(ctx, "get_junos_config") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "get_junos_config", &args.router_name) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        let result = get_config::handle(args, self.dm.clone()).await;
        match &result {
            Ok(v) => {
                audit.meta("output_bytes", v.to_string().len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail(e),
        }
        Self::to_call_result(result)
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
        let mut audit = AuditScope::new(ctx, "junos_config_diff", "read", vec![args.router_name.clone()]);

        if let Err(e) = self.check_tool_scope(ctx, "junos_config_diff") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "junos_config_diff", &args.router_name) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        let result = config_diff::handle(args, self.dm.clone()).await;
        match &result {
            Ok(v) => {
                audit.meta("output_bytes", v.to_string().len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail(e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "load_and_commit_config",
        description = "Load and commit configuration on a Junos router"
    )]
    async fn load_and_commit_config(
        &self,
        Parameters(args): Parameters<LoadCommitArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(ctx, "load_and_commit_config", "commit", vec![args.router_name.clone()]);

        if let Err(e) = self.check_tool_scope(ctx, "load_and_commit_config") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "load_and_commit_config", &args.router_name) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        audit.meta("config_bytes", args.config_text.len() as u64);
        let mut hasher = Sha256::new();
        hasher.update(args.config_text.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        audit.meta("config_sha256", hash);
        if let Some(confirm_mins) = args.confirm_timeout_mins {
            audit.meta("commit_confirmed", confirm_mins as u64);
        }
        audit.meta("comment_present", !args.commit_comment.is_empty());

        let result = load_commit::handle_with_cancel(args, self.dm.clone(), self.policy.load_full(), ct).await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "commit_check_config",
        description = "Validate a candidate configuration on a Junos router without committing (commit check). Loads config into a candidate, runs commit-check, returns {success, diff, error?}, then discards the candidate. Never activates config."
    )]
    async fn commit_check_config(
        &self,
        Parameters(args): Parameters<CommitCheckArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(ctx, "commit_check_config", "commit-check", vec![args.router_name.clone()]);

        if let Err(e) = self.check_tool_scope(ctx, "commit_check_config") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "commit_check_config", &args.router_name) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        audit.meta("config_bytes", args.config_text.len() as u64);
        let mut hasher = Sha256::new();
        hasher.update(args.config_text.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        audit.meta("config_sha256", hash);

        let result = commit_check::handle_with_cancel(args, self.dm.clone(), self.policy.load_full(), ct).await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "discard_candidate",
        description = "Discard uncommitted candidate configuration changes on a Junos router (rollback 0), returning the candidate to the running config. Never changes the running config. Use to recover a candidate left dirty (e.g. 'configuration database modified')."
    )]
    async fn discard_candidate(
        &self,
        Parameters(args): Parameters<DiscardCandidateArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(ctx, "discard_candidate", "discard", vec![args.router_name.clone()]);

        if let Err(e) = self.check_tool_scope(ctx, "discard_candidate") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "discard_candidate", &args.router_name) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        let result = discard_candidate::handle_with_cancel(args, self.dm.clone(), ct).await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "execute_junos_pfe_command",
        description = "Execute a single PFE-shell command on one router via 'request pfe execute target <fpc> command \"<cmd>\"'. Supports optional max_lines/max_bytes/tail output caps, and honors trailing '| last N' / '| count'."
    )]
    async fn execute_junos_pfe_command(
        &self,
        Parameters(args): Parameters<ExecutePfeArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(ctx, "execute_junos_pfe_command", "execute", vec![args.router_name.clone()]);

        if let Err(e) = self.check_tool_scope(ctx, "execute_junos_pfe_command") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "execute_junos_pfe_command", &args.router_name) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }
        audit.meta("command", args.pfe_command.clone());

        let result = pfe::handle(args, self.dm.clone(), self.policy.load_full()).await;
        match &result {
            Ok(v) => {
                audit.meta("output_bytes", v.to_string().len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail(e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "execute_junos_command_batch",
        description = "Run N operational CLI commands across M routers, parallel across routers, sequential per router. Returns a per-router array of {command, ok, value?, error?} entries. Supports optional max_lines/max_bytes/tail output caps, and honors trailing '| last N' / '| count'."
    )]
    async fn execute_junos_command_batch(
        &self,
        Parameters(args): Parameters<ExecuteBatchArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(ctx, "execute_junos_command_batch", "execute-batch", args.routers.clone());

        if let Err(e) = self.check_tool_scope(ctx, "execute_junos_command_batch") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        for r in &args.routers {
            if let Err(e) = self.check_router_scope(ctx, "execute_junos_command_batch", r) {
                audit.deny("router_scope");
                return Self::scope_to_call_result(e);
            }
        }
        audit.meta("command_count", args.commands.len() as u64);

        let result = batch::handle(args, self.dm.clone(), self.policy.load_full()).await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "render_and_apply_j2_template",
        description = "Render a Jinja2 template (inline) with JSON vars. Optionally commit the rendered config to one or more routers; supports dry-run. (YAML vars are no longer accepted as of v0.5.2.)"
    )]
    async fn render_and_apply_j2_template(
        &self,
        Parameters(args): Parameters<TemplateArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let resolved = match (&args.router_name, &args.router_names) {
            (Some(one), None) => vec![one.clone()],
            (None, Some(many)) => many.clone(),
            _ => Vec::new(),
        };
        let mut audit = AuditScope::new(ctx, "render_and_apply_j2_template", "apply", resolved.clone());

        if let Err(e) = self.check_tool_scope(ctx, "render_and_apply_j2_template") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        for r in &resolved {
            if let Err(e) = self.check_router_scope(ctx, "render_and_apply_j2_template", r) {
                audit.deny("router_scope");
                return Self::scope_to_call_result(e);
            }
        }

        // Parse vars_content to count vars
        if let Ok(vars) = serde_json::from_str::<serde_json::Value>(&args.vars_content) {
            if let Some(obj) = vars.as_object() {
                audit.meta("var_count", obj.len() as u64);
            }
        }
        audit.meta("committed", args.apply_config && !args.dry_run);

        let result = template::handle_with_cancel(args, self.dm.clone(), self.policy.load_full(), ct).await;
        match &result {
            Ok(v) => {
                if let Some(rendered) = v.get("rendered").and_then(|r| r.as_str()) {
                    audit.meta("rendered_bytes", rendered.len() as u64);
                }
                audit.succeed();
            }
            Err(e) => audit.fail(e),
        }
        Self::to_call_result(result)
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
        let mut audit = AuditScope::new(ctx, "add_device", "add-device", vec![]);

        if let Err(e) = self.check_tool_scope(ctx, "add_device") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }

        if let Some(name) = &args.device_name {
            audit.meta("name", name.clone());
        }
        if let Some(host) = &args.device_ip {
            audit.meta("host", host.clone());
        }
        if let Some(auth) = &args.auth {
            let auth_kind = match auth {
                rust_junosmcp_core::inventory::AuthConfig::Password { .. } => "password",
                rust_junosmcp_core::inventory::AuthConfig::SshKey { .. } => "ssh_key",
            };
            audit.meta("auth_kind", auth_kind);
        }

        let result = add_device::handle(args, self.dm.clone()).await;
        match &result {
            Ok(_) => {
                self.rebuild_policy();
                audit.succeed();
            }
            Err(e) => {
                if matches!(e, rust_junosmcp_core::JmcpError::InventoryReadonly) {
                    audit.deny("inventory_readonly");
                } else {
                    audit.fail(e);
                }
            }
        }
        Self::to_call_result(result)
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
        let mut audit = AuditScope::new(ctx, "reload_devices", "reload-inventory", vec![]);

        if let Err(e) = self.check_tool_scope(ctx, "reload_devices") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }

        let result = reload_devices::handle(args, self.dm.clone()).await;
        match &result {
            Ok(v) => {
                self.rebuild_policy();
                if let Some(added) = v.get("added").and_then(|a| a.as_array()) {
                    if let Some(removed) = v.get("removed").and_then(|r| r.as_array()) {
                        let total = added.len() + removed.len();
                        audit.meta("device_count", total as u64);
                    }
                }
                audit.succeed();
            }
            Err(e) => {
                if matches!(e, rust_junosmcp_core::JmcpError::InventoryReadonly) {
                    audit.deny("inventory_readonly");
                } else {
                    audit.fail(e);
                }
            }
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "transfer_file",
        description = "Push a local file from the staging dir to /var/tmp/ on a Junos device via SCP. Idempotent on matching SHA-256."
    )]
    async fn transfer_file(
        &self,
        Parameters(args): Parameters<TransferFileArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(ctx, "transfer_file", "transfer", vec![args.router_name.clone()]);

        if let Err(e) = self.check_tool_scope(ctx, "transfer_file") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "transfer_file", &args.router_name) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }
        audit.meta("basename", args.source_path.clone());

        let result = transfer_file::handle(args, self.dm.clone(), self.transfer_config().clone(), ct).await;
        match &result {
            Ok(v) => {
                if let Some(sha256) = v.get("sha256").and_then(|s| s.as_str()) {
                    audit.meta("sha256", sha256);
                }
                audit.succeed();
            }
            Err(e) => audit.fail(e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "fetch_file",
        description = "Download a file from a Junos device's /var/tmp/<basename> to the host staging directory, with sha256 verification. Mirror of transfer_file."
    )]
    async fn fetch_file(
        &self,
        Parameters(args): Parameters<FetchFileArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(ctx, "fetch_file", "fetch", vec![args.router_name.clone()]);

        if let Err(e) = self.check_tool_scope(ctx, "fetch_file") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "fetch_file", &args.router_name) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }
        audit.meta("basename", args.remote_path.clone());

        let result = fetch_file::handle(args, self.dm.clone(), self.transfer_config().clone(), ct).await;
        match &result {
            Ok(v) => {
                if let Some(sha256) = v.get("sha256").and_then(|s| s.as_str()) {
                    audit.meta("sha256", sha256);
                }
                audit.succeed();
            }
            Err(e) => audit.fail(e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "upgrade_junos",
        description = "DESTRUCTIVE: installs a new Junos image and REBOOTS the device. Outage ~5-7 min. Requires confirm=true to proceed; first call with confirm=false returns a ConfirmationRequired error containing the upgrade plan (current version, target version, image, free disk, estimated outage). v1 supports standalone devices only; chassis clusters are refused."
    )]
    async fn upgrade_junos(
        &self,
        Parameters(args): Parameters<UpgradeJunosArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = AuditScope::new(ctx, "upgrade_junos", "upgrade", vec![args.router_name.clone()]);

        if let Err(e) = self.check_tool_scope(ctx, "upgrade_junos") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "upgrade_junos", &args.router_name) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        audit.meta("basename", args.source_path.clone());
        audit.meta("target_version", args.target_version.clone());
        let correlation_id = mint_request_id();

        let result = upgrade_junos::handle(
            args,
            self.dm.clone(),
            self.upgrade_cfg.clone(),
            ct,
            correlation_id,
        )
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "list_staged_files",
        description = "List host-staging files (always); also lists /var/tmp/ on a Junos device when router_name is supplied"
    )]
    async fn list_staged_files(
        &self,
        Parameters(args): Parameters<ListStagedFilesArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let routers = if let Some(ref r) = args.router_name {
            vec![r.clone()]
        } else {
            vec![]
        };
        let mut audit = AuditScope::new(ctx, "list_staged_files", "read", routers);

        if let Err(e) = self.check_tool_scope(ctx, "list_staged_files") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Some(router) = args.router_name.as_deref() {
            if let Err(e) = self.check_router_scope(ctx, "list_staged_files", router) {
                audit.deny("router_scope");
                return Self::scope_to_call_result(e);
            }
        }

        let result = list_staged_files::handle(
            args,
            self.dm.clone(),
            self.transfer_config().staging_dir.clone(),
        )
        .await;
        match &result {
            Ok(v) => {
                if let Some(arr) = v.get("staged_files").and_then(|a| a.as_array()) {
                    audit.meta("count", arr.len() as u64);
                }
                audit.succeed();
            }
            Err(e) => audit.fail(e),
        }
        Self::to_call_result(result)
    }
}

#[tool_handler(router = Self::tool_router())]
impl ServerHandler for JmcpHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "jmcp-server",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "Junos MCP server (Rust port). Use get_router_list to enumerate \
                 available routers, then run operational commands or load config.",
            )
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    use rust_junosmcp_auth::caller::CallerCtx;
    use rust_junosmcp_auth::ScopeSet;

    fn test_transfer_cfg() -> rust_junosmcp_core::TransferConfig {
        rust_junosmcp_core::TransferConfig {
            staging_dir: std::path::PathBuf::from("/tmp/staging"),
            known_hosts_file: std::path::PathBuf::from("/tmp/known_hosts"),
            scp_runner: std::sync::Arc::new(
                rust_junosmcp_core::tools::transfer_file::OpenSshScpRunner,
            ),
            transfer_locks: std::sync::Arc::new(
                rust_junosmcp_core::tools::transfer_file::TransferLocks::default(),
            ),
            accept_new_host_keys: false,
        }
    }

    fn test_device_leases() -> Arc<rust_junosmcp_core::DeviceLeaseManager> {
        let path =
            std::env::temp_dir().join(format!("rustjunosmcp-server-tests-{}", std::process::id()));
        Arc::new(rust_junosmcp_core::DeviceLeaseManager::for_directory(path).unwrap())
    }

    fn make_handler() -> JmcpHandler {
        let inv = Arc::new(rust_junosmcp_core::Inventory::empty());
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = Arc::new(Policy::build(&inv).unwrap());
        let transfer_cfg = test_transfer_cfg();
        let upgrade_cfg = rust_junosmcp_core::UpgradeConfig {
            transfer_cfg: transfer_cfg.clone(),
            device_leases: test_device_leases(),
        };
        JmcpHandler::new(dm, policy, transfer_cfg, upgrade_cfg)
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
    fn handler_carries_transfer_config() {
        use rust_junosmcp_core::tools::transfer_file::OpenSshScpRunner;
        use rust_junosmcp_core::TransferConfig;

        let inv = Arc::new(rust_junosmcp_core::Inventory::empty());
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = Arc::new(Policy::build(&inv).unwrap());
        let cfg = TransferConfig {
            staging_dir: std::path::PathBuf::from("/tmp/x"),
            known_hosts_file: std::path::PathBuf::from("/tmp/khosts"),
            scp_runner: std::sync::Arc::new(OpenSshScpRunner),
            transfer_locks: std::sync::Arc::new(
                rust_junosmcp_core::tools::transfer_file::TransferLocks::default(),
            ),
            accept_new_host_keys: false,
        };
        let upgrade_cfg = rust_junosmcp_core::UpgradeConfig {
            transfer_cfg: cfg.clone(),
            device_leases: test_device_leases(),
        };
        let h = JmcpHandler::new(dm, policy, cfg.clone(), upgrade_cfg);
        assert_eq!(h.transfer_config().staging_dir, cfg.staging_dir);
    }

    #[test]
    fn transfer_file_tool_scope_denies_when_not_listed() {
        let handler = make_handler();
        let ctx = CallerCtx {
            token_name: "alice".into(),
            routers: ScopeSet::Wildcard,
            tools: ScopeSet::Allowlist(vec!["execute_junos_command".into()]),
        };
        assert!(matches!(
            handler.check_tool_scope(Some(&ctx), "transfer_file"),
            Err(ScopeError::ToolNotInScope { .. })
        ));
    }

    #[test]
    fn list_staged_files_tool_scope_denies_when_not_listed() {
        let handler = make_handler();
        let ctx = CallerCtx {
            token_name: "alice".into(),
            routers: ScopeSet::Wildcard,
            tools: ScopeSet::Allowlist(vec!["execute_junos_command".into()]),
        };
        assert!(matches!(
            handler.check_tool_scope(Some(&ctx), "list_staged_files"),
            Err(ScopeError::ToolNotInScope { .. })
        ));
    }

    #[test]
    fn transfer_file_router_scope_denies_when_not_listed() {
        // Token has tool scope for transfer_file but only `other` is in router scope;
        // a request for `vsrx-test10` must surface RouterNotInScope.
        let handler = make_handler();
        let ctx = CallerCtx {
            token_name: "alice".into(),
            routers: ScopeSet::Allowlist(vec!["other".into()]),
            tools: ScopeSet::Allowlist(vec!["transfer_file".into()]),
        };
        assert!(handler
            .check_tool_scope(Some(&ctx), "transfer_file")
            .is_ok());
        assert!(matches!(
            handler.check_router_scope(Some(&ctx), "transfer_file", "vsrx-test10"),
            Err(ScopeError::RouterNotInScope { .. })
        ));
    }

    #[test]
    fn fetch_file_tool_scope_denies_when_not_listed() {
        let handler = make_handler();
        let ctx = CallerCtx {
            token_name: "alice".into(),
            routers: ScopeSet::Wildcard,
            tools: ScopeSet::Allowlist(vec!["execute_junos_command".into()]),
        };
        assert!(matches!(
            handler.check_tool_scope(Some(&ctx), "fetch_file"),
            Err(ScopeError::ToolNotInScope { .. })
        ));
    }

    #[test]
    fn fetch_file_router_scope_denies_when_not_listed() {
        // Token has tool scope for fetch_file but only `other` is in router scope;
        // a request for `vsrx-test10` must surface RouterNotInScope.
        let handler = make_handler();
        let ctx = CallerCtx {
            token_name: "alice".into(),
            routers: ScopeSet::Allowlist(vec!["other".into()]),
            tools: ScopeSet::Allowlist(vec!["fetch_file".into()]),
        };
        assert!(handler.check_tool_scope(Some(&ctx), "fetch_file").is_ok());
        assert!(matches!(
            handler.check_router_scope(Some(&ctx), "fetch_file", "vsrx-test10"),
            Err(ScopeError::RouterNotInScope { .. })
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
