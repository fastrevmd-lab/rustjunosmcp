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
        add_device, batch, commit_check, config_diff, execute_command, facts, fetch_file,
        get_config, list_staged_files, load_commit, pfe, reload_devices, router_list, template,
        transfer_file, upgrade_junos, AddDeviceArgs, CommitCheckArgs, ConfigDiffArgs,
        ExecuteBatchArgs, ExecuteCommandArgs, ExecutePfeArgs, FetchFileArgs, GatherFactsArgs,
        GetConfigArgs, ListStagedFilesArgs, LoadCommitArgs, ReloadDevicesArgs, TemplateArgs,
        TransferFileArgs, UpgradeJunosArgs,
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

/// Outcome of an `upgrade_junos` call, as observed by `UpgradeAuditGuard`.
///
/// - `Settled`: the normal Ok/Err path completed; the match arms below
///   already emitted the canonical `audit` line, so the guard stays silent.
/// - `Cancelled`: the in-flight call returned `JmcpError::Cancelled` because
///   the rmcp `RequestContext::ct` fired (issue #44 Half A — explicit
///   `notifications/cancelled` or server-side timeout). The guard emits
///   `outcome="cancelled"` so the journal captures it.
/// - `Unsettled`: the future was dropped before reaching either the
///   `Settled` or `Cancelled` assignment. Under the rmcp 0.8.5
///   streamable-HTTP transport this is the raw TCP-disconnect path (Half B,
///   tracked upstream): the request token does not fire, but our future is
///   nevertheless dropped. The guard emits `outcome="unsettled"` so this
///   case stays auditable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UpgradeOutcome {
    Unsettled,
    Cancelled,
    Settled,
}

/// RAII guard that emits an `audit` line for `upgrade_junos` calls that
/// did NOT reach the normal Ok/Err match arms below — i.e. cancellations
/// (token fired) or future drops (transport disconnect under rmcp 0.8.5
/// streamable-HTTP, Half B). The normal completed paths set
/// `outcome = Settled` so the guard stays silent. (#44, #42)
struct UpgradeAuditGuard {
    outcome: UpgradeOutcome,
    token: String,
    router: String,
    basename: String,
    target_version: String,
}

impl Drop for UpgradeAuditGuard {
    fn drop(&mut self) {
        // #44 diagnostic: every drop logs once so we can correlate guard
        // lifetime with the journal during a live destructive run.
        tracing::info!(
            tool = "upgrade_junos",
            router = %self.router,
            outcome = ?self.outcome,
            "upgrade_junos.drop_diag: guard dropped"
        );
        let outcome_str = match self.outcome {
            UpgradeOutcome::Settled => return,
            UpgradeOutcome::Cancelled => "cancelled",
            UpgradeOutcome::Unsettled => "unsettled",
        };
        tracing::info!(
            tool = "upgrade_junos",
            token = %self.token,
            router = %self.router,
            basename = %self.basename,
            target_version = %self.target_version,
            outcome = outcome_str,
            "audit"
        );
    }
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
/// Listed in source-declaration order below (alphabetized in `KNOWN_TOOLS`).
/// Must stay in sync with `rust_junosmcp_auth::file::KNOWN_TOOLS`; the
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
    use rust_junosmcp_auth::file::KNOWN_TOOLS;
    use std::collections::HashSet;

    /// Tripwire: changing tool count without updating `SERVER_TOOLS` breaks
    /// the build. Bump this number deliberately when adding/removing tools.
    #[test]
    fn server_tools_len_is_16() {
        assert_eq!(SERVER_TOOLS.len(), 16);
    }

    #[test]
    fn server_tools_has_no_duplicates() {
        let mut seen = HashSet::new();
        for t in SERVER_TOOLS {
            assert!(seen.insert(*t), "duplicate tool name in SERVER_TOOLS: {t}");
        }
    }

    /// RJMCP-SEC-001: prevent `KNOWN_TOOLS` (auth crate) drifting from
    /// `SERVER_TOOLS` (this crate). If a new `#[tool(name = "x")]` is added
    /// without updating both, this test fails and the operator cannot mint a
    /// scoped token for "x" — and would be tempted to fall back to wildcard.
    #[test]
    fn server_tools_matches_known_tools_as_set() {
        let server: HashSet<&str> = SERVER_TOOLS.iter().copied().collect();
        let known: HashSet<&str> = KNOWN_TOOLS.iter().copied().collect();
        assert_eq!(
            server,
            known,
            "SERVER_TOOLS / KNOWN_TOOLS drift: only-in-server={:?}, only-in-known={:?}",
            server.difference(&known).collect::<Vec<_>>(),
            known.difference(&server).collect::<Vec<_>>(),
        );
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
        Self::to_call_result(router_list::handle(self.dm.inventory()).await)
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
            execute_command::handle(args, self.dm.clone(), self.policy.load_full()).await,
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
        Self::to_call_result(
            load_commit::handle(args, self.dm.clone(), self.policy.load_full()).await,
        )
    }

    #[tool(
        name = "commit_check_config",
        description = "Validate a candidate configuration on a Junos router without committing (commit check). Loads config into a candidate, runs commit-check, returns {success, diff, error?}, then discards the candidate. Never activates config."
    )]
    async fn commit_check_config(
        &self,
        Parameters(args): Parameters<CommitCheckArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "commit_check_config") {
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "commit_check_config", &args.router_name) {
            return Self::scope_to_call_result(e);
        }
        Self::to_call_result(
            commit_check::handle(args, self.dm.clone(), self.policy.load_full()).await,
        )
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
        Self::to_call_result(pfe::handle(args, self.dm.clone(), self.policy.load_full()).await)
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
        Self::to_call_result(batch::handle(args, self.dm.clone(), self.policy.load_full()).await)
    }

    #[tool(
        name = "render_and_apply_j2_template",
        description = "Render a Jinja2 template (inline) with JSON vars. Optionally commit the rendered config to one or more routers; supports dry-run. (YAML vars are no longer accepted as of v0.5.2.)"
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
        Self::to_call_result(template::handle(args, self.dm.clone(), self.policy.load_full()).await)
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
        let result = add_device::handle(args, self.dm.clone()).await;
        // Rebuild policy from updated inventory so new device's blocklist rules
        // take effect immediately.
        if result.is_ok() {
            self.rebuild_policy();
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
        if let Err(e) = self.check_tool_scope(ctx, "reload_devices") {
            return Self::scope_to_call_result(e);
        }
        let result = reload_devices::handle(args, self.dm.clone()).await;
        // Rebuild policy from updated inventory so blocklist rules track the
        // new device set.
        if result.is_ok() {
            self.rebuild_policy();
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
        if let Err(e) = self.check_tool_scope(ctx, "transfer_file") {
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "transfer_file", &args.router_name) {
            return Self::scope_to_call_result(e);
        }
        let token = ctx.map(|c| c.token_name.as_str()).unwrap_or("stdio");
        let router = args.router_name.clone();
        let basename = args.source_path.clone();
        let result =
            transfer_file::handle(args, self.dm.clone(), self.transfer_config().clone(), ct).await;
        match &result {
            Ok(v) => tracing::info!(
                tool = "transfer_file",
                token = token,
                router = %router,
                basename = %basename,
                status = v.get("status").and_then(|s| s.as_str()).unwrap_or("ok"),
                sha256 = v.get("sha256").and_then(|s| s.as_str()).unwrap_or(""),
                "audit"
            ),
            Err(e) => tracing::info!(
                tool = "transfer_file",
                token = token,
                router = %router,
                basename = %basename,
                outcome = "error",
                error = %e,
                "audit"
            ),
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
        if let Err(e) = self.check_tool_scope(ctx, "fetch_file") {
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "fetch_file", &args.router_name) {
            return Self::scope_to_call_result(e);
        }
        let token = ctx.map(|c| c.token_name.as_str()).unwrap_or("stdio");
        let router = args.router_name.clone();
        let basename = args.remote_path.clone();
        let result =
            fetch_file::handle(args, self.dm.clone(), self.transfer_config().clone(), ct).await;
        match &result {
            Ok(v) => tracing::info!(
                tool = "fetch_file",
                token = token,
                router = %router,
                basename = %basename,
                status = v.get("status").and_then(|s| s.as_str()).unwrap_or("ok"),
                sha256 = v.get("sha256").and_then(|s| s.as_str()).unwrap_or(""),
                "audit"
            ),
            Err(e) => tracing::info!(
                tool = "fetch_file",
                token = token,
                router = %router,
                basename = %basename,
                outcome = "error",
                error = %e,
                "audit"
            ),
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
        if let Err(e) = self.check_tool_scope(ctx, "upgrade_junos") {
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "upgrade_junos", &args.router_name) {
            return Self::scope_to_call_result(e);
        }
        let token = ctx
            .map(|c| c.token_name.as_str())
            .unwrap_or("stdio")
            .to_string();
        let router = args.router_name.clone();
        let basename = args.source_path.clone();
        let target_version = args.target_version.clone();
        // #44 diagnostic: confirm handler entry — proves the future ran far
        // enough to construct the guard. If this fires but the drop diagnostic
        // does not, the future is being detached/leaked by the rmcp transport
        // (not dropped) on client disconnect.
        tracing::info!(
            tool = "upgrade_junos",
            token = %token,
            router = %router,
            basename = %basename,
            target_version = %target_version,
            "upgrade_junos.entry_diag: handler entered, constructing guard"
        );
        // Cancellation guard: tracks the outcome so Drop can emit the
        // appropriate audit line. (#42, #44 Half A)
        // - Settled: normal Ok/Err completed → guard stays silent.
        // - Cancelled: `JmcpError::Cancelled` returned → guard emits
        //   `outcome="cancelled"`.
        // - Unsettled (default): future was dropped without ever reaching
        //   the assignment below — the rmcp 0.8.5 streamable-HTTP raw
        //   TCP-disconnect path (Half B). Guard emits `outcome="unsettled"`.
        let mut guard = UpgradeAuditGuard {
            outcome: UpgradeOutcome::Unsettled,
            token: token.clone(),
            router: router.clone(),
            basename: basename.clone(),
            target_version: target_version.clone(),
        };
        let result =
            upgrade_junos::handle(args, self.dm.clone(), self.upgrade_cfg.clone(), ct).await;
        match &result {
            Ok(v) => tracing::info!(
                tool = "upgrade_junos",
                token = %token,
                router = %router,
                basename = %basename,
                target_version = %target_version,
                status = v.get("status").and_then(|s| s.as_str()).unwrap_or("ok"),
                "audit"
            ),
            Err(e) => tracing::info!(
                tool = "upgrade_junos",
                token = %token,
                router = %router,
                basename = %basename,
                target_version = %target_version,
                outcome = "error",
                error = %e,
                "audit"
            ),
        }
        guard.outcome = match &result {
            Err(rust_junosmcp_core::JmcpError::Cancelled) => UpgradeOutcome::Cancelled,
            _ => UpgradeOutcome::Settled,
        };
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
        if let Err(e) = self.check_tool_scope(ctx, "list_staged_files") {
            return Self::scope_to_call_result(e);
        }
        if let Some(router) = args.router_name.as_deref() {
            if let Err(e) = self.check_router_scope(ctx, "list_staged_files", router) {
                return Self::scope_to_call_result(e);
            }
        }
        let token = ctx.map(|c| c.token_name.as_str()).unwrap_or("stdio");
        let router = args.router_name.clone().unwrap_or_default();
        let result = list_staged_files::handle(
            args,
            self.dm.clone(),
            self.transfer_config().staging_dir.clone(),
        )
        .await;
        match &result {
            Ok(v) => tracing::info!(
                tool = "list_staged_files",
                token = token,
                router = %router,
                staged_count = v
                    .get("staged_files")
                    .and_then(|a| a.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0),
                "audit"
            ),
            Err(e) => tracing::info!(
                tool = "list_staged_files",
                token = token,
                router = %router,
                outcome = "error",
                error = %e,
                "audit"
            ),
        }
        Self::to_call_result(result)
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

    fn make_handler() -> JmcpHandler {
        let inv = Arc::new(rust_junosmcp_core::Inventory::empty());
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = Arc::new(Policy::build(&inv).unwrap());
        let transfer_cfg = test_transfer_cfg();
        let upgrade_cfg = rust_junosmcp_core::UpgradeConfig {
            transfer_cfg: transfer_cfg.clone(),
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

#[cfg(test)]
mod upgrade_audit_guard_tests {
    use super::{UpgradeAuditGuard, UpgradeOutcome};
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    /// MakeWriter that captures all formatted log output into a shared
    /// buffer so tests can assert on the emitted line.
    #[derive(Clone, Default)]
    struct CapturingWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CapturingWriter {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn run_with_capture<F: FnOnce()>(f: F) -> String {
        let cap = CapturingWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(cap.clone())
            .with_ansi(false)
            .with_level(false)
            .with_target(false)
            .with_max_level(tracing::Level::INFO)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = cap.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    fn guard() -> UpgradeAuditGuard {
        UpgradeAuditGuard {
            outcome: UpgradeOutcome::Unsettled,
            token: "claude-client".into(),
            router: "vsrx-test10".into(),
            basename: "junos-25.4R1.12.tgz".into(),
            target_version: "25.4R1.12".into(),
        }
    }

    #[test]
    fn emits_unsettled_audit_when_dropped_without_outcome() {
        // #44 Half B / #42: a future dropped by the rmcp HTTP transport
        // without the in-band cancel token firing leaves the guard at
        // `Unsettled`. The journal must still capture the tool call.
        let captured = run_with_capture(|| {
            let g = guard();
            drop(g);
        });
        // `tracing`'s default `fmt` layer formats `%`-display fields
        // unquoted: `router=vsrx-test10 …`. Quoted-string fields (e.g.
        // string literals or `?`-debug) show as `tool="upgrade_junos"`.
        assert!(
            captured.contains("audit"),
            "expected an `audit` message in: {captured}"
        );
        assert!(captured.contains("tool=\"upgrade_junos\""));
        assert!(captured.contains("router=vsrx-test10"));
        assert!(captured.contains("basename=junos-25.4R1.12.tgz"));
        assert!(captured.contains("target_version=25.4R1.12"));
        assert!(captured.contains("outcome=\"unsettled\""));
    }

    #[test]
    fn emits_cancelled_audit_when_outcome_cancelled() {
        // #44 Half A: when `JmcpError::Cancelled` is observed (the rmcp
        // request token fired), the handler sets `outcome=Cancelled` and
        // the guard emits `outcome="cancelled"` in the audit line.
        let captured = run_with_capture(|| {
            let mut g = guard();
            g.outcome = UpgradeOutcome::Cancelled;
            drop(g);
        });
        assert!(captured.contains("outcome=\"cancelled\""));
    }

    #[test]
    fn silent_when_outcome_settled() {
        // Normal Ok/Err paths set `outcome = Settled`; the guard must
        // NOT emit a duplicate `audit` line on top of the canonical
        // status/error one.
        let captured = run_with_capture(|| {
            let mut g = guard();
            g.outcome = UpgradeOutcome::Settled;
            drop(g);
        });
        assert!(
            !captured.contains("audit"),
            "expected no audit output when outcome=Settled, got: {captured}"
        );
    }
}
