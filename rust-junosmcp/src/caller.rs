//! Per-request caller context populated by the auth middleware.

use rust_junosmcp_auth::{ScopeSet, TokenEntry};

// Consumed by the #[tool] adapters via `caller_ctx(&parts)` in `server.rs`;
// T11 wires it through the auth middleware on the streamable-http path.
#[derive(Debug, Clone)]
pub struct CallerCtx {
    pub token_name: String,
    pub routers: ScopeSet,
    pub tools: ScopeSet,
}

impl From<&TokenEntry> for CallerCtx {
    fn from(e: &TokenEntry) -> Self {
        Self {
            token_name: e.name.clone(),
            routers: e.routers.clone(),
            tools: e.tools.clone(),
        }
    }
}
