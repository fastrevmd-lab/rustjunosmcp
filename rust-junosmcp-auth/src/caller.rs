//! Per-request caller context populated by the auth middleware.

use crate::{ScopeSet, TokenEntry};

// Consumed by the #[tool] adapters via `caller_ctx(&parts)` in `server.rs`
// (in the `rust-junosmcp` binary). The auth middleware (also in this crate,
// once Task 4 lands) wires it through on the streamable-http path.
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
