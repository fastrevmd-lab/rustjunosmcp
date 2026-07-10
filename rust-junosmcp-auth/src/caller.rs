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

/// Return the current inventory names visible to this caller.
///
/// Filtering starts from inventory names, not scope entries, so stale token
/// entries never disclose or synthesize routers. Missing caller context is the
/// intentional stdio / explicit no-auth behavior and preserves the full list.
/// An empty allowlist or empty intersection returns an empty vector.
pub fn filter_router_names(ctx: Option<&CallerCtx>, names: Vec<String>) -> Vec<String> {
    match ctx {
        Some(ctx) => names
            .into_iter()
            .filter(|name| ctx.routers.allows(name))
            .collect(),
        None => names,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(routers: ScopeSet) -> CallerCtx {
        CallerCtx {
            token_name: "test".into(),
            routers,
            tools: ScopeSet::Wildcard,
        }
    }

    fn inventory_names() -> Vec<String> {
        vec!["core-01".into(), "edge-01".into(), "edge-02".into()]
    }

    #[test]
    fn wildcard_preserves_full_inventory() {
        let ctx = caller(ScopeSet::Wildcard);
        assert_eq!(
            filter_router_names(Some(&ctx), inventory_names()),
            inventory_names()
        );
    }

    #[test]
    fn allowlist_returns_only_inventory_intersection() {
        let ctx = caller(ScopeSet::Allowlist(vec![
            "edge-02".into(),
            "core-01".into(),
        ]));
        assert_eq!(
            filter_router_names(Some(&ctx), inventory_names()),
            vec!["core-01".to_string(), "edge-02".to_string()]
        );
    }

    #[test]
    fn stale_scope_entries_are_not_returned() {
        let ctx = caller(ScopeSet::Allowlist(vec![
            "edge-01".into(),
            "retired-99".into(),
        ]));
        assert_eq!(
            filter_router_names(Some(&ctx), inventory_names()),
            vec!["edge-01".to_string()]
        );
    }

    #[test]
    fn empty_allowlist_returns_empty_success_set() {
        let ctx = caller(ScopeSet::Allowlist(Vec::new()));
        assert!(filter_router_names(Some(&ctx), inventory_names()).is_empty());
    }

    #[test]
    fn missing_caller_context_preserves_full_inventory() {
        assert_eq!(
            filter_router_names(None, inventory_names()),
            inventory_names()
        );
    }
}
