//! Generic nested-set resolution shared by `srx_resolve_address` and
//! `srx_resolve_application`.
//!
//! Junos address-sets and application-sets can nest arbitrarily (a set naming
//! other sets as members). There is no RPC that resolves this for us —
//! resolution is a config-time concept, not device state — so this walks the
//! name graph ourselves, deterministically, in Rust (deterministic core: the
//! device is never asked to interpret its own membership on our behalf).
//!
//! A firewall tool that hangs or returns a wrong partial answer on a
//! malformed config is worse than one that refuses (fail-closed / no-panics),
//! so cycles are rejected explicitly rather than looped or silently
//! truncated, with [`MAX_RESOLUTION_DEPTH`] as a second backstop.

use crate::SrxError;
use std::collections::{HashMap, HashSet};

/// One entry in a name→node map built from device configuration.
pub(crate) enum ConfigNode<L> {
    /// A concrete, non-nesting record (an address or an application).
    Leaf(L),
    /// A named set referencing other names, which may themselves be sets.
    Set(Vec<String>),
}

/// Maximum nesting depth before resolution refuses to continue.
pub(crate) const MAX_RESOLUTION_DEPTH: usize = 16;

/// Resolve `root` to its flattened, deduplicated leaves.
///
/// Returns `(leaves, truncated)`: leaves are `(name, value)` pairs in
/// first-seen order, deduplicated by name. `cap` bounds the returned leaf
/// count; `truncated` reports whether the walk produced more than `cap` and
/// was cut short — the caller must surface `truncated`, never silently drop
/// members past the cap.
///
/// Errors:
/// - [`SrxError::ResolutionNameNotFound`] if `root`, or any name reached
///   while walking a set's members, is absent from `nodes`.
/// - [`SrxError::ResolutionCycle`] if the walk re-enters a set already on the
///   current path.
/// - [`SrxError::ResolutionDepthExceeded`] if nesting exceeds
///   [`MAX_RESOLUTION_DEPTH`].
pub(crate) fn resolve<L: Clone>(
    router: &str,
    nodes: &HashMap<String, ConfigNode<L>>,
    root: &str,
    book: &str,
    cap: usize,
) -> Result<(Vec<(String, L)>, bool), SrxError> {
    let mut out: Vec<(String, L)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut path: Vec<String> = Vec::new();
    walk(router, nodes, root, book, 0, &mut path, &mut seen, &mut out)?;
    let truncated = out.len() > cap;
    if truncated {
        out.truncate(cap);
    }
    Ok((out, truncated))
}

#[allow(clippy::too_many_arguments)]
fn walk<L: Clone>(
    router: &str,
    nodes: &HashMap<String, ConfigNode<L>>,
    name: &str,
    book: &str,
    depth: usize,
    path: &mut Vec<String>,
    seen: &mut HashSet<String>,
    out: &mut Vec<(String, L)>,
) -> Result<(), SrxError> {
    if depth > MAX_RESOLUTION_DEPTH {
        return Err(SrxError::ResolutionDepthExceeded {
            router: router.to_string(),
            name: name.to_string(),
            max_depth: MAX_RESOLUTION_DEPTH,
        });
    }
    if let Some(pos) = path.iter().position(|n| n == name) {
        let mut chain = path[pos..].to_vec();
        chain.push(name.to_string());
        return Err(SrxError::ResolutionCycle {
            router: router.to_string(),
            name: name.to_string(),
            chain: chain.join(" -> "),
        });
    }
    let node = nodes
        .get(name)
        .ok_or_else(|| SrxError::ResolutionNameNotFound {
            router: router.to_string(),
            name: name.to_string(),
            book: book.to_string(),
        })?;
    match node {
        ConfigNode::Leaf(l) => {
            if seen.insert(name.to_string()) {
                out.push((name.to_string(), l.clone()));
            }
        }
        ConfigNode::Set(members) => {
            path.push(name.to_string());
            for m in members {
                walk(router, nodes, m, book, depth + 1, path, seen, out)?;
            }
            path.pop();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: Vec<(&str, ConfigNode<u32>)>) -> HashMap<String, ConfigNode<u32>> {
        pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    #[test]
    fn resolves_flat_leaf() {
        let nodes = map(vec![("a", ConfigNode::Leaf(1))]);
        let (leaves, truncated) = resolve("r1", &nodes, "a", "book", 100).unwrap();
        assert_eq!(leaves, vec![("a".to_string(), 1)]);
        assert!(!truncated);
    }

    #[test]
    fn resolves_two_level_nested_set() {
        let nodes = map(vec![
            (
                "outer",
                ConfigNode::Set(vec!["inner".to_string(), "leaf2".to_string()]),
            ),
            ("inner", ConfigNode::Set(vec!["leaf1".to_string()])),
            ("leaf1", ConfigNode::Leaf(1)),
            ("leaf2", ConfigNode::Leaf(2)),
        ]);
        let (leaves, truncated) = resolve("r1", &nodes, "outer", "book", 100).unwrap();
        assert_eq!(
            leaves,
            vec![("leaf1".to_string(), 1), ("leaf2".to_string(), 2)]
        );
        assert!(!truncated);
    }

    #[test]
    fn mixed_set_dedupes_shared_leaf() {
        let nodes = map(vec![
            (
                "mixed",
                ConfigNode::Set(vec!["a".to_string(), "sub".to_string()]),
            ),
            ("sub", ConfigNode::Set(vec!["a".to_string()])),
            ("a", ConfigNode::Leaf(1)),
        ]);
        let (leaves, _) = resolve("r1", &nodes, "mixed", "book", 100).unwrap();
        assert_eq!(leaves, vec![("a".to_string(), 1)]);
    }

    #[test]
    fn direct_cycle_rejected() {
        let nodes = map(vec![
            ("a", ConfigNode::Set(vec!["b".to_string()])),
            ("b", ConfigNode::Set(vec!["a".to_string()])),
        ]);
        let err = resolve("r1", &nodes, "a", "book", 100).unwrap_err();
        assert!(matches!(err, SrxError::ResolutionCycle { .. }), "{err}");
        assert!(err.to_string().contains("code=resolution_cycle"));
    }

    #[test]
    fn self_cycle_rejected() {
        let nodes = map(vec![("a", ConfigNode::Set(vec!["a".to_string()]))]);
        let err = resolve("r1", &nodes, "a", "book", 100).unwrap_err();
        assert!(matches!(err, SrxError::ResolutionCycle { .. }), "{err}");
    }

    #[test]
    fn missing_name_reports_not_found() {
        let nodes: HashMap<String, ConfigNode<u32>> = HashMap::new();
        let err = resolve("r1", &nodes, "ghost", "global address-book", 100).unwrap_err();
        assert!(
            matches!(err, SrxError::ResolutionNameNotFound { .. }),
            "{err}"
        );
    }

    #[test]
    fn depth_beyond_cap_is_rejected() {
        // Build a chain of MAX_RESOLUTION_DEPTH + 2 nested sets — no cycle,
        // just too deep.
        let mut pairs: Vec<(&'static str, ConfigNode<u32>)> = Vec::new();
        let names: Vec<String> = (0..(MAX_RESOLUTION_DEPTH + 3))
            .map(|i| format!("n{i}"))
            .collect();
        let leaked: Vec<&'static str> = names
            .iter()
            .map(|s| &*Box::leak(s.clone().into_boxed_str()))
            .collect();
        for i in 0..leaked.len() - 1 {
            pairs.push((leaked[i], ConfigNode::Set(vec![leaked[i + 1].to_string()])));
        }
        pairs.push((leaked[leaked.len() - 1], ConfigNode::Leaf(1)));
        let nodes = map(pairs);
        let err = resolve("r1", &nodes, leaked[0], "book", 1000).unwrap_err();
        assert!(
            matches!(err, SrxError::ResolutionDepthExceeded { .. }),
            "{err}"
        );
    }

    #[test]
    fn cap_truncates_and_reports() {
        let nodes = map(vec![
            (
                "set",
                ConfigNode::Set(vec!["a".to_string(), "b".to_string(), "c".to_string()]),
            ),
            ("a", ConfigNode::Leaf(1)),
            ("b", ConfigNode::Leaf(2)),
            ("c", ConfigNode::Leaf(3)),
        ]);
        let (leaves, truncated) = resolve("r1", &nodes, "set", "book", 2).unwrap();
        assert_eq!(leaves.len(), 2);
        assert!(truncated);
    }
}
