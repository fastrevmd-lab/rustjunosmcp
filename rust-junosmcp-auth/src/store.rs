//! Pure in-memory token store and scope evaluation.

use crate::token::TokenHash;
use chrono::{DateTime, Utc};
use std::collections::HashSet;

/// Allowed-name set for routers or tools. Distinct from `Vec<String>` so the
/// wildcard case is type-level, not a magic string inside a list.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(from = "Vec<String>", into = "Vec<String>")]
pub enum ScopeSet {
    /// Raw form was `["*"]`.
    Wildcard,
    /// Literal allowlist (may be empty).
    Allowlist(Vec<String>),
}

impl ScopeSet {
    pub fn allows(&self, name: &str) -> bool {
        match self {
            ScopeSet::Wildcard => true,
            ScopeSet::Allowlist(list) => list.iter().any(|n| n == name),
        }
    }

    /// True if this scope is `Allowlist([])` — useful for load-time linting.
    pub fn is_empty_allowlist(&self) -> bool {
        matches!(self, ScopeSet::Allowlist(list) if list.is_empty())
    }
}

impl<S: AsRef<str>> FromIterator<S> for ScopeSet {
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
        let v: Vec<String> = iter.into_iter().map(|s| s.as_ref().to_string()).collect();
        if v.len() == 1 && v[0] == "*" {
            ScopeSet::Wildcard
        } else {
            ScopeSet::Allowlist(v)
        }
    }
}

impl From<Vec<String>> for ScopeSet {
    fn from(v: Vec<String>) -> Self {
        if v.len() == 1 && v[0] == "*" {
            ScopeSet::Wildcard
        } else {
            ScopeSet::Allowlist(v)
        }
    }
}

impl From<ScopeSet> for Vec<String> {
    fn from(s: ScopeSet) -> Self {
        match s {
            ScopeSet::Wildcard => vec!["*".into()],
            ScopeSet::Allowlist(v) => v,
        }
    }
}

/// Single token entry as stored on disk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenEntry {
    pub name: String,
    pub hash: TokenHash,
    #[serde(default = "ScopeSet::wildcard")]
    pub routers: ScopeSet,
    #[serde(default = "ScopeSet::wildcard")]
    pub tools: ScopeSet,
    pub created_at: DateTime<Utc>,
}

impl ScopeSet {
    fn wildcard() -> ScopeSet {
        ScopeSet::Wildcard
    }
}

/// In-memory store. Lookup is O(n) linear over hash compares — small N
/// (tens of tokens) and constant-time-equal per compare.
#[derive(Debug, Clone)]
pub struct TokenStore {
    entries: Vec<TokenEntry>,
}

impl TokenStore {
    /// Construct without uniqueness checks (for tests). Callers in production
    /// paths should use `try_new`.
    pub fn new(entries: Vec<TokenEntry>) -> Self {
        Self { entries }
    }

    pub fn try_new(entries: Vec<TokenEntry>) -> Result<Self, DuplicateName> {
        let mut seen = HashSet::new();
        for e in &entries {
            if !seen.insert(e.name.clone()) {
                return Err(DuplicateName(e.name.clone()));
            }
        }
        Ok(Self { entries })
    }

    pub fn find(&self, candidate_secret: &str) -> Option<&TokenEntry> {
        self.entries
            .iter()
            .find(|e| e.hash.verify(candidate_secret))
    }

    pub fn entries(&self) -> &[TokenEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("duplicate token name: {0}")]
pub struct DuplicateName(pub String);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::TokenHash;

    #[allow(dead_code)]
    fn entry(name: &str, routers: ScopeSet, tools: ScopeSet) -> TokenEntry {
        TokenEntry {
            name: name.into(),
            hash: TokenHash::from_secret("dummy"),
            routers,
            tools,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn wildcard_allows_anything() {
        let s = ScopeSet::Wildcard;
        assert!(s.allows("anything"));
        assert!(s.allows(""));
    }

    #[test]
    fn allowlist_allows_only_listed() {
        let s = ScopeSet::Allowlist(vec!["r1".into(), "r2".into()]);
        assert!(s.allows("r1"));
        assert!(s.allows("r2"));
        assert!(!s.allows("r3"));
    }

    #[test]
    fn empty_allowlist_allows_nothing() {
        let s = ScopeSet::Allowlist(vec![]);
        assert!(!s.allows("anything"));
    }

    #[test]
    fn parse_scope_list_wildcard() {
        let s: ScopeSet = ["*"].iter().copied().collect();
        assert!(matches!(s, ScopeSet::Wildcard));
    }

    #[test]
    fn parse_scope_list_names() {
        let s: ScopeSet = ["r1", "r2"].iter().copied().collect();
        match s {
            ScopeSet::Allowlist(v) => assert_eq!(v, vec!["r1".to_string(), "r2".into()]),
            _ => panic!("expected Allowlist"),
        }
    }

    #[test]
    fn store_lookup_hits_correct_secret() {
        let (secret, hash) = crate::token::Secret::mint();
        let e = TokenEntry {
            name: "alice".into(),
            hash,
            routers: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            created_at: chrono::Utc::now(),
        };
        let store = TokenStore::new(vec![e]);
        let hit = store.find(secret.expose()).expect("hit");
        assert_eq!(hit.name, "alice");
    }

    #[test]
    fn store_lookup_misses_wrong_secret() {
        let (_, hash) = crate::token::Secret::mint();
        let e = TokenEntry {
            name: "alice".into(),
            hash,
            routers: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            created_at: chrono::Utc::now(),
        };
        let store = TokenStore::new(vec![e]);
        assert!(store.find("not-the-real-secret").is_none());
    }

    #[test]
    fn store_rejects_duplicate_names_at_construction() {
        let (_, h1) = crate::token::Secret::mint();
        let (_, h2) = crate::token::Secret::mint();
        let dup = vec![
            TokenEntry {
                name: "x".into(),
                hash: h1,
                routers: ScopeSet::Wildcard,
                tools: ScopeSet::Wildcard,
                created_at: chrono::Utc::now(),
            },
            TokenEntry {
                name: "x".into(),
                hash: h2,
                routers: ScopeSet::Wildcard,
                tools: ScopeSet::Wildcard,
                created_at: chrono::Utc::now(),
            },
        ];
        assert!(TokenStore::try_new(dup).is_err());
    }
}
