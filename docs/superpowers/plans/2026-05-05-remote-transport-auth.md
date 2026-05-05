# Remote Transport + Auth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Light up the `streamable-http` MCP transport with bearer-token auth, per-token router/tool scopes, optional rustls TLS, and SIGHUP-driven hot reload — without disturbing the stdio happy path.

**Architecture:** New workspace crate `rust-junosmcp-auth` holds a pure `TokenStore` (mint/verify/scope eval) and a `TokenStoreFile` (atomic load/save). The binary gets a tower `AuthLayer` middleware that authenticates requests and stuffs a `CallerCtx` into request extensions; `#[tool]` adapters check scopes before consulting the existing blocklist Policy. The same binary gains a `token` subcommand for store management. Hot reload uses `ArcSwap<TokenStore>`.

**Tech Stack:** rmcp 0.8 (streamable-http feature), axum 0.8, tower 0.5, tower-http 0.6, arc-swap 1, sha2 0.10, rand 0.8, subtle 2, base64ct 1, chrono 0.4 (no-default-features + serde + clock), rustls 0.23 + tokio-rustls 0.26 + rustls-pemfile 2 (behind `tls` feature, default-on).

---

## Task 0: rmcp 0.8 streamable-http verification spike

**Files:**
- Create: `docs/spikes/2026-05-05-rmcp-streamable-http-spike.md`

This is a research task. The spike's deliverable is a one-page memo confirming three things needed by Tasks 14–15:
1. The exact rmcp 0.8 cargo feature that enables streamable-http (working assumption: `transport-streamable-http-axum`).
2. Whether the rmcp service can be mounted under an outer axum 0.8 router.
3. Whether `#[tool]` methods can read request extensions populated by an outer middleware (path A from the spec) or whether we need the `DashMap<RequestId, CallerCtx>` fallback (path B).

- [ ] **Step 1: Read rmcp 0.8.5 source for streamable-http**

Run: `cargo doc -p rmcp --no-deps --open` and search for `streamable_http`, or read `~/.cargo/registry/src/*/rmcp-0.8.5/src/transport/`. Capture the feature flag name and the public mount API.

- [ ] **Step 2: Sanity-build a hello-world**

In a scratch directory (NOT in this repo):

```bash
cargo new --bin /tmp/rmcp-spike && cd /tmp/rmcp-spike
```

Add to `Cargo.toml`:
```toml
[dependencies]
rmcp = { version = "0.8", features = ["server", "macros", "schemars", "transport-streamable-http-axum"] }
axum = "0.8"
tokio = { version = "1", features = ["full"] }
tower = "0.5"
```

Write a minimal handler with one `#[tool]` method that reads request extensions, mount it under axum, and bind on `127.0.0.1:0`. If the feature name is wrong, cargo will tell you — try the next likely name (`transport-streamable-http`, `streamable-http-server`).

Run: `cargo build`
Expected: builds clean. If not: record the actual feature flag name in the memo.

- [ ] **Step 3: Test extension propagation**

Send an HTTP request to the spike with a custom header. The middleware copies it into request extensions. Confirm the `#[tool]` body sees the value (or doesn't — that decides path A vs path B).

- [ ] **Step 4: Write the memo**

Create `docs/spikes/2026-05-05-rmcp-streamable-http-spike.md` (in this repo, on the feature branch):

```markdown
# rmcp 0.8 streamable-http spike

**Date:** 2026-05-05
**Outcome:** [success / fallback-B-required]

## Findings

- **Feature flag:** `<actual flag name>`
- **Mount API:** `<one-line summary, e.g. ServiceExt::serve(...) returns Router>`
- **Extension access from `#[tool]`:** [yes / no]
  - If yes: ergonomic? what type does the macro expose?
  - If no: which fallback do we take?

## Decision

Implementation Tasks 14–15 use [path A / path B] from the design doc.
```

- [ ] **Step 5: Commit**

```bash
git add docs/spikes/2026-05-05-rmcp-streamable-http-spike.md
git commit -m "spike: rmcp 0.8 streamable-http feature + extension access"
```

---

## Task 1: Workspace dependency additions and `rust-junosmcp-auth` crate skeleton

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Create: `rust-junosmcp-auth/Cargo.toml`
- Create: `rust-junosmcp-auth/src/lib.rs`

- [ ] **Step 1: Add workspace dependencies**

Edit root `Cargo.toml`. Add to `[workspace.members]`:
```toml
members = ["rust-junosmcp-core", "rust-junosmcp", "rust-junosmcp-auth"]
```

Add to `[workspace.dependencies]`:
```toml
arc-swap     = "1"
sha2         = "0.10"
rand         = "0.8"
subtle       = "2"
base64ct     = { version = "1", features = ["alloc"] }
chrono       = { version = "0.4", default-features = false, features = ["serde", "clock"] }
axum         = "0.8"
tower        = "0.5"
tower-http   = "0.6"
rustls           = "0.23"
tokio-rustls     = "0.26"
rustls-pemfile  = "2"
```

- [ ] **Step 2: Create the crate manifest**

`rust-junosmcp-auth/Cargo.toml`:
```toml
[package]
name        = "rust-junosmcp-auth"
version.workspace     = true
edition.workspace     = true
license.workspace     = true
repository.workspace  = true
authors.workspace     = true
description = "Bearer-token authentication and per-token scopes for rust-junosmcp."

[dependencies]
serde        = { workspace = true }
serde_json   = { workspace = true }
thiserror    = { workspace = true }
sha2         = { workspace = true }
rand         = { workspace = true }
subtle       = { workspace = true }
base64ct     = { workspace = true }
chrono       = { workspace = true }
arc-swap     = { workspace = true }
tracing      = { workspace = true }

[dev-dependencies]
tempfile     = "3"
```

- [ ] **Step 3: Create empty lib.rs with module stubs**

`rust-junosmcp-auth/src/lib.rs`:
```rust
//! Bearer-token authentication and per-token scopes for rust-junosmcp.
//!
//! Pure data + I/O glue, no async, no HTTP.

pub mod token;
pub mod store;
pub mod file;

pub use store::{ScopeSet, TokenEntry, TokenStore};
pub use file::{TokenStoreError, TokenStoreFile};
```

Create empty placeholder files so the crate compiles:

`rust-junosmcp-auth/src/token.rs`:
```rust
//! Token mint, hash, and constant-time verify.
```

`rust-junosmcp-auth/src/store.rs`:
```rust
//! Pure in-memory token store and scope evaluation.
```

`rust-junosmcp-auth/src/file.rs`:
```rust
//! On-disk token store: load, validate, atomic save.

#[derive(Debug, thiserror::Error)]
pub enum TokenStoreError {
    #[error("token store invalid: {0}")]
    Invalid(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct TokenStoreFile;
```

- [ ] **Step 4: Verify the crate compiles**

Run: `cargo build -p rust-junosmcp-auth`
Expected: builds clean. (`pub use file::TokenStoreFile` resolves to the empty unit struct; that's fine for now.)

Run: `cargo test -p rust-junosmcp-core -p rust-junosmcp`
Expected: 75 tests pass (existing baseline undisturbed).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml rust-junosmcp-auth/
git commit -m "feat(auth): add rust-junosmcp-auth crate skeleton + workspace deps"
```

---

## Task 2: Token types — `Secret`, `TokenHash`, mint, verify

**Files:**
- Modify: `rust-junosmcp-auth/src/token.rs`

- [ ] **Step 1: Write the failing tests**

`rust-junosmcp-auth/src/token.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_produces_43_char_base64url_secret() {
        let (secret, _hash) = Secret::mint();
        let s = secret.expose();
        assert_eq!(s.len(), 43, "expected 43-char unpadded base64url, got {}", s.len());
        assert!(s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "non-base64url char in secret: {s:?}");
    }

    #[test]
    fn hash_format_is_sha256_prefix_plus_43_chars() {
        let (_secret, hash) = Secret::mint();
        let s = hash.as_str();
        assert!(s.starts_with("sha256:"), "missing prefix: {s}");
        assert_eq!(s.len(), "sha256:".len() + 43);
    }

    #[test]
    fn verify_matches_correct_secret() {
        let (secret, hash) = Secret::mint();
        assert!(hash.verify(secret.expose()));
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let (_secret, hash) = Secret::mint();
        let (other, _) = Secret::mint();
        assert!(!hash.verify(other.expose()));
    }

    #[test]
    fn parse_hash_from_str_round_trip() {
        let (_secret, hash) = Secret::mint();
        let s = hash.as_str().to_string();
        let parsed = TokenHash::parse(&s).expect("parse");
        assert_eq!(parsed.as_str(), s);
    }

    #[test]
    fn parse_hash_rejects_missing_prefix() {
        assert!(TokenHash::parse("VYV9w8c").is_err());
    }

    #[test]
    fn parse_hash_rejects_wrong_length() {
        assert!(TokenHash::parse("sha256:short").is_err());
    }

    #[test]
    fn parse_hash_rejects_non_base64url() {
        let bad = format!("sha256:{}", "A".repeat(42) + "+");
        assert!(TokenHash::parse(&bad).is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p rust-junosmcp-auth token::tests -- --nocapture`
Expected: FAIL with "cannot find type `Secret`" / "cannot find type `TokenHash`".

- [ ] **Step 3: Implement `Secret` and `TokenHash`**

Replace `rust-junosmcp-auth/src/token.rs` content (keep the `#[cfg(test)] mod tests` block at bottom):

```rust
//! Token mint, hash, and constant-time verify.

use base64ct::{Base64UrlUnpadded, Encoding};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// A freshly-minted token secret. The plaintext leaves the process exactly
/// once (printed by `token add`/`rotate`), so this type holds only the
/// base64url-unpadded ASCII string and is `Drop`-zeroed.
pub struct Secret(String);

impl Secret {
    /// Mint a fresh 32-byte random secret and return the (secret, hash) pair.
    pub fn mint() -> (Self, TokenHash) {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let s = Base64UrlUnpadded::encode_string(&bytes);
        let hash = TokenHash::from_secret(&s);
        (Secret(s), hash)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Best-effort zeroize. Not constant-time, but the process is on its way
        // out for token-management subcommands.
        unsafe {
            for b in self.0.as_bytes_mut() {
                std::ptr::write_volatile(b, 0u8);
            }
        }
    }
}

/// SHA-256 hash of a token secret, formatted as `sha256:<base64url-unpadded>`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TokenHash(String);

impl TokenHash {
    pub fn from_secret(secret: &str) -> Self {
        let digest = Sha256::digest(secret.as_bytes());
        let s = format!("sha256:{}", Base64UrlUnpadded::encode_string(&digest));
        TokenHash(s)
    }

    pub fn parse(s: &str) -> Result<Self, ParseTokenHashError> {
        let rest = s.strip_prefix("sha256:").ok_or(ParseTokenHashError::MissingPrefix)?;
        if rest.len() != 43 {
            return Err(ParseTokenHashError::WrongLength { got: rest.len() });
        }
        // Validate base64url-unpadded char set by attempting a decode.
        Base64UrlUnpadded::decode_vec(rest)
            .map_err(|_| ParseTokenHashError::NotBase64Url)?;
        Ok(TokenHash(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Constant-time compare: hash this candidate secret and compare against self.
    pub fn verify(&self, candidate_secret: &str) -> bool {
        let candidate = TokenHash::from_secret(candidate_secret);
        self.0.as_bytes().ct_eq(candidate.0.as_bytes()).into()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseTokenHashError {
    #[error("missing 'sha256:' prefix")]
    MissingPrefix,
    #[error("wrong length: expected 43 chars after prefix, got {got}")]
    WrongLength { got: usize },
    #[error("not valid base64url-unpadded")]
    NotBase64Url,
}

impl TryFrom<String> for TokenHash {
    type Error = ParseTokenHashError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        TokenHash::parse(&s)
    }
}

impl From<TokenHash> for String {
    fn from(h: TokenHash) -> String {
        h.0
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rust-junosmcp-auth token::tests`
Expected: 8 tests pass.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-auth/src/token.rs
git commit -m "feat(auth): Secret/TokenHash with mint, parse, constant-time verify"
```

---

## Task 3: `ScopeSet`, `TokenEntry`, `TokenStore`

**Files:**
- Modify: `rust-junosmcp-auth/src/store.rs`

- [ ] **Step 1: Write the failing tests**

`rust-junosmcp-auth/src/store.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::TokenHash;

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
            TokenEntry { name: "x".into(), hash: h1, routers: ScopeSet::Wildcard, tools: ScopeSet::Wildcard, created_at: chrono::Utc::now() },
            TokenEntry { name: "x".into(), hash: h2, routers: ScopeSet::Wildcard, tools: ScopeSet::Wildcard, created_at: chrono::Utc::now() },
        ];
        assert!(TokenStore::try_new(dup).is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p rust-junosmcp-auth store::tests`
Expected: FAIL — types not defined.

- [ ] **Step 3: Implement `ScopeSet`, `TokenEntry`, `TokenStore`**

Replace `rust-junosmcp-auth/src/store.rs` content:

```rust
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
    fn wildcard() -> ScopeSet { ScopeSet::Wildcard }
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
        self.entries.iter().find(|e| e.hash.verify(candidate_secret))
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
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rust-junosmcp-auth store::tests`
Expected: 8 tests pass.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-auth/src/store.rs
git commit -m "feat(auth): ScopeSet + TokenEntry + TokenStore with name-uniqueness check"
```

---

## Task 4: `TokenStoreFile::load` with full validation

**Files:**
- Modify: `rust-junosmcp-auth/src/file.rs`

The list of known v0.1 tool names lives here so unknown-tool typos in the
file are fatal at load. When sub-projects #3/#4 add new tools, this list
gets a one-line update.

- [ ] **Step 1: Write failing tests**

Append to `rust-junosmcp-auth/src/file.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(json: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f
    }

    #[test]
    fn loads_minimal_valid_file() {
        let f = write_tmp(r#"{"version":1,"tokens":[]}"#);
        let store = TokenStoreFile::load(f.path(), &[]).unwrap();
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn loads_one_token() {
        let f = write_tmp(r#"{
            "version":1,
            "tokens":[{
                "name":"a",
                "hash":"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "routers":["*"],
                "tools":["*"],
                "created_at":"2026-05-05T00:00:00Z"
            }]
        }"#);
        let store = TokenStoreFile::load(f.path(), &[]).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.entries()[0].name, "a");
    }

    #[test]
    fn rejects_wrong_version() {
        let f = write_tmp(r#"{"version":2,"tokens":[]}"#);
        let err = TokenStoreFile::load(f.path(), &[]).unwrap_err();
        assert!(matches!(err, TokenStoreError::Invalid(s) if s.contains("version")));
    }

    #[test]
    fn rejects_duplicate_names() {
        let f = write_tmp(r#"{
            "version":1,
            "tokens":[
                {"name":"a","hash":"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","routers":["*"],"tools":["*"],"created_at":"2026-05-05T00:00:00Z"},
                {"name":"a","hash":"sha256:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE","routers":["*"],"tools":["*"],"created_at":"2026-05-05T00:00:00Z"}
            ]
        }"#);
        let err = TokenStoreFile::load(f.path(), &[]).unwrap_err();
        assert!(matches!(err, TokenStoreError::Invalid(s) if s.contains("duplicate")));
    }

    #[test]
    fn rejects_unknown_tool_name() {
        let f = write_tmp(r#"{
            "version":1,
            "tokens":[{
                "name":"a","hash":"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "routers":["*"],"tools":["does_not_exist"],
                "created_at":"2026-05-05T00:00:00Z"
            }]
        }"#);
        let err = TokenStoreFile::load(f.path(), &[]).unwrap_err();
        assert!(matches!(err, TokenStoreError::Invalid(s) if s.contains("does_not_exist")));
    }

    #[test]
    fn rejects_malformed_hash() {
        let f = write_tmp(r#"{
            "version":1,
            "tokens":[{
                "name":"a","hash":"plaintext-bad",
                "routers":["*"],"tools":["*"],
                "created_at":"2026-05-05T00:00:00Z"
            }]
        }"#);
        let err = TokenStoreFile::load(f.path(), &[]).unwrap_err();
        // Serde returns a Json error here because TokenHash deserialization fails.
        assert!(matches!(err, TokenStoreError::Json(_)));
    }

    #[test]
    fn rejects_wildcard_mixed_into_allowlist() {
        // "*" inside an allowlist is ambiguous (would never act as wildcard
        // since ScopeSet::From<Vec<String>> only treats single-element ["*"]
        // as Wildcard). Make this fatal at load to keep one canonical spelling.
        let f = write_tmp(r#"{
            "version":1,
            "tokens":[{
                "name":"a","hash":"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "routers":["*","r1"],"tools":["*"],
                "created_at":"2026-05-05T00:00:00Z"
            }]
        }"#);
        let err = TokenStoreFile::load(f.path(), &[]).unwrap_err();
        assert!(matches!(err, TokenStoreError::Invalid(s) if s.contains("'*'")));
    }

    #[test]
    fn warns_but_keeps_unknown_router_name() {
        // unknown_routers: known_routers passed in is &[]; the entry references
        // "r1" which is not in that list. Load should still succeed.
        let f = write_tmp(r#"{
            "version":1,
            "tokens":[{
                "name":"a","hash":"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "routers":["r1"],"tools":["*"],
                "created_at":"2026-05-05T00:00:00Z"
            }]
        }"#);
        let store = TokenStoreFile::load(f.path(), &[]).unwrap();
        assert_eq!(store.len(), 1);
    }
}
```

- [ ] **Step 2: Replace `file.rs` skeleton with the real impl**

```rust
//! On-disk token store: load, validate, atomic save.

use crate::store::{ScopeSet, TokenEntry, TokenStore};
use std::path::Path;

/// All v0.1 tool names. New sub-projects extend this list.
pub const KNOWN_TOOLS: &[&str] = &[
    "get_router_list",
    "gather_device_facts",
    "execute_junos_command",
    "get_junos_config",
    "junos_config_diff",
    "load_and_commit_config",
];

#[derive(Debug, thiserror::Error)]
pub enum TokenStoreError {
    #[error("token store invalid: {0}")]
    Invalid(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(serde::Serialize, serde::Deserialize)]
struct OnDisk {
    version: u32,
    #[serde(default)]
    tokens: Vec<TokenEntry>,
}

pub struct TokenStoreFile;

impl TokenStoreFile {
    /// Load and validate. `known_routers` is from the current `devices.json`;
    /// unknown router names emit a `WARN` but keep the entry. Unknown tool
    /// names are fatal.
    pub fn load(path: &Path, known_routers: &[&str]) -> Result<TokenStore, TokenStoreError> {
        let bytes = std::fs::read(path)?;
        let parsed: OnDisk = serde_json::from_slice(&bytes)?;
        if parsed.version != 1 {
            return Err(TokenStoreError::Invalid(format!(
                "unsupported version: expected 1, got {}",
                parsed.version
            )));
        }

        // Validate each entry.
        for e in &parsed.tokens {
            if let ScopeSet::Allowlist(list) = &e.tools {
                for t in list {
                    if t == "*" {
                        return Err(TokenStoreError::Invalid(format!(
                            "token '{}' tools list mixes '*' with other names — \
                             use either [\"*\"] for wildcard or a list without '*'",
                            e.name
                        )));
                    }
                    if !KNOWN_TOOLS.contains(&t.as_str()) {
                        return Err(TokenStoreError::Invalid(format!(
                            "unknown tool name '{}' in token '{}': known tools are {:?}",
                            t, e.name, KNOWN_TOOLS
                        )));
                    }
                }
            }
            if let ScopeSet::Allowlist(list) = &e.routers {
                for r in list {
                    if r == "*" {
                        return Err(TokenStoreError::Invalid(format!(
                            "token '{}' routers list mixes '*' with other names — \
                             use either [\"*\"] for wildcard or a list without '*'",
                            e.name
                        )));
                    }
                }
                if !known_routers.is_empty() {
                    for r in list {
                        if !known_routers.iter().any(|kr| kr == r) {
                            tracing::warn!(token = %e.name, router = %r,
                                "token references router not present in current devices.json");
                        }
                    }
                }
            }
            if e.routers.is_empty_allowlist() {
                tracing::warn!(token = %e.name, "token routers scope is empty — token cannot reach any router");
            }
            if e.tools.is_empty_allowlist() {
                tracing::warn!(token = %e.name, "token tools scope is empty — token cannot call any tool");
            }
        }

        TokenStore::try_new(parsed.tokens).map_err(|e| TokenStoreError::Invalid(format!("duplicate: {}", e.0)))
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rust-junosmcp-auth file::tests`
Expected: 7 tests pass.

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp-auth/src/file.rs
git commit -m "feat(auth): TokenStoreFile::load with full validation and known-tool gate"
```

---

## Task 5: `TokenStoreFile::save` (atomic write) + `add` / `revoke` mutation helpers

**Files:**
- Modify: `rust-junosmcp-auth/src/file.rs`

- [ ] **Step 1: Write failing tests**

Append to the existing `mod tests` in `file.rs`:

```rust
    #[test]
    fn save_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        TokenStoreFile::save(&path, &TokenStore::new(vec![])).unwrap();
        let reloaded = TokenStoreFile::load(&path, &[]).unwrap();
        assert_eq!(reloaded.len(), 0);
    }

    #[test]
    fn save_is_atomic_no_temp_files_left() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        TokenStoreFile::save(&path, &TokenStore::new(vec![])).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path()).unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != "tokens.json")
            .collect();
        assert!(leftovers.is_empty(), "stray temp files: {leftovers:?}");
    }

    #[test]
    fn add_appends_new_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        TokenStoreFile::save(&path, &TokenStore::new(vec![])).unwrap();

        let secret = TokenStoreFile::add(
            &path,
            "alice",
            ScopeSet::Wildcard,
            ScopeSet::Allowlist(vec!["get_router_list".into()]),
        ).unwrap();
        assert_eq!(secret.expose().len(), 43);

        let store = TokenStoreFile::load(&path, &[]).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.entries()[0].name, "alice");
        // Hash on disk is not the secret.
        assert_ne!(store.entries()[0].hash.as_str(), secret.expose());
    }

    #[test]
    fn add_rejects_duplicate_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        TokenStoreFile::save(&path, &TokenStore::new(vec![])).unwrap();
        TokenStoreFile::add(&path, "alice", ScopeSet::Wildcard, ScopeSet::Wildcard).unwrap();
        let err = TokenStoreFile::add(&path, "alice", ScopeSet::Wildcard, ScopeSet::Wildcard).unwrap_err();
        assert!(matches!(err, TokenStoreError::Invalid(s) if s.contains("alice")));
    }

    #[test]
    fn revoke_removes_named_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        TokenStoreFile::save(&path, &TokenStore::new(vec![])).unwrap();
        TokenStoreFile::add(&path, "alice", ScopeSet::Wildcard, ScopeSet::Wildcard).unwrap();
        let removed = TokenStoreFile::revoke(&path, "alice").unwrap();
        assert!(removed);
        assert_eq!(TokenStoreFile::load(&path, &[]).unwrap().len(), 0);
    }

    #[test]
    fn revoke_missing_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        TokenStoreFile::save(&path, &TokenStore::new(vec![])).unwrap();
        let removed = TokenStoreFile::revoke(&path, "nobody").unwrap();
        assert!(!removed);
    }
```

- [ ] **Step 2: Implement save / add / revoke**

Append to `file.rs` (inside `impl TokenStoreFile`):

```rust
    pub fn save(path: &Path, store: &TokenStore) -> Result<(), TokenStoreError> {
        use std::io::Write;
        let parent = path.parent().ok_or_else(|| TokenStoreError::Invalid(
            format!("path has no parent: {}", path.display())
        ))?;
        let on_disk = OnDisk { version: 1, tokens: store.entries().to_vec() };
        let json = serde_json::to_vec_pretty(&on_disk)?;

        let tmp = tempfile::Builder::new()
            .prefix(".tokens-")
            .suffix(".tmp")
            .tempfile_in(parent)?;
        {
            let (mut file, tmp_path) = tmp.keep().map_err(|e| TokenStoreError::Io(e.error))?;
            file.write_all(&json)?;
            file.sync_all()?;
            std::fs::rename(&tmp_path, path)?;
        }
        Ok(())
    }

    pub fn add(
        path: &Path,
        name: &str,
        routers: ScopeSet,
        tools: ScopeSet,
    ) -> Result<crate::token::Secret, TokenStoreError> {
        // Validate tools against KNOWN_TOOLS up front.
        if let ScopeSet::Allowlist(list) = &tools {
            for t in list {
                if !KNOWN_TOOLS.contains(&t.as_str()) {
                    return Err(TokenStoreError::Invalid(format!(
                        "unknown tool '{}': known tools are {:?}", t, KNOWN_TOOLS
                    )));
                }
            }
        }

        let store = if path.exists() {
            Self::load(path, &[])?
        } else {
            TokenStore::new(vec![])
        };
        if store.entries().iter().any(|e| e.name == name) {
            return Err(TokenStoreError::Invalid(format!("token '{name}' already exists")));
        }
        let (secret, hash) = crate::token::Secret::mint();
        let mut entries = store.entries().to_vec();
        entries.push(TokenEntry {
            name: name.into(),
            hash,
            routers,
            tools,
            created_at: chrono::Utc::now(),
        });
        Self::save(path, &TokenStore::try_new(entries).map_err(|e| TokenStoreError::Invalid(e.0))?)?;
        Ok(secret)
    }

    pub fn revoke(path: &Path, name: &str) -> Result<bool, TokenStoreError> {
        let store = Self::load(path, &[])?;
        let before = store.len();
        let entries: Vec<_> = store.entries().iter().filter(|e| e.name != name).cloned().collect();
        let removed = entries.len() < before;
        Self::save(path, &TokenStore::new(entries))?;
        Ok(removed)
    }
```

You'll also need `tempfile` as a (non-dev) dependency now — add to `rust-junosmcp-auth/Cargo.toml`'s `[dependencies]`:
```toml
tempfile     = "3"
```
(and remove the duplicate from `[dev-dependencies]` if present; tempfile is now needed at runtime).

- [ ] **Step 3: Run tests**

Run: `cargo test -p rust-junosmcp-auth`
Expected: 21 tests pass (8 token + 8 store + ~13 file).

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp-auth/Cargo.toml rust-junosmcp-auth/src/file.rs
git commit -m "feat(auth): atomic save + add/revoke helpers on TokenStoreFile"
```

---

## Task 6: `token` subcommand wiring in `rust-junosmcp` (CLI shape only)

**Files:**
- Modify: `rust-junosmcp/Cargo.toml`
- Modify: `rust-junosmcp/src/cli.rs`
- Create: `rust-junosmcp/src/token_cmd.rs`
- Modify: `rust-junosmcp/src/main.rs`

This task only wires up the clap subcommand structure. The implementations
of `add` / `list` / `revoke` / `rotate` come in Task 7 — this task makes
them stubs that print "not implemented" so the CLI shape is settled first.

- [ ] **Step 1: Add the auth crate as a dep**

`rust-junosmcp/Cargo.toml` `[dependencies]`:
```toml
rust-junosmcp-auth = { path = "../rust-junosmcp-auth" }
```

- [ ] **Step 2: Restructure the CLI to support subcommands**

Replace `rust-junosmcp/src/cli.rs`:
```rust
//! Command-line arguments. Two top-level modes: serve (default) and token
//! management subcommand.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Transport {
    Stdio,
    StreamableHttp,
}

#[derive(Debug, Parser)]
#[command(name = "rust-junosmcp", version, about = "Junos MCP server (Rust)")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// JSON file with device mapping (Juniper junos-mcp-server compatible).
    #[arg(short = 'f', long, default_value = "devices.json", global = true)]
    pub device_mapping: PathBuf,

    /// Transport.
    #[arg(short = 't', long, default_value = "stdio", value_enum)]
    pub transport: Transport,

    /// Bind host (streamable-http only).
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub host: String,

    /// Bind port (streamable-http only).
    #[arg(short = 'p', long, default_value_t = 30030)]
    pub port: u16,

    /// Bearer-token file. Required for streamable-http unless --allow-no-auth.
    #[arg(long)]
    pub tokens_file: Option<PathBuf>,

    /// PEM-encoded TLS cert (streamable-http only). Pair with --tls-key.
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// PEM-encoded TLS key (streamable-http only). Pair with --tls-cert.
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// Disable bearer-token auth. Refuses to bind off-loopback.
    #[arg(long)]
    pub allow_no_auth: bool,

    /// Bind off-loopback over plain HTTP. Required for non-127.0.0.1 hosts when TLS is not configured.
    #[arg(long)]
    pub allow_insecure_bind: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage the bearer-token store.
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum TokenAction {
    /// Mint a new token and append to the file.
    Add {
        #[arg(long)] tokens_file: PathBuf,
        #[arg(long)] name: String,
        /// Comma-separated router names, or '*' for all.
        #[arg(long, value_delimiter = ',')] routers: Vec<String>,
        /// Comma-separated tool names, or '*' for all.
        #[arg(long, value_delimiter = ',')] tools: Vec<String>,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)] server_pid: Option<i32>,
    },
    /// List token names + scopes (never the hash or secret).
    List {
        #[arg(long)] tokens_file: PathBuf,
    },
    /// Remove a token by name.
    Revoke {
        #[arg(long)] tokens_file: PathBuf,
        #[arg(long)] name: String,
        #[arg(long)] server_pid: Option<i32>,
    },
    /// Revoke + re-add under the same scopes; prints a new secret.
    Rotate {
        #[arg(long)] tokens_file: PathBuf,
        #[arg(long)] name: String,
        #[arg(long)] server_pid: Option<i32>,
    },
}
```

- [ ] **Step 3: Stub the subcommand dispatcher**

Create `rust-junosmcp/src/token_cmd.rs`:
```rust
//! `rust-junosmcp token …` subcommand. Implementations land in Task 7.

use crate::cli::TokenAction;
use anyhow::Result;

pub fn run(action: TokenAction) -> Result<()> {
    match action {
        TokenAction::Add { .. } => anyhow::bail!("token add: not implemented yet"),
        TokenAction::List { .. } => anyhow::bail!("token list: not implemented yet"),
        TokenAction::Revoke { .. } => anyhow::bail!("token revoke: not implemented yet"),
        TokenAction::Rotate { .. } => anyhow::bail!("token rotate: not implemented yet"),
    }
}
```

- [ ] **Step 4: Wire into `main.rs`**

In `rust-junosmcp/src/main.rs`, add `mod token_cmd;` near the top, and dispatch before the inventory load:

```rust
mod cli;
mod server;
mod token_cmd;

use anyhow::{bail, Context, Result};
use clap::Parser;
use cli::{Cli, Command, Transport};
// ... existing uses ...

#[tokio::main]
async fn main() -> Result<()> {
    // tracing init unchanged ...

    let args = Cli::parse();

    if let Some(Command::Token { action }) = args.command {
        return token_cmd::run(action);
    }

    // existing serve path unchanged ...
}
```

- [ ] **Step 5: Verify the CLI parses**

Run: `cargo build -p rust-junosmcp`
Expected: builds clean.

Run: `target/debug/rust-junosmcp token --help`
Expected: shows `add`, `list`, `revoke`, `rotate` subcommands.

Run: `target/debug/rust-junosmcp token add --tokens-file /tmp/x.json --name foo --routers '*' --tools '*'`
Expected: `Error: token add: not implemented yet` (stub).

Run: `cargo test -p rust-junosmcp-core -p rust-junosmcp`
Expected: 75 tests pass + the existing CLI defaults test still passes (note: CLI defaults test will need an update because `host`/`port` defaults are unchanged but `command: None` is now expected).

- [ ] **Step 6: Update the existing CLI defaults test**

In `rust-junosmcp/src/cli.rs` `mod tests`, the `defaults()` test now needs:
```rust
    #[test]
    fn defaults() {
        let cli = Cli::parse_from(["rust-junosmcp"]);
        assert_eq!(cli.device_mapping, PathBuf::from("devices.json"));
        assert_eq!(cli.transport, Transport::Stdio);
        assert_eq!(cli.host, "127.0.0.1");
        assert_eq!(cli.port, 30030);
        assert!(cli.command.is_none());
        assert!(cli.tokens_file.is_none());
        assert!(!cli.allow_no_auth);
        assert!(!cli.allow_insecure_bind);
    }

    #[test]
    fn parses_token_add_subcommand() {
        let cli = Cli::parse_from([
            "rust-junosmcp", "token", "add",
            "--tokens-file", "/tmp/t.json",
            "--name", "alice",
            "--routers", "*",
            "--tools", "*",
        ]);
        assert!(matches!(cli.command, Some(Command::Token { .. })));
    }
```

Run: `cargo test -p rust-junosmcp`
Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add rust-junosmcp/Cargo.toml rust-junosmcp/src/cli.rs rust-junosmcp/src/token_cmd.rs rust-junosmcp/src/main.rs
git commit -m "feat(bin): wire 'token' subcommand shape (stubs) and new server flags"
```

---

## Task 7: Implement `token add` / `list` / `revoke` / `rotate`

**Files:**
- Modify: `rust-junosmcp/src/token_cmd.rs`
- Create: `rust-junosmcp/tests/token_subcommand.rs`

- [ ] **Step 1: Write failing CLI integration tests**

`rust-junosmcp/tests/token_subcommand.rs`:
```rust
//! Spawn the `rust-junosmcp` binary and exercise the `token` subcommand.

use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("target");
    p.push(if cfg!(debug_assertions) { "debug" } else { "release" });
    p.push("rust-junosmcp");
    p
}

fn ensure_built() {
    let s = Command::new("cargo").args(["build", "-p", "rust-junosmcp"]).status().unwrap();
    assert!(s.success());
}

#[test]
fn add_then_list_reports_name_no_secret() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");

    let out = Command::new(binary_path())
        .args(["token", "add",
               "--tokens-file", tokens.to_str().unwrap(),
               "--name", "alice",
               "--routers", "*",
               "--tools", "get_router_list,get_junos_config"])
        .output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let secret = String::from_utf8(out.stdout).unwrap().trim().to_string();
    assert_eq!(secret.len(), 43);

    let out = Command::new(binary_path())
        .args(["token", "list", "--tokens-file", tokens.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let body = String::from_utf8(out.stdout).unwrap();
    assert!(body.contains("alice"));
    assert!(!body.contains(&secret), "secret leaked into list output");
    assert!(!body.contains("sha256:"), "hash leaked into list output");
}

#[test]
fn revoke_then_list_omits_name() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");

    Command::new(binary_path())
        .args(["token", "add", "--tokens-file", tokens.to_str().unwrap(),
               "--name", "bob", "--routers", "*", "--tools", "*"])
        .status().unwrap();
    let out = Command::new(binary_path())
        .args(["token", "revoke", "--tokens-file", tokens.to_str().unwrap(), "--name", "bob"])
        .output().unwrap();
    assert!(out.status.success());

    let out = Command::new(binary_path())
        .args(["token", "list", "--tokens-file", tokens.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let body = String::from_utf8(out.stdout).unwrap();
    assert!(!body.contains("bob"));
}

#[test]
fn rotate_changes_secret_keeps_scopes() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");

    let out1 = Command::new(binary_path())
        .args(["token", "add", "--tokens-file", tokens.to_str().unwrap(),
               "--name", "carol", "--routers", "r1,r2", "--tools", "execute_junos_command"])
        .output().unwrap();
    let secret1 = String::from_utf8(out1.stdout).unwrap().trim().to_string();

    let out2 = Command::new(binary_path())
        .args(["token", "rotate", "--tokens-file", tokens.to_str().unwrap(), "--name", "carol"])
        .output().unwrap();
    assert!(out2.status.success());
    let secret2 = String::from_utf8(out2.stdout).unwrap().trim().to_string();
    assert_ne!(secret1, secret2);

    let body = std::fs::read_to_string(&tokens).unwrap();
    assert!(body.contains("\"r1\""));
    assert!(body.contains("execute_junos_command"));
}

#[test]
fn add_rejects_unknown_tool() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let out = Command::new(binary_path())
        .args(["token", "add", "--tokens-file", tokens.to_str().unwrap(),
               "--name", "dan", "--routers", "*", "--tools", "no_such_tool"])
        .output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(stderr.contains("no_such_tool"));
}
```

- [ ] **Step 2: Implement the dispatcher**

Replace `rust-junosmcp/src/token_cmd.rs`:
```rust
//! `rust-junosmcp token …` subcommand.

use crate::cli::TokenAction;
use anyhow::{bail, Context, Result};
use rust_junosmcp_auth::{ScopeSet, TokenStoreFile};
use std::io::Write;
use std::path::Path;

pub fn run(action: TokenAction) -> Result<()> {
    match action {
        TokenAction::Add { tokens_file, name, routers, tools, server_pid } => {
            let routers = parse_scope(routers);
            let tools = parse_scope(tools);
            let secret = TokenStoreFile::add(&tokens_file, &name, routers, tools)
                .with_context(|| format!("adding token '{name}'"))?;
            // Print only the secret to stdout; nothing else, so it can be
            // piped/captured.
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}", secret.expose())?;
            sighup_if_requested(server_pid);
            Ok(())
        }
        TokenAction::List { tokens_file } => list(&tokens_file),
        TokenAction::Revoke { tokens_file, name, server_pid } => {
            let removed = TokenStoreFile::revoke(&tokens_file, &name)
                .with_context(|| format!("revoking '{name}'"))?;
            if removed {
                eprintln!("revoked '{name}'");
            } else {
                eprintln!("no such token '{name}' (no-op)");
            }
            sighup_if_requested(server_pid);
            Ok(())
        }
        TokenAction::Rotate { tokens_file, name, server_pid } => {
            let store = TokenStoreFile::load(&tokens_file, &[])
                .with_context(|| format!("loading {}", tokens_file.display()))?;
            let existing = store.entries().iter().find(|e| e.name == name)
                .ok_or_else(|| anyhow::anyhow!("no such token '{name}'"))?;
            let routers = existing.routers.clone();
            let tools = existing.tools.clone();
            TokenStoreFile::revoke(&tokens_file, &name)?;
            let secret = TokenStoreFile::add(&tokens_file, &name, routers, tools)?;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}", secret.expose())?;
            sighup_if_requested(server_pid);
            Ok(())
        }
    }
}

fn parse_scope(parts: Vec<String>) -> ScopeSet {
    if parts.len() == 1 && parts[0] == "*" {
        ScopeSet::Wildcard
    } else {
        ScopeSet::Allowlist(parts)
    }
}

fn list(path: &Path) -> Result<()> {
    let store = TokenStoreFile::load(path, &[])
        .with_context(|| format!("loading {}", path.display()))?;
    if store.is_empty() {
        eprintln!("(no tokens)");
        return Ok(());
    }
    let mut out = std::io::stdout().lock();
    writeln!(out, "{:<32} {:<24} {:<24} {}", "NAME", "ROUTERS", "TOOLS", "CREATED_AT")?;
    for e in store.entries() {
        let routers = match &e.routers {
            ScopeSet::Wildcard => "*".into(),
            ScopeSet::Allowlist(v) => v.join(","),
        };
        let tools = match &e.tools {
            ScopeSet::Wildcard => "*".into(),
            ScopeSet::Allowlist(v) => v.join(","),
        };
        writeln!(out, "{:<32} {:<24} {:<24} {}", e.name, routers, tools, e.created_at.to_rfc3339())?;
    }
    Ok(())
}

#[cfg(unix)]
fn sighup_if_requested(pid: Option<i32>) {
    if let Some(pid) = pid {
        let r = unsafe { libc::kill(pid, libc::SIGHUP) };
        if r != 0 {
            tracing::warn!(pid, errno = std::io::Error::last_os_error().raw_os_error(),
                "kill(SIGHUP) failed");
        }
    }
}

#[cfg(not(unix))]
fn sighup_if_requested(_pid: Option<i32>) {
    // SIGHUP is unix-only; on non-unix we silently skip.
}
```

Add `libc = "0.2"` to `rust-junosmcp/Cargo.toml` `[target.'cfg(unix)'.dependencies]`:
```toml
[target.'cfg(unix)'.dependencies]
libc = "0.2"
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rust-junosmcp --test token_subcommand`
Expected: 4 tests pass.

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp/Cargo.toml rust-junosmcp/src/token_cmd.rs rust-junosmcp/tests/token_subcommand.rs
git commit -m "feat(bin): implement token add/list/revoke/rotate with SIGHUP convenience"
```

---

## Task 8: CLI refusal matrix (validation function + tests)

**Files:**
- Create: `rust-junosmcp/src/cli_validate.rs`
- Modify: `rust-junosmcp/src/main.rs`

The flags from Task 6 exist but are not yet enforced. This task adds a
pure-function validator with exhaustive coverage of the refusal matrix
from the design doc.

- [ ] **Step 1: Write failing tests**

Create `rust-junosmcp/src/cli_validate.rs`:
```rust
//! Validates the parsed CLI args against the design's refusal matrix.

use crate::cli::{Cli, Transport};
use std::net::IpAddr;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CliRefusal {
    #[error("--transport streamable-http requires --tokens-file (or --allow-no-auth on loopback)")]
    AuthRequired,
    #[error("--allow-no-auth refuses to bind off-loopback (host '{host}' is not 127.0.0.1 or ::1)")]
    NoAuthOffLoopback { host: String },
    #[error("non-loopback bind '{host}' over plain HTTP requires --allow-insecure-bind (or supply --tls-cert/--tls-key)")]
    InsecureBindRequired { host: String },
    #[error("--tls-cert and --tls-key must be set together (got cert={cert}, key={key})")]
    TlsPairIncomplete { cert: bool, key: bool },
}

pub fn validate(cli: &Cli) -> Result<(), CliRefusal> {
    if cli.transport == Transport::Stdio {
        return Ok(());
    }

    let tls_configured = match (cli.tls_cert.is_some(), cli.tls_key.is_some()) {
        (true, true) => true,
        (false, false) => false,
        (cert, key) => return Err(CliRefusal::TlsPairIncomplete { cert, key }),
    };

    let host_is_loopback = match cli.host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false, // hostnames are treated as non-loopback
    };

    // Auth requirement.
    if cli.tokens_file.is_none() && !cli.allow_no_auth {
        return Err(CliRefusal::AuthRequired);
    }
    if cli.tokens_file.is_none() && cli.allow_no_auth && !host_is_loopback {
        return Err(CliRefusal::NoAuthOffLoopback { host: cli.host.clone() });
    }

    // Insecure-bind requirement.
    if !host_is_loopback && !tls_configured && !cli.allow_insecure_bind {
        return Err(CliRefusal::InsecureBindRequired { host: cli.host.clone() });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("rust-junosmcp").chain(args.iter().copied()))
    }

    #[test]
    fn stdio_always_ok() {
        assert!(validate(&parse(&[])).is_ok());
        assert!(validate(&parse(&["-t", "stdio", "-H", "10.0.0.1"])).is_ok());
    }

    #[test]
    fn http_requires_tokens_file() {
        let r = validate(&parse(&["-t", "streamable-http"]));
        assert_eq!(r, Err(CliRefusal::AuthRequired));
    }

    #[test]
    fn http_no_auth_loopback_ok() {
        let r = validate(&parse(&["-t", "streamable-http", "--allow-no-auth"]));
        assert!(r.is_ok());
    }

    #[test]
    fn http_no_auth_off_loopback_refused() {
        let r = validate(&parse(&["-t", "streamable-http", "--allow-no-auth", "-H", "0.0.0.0"]));
        assert!(matches!(r, Err(CliRefusal::NoAuthOffLoopback { .. })));
    }

    #[test]
    fn http_with_tokens_loopback_ok() {
        let r = validate(&parse(&["-t", "streamable-http", "--tokens-file", "/tmp/t.json"]));
        assert!(r.is_ok());
    }

    #[test]
    fn http_off_loopback_plain_refused() {
        let r = validate(&parse(&["-t", "streamable-http", "--tokens-file", "/tmp/t.json", "-H", "0.0.0.0"]));
        assert!(matches!(r, Err(CliRefusal::InsecureBindRequired { .. })));
    }

    #[test]
    fn http_off_loopback_insecure_bind_ok() {
        let r = validate(&parse(&["-t", "streamable-http", "--tokens-file", "/tmp/t.json", "-H", "0.0.0.0", "--allow-insecure-bind"]));
        assert!(r.is_ok());
    }

    #[test]
    fn http_off_loopback_tls_ok() {
        let r = validate(&parse(&[
            "-t", "streamable-http", "--tokens-file", "/tmp/t.json",
            "-H", "0.0.0.0",
            "--tls-cert", "/tmp/c.pem", "--tls-key", "/tmp/k.pem",
        ]));
        assert!(r.is_ok());
    }

    #[test]
    fn tls_pair_incomplete_refused() {
        let r = validate(&parse(&["-t", "streamable-http", "--tokens-file", "/tmp/t.json", "--tls-cert", "/tmp/c.pem"]));
        assert!(matches!(r, Err(CliRefusal::TlsPairIncomplete { .. })));
    }

    #[test]
    fn ipv6_loopback_recognized() {
        let r = validate(&parse(&["-t", "streamable-http", "--tokens-file", "/tmp/t.json", "-H", "::1"]));
        assert!(r.is_ok());
    }
}
```

- [ ] **Step 2: Wire into main.rs**

In `rust-junosmcp/src/main.rs`, add `mod cli_validate;` near top, and after parsing + before any other action:
```rust
    if let Some(Command::Token { action }) = args.command {
        return token_cmd::run(action);
    }

    cli_validate::validate(&args).map_err(|e| anyhow::anyhow!("{}", e))?;
```

Remove the old `if matches!(args.transport, Transport::StreamableHttp) { bail!(...) }` block — the validator now owns that decision and the `streamable-http` path will be implemented in Task 11.

For now, replace the bail with a temporary `bail!` after validation (so the binary still refuses to actually serve HTTP until Task 11 lands):
```rust
    if matches!(args.transport, Transport::StreamableHttp) {
        bail!("streamable-http transport implementation lands in Task 11");
    }
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rust-junosmcp cli_validate::`
Expected: 10 tests pass.

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp/src/cli_validate.rs rust-junosmcp/src/main.rs
git commit -m "feat(bin): CLI refusal matrix for streamable-http auth/bind/TLS"
```

---

## Task 9: `CallerCtx` + `JmcpHandler` accepts optional token store

**Files:**
- Create: `rust-junosmcp/src/caller.rs`
- Modify: `rust-junosmcp/src/server.rs`

This task changes the handler shape but does NOT yet enforce scopes — the
`Option<Arc<ArcSwap<TokenStore>>>` is `None` everywhere it's constructed
in stdio mode, and the adapter functions ignore it. Task 10 adds the
enforcement.

- [ ] **Step 1: Define `CallerCtx`**

`rust-junosmcp/src/caller.rs`:
```rust
//! Per-request caller context populated by the auth middleware.

use rust_junosmcp_auth::{ScopeSet, TokenEntry};

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
```

- [ ] **Step 2: Modify `JmcpHandler` to carry the optional store**

In `rust-junosmcp/src/server.rs`:
```rust
use arc_swap::ArcSwap;
use rust_junosmcp_auth::TokenStore;
// ... existing uses ...

#[derive(Clone)]
pub struct JmcpHandler {
    inv: Arc<Inventory>,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
    token_store: Option<Arc<ArcSwap<TokenStore>>>,
}

impl JmcpHandler {
    pub fn new(
        inv: Arc<Inventory>,
        dm: Arc<DeviceManager>,
        policy: Arc<Policy>,
        token_store: Option<Arc<ArcSwap<TokenStore>>>,
    ) -> Self {
        Self { inv, dm, policy, token_store }
    }
    // existing to_call_result method unchanged ...
}
```

- [ ] **Step 3: Update the call site in `main.rs`**

```rust
    let handler = JmcpHandler::new(inventory, dev_manager, policy, None);
```

(stdio path: `None`. Streamable-http path will pass `Some(store)` in Task 11.)

- [ ] **Step 4: Build + test**

Run: `cargo build -p rust-junosmcp`
Expected: builds clean.

Run: `cargo test -p rust-junosmcp-core -p rust-junosmcp -p rust-junosmcp-auth`
Expected: all existing tests still pass (this is a no-op refactor for stdio).

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp/src/caller.rs rust-junosmcp/src/server.rs rust-junosmcp/src/main.rs
git commit -m "feat(bin): JmcpHandler carries optional Arc<ArcSwap<TokenStore>>"
```

---

## Task 10: `ScopeError` + scope enforcement in `#[tool]` adapters

**Files:**
- Modify: `rust-junosmcp/src/server.rs`

Each `#[tool]` adapter consults the `CallerCtx` (when present) before
delegating to core's tool handler. `get_router_list` is special-cased to
filter results by `ctx.routers`.

The `CallerCtx` is read from rmcp's per-request extensions if path A from
the spike worked, or from the `RequestId`-keyed map if path B was needed.
This task assumes path A; if the spike memo says path B, swap the helper
function `extract_caller_ctx` to read from the map instead.

- [ ] **Step 1: Define `ScopeError` + helper**

In `rust-junosmcp/src/server.rs` (top of file):
```rust
use rust_junosmcp_auth::ScopeSet;

#[derive(Debug, thiserror::Error)]
pub enum ScopeError {
    #[error("token '{token}' is not authorized for tool '{tool}'")]
    ToolNotInScope { token: String, tool: &'static str },
    #[error("token '{token}' is not authorized for router '{router}' (tool '{tool}')")]
    RouterNotInScope { token: String, router: String, tool: &'static str },
}

impl JmcpHandler {
    /// Convert ScopeError into the same kind of CallToolResult { isError: true }
    /// that JmcpError::Denied produces. Mirrors `to_call_result`.
    fn scope_to_call_result(e: ScopeError) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(CallToolResult::error(vec![Content::text(e.to_string())]))
    }

    /// Check tool scope. Returns Err(ScopeError) if denied, Ok(()) if allowed
    /// or if no token store is configured (stdio path).
    fn check_tool_scope(
        &self,
        ctx: Option<&crate::caller::CallerCtx>,
        tool: &'static str,
    ) -> Result<(), ScopeError> {
        if let Some(ctx) = ctx {
            if !ctx.tools.allows(tool) {
                return Err(ScopeError::ToolNotInScope { token: ctx.token_name.clone(), tool });
            }
        }
        Ok(())
    }

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
```

- [ ] **Step 2: Update each `#[tool]` adapter**

Per the Task 0 spike, rmcp inserts the whole `http::request::Parts` into the
per-request extensions, so the tool reads `CallerCtx` via
`Extension<http::request::Parts>` and then `parts.extensions.get::<CallerCtx>()`.
(Direct `Extension<CallerCtx>` does NOT work — rmcp does not auto-propagate
arbitrary axum extensions; only the `Parts` object is forwarded.)

Add a tiny helper at the top of `server.rs`:
```rust
use http::request::Parts;
use rmcp::handler::server::tool::Extension;

fn caller_ctx(parts: &Parts) -> Option<&crate::caller::CallerCtx> {
    parts.extensions.get::<crate::caller::CallerCtx>()
}
```

For each existing `#[tool]` method, modify the signature and body:

```rust
    #[tool(name = "execute_junos_command", description = "...")]
    async fn execute_junos_command(
        &self,
        Parameters(args): Parameters<ExecuteCommandArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&parts);
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
```

**Stdio compatibility caveat:** The spike confirmed `Extension<Parts>` works on
the streamable-http path, but it did NOT verify the stdio path. The stdio
transport (`transport-io`) does not have an `http::Request` to split into Parts,
so a required `Extension<Parts>` extractor may fail under stdio. Before
committing this task, the implementer must verify the existing stdio smoke tests
(`lists_six_tools`, `denied_command_returns_tool_error`) still pass. If
`Extension<Parts>` breaks stdio, switch the extractor to `Option<Extension<Parts>>`
(rmcp's idiomatic optional extractor) and treat `None` the same as
"no `CallerCtx` present" — `check_*_scope` already permits this. Document the
finding in the commit message.

Apply the same pattern to:
- `gather_device_facts` (router scope)
- `get_junos_config` (router scope)
- `junos_config_diff` (router scope)
- `load_and_commit_config` (router scope)
- `get_router_list` (tool scope only — router filtering is in Task 11)

- [ ] **Step 3: Add a unit test for the scope helpers**

Append to `rust-junosmcp/src/server.rs`:
```rust
#[cfg(test)]
mod scope_tests {
    use super::*;
    use crate::caller::CallerCtx;
    use rust_junosmcp_auth::ScopeSet;

    fn make_handler() -> JmcpHandler {
        // Don't actually need an Inventory or Policy for scope-only checks.
        // Build minimal versions.
        let inv = Arc::new(Inventory::empty());
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = Arc::new(Policy::build(&inv).unwrap());
        JmcpHandler::new(inv, dm, policy, None)
    }

    #[test]
    fn no_ctx_allows_anything() {
        let h = make_handler();
        assert!(h.check_tool_scope(None, "execute_junos_command").is_ok());
        assert!(h.check_router_scope(None, "execute_junos_command", "r1").is_ok());
    }

    #[test]
    fn tool_scope_denies_when_not_listed() {
        let h = make_handler();
        let ctx = CallerCtx {
            token_name: "alice".into(),
            routers: ScopeSet::Wildcard,
            tools: ScopeSet::Allowlist(vec!["get_router_list".into()]),
        };
        assert!(h.check_tool_scope(Some(&ctx), "get_router_list").is_ok());
        assert!(matches!(
            h.check_tool_scope(Some(&ctx), "execute_junos_command"),
            Err(ScopeError::ToolNotInScope { .. })
        ));
    }

    #[test]
    fn router_scope_denies_when_not_listed() {
        let h = make_handler();
        let ctx = CallerCtx {
            token_name: "alice".into(),
            routers: ScopeSet::Allowlist(vec!["r1".into()]),
            tools: ScopeSet::Wildcard,
        };
        assert!(h.check_router_scope(Some(&ctx), "execute_junos_command", "r1").is_ok());
        assert!(matches!(
            h.check_router_scope(Some(&ctx), "execute_junos_command", "r2"),
            Err(ScopeError::RouterNotInScope { .. })
        ));
    }
}
```

You may need to add `Inventory::empty()` to `rust-junosmcp-core/src/inventory.rs`:
```rust
    pub fn empty() -> Self {
        Inventory { devices: Default::default(), blocklist_defaults: None }
    }
```
(Adjust struct fields to match the actual type.)

- [ ] **Step 4: Run tests**

Run: `cargo test -p rust-junosmcp-core -p rust-junosmcp -p rust-junosmcp-auth`
Expected: all tests pass, including 3 new scope_tests. Stdio smoke (`lists_six_tools`, `denied_command_returns_tool_error`) must still pass — proves no regression.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp/src/server.rs rust-junosmcp-core/src/inventory.rs
git commit -m "feat(bin): scope enforcement in #[tool] adapters"
```

---

## Task 11: Streamable-HTTP transport wiring + AuthLayer middleware

**Files:**
- Create: `rust-junosmcp/src/auth_layer.rs`
- Create: `rust-junosmcp/src/http_transport.rs`
- Modify: `rust-junosmcp/Cargo.toml`
- Modify: `rust-junosmcp/src/main.rs`

This is the largest task. The exact rmcp mount API depends on the spike
outcome (Task 0). What follows assumes the spike confirmed path A; if path
B, swap the extension-population for the DashMap-keyed lookup.

- [ ] **Step 1: Add HTTP-stack deps**

`rust-junosmcp/Cargo.toml`:
```toml
[dependencies]
# existing ...
arc-swap   = { workspace = true }
axum       = { workspace = true }
tower      = { workspace = true }
tower-http = { workspace = true, features = ["trace"] }

# rmcp streamable-http feature (confirmed by Task 0 spike memo):
rmcp = { version = "0.8", features = [
    "server", "macros", "transport-io", "schemars",
    "transport-streamable-http-server",
] }
```

- [ ] **Step 2: Implement the AuthLayer middleware**

`rust-junosmcp/src/auth_layer.rs`:
```rust
//! Tower middleware: extract `Authorization: Bearer …`, look up the token in
//! the current `Arc<TokenStore>`, and stuff a `CallerCtx` into request
//! extensions. Reject otherwise with HTTP 401.

use crate::caller::CallerCtx;
use arc_swap::ArcSwap;
use axum::{
    body::Body,
    http::{header, HeaderValue, Request, Response, StatusCode},
    middleware::Next,
};
use rust_junosmcp_auth::TokenStore;
use std::sync::Arc;

#[derive(Clone)]
pub struct AuthState {
    pub store: Arc<ArcSwap<TokenStore>>,
}

pub async fn auth_layer(
    axum::extract::State(state): axum::extract::State<AuthState>,
    mut req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let store_snapshot = state.store.load_full();

    let header_value = match req.headers().get(header::AUTHORIZATION) {
        Some(v) => v,
        None => return reject(StatusCode::UNAUTHORIZED, "missing Authorization header", true),
    };
    let secret = match parse_bearer(header_value) {
        Some(s) => s,
        None => return reject(StatusCode::UNAUTHORIZED, "Authorization header must use Bearer scheme", true),
    };

    match store_snapshot.find(secret) {
        Some(entry) => {
            let ctx: CallerCtx = entry.into();
            req.extensions_mut().insert(ctx);
            next.run(req).await
        }
        None => {
            tracing::warn!(remote = ?req.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>(),
                "auth_failed: no matching token");
            reject(StatusCode::UNAUTHORIZED, "invalid bearer token", false)
        }
    }
}

fn parse_bearer(v: &HeaderValue) -> Option<&str> {
    let s = v.to_str().ok()?;
    s.strip_prefix("Bearer ").map(|t| t.trim())
}

fn reject(code: StatusCode, msg: &str, include_challenge: bool) -> Response<Body> {
    let mut resp = Response::builder().status(code);
    if include_challenge {
        resp = resp.header(header::WWW_AUTHENTICATE, "Bearer");
    }
    resp.body(Body::from(msg.to_string())).unwrap()
}
```

- [ ] **Step 3: Implement the HTTP transport**

`rust-junosmcp/src/http_transport.rs`:
```rust
//! axum router: AuthLayer + rmcp streamable-http handler.
//! Mount API confirmed by Task 0 spike (path A): rmcp's `StreamableHttpService`
//! is a `tower::Service<http::Request<B>>`, mounted under axum 0.8 via
//! `Router::nest_service("/mcp", svc)`. The service splits requests into
//! `(Parts, Body)` and inserts the whole `http::request::Parts` into rmcp's
//! per-request extensions, so anything our outer middleware put on the axum
//! request extensions (e.g. `CallerCtx`) rides along inside `parts.extensions`.

use crate::auth_layer::{auth_layer, AuthState};
use crate::server::JmcpHandler;
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use axum::Router;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rust_junosmcp_auth::TokenStore;
use std::net::SocketAddr;
use std::sync::Arc;

pub async fn serve(
    handler_factory: impl Fn() -> std::io::Result<JmcpHandler> + Send + Sync + Clone + 'static,
    addr: SocketAddr,
    token_store: Option<Arc<ArcSwap<TokenStore>>>,
) -> Result<()> {
    let svc = StreamableHttpService::new(
        handler_factory,
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );

    let rmcp_router = Router::new().nest_service("/mcp", svc);

    let app = if let Some(store) = token_store {
        rmcp_router.layer(axum::middleware::from_fn_with_state(
            AuthState { store },
            auth_layer,
        ))
    } else {
        // --allow-no-auth path: no middleware, no token check.
        rmcp_router
    };

    let listener = tokio::net::TcpListener::bind(addr).await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!(addr = %addr, "streamable-http listening");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("axum::serve")?;
    Ok(())
}
```

> The implementer should call `serve(...)` from `main.rs` by passing a closure that clones the prebuilt `JmcpHandler` (since `JmcpHandler::new` is cheap — it just wraps `Arc`s — but the factory shape lets rmcp build a fresh handler per session if we ever want stateless mode). The exact module path is `rmcp::transport::streamable_http_server::{StreamableHttpService, StreamableHttpServerConfig, session::local::LocalSessionManager}`.

- [ ] **Step 4: Update `main.rs`**

```rust
mod auth_layer;
mod caller;
mod cli;
mod cli_validate;
mod http_transport;
mod server;
mod token_cmd;

// ... existing main body up to handler construction ...

    let token_store = match (&args.tokens_file, args.allow_no_auth) {
        (Some(path), _) => {
            let known: Vec<&str> = inventory.names().iter().map(|s| s.as_str()).collect();
            let store = TokenStoreFile::load(path, &known)
                .with_context(|| format!("loading {}", path.display()))?;
            tracing::info!(tokens = store.len(), "token store loaded");
            Some(Arc::new(arc_swap::ArcSwap::from_pointee(store)))
        }
        (None, true) => {
            tracing::warn!("--allow-no-auth: streamable-http will accept unauthenticated requests");
            None
        }
        (None, false) if matches!(args.transport, Transport::StreamableHttp) => {
            unreachable!("cli_validate::validate should have refused this combination");
        }
        _ => None,
    };

    let handler = JmcpHandler::new(inventory.clone(), dev_manager, policy, token_store.clone());

    match args.transport {
        Transport::Stdio => {
            let service = handler.serve((tokio::io::stdin(), tokio::io::stdout()))
                .await.context("starting MCP stdio service")?;
            service.waiting().await.context("MCP service exited with error")?;
        }
        Transport::StreamableHttp => {
            let addr: std::net::SocketAddr = format!("{}:{}", args.host, args.port).parse()
                .with_context(|| format!("parsing {}:{}", args.host, args.port))?;
            http_transport::serve(handler, addr, token_store).await?;
        }
    }
```

- [ ] **Step 5: Build**

Run: `cargo build -p rust-junosmcp`
Expected: builds clean. If the rmcp mount API name was wrong, the spike memo names the right one; update Step 3.

Run: `cargo test -p rust-junosmcp-core -p rust-junosmcp -p rust-junosmcp-auth`
Expected: all existing tests still pass (stdio path unchanged).

- [ ] **Step 6: Commit**

```bash
git add rust-junosmcp/Cargo.toml rust-junosmcp/src/auth_layer.rs rust-junosmcp/src/http_transport.rs rust-junosmcp/src/main.rs
git commit -m "feat(bin): streamable-http transport with bearer-token AuthLayer"
```

---

## Task 12: HTTP smoke tests — auth + scope + blocklist order

**Files:**
- Create: `rust-junosmcp/tests/http_smoke.rs`

- [ ] **Step 1: Write the smoke tests**

`rust-junosmcp/tests/http_smoke.rs`:
```rust
//! End-to-end streamable-http smoke: spawn the binary on an ephemeral port,
//! send HTTP, assert auth + scope + blocklist behavior.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn binary_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("target");
    p.push(if cfg!(debug_assertions) { "debug" } else { "release" });
    p.push("rust-junosmcp");
    p
}

fn ensure_built() {
    let s = Command::new("cargo").args(["build", "-p", "rust-junosmcp"]).status().unwrap();
    assert!(s.success());
}

fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// RAII child guard: kills + waits on drop so panics don't leak processes.
struct Server { child: Child, port: u16 }
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn(inv_path: &std::path::Path, tokens_path: &std::path::Path) -> Server {
    let port = pick_port();
    let mut child = Command::new(binary_path())
        .args([
            "-f", inv_path.to_str().unwrap(),
            "-t", "streamable-http",
            "-H", "127.0.0.1",
            "-p", &port.to_string(),
            "--tokens-file", tokens_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn().expect("spawn");
    // Wait until the listener is up.
    let stderr = child.stderr.take().unwrap();
    let reader = BufReader::new(stderr);
    let deadline = Instant::now() + Duration::from_secs(15);
    for line in reader.lines() {
        if Instant::now() > deadline { break; }
        if let Ok(line) = line {
            if line.contains("streamable-http listening") {
                return Server { child, port };
            }
        }
    }
    let _ = child.kill();
    panic!("server did not start within 15s");
}

fn http_post(port: u16, bearer: Option<&str>, body: Value) -> (u16, Value) {
    let mut req = ureq::post(&format!("http://127.0.0.1:{port}/mcp"));
    if let Some(b) = bearer {
        req = req.set("Authorization", &format!("Bearer {b}"));
    }
    match req.send_json(body) {
        Ok(resp) => {
            let code = resp.status();
            let v: Value = resp.into_json().unwrap_or(json!({}));
            (code, v)
        }
        Err(ureq::Error::Status(code, resp)) => {
            let v: Value = resp.into_json().unwrap_or(json!({}));
            (code, v)
        }
        Err(e) => panic!("transport error: {e}"),
    }
}

const INIT: Value = json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
    "protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}
}});

fn write_inv(json: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), json).unwrap();
    f
}

fn write_tokens(json: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), json).unwrap();
    f
}

#[test]
fn missing_authorization_returns_401() {
    ensure_built();
    let inv = write_inv(r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#);
    let toks = write_tokens(r#"{"version":1,"tokens":[]}"#);
    let s = spawn(inv.path(), toks.path());
    let (code, _) = http_post(s.port, None, json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}));
    assert_eq!(code, 401);
}

#[test]
fn wrong_bearer_returns_401() {
    ensure_built();
    let inv = write_inv(r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#);
    let toks = write_tokens(r#"{"version":1,"tokens":[]}"#);
    let s = spawn(inv.path(), toks.path());
    let (code, _) = http_post(s.port, Some("not-a-real-token"), json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}));
    assert_eq!(code, 401);
}

#[test]
fn router_scope_denial_returns_tool_error_with_message() {
    ensure_built();
    // Mint a token via the subcommand so we have the secret.
    let inv = write_inv(r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#);
    let dir = tempfile::tempdir().unwrap();
    let toks = dir.path().join("tokens.json");
    let out = Command::new(binary_path()).args([
        "token", "add", "--tokens-file", toks.to_str().unwrap(),
        "--name", "scoped",
        "--routers", "other-router",
        "--tools", "*",
    ]).output().unwrap();
    let secret = String::from_utf8(out.stdout).unwrap().trim().to_string();

    let s = spawn(inv.path(), &toks);

    // Initialize first
    let _ = http_post(s.port, Some(&secret), INIT);
    let (code, body) = http_post(s.port, Some(&secret),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":{"router_name":"r1","command":"show version","timeout":1}
        }}));
    assert_eq!(code, 200);
    let result = body.pointer("/result").expect("result");
    assert_eq!(result.get("isError"), Some(&json!(true)));
    let text = serde_json::to_string(result).unwrap();
    assert!(text.contains("not authorized for router"), "expected scope denial, got {text}");
}

#[test]
fn auth_then_scope_then_blocklist_ordering() {
    // Token allows everything, but blocklist denies. Expect blocklist message
    // (proves ordering: scope passes first, blocklist runs after).
    ensure_built();
    let inv = write_inv(r#"{
        "_blocklist_defaults":{"commands":[{"action":"deny","pattern":"request system *"}]},
        "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
    }"#);
    let dir = tempfile::tempdir().unwrap();
    let toks = dir.path().join("tokens.json");
    let out = Command::new(binary_path()).args([
        "token", "add", "--tokens-file", toks.to_str().unwrap(),
        "--name", "all",
        "--routers", "*", "--tools", "*",
    ]).output().unwrap();
    let secret = String::from_utf8(out.stdout).unwrap().trim().to_string();

    let s = spawn(inv.path(), &toks);
    let _ = http_post(s.port, Some(&secret), INIT);
    let (code, body) = http_post(s.port, Some(&secret),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":{"router_name":"r1","command":"request system reboot","timeout":1}
        }}));
    assert_eq!(code, 200);
    let result = body.pointer("/result").expect("result");
    assert_eq!(result.get("isError"), Some(&json!(true)));
    let text = serde_json::to_string(result).unwrap();
    assert!(text.contains("denied by blocklist"), "expected blocklist denial, got {text}");
}
```

Add `ureq = "2"` to `rust-junosmcp/Cargo.toml` `[dev-dependencies]`.

- [ ] **Step 2: Run the tests**

Run: `cargo test -p rust-junosmcp --test http_smoke -- --test-threads=1`
Expected: 4 tests pass (sequential because they spawn binaries).

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp/Cargo.toml rust-junosmcp/tests/http_smoke.rs
git commit -m "test: streamable-http smoke (auth + scope + blocklist ordering)"
```

---

## Task 13: SIGHUP hot reload of the token store

**Files:**
- Modify: `rust-junosmcp/src/main.rs` (spawn a SIGHUP listener task)
- Create: `rust-junosmcp/tests/http_reload.rs`

**Goal:** When the server receives SIGHUP, it re-reads the tokens file and atomically swaps the `Arc<ArcSwap<TokenStore>>` so subsequent requests see the new state. The `AuthLayer` already reads through the `ArcSwap`, so no middleware change is needed.

- [ ] **Step 1: Write the failing reload smoke test**

Create `rust-junosmcp/tests/http_reload.rs`:

```rust
//! SIGHUP hot reload smoke. Unix-only.
#![cfg(unix)]

use serde_json::{json, Value};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn binary_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_rust-junosmcp"))
}

fn write(p: &std::path::Path, body: &str) {
    std::fs::write(p, body).unwrap();
}

fn http_post(port: u16, bearer: Option<&str>, body: Value) -> (u16, Value) {
    let mut req = ureq::post(&format!("http://127.0.0.1:{port}/mcp"))
        .set("content-type", "application/json");
    if let Some(b) = bearer {
        req = req.set("authorization", &format!("Bearer {b}"));
    }
    match req.send_json(body) {
        Ok(r) => (r.status(), r.into_json().unwrap_or(Value::Null)),
        Err(ureq::Error::Status(code, r)) => {
            (code, r.into_json().unwrap_or(Value::Null))
        }
        Err(e) => panic!("transport error: {e}"),
    }
}

struct Server {
    child: Child,
    port: u16,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn(inv: &std::path::Path, toks: &std::path::Path) -> Server {
    let mut child = Command::new(binary_path())
        .args([
            "--device-mapping", inv.to_str().unwrap(),
            "--transport", "streamable-http",
            "--bind", "127.0.0.1:0",
            "--print-listen-port",
            "--tokens-file", toks.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.as_mut().unwrap();
    let mut buf = String::new();
    use std::io::{BufRead, BufReader};
    BufReader::new(stdout).read_line(&mut buf).unwrap();
    let port: u16 = buf.trim().parse().expect("port line");
    Server { child, port }
}

const INIT: Value = json!({"jsonrpc":"2.0","id":1,"method":"initialize",
    "params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"0"}}});

#[test]
fn sighup_reloads_token_store() {
    let dir = tempfile::tempdir().unwrap();
    let inv = dir.path().join("inv.json");
    write(&inv, r#"{"version":1,"devices":[
        {"name":"r1","ip":"10.0.0.1","username":"u","password":"p"}
    ]}"#);
    let toks = dir.path().join("tokens.json");
    let bin = binary_path();

    // Mint a token via the subcommand.
    let out = Command::new(&bin).args([
        "token", "add", "--tokens-file", toks.to_str().unwrap(),
        "--name", "all", "--routers", "*", "--tools", "*",
    ]).output().unwrap();
    let secret = String::from_utf8(out.stdout).unwrap().trim().to_string();

    let s = spawn(&inv, &toks);
    let (code, _) = http_post(s.port, Some(&secret), INIT);
    assert_eq!(code, 200, "token works before revoke");

    // Revoke and SIGHUP.
    let _ = Command::new(&bin).args([
        "token", "revoke", "--tokens-file", toks.to_str().unwrap(), "--name", "all",
    ]).output().unwrap();
    let pid = s.child.id() as i32;
    unsafe { libc::kill(pid, libc::SIGHUP); }

    // Give the reload a moment.
    std::thread::sleep(Duration::from_millis(200));

    let (code, _) = http_post(s.port, Some(&secret), INIT);
    assert_eq!(code, 401, "revoked token rejected after SIGHUP");
}
```

Add to `rust-junosmcp/Cargo.toml`:
```toml
[target.'cfg(unix)'.dev-dependencies]
libc = "0.2"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p rust-junosmcp --test http_reload`
Expected: FAIL — main.rs has no SIGHUP handler yet, so the second call still returns 200.

- [ ] **Step 3: Implement the SIGHUP handler in main.rs**

In `rust-junosmcp/src/main.rs`, after the token store is loaded into an `Arc<ArcSwap<TokenStore>>`, spawn a unix-only task:

```rust
#[cfg(unix)]
{
    let store = token_store.clone();
    let path = args.tokens_file.clone();
    tokio::spawn(async move {
        let mut hup = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::hangup()
        ).expect("install SIGHUP handler");
        while hup.recv().await.is_some() {
            match rust_junosmcp_auth::TokenStoreFile::load(&path, rust_junosmcp_auth::KNOWN_TOOLS) {
                Ok(new_store) => {
                    store.store(std::sync::Arc::new(new_store));
                    tracing::info!(path = %path.display(), "token store reloaded");
                }
                Err(e) => tracing::error!(error = %e, "SIGHUP reload failed; keeping previous store"),
            }
        }
    });
}
```

(`TokenStoreFile::load` returns a `TokenStore` directly — see Task 4. `KNOWN_TOOLS` is the `&[&str]` of tool names exported from the auth crate, populated in Task 4.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p rust-junosmcp --test http_reload`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp/Cargo.toml rust-junosmcp/src/main.rs rust-junosmcp/tests/http_reload.rs
git commit -m "feat(server): SIGHUP hot reload of token store"
```

---

## Task 14: Optional rustls TLS

**Files:**
- Modify: `rust-junosmcp/Cargo.toml` (add `tls` feature, default-on)
- Modify: `rust-junosmcp/src/main.rs` (TLS branch in HTTP bind)
- Create: `rust-junosmcp/src/tls.rs`
- Create: `rust-junosmcp/tests/http_tls.rs`

- [ ] **Step 1: Add the feature and dependencies**

In `rust-junosmcp/Cargo.toml`:
```toml
[features]
default = ["tls"]
tls = ["dep:rustls", "dep:tokio-rustls", "dep:rustls-pemfile"]

[dependencies]
rustls = { version = "0.23", optional = true, default-features = false, features = ["ring", "std"] }
tokio-rustls = { version = "0.26", optional = true }
rustls-pemfile = { version = "2", optional = true }
```

- [ ] **Step 2: Write the failing TLS smoke test**

Create `rust-junosmcp/tests/http_tls.rs`:

```rust
#![cfg(feature = "tls")]

use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

fn binary_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_rust-junosmcp"))
}

fn write_self_signed(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    use rcgen::generate_simple_self_signed;
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.serialize_pem().unwrap()).unwrap();
    std::fs::write(&key_path, cert.serialize_private_key_pem()).unwrap();
    (cert_path, key_path)
}

#[test]
fn tls_handshake_completes_and_auth_works() {
    let dir = tempfile::tempdir().unwrap();
    let inv = dir.path().join("inv.json");
    std::fs::write(&inv, r#"{"version":1,"devices":[
        {"name":"r1","ip":"10.0.0.1","username":"u","password":"p"}
    ]}"#).unwrap();
    let toks = dir.path().join("tokens.json");
    let (cert, key) = write_self_signed(dir.path());

    let out = Command::new(binary_path()).args([
        "token", "add", "--tokens-file", toks.to_str().unwrap(),
        "--name", "all", "--routers", "*", "--tools", "*",
    ]).output().unwrap();
    let secret = String::from_utf8(out.stdout).unwrap().trim().to_string();

    let mut child = Command::new(binary_path()).args([
        "--device-mapping", inv.to_str().unwrap(),
        "--transport", "streamable-http",
        "--bind", "127.0.0.1:0",
        "--print-listen-port",
        "--tokens-file", toks.to_str().unwrap(),
        "--tls-cert", cert.to_str().unwrap(),
        "--tls-key",  key.to_str().unwrap(),
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .spawn().unwrap();
    let mut buf = String::new();
    BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut buf).unwrap();
    let port: u16 = buf.trim().parse().unwrap();

    // rustls client that trusts our self-signed cert.
    let pem = std::fs::read(&cert).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut &pem[..]) {
        roots.add(c.unwrap()).unwrap();
    }
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let agent = ureq::AgentBuilder::new().tls_config(Arc::new(cfg)).build();

    let r = agent.post(&format!("https://localhost:{port}/mcp"))
        .set("authorization", &format!("Bearer {secret}"))
        .set("content-type", "application/json")
        .send_json(json!({"jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2024-11-05","capabilities":{},
                      "clientInfo":{"name":"t","version":"0"}}}))
        .unwrap();
    assert_eq!(r.status(), 200);
    let _: Value = r.into_json().unwrap();

    let _ = child.kill();
    let _ = child.wait();
}
```

Add to `[dev-dependencies]`: `rcgen = "0.13"`, `rustls = { version = "0.23", default-features = false, features = ["ring","std"] }`, `rustls-pemfile = "2"`, `ureq = { version = "2", features = ["tls"] }`.

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p rust-junosmcp --features tls --test http_tls`
Expected: FAIL — `--tls-cert`/`--tls-key` flags accepted but main.rs still binds plain HTTP.

- [ ] **Step 4: Implement the TLS bind branch**

Create `rust-junosmcp/src/tls.rs`:
```rust
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;

pub fn load(cert: &Path, key: &Path) -> Result<Arc<rustls::ServerConfig>> {
    let cert_bytes = std::fs::read(cert).with_context(|| format!("read {}", cert.display()))?;
    let key_bytes  = std::fs::read(key).with_context(|| format!("read {}", key.display()))?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_bytes[..])
        .collect::<std::result::Result<_, _>>()
        .context("parse cert PEM")?;
    let key = rustls_pemfile::private_key(&mut &key_bytes[..])
        .context("parse key PEM")?
        .context("no private key found in key file")?;

    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("rustls server config")?;
    Ok(Arc::new(cfg))
}
```

In `main.rs`, after the axum router is built and bound to a `TcpListener`, branch:
```rust
if let (Some(cert), Some(key)) = (args.tls_cert.as_deref(), args.tls_key.as_deref()) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls::load(cert, key)?);
    // Wrap the listener: accept TCP, do the rustls handshake, hand the
    // resulting stream to hyper. Use axum_server with rustls config, OR
    // a small accept loop that calls hyper::server::conn::http1::Builder
    // ::serve_connection on the TLS stream after handshake.
    serve_tls(listener, acceptor, app).await?;
} else if !args.allow_insecure_bind && is_non_loopback(&listener.local_addr()?) {
    bail!("refusing to bind {} without TLS; pass --allow-insecure-bind to override", listener.local_addr()?);
} else {
    axum::serve(listener, app).await?;
}
```

`serve_tls` is a small helper that loops `listener.accept()`, runs `acceptor.accept(stream)`, and hands each TLS stream to `hyper::server::conn::http1::Builder::new().serve_connection(stream, app.clone())`. (Or use `axum-server = { version = "0.7", features = ["tls-rustls"] }` if simpler — that's a one-line decision in the implementer's hands; either is fine if tested.)

`is_non_loopback` returns true unless the bound IP is in `127.0.0.0/8` or `::1`.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p rust-junosmcp --features tls --test http_tls`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add rust-junosmcp/Cargo.toml rust-junosmcp/src/main.rs rust-junosmcp/src/tls.rs rust-junosmcp/tests/http_tls.rs
git commit -m "feat(server): optional rustls TLS for streamable-http"
```

---

## Task 15: README + tokens-template.json + final CI verification

**Files:**
- Modify: `README.md`
- Create: `tokens-template.json`

- [ ] **Step 1: Add the "Remote transport + auth" section to README.md**

Insert a new section after the existing "Quick start" / before "Coming in v0.2", titled `### Remote transport + auth (v0.2)`. Cover, in this order, with copy-paste-runnable commands:

1. Mint a token: `cargo run -- token add --tokens-file tokens.json --name ops --routers '*' --tools execute_junos_command,get_facts`
2. Run with auth: `cargo run -- --device-mapping devices.json --transport streamable-http --bind 127.0.0.1:8765 --tokens-file tokens.json`
3. Loopback escape hatch: `--allow-no-auth` (loopback only — refuses on non-loopback).
4. Non-loopback requires TLS: `--bind 0.0.0.0:8765 --tls-cert cert.pem --tls-key key.pem` (or `--allow-insecure-bind` to override, with a strong warning).
5. Hot reload: `kill -HUP <pid>` after `token revoke ...` / `token rotate ...`.
6. Refusal matrix table (4 rows): no flags (refuse), only `--allow-no-auth` non-loopback (refuse), only `--tokens-file` non-loopback no TLS (refuse without `--allow-insecure-bind`), `--tokens-file --tls-cert --tls-key` (OK).

Update the "Coming in v0.2" line to remove `streamable-http transport` and `bearer-token auth`.

Also update the top-level feature list (the bullets near the top of README) to mention `streamable-http transport (with optional rustls TLS)` and `bearer-token auth with per-token router/tool scopes`.

- [ ] **Step 2: Create `tokens-template.json`**

```json
{
  "version": 1,
  "tokens": [
    {
      "id": "REPLACE_WITH_UUID",
      "name": "example-readonly",
      "hash": "sha256:REPLACE_WITH_HASH",
      "routers": ["*"],
      "tools": ["get_facts", "execute_junos_command"],
      "created_at": "2026-05-05T00:00:00Z"
    }
  ]
}
```

Add a comment-style header in the README pointing here ("see `tokens-template.json` for shape; mint with `token add` rather than editing by hand").

- [ ] **Step 3: Run the full CI sweep locally**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test  --workspace --all-features
cargo test  --workspace --no-default-features
cargo audit
```

Expected: all clean. (`--no-default-features` proves the `tls` feature is truly optional.)

- [ ] **Step 4: Commit docs**

```bash
git add README.md tokens-template.json
git commit -m "docs: README + tokens-template for remote transport + auth"
```

---

## Final Verification

Before handing off:

- [ ] Total commit count on branch is reasonable (one commit per task — ~16 commits including the spike).
- [ ] `git log --oneline main..HEAD` shows a clean, single-purpose commit per task.
- [ ] All four CI invocations from Task 15 Step 3 still pass at HEAD.
- [ ] Stdio path still works: `echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}' | cargo run -- --device-mapping devices-template.json` still returns a `result` (no auth required on stdio).
- [ ] The blocklist guardrails added in sub-project #1 still gate every tool call, regardless of token scope.
