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

    /// Atomically write the store to `path` (tempfile-in-same-dir → write →
    /// fsync → rename). The rename is atomic on the same filesystem, so
    /// readers never see a half-written file.
    pub fn save(path: &Path, store: &TokenStore) -> Result<(), TokenStoreError> {
        use std::io::Write;
        let parent = path.parent().ok_or_else(|| TokenStoreError::Invalid(
            format!("path has no parent: {}", path.display())
        ))?;
        let on_disk = OnDisk { version: 1, tokens: store.entries().to_vec() };
        let json = serde_json::to_vec_pretty(&on_disk)?;

        // Use NamedTempFile::persist so the tempfile handle remains owned
        // until the rename succeeds. If write/sync/persist fails, Drop on
        // NamedTempFile (or on the PersistError that owns it) cleans up the
        // `.tokens-*.tmp` file — no leak.
        let mut tmp = tempfile::Builder::new()
            .prefix(".tokens-")
            .suffix(".tmp")
            .tempfile_in(parent)?;
        tmp.write_all(&json)?;
        tmp.as_file().sync_all()?;
        tmp.persist(path).map_err(|e| TokenStoreError::Io(e.error))?;
        Ok(())
    }

    /// Mint a new token, append it to the store at `path`, and persist.
    /// Returns the freshly-minted secret (the only time the plaintext exists).
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

    /// Remove the named entry. Returns `true` if a token was removed,
    /// `false` if no entry by that name existed (idempotent).
    pub fn revoke(path: &Path, name: &str) -> Result<bool, TokenStoreError> {
        let store = Self::load(path, &[])?;
        let before = store.len();
        let entries: Vec<_> = store.entries().iter().filter(|e| e.name != name).cloned().collect();
        let removed = entries.len() < before;
        Self::save(path, &TokenStore::new(entries))?;
        Ok(removed)
    }

    /// Atomically rotate the secret for the named entry. Loads the store,
    /// finds the entry by name (or returns `Invalid` if missing), mints a new
    /// `(Secret, TokenHash)`, replaces the entry's hash and `created_at`
    /// (preserving `routers` and `tools`), and saves the result in a single
    /// atomic rename. Returns the freshly-minted secret.
    ///
    /// Unlike `revoke + add`, this is all-or-nothing: a failure mid-rotation
    /// cannot leave the store without an entry for `name`.
    pub fn rotate(path: &Path, name: &str) -> Result<crate::token::Secret, TokenStoreError> {
        let store = Self::load(path, &[])?;
        if !store.entries().iter().any(|e| e.name == name) {
            return Err(TokenStoreError::Invalid(format!("no such token '{name}'")));
        }
        let (secret, hash) = crate::token::Secret::mint();
        let entries: Vec<TokenEntry> = store
            .entries()
            .iter()
            .map(|e| {
                if e.name == name {
                    TokenEntry {
                        name: e.name.clone(),
                        hash: hash.clone(),
                        routers: e.routers.clone(),
                        tools: e.tools.clone(),
                        created_at: chrono::Utc::now(),
                    }
                } else {
                    e.clone()
                }
            })
            .collect();
        Self::save(
            path,
            &TokenStore::try_new(entries).map_err(|e| TokenStoreError::Invalid(e.0))?,
        )?;
        Ok(secret)
    }
}

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

    // Two distinct valid base64url-unpadded SHA-256 hashes (43 chars each).
    // base64ct enforces the trailing-bits-zero rule, so the last char must be
    // one of A/E/I/M/Q/U/Y/c/g/k/o/s/w/0/4/8 (bottom 2 bits zero).
    const HASH_A: &str = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const HASH_B: &str = "sha256:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";

    #[test]
    fn loads_one_token() {
        let f = write_tmp(&format!(r#"{{
            "version":1,
            "tokens":[{{
                "name":"a",
                "hash":"{HASH_A}",
                "routers":["*"],
                "tools":["*"],
                "created_at":"2026-05-05T00:00:00Z"
            }}]
        }}"#));
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
        let f = write_tmp(&format!(r#"{{
            "version":1,
            "tokens":[
                {{"name":"a","hash":"{HASH_A}","routers":["*"],"tools":["*"],"created_at":"2026-05-05T00:00:00Z"}},
                {{"name":"a","hash":"{HASH_B}","routers":["*"],"tools":["*"],"created_at":"2026-05-05T00:00:00Z"}}
            ]
        }}"#));
        let err = TokenStoreFile::load(f.path(), &[]).unwrap_err();
        assert!(matches!(err, TokenStoreError::Invalid(s) if s.contains("duplicate")));
    }

    #[test]
    fn rejects_unknown_tool_name() {
        let f = write_tmp(&format!(r#"{{
            "version":1,
            "tokens":[{{
                "name":"a","hash":"{HASH_A}",
                "routers":["*"],"tools":["does_not_exist"],
                "created_at":"2026-05-05T00:00:00Z"
            }}]
        }}"#));
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
        let f = write_tmp(&format!(r#"{{
            "version":1,
            "tokens":[{{
                "name":"a","hash":"{HASH_A}",
                "routers":["*","r1"],"tools":["*"],
                "created_at":"2026-05-05T00:00:00Z"
            }}]
        }}"#));
        let err = TokenStoreFile::load(f.path(), &[]).unwrap_err();
        assert!(matches!(err, TokenStoreError::Invalid(s) if s.contains("'*'")));
    }

    #[test]
    fn warns_but_keeps_unknown_router_name() {
        // unknown_routers: known_routers passed in is &[]; the entry references
        // "r1" which is not in that list. Load should still succeed.
        let f = write_tmp(&format!(r#"{{
            "version":1,
            "tokens":[{{
                "name":"a","hash":"{HASH_A}",
                "routers":["r1"],"tools":["*"],
                "created_at":"2026-05-05T00:00:00Z"
            }}]
        }}"#));
        let store = TokenStoreFile::load(f.path(), &[]).unwrap();
        assert_eq!(store.len(), 1);
    }

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
    fn save_failure_does_not_leak_tempfile() {
        let dir = tempfile::tempdir().unwrap();
        // Pre-create `tokens.json` as a directory; rename-onto-non-empty-dir fails on Linux.
        let path = dir.path().join("tokens.json");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("dummy"), b"x").unwrap(); // make it non-empty so rename fails

        let err = TokenStoreFile::save(&path, &TokenStore::new(vec![])).unwrap_err();
        assert!(matches!(err, TokenStoreError::Io(_)), "expected Io, got {err:?}");

        let leftovers: Vec<_> = std::fs::read_dir(dir.path()).unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != "tokens.json")
            .collect();
        assert!(leftovers.is_empty(), "tempfile leaked on save failure: {leftovers:?}");
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
        // Can't use `.unwrap_err()` here because `Secret` deliberately does
        // not impl `Debug` (keeps plaintext out of panic messages / logs).
        let err = match TokenStoreFile::add(&path, "alice", ScopeSet::Wildcard, ScopeSet::Wildcard) {
            Ok(_) => panic!("expected duplicate-name rejection"),
            Err(e) => e,
        };
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

    #[test]
    fn rotate_preserves_scopes_and_changes_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        TokenStoreFile::save(&path, &TokenStore::new(vec![])).unwrap();
        let _s1 = TokenStoreFile::add(
            &path, "alice",
            ScopeSet::Allowlist(vec!["mx-01".into()]),
            ScopeSet::Allowlist(vec!["get_router_list".into()]),
        ).unwrap();
        let hash_before = TokenStoreFile::load(&path, &[]).unwrap().entries()[0].hash.as_str().to_string();

        let _s2 = TokenStoreFile::rotate(&path, "alice").unwrap();
        let store_after = TokenStoreFile::load(&path, &[]).unwrap();
        let entry = &store_after.entries()[0];
        assert_eq!(entry.name, "alice");
        assert_ne!(entry.hash.as_str(), hash_before);
        // Scopes unchanged.
        match &entry.routers { ScopeSet::Allowlist(v) => assert_eq!(v, &vec!["mx-01".to_string()]), _ => panic!() }
        match &entry.tools { ScopeSet::Allowlist(v) => assert_eq!(v, &vec!["get_router_list".to_string()]), _ => panic!() }
    }

    #[test]
    fn rotate_missing_name_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        TokenStoreFile::save(&path, &TokenStore::new(vec![])).unwrap();
        // Can't use `.unwrap_err()` because `Secret` deliberately does not impl `Debug`.
        let err = match TokenStoreFile::rotate(&path, "ghost") {
            Ok(_) => panic!("expected missing-name rejection"),
            Err(e) => e,
        };
        assert!(matches!(err, TokenStoreError::Invalid(s) if s.contains("ghost")));
    }
}
