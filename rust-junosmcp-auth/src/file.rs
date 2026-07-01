//! On-disk token store: load, validate, atomic save.

use crate::store::{ScopeSet, TokenEntry, TokenStore};
use std::path::Path;

/// All known tool names, kept alphabetized. Must stay in sync with
/// `rust_junosmcp::server::SERVER_TOOLS`; the
/// `known_tools_matches_server_tools` integration test enforces this.
pub const KNOWN_TOOLS: &[&str] = &[
    "add_device",
    "commit_check_config",
    "execute_junos_command",
    "execute_junos_command_batch",
    "execute_junos_pfe_command",
    "fetch_file",
    "gather_device_facts",
    "get_junos_config",
    "get_router_list",
    "junos_config_diff",
    "list_staged_files",
    "load_and_commit_config",
    "reload_devices",
    "render_and_apply_j2_template",
    "transfer_file",
    "upgrade_junos",
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
        let bytes = std::fs::read(path).map_err(|e| friendly_read_error(path, e))?;
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

        TokenStore::try_new(parsed.tokens)
            .map_err(|e| TokenStoreError::Invalid(format!("duplicate: {}", e.0)))
    }

    /// Atomically write the store to `path` (tempfile-in-same-dir → write →
    /// fsync → rename). The rename is atomic on the same filesystem, so
    /// readers never see a half-written file.
    pub fn save(path: &Path, store: &TokenStore) -> Result<(), TokenStoreError> {
        use std::io::Write;
        let parent = path.parent().ok_or_else(|| {
            TokenStoreError::Invalid(format!("path has no parent: {}", path.display()))
        })?;
        let on_disk = OnDisk {
            version: 1,
            tokens: store.entries().to_vec(),
        };
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

        // Preserve the existing file's ownership and permission bits across the
        // atomic replace. Without this, minting/rotating a token as root (while
        // the server runs as a dedicated user such as `User=jmcp`) rewrites
        // tokens.json as root:root 0600, and the next reload fails with EACCES.
        // This is the write-side companion to the friendly read error (#22).
        #[cfg(unix)]
        preserve_owner_and_mode(path, tmp.path());

        tmp.persist(path)
            .map_err(|e| TokenStoreError::Io(e.error))?;
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
                        "unknown tool '{}': known tools are {:?}",
                        t, KNOWN_TOOLS
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
            return Err(TokenStoreError::Invalid(format!(
                "token '{name}' already exists"
            )));
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
        Self::save(
            path,
            &TokenStore::try_new(entries).map_err(|e| TokenStoreError::Invalid(e.0))?,
        )?;
        Ok(secret)
    }

    /// Remove the named entry. Returns `true` if a token was removed,
    /// `false` if no entry by that name existed (idempotent).
    pub fn revoke(path: &Path, name: &str) -> Result<bool, TokenStoreError> {
        let store = Self::load(path, &[])?;
        let before = store.len();
        let entries: Vec<_> = store
            .entries()
            .iter()
            .filter(|e| e.name != name)
            .cloned()
            .collect();
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

/// Wrap `std::fs::read` errors with operator-actionable hints. The headline
/// case (issue #22): an admin minted `tokens.json` as `root` while the
/// systemd unit runs as `User=jmcp`, the service then crash-loops with a
/// bare `Permission denied (os error 13)` that doesn't point at ownership.
///
/// When we get `EACCES` on Unix, surface the file's owner uid + mode and
/// the running process's uid, plus a hint to either `sudo -u <user>` the
/// token subcommands or `chown` the file. All other errors flow through
/// unchanged.
fn friendly_read_error(path: &Path, err: std::io::Error) -> TokenStoreError {
    if err.kind() != std::io::ErrorKind::PermissionDenied {
        return TokenStoreError::Io(err);
    }
    eacces_to_friendly(path, err)
}

#[cfg(unix)]
fn eacces_to_friendly(path: &Path, _err: std::io::Error) -> TokenStoreError {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: `getuid()` has no preconditions and is async-signal-safe.
    let caller_uid = unsafe { libc::getuid() };
    let owner_info = match std::fs::metadata(path) {
        Ok(md) => format!("owner uid {}, mode {:o}", md.uid(), md.mode() & 0o777),
        // Metadata can fail (e.g. EACCES on the parent dir); fall back
        // to caller info alone so the hint stays useful.
        Err(_) => "owner unknown".to_string(),
    };
    TokenStoreError::Invalid(format!(
        "cannot read {}: permission denied ({owner_info}; running as uid {caller_uid}). \
         Hint: if a systemd unit runs the server as a dedicated user (e.g. `User=jmcp`), \
         token subcommands minted the file with the wrong ownership. Either \
         `sudo -u <service-user> rust-junosmcp token ...` next time, or fix the \
         current file: `chown <service-user>:<service-group> {}`",
        path.display(),
        path.display()
    ))
}

#[cfg(not(unix))]
fn eacces_to_friendly(_path: &Path, err: std::io::Error) -> TokenStoreError {
    TokenStoreError::Io(err)
}

/// Copy the ownership (uid/gid) and permission bits from the existing
/// `tokens.json` onto the freshly-written tempfile, so the atomic rename that
/// replaces it does not silently change who can read the store.
///
/// Best-effort by design: a brand-new store (no existing file) has nothing to
/// preserve, and a caller lacking the privilege to `chown` (the rare non-root,
/// non-owner case) gets a `WARN` rather than a hard failure — the token has
/// already been minted, so aborting the save would be worse than an ownership
/// drift the operator can correct with `chown`.
#[cfg(unix)]
fn preserve_owner_and_mode(target: &Path, tmp: &Path) {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    // No existing file → first-time creation; nothing to preserve.
    let Ok(md) = std::fs::metadata(target) else {
        return;
    };

    if let Err(e) =
        std::fs::set_permissions(tmp, std::fs::Permissions::from_mode(md.mode() & 0o7777))
    {
        tracing::warn!(error = %e, path = %tmp.display(),
            "could not preserve tokens.json permission bits across save");
    }

    if let Err(e) = std::os::unix::fs::chown(tmp, Some(md.uid()), Some(md.gid())) {
        tracing::warn!(error = %e, uid = md.uid(), gid = md.gid(),
            "could not preserve tokens.json ownership across save — if the \
             server runs as a dedicated user you may need to `chown` the file \
             manually so the next reload can read it");
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
        let f = write_tmp(&format!(
            r#"{{
            "version":1,
            "tokens":[{{
                "name":"a",
                "hash":"{HASH_A}",
                "routers":["*"],
                "tools":["*"],
                "created_at":"2026-05-05T00:00:00Z"
            }}]
        }}"#
        ));
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
        let f = write_tmp(&format!(
            r#"{{
            "version":1,
            "tokens":[
                {{"name":"a","hash":"{HASH_A}","routers":["*"],"tools":["*"],"created_at":"2026-05-05T00:00:00Z"}},
                {{"name":"a","hash":"{HASH_B}","routers":["*"],"tools":["*"],"created_at":"2026-05-05T00:00:00Z"}}
            ]
        }}"#
        ));
        let err = TokenStoreFile::load(f.path(), &[]).unwrap_err();
        assert!(matches!(err, TokenStoreError::Invalid(s) if s.contains("duplicate")));
    }

    #[test]
    fn rejects_unknown_tool_name() {
        let f = write_tmp(&format!(
            r#"{{
            "version":1,
            "tokens":[{{
                "name":"a","hash":"{HASH_A}",
                "routers":["*"],"tools":["does_not_exist"],
                "created_at":"2026-05-05T00:00:00Z"
            }}]
        }}"#
        ));
        let err = TokenStoreFile::load(f.path(), &[]).unwrap_err();
        assert!(matches!(err, TokenStoreError::Invalid(s) if s.contains("does_not_exist")));
    }

    #[test]
    fn rejects_malformed_hash() {
        let f = write_tmp(
            r#"{
            "version":1,
            "tokens":[{
                "name":"a","hash":"plaintext-bad",
                "routers":["*"],"tools":["*"],
                "created_at":"2026-05-05T00:00:00Z"
            }]
        }"#,
        );
        let err = TokenStoreFile::load(f.path(), &[]).unwrap_err();
        // Serde returns a Json error here because TokenHash deserialization fails.
        assert!(matches!(err, TokenStoreError::Json(_)));
    }

    #[test]
    fn rejects_wildcard_mixed_into_allowlist() {
        // "*" inside an allowlist is ambiguous (would never act as wildcard
        // since ScopeSet::From<Vec<String>> only treats single-element ["*"]
        // as Wildcard). Make this fatal at load to keep one canonical spelling.
        let f = write_tmp(&format!(
            r#"{{
            "version":1,
            "tokens":[{{
                "name":"a","hash":"{HASH_A}",
                "routers":["*","r1"],"tools":["*"],
                "created_at":"2026-05-05T00:00:00Z"
            }}]
        }}"#
        ));
        let err = TokenStoreFile::load(f.path(), &[]).unwrap_err();
        assert!(matches!(err, TokenStoreError::Invalid(s) if s.contains("'*'")));
    }

    #[test]
    fn warns_but_keeps_unknown_router_name() {
        // unknown_routers: known_routers passed in is &[]; the entry references
        // "r1" which is not in that list. Load should still succeed.
        let f = write_tmp(&format!(
            r#"{{
            "version":1,
            "tokens":[{{
                "name":"a","hash":"{HASH_A}",
                "routers":["r1"],"tools":["*"],
                "created_at":"2026-05-05T00:00:00Z"
            }}]
        }}"#
        ));
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
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
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
        assert!(
            matches!(err, TokenStoreError::Io(_)),
            "expected Io, got {err:?}"
        );

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != "tokens.json")
            .collect();
        assert!(
            leftovers.is_empty(),
            "tempfile leaked on save failure: {leftovers:?}"
        );
    }

    /// Write-side companion to the EACCES read fix (#22): a `save()` that
    /// replaces an existing store must preserve its permission bits, so minting
    /// or rotating a token does not silently reset tokens.json to the tempfile
    /// default (0600) and lock out a server running as a dedicated user.
    #[cfg(unix)]
    #[test]
    fn save_preserves_existing_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        TokenStoreFile::save(&path, &TokenStore::new(vec![])).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        // A subsequent save (here via `add`) must keep mode 0640.
        TokenStoreFile::add(&path, "alice", ScopeSet::Wildcard, ScopeSet::Wildcard).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "save() must preserve the prior file mode");
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
        )
        .unwrap();
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
        let err = match TokenStoreFile::add(&path, "alice", ScopeSet::Wildcard, ScopeSet::Wildcard)
        {
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
            &path,
            "alice",
            ScopeSet::Allowlist(vec!["mx-01".into()]),
            ScopeSet::Allowlist(vec!["get_router_list".into()]),
        )
        .unwrap();
        let hash_before = TokenStoreFile::load(&path, &[]).unwrap().entries()[0]
            .hash
            .as_str()
            .to_string();

        let _s2 = TokenStoreFile::rotate(&path, "alice").unwrap();
        let store_after = TokenStoreFile::load(&path, &[]).unwrap();
        let entry = &store_after.entries()[0];
        assert_eq!(entry.name, "alice");
        assert_ne!(entry.hash.as_str(), hash_before);
        // Scopes unchanged.
        match &entry.routers {
            ScopeSet::Allowlist(v) => assert_eq!(v, &vec!["mx-01".to_string()]),
            _ => panic!(),
        }
        match &entry.tools {
            ScopeSet::Allowlist(v) => assert_eq!(v, &vec!["get_router_list".to_string()]),
            _ => panic!(),
        }
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

    #[test]
    fn known_tools_includes_pfe_and_batch() {
        assert!(KNOWN_TOOLS.contains(&"execute_junos_pfe_command"));
        assert!(KNOWN_TOOLS.contains(&"execute_junos_command_batch"));
    }

    /// Issue #22: when `tokens.json` is unreadable by the running process,
    /// surface the file's mode and the caller's uid so the operator can fix
    /// ownership without trawling logs. Unix-only because the friendly path
    /// is `cfg(unix)`; the test would not be meaningful otherwise.
    ///
    /// Skipped when the test process is running as root, since root reads
    /// regardless of mode bits and we'd never hit the `EACCES` path that the
    /// test is exercising.
    #[cfg(unix)]
    #[test]
    fn eacces_surfaces_friendly_message_with_uid_and_mode() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: `getuid()` has no preconditions.
        let caller_uid = unsafe { libc::getuid() };
        if caller_uid == 0 {
            eprintln!("skipping: running as root, can't reproduce EACCES on owned file");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        std::fs::write(&path, r#"{"version":1,"tokens":[]}"#).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let err = TokenStoreFile::load(&path, &[]).unwrap_err();
        // Restore so tempdir cleanup can proceed even if assertions panic.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));

        let msg = match err {
            TokenStoreError::Invalid(s) => s,
            other => panic!("expected Invalid with friendly hint, got {other:?}"),
        };
        assert!(
            msg.contains("permission denied"),
            "missing core phrase: {msg}"
        );
        assert!(
            msg.contains(&format!("uid {caller_uid}")),
            "missing caller uid {caller_uid}: {msg}"
        );
        assert!(msg.contains("mode 0"), "missing file mode: {msg}");
        assert!(
            msg.contains("chown"),
            "missing actionable chown hint: {msg}"
        );
    }

    #[test]
    fn add_accepts_new_tool_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        TokenStoreFile::save(&path, &TokenStore::new(vec![])).unwrap();
        let _ = TokenStoreFile::add(
            &path,
            "ops",
            ScopeSet::Wildcard,
            ScopeSet::Allowlist(vec![
                "execute_junos_pfe_command".into(),
                "execute_junos_command_batch".into(),
            ]),
        )
        .unwrap();
        let store = TokenStoreFile::load(&path, &[]).unwrap();
        assert_eq!(store.len(), 1);
    }

    /// RJMCP-SEC-001: prior to v0.5.2 `KNOWN_TOOLS` was stale and operators
    /// could not mint non-wildcard tokens for the three newest sensitive tools.
    /// Lock these in so the regression cannot recur.
    #[test]
    fn known_tools_includes_transfer_list_staged_and_upgrade() {
        assert!(KNOWN_TOOLS.contains(&"transfer_file"));
        assert!(KNOWN_TOOLS.contains(&"list_staged_files"));
        assert!(KNOWN_TOOLS.contains(&"upgrade_junos"));
    }

    #[test]
    fn known_tools_is_alphabetized() {
        let mut sorted = KNOWN_TOOLS.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            KNOWN_TOOLS,
            sorted.as_slice(),
            "KNOWN_TOOLS must stay alphabetized for easy diff/audit"
        );
    }

    #[test]
    fn load_accepts_scoped_transfer_file_token() {
        let f = write_tmp(&format!(
            r#"{{
            "version":1,
            "tokens":[{{
                "name":"transfer-only","hash":"{HASH_A}",
                "routers":["*"],"tools":["transfer_file"],
                "created_at":"2026-05-18T00:00:00Z"
            }}]
        }}"#
        ));
        let store = TokenStoreFile::load(f.path(), &[]).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn load_accepts_scoped_list_staged_files_token() {
        let f = write_tmp(&format!(
            r#"{{
            "version":1,
            "tokens":[{{
                "name":"list-only","hash":"{HASH_A}",
                "routers":["*"],"tools":["list_staged_files"],
                "created_at":"2026-05-18T00:00:00Z"
            }}]
        }}"#
        ));
        let store = TokenStoreFile::load(f.path(), &[]).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn load_accepts_scoped_upgrade_junos_token() {
        let f = write_tmp(&format!(
            r#"{{
            "version":1,
            "tokens":[{{
                "name":"upgrade-only","hash":"{HASH_A}",
                "routers":["*"],"tools":["upgrade_junos"],
                "created_at":"2026-05-18T00:00:00Z"
            }}]
        }}"#
        ));
        let store = TokenStoreFile::load(f.path(), &[]).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn add_accepts_transfer_list_staged_and_upgrade() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        TokenStoreFile::save(&path, &TokenStore::new(vec![])).unwrap();
        let _ = TokenStoreFile::add(
            &path,
            "fleet-ops",
            ScopeSet::Wildcard,
            ScopeSet::Allowlist(vec![
                "transfer_file".into(),
                "list_staged_files".into(),
                "upgrade_junos".into(),
            ]),
        )
        .unwrap();
        let store = TokenStoreFile::load(&path, &[]).unwrap();
        assert_eq!(store.len(), 1);
    }
}
