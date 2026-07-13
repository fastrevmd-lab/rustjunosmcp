# Per-Field Audit Metadata Redaction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional, off-by-default per-field transform (keep/drop/hmac) for a closed set of sensitive audit fields, so operators can obscure device identifiers before audit lines leave the process.

**Architecture:** A new `redact` module in `rust-junosmcp-audit` holds a validated `AuditRedaction` policy (a `field → transform` map plus an optional HMAC key). The policy is parsed and validated at startup, installed in a process-global `OnceLock`, and consulted by the existing `AuditScope::Drop` emit path via a pure `render()` helper — so none of the 26 handler call sites change. Both binaries gain `--audit-redact` / `--audit-hmac-key-file` flags that fail fast on misconfiguration.

**Tech Stack:** Rust, `hmac = "0.12"` + existing `sha2 = "0.10"` (RustCrypto), `tracing`, `clap`.

## Global Constraints

- **Off by default, byte-for-byte compatible:** no config → today's audit output unchanged. (spec: Rollout / compatibility)
- **Transforms are exactly `keep` / `drop` / `hmac`.** `hmac` = `HMAC-SHA256(key, value)` emitted as `hmac:<lowercase-hex>`. No reversible encryption. (spec: Approach)
- **Closed redactable field set:** `routers`, `host`, `name`, `basename`, `command`, `pfe_command`. Any other field named in config is a **startup error**. `caller` and all structural fields are never redactable. (spec: Redactable fields)
- **`routers` is HMAC'd per-name then re-joined** (`hmac:<h1>,hmac:<h2>`); `router_count` stays cleartext and counts the original routers. (spec: Redactable fields)
- **Fail-fast at startup** on any misconfig (unknown field, unknown transform, malformed entry, hmac-without-key, unreadable key file, empty key file) — never a silent fallback. (spec: Error handling)
- **HMAC key comes from a file path only**, never a CLI arg/env value. The key bytes are never logged, serialized, or `Debug`-printed. (spec: Wiring; user rule: no secrets in args/logs)
- **Minimal deps:** add only `hmac`; no `zeroize`, no `hex` crate (hex-encode inline). (user decision)
- **`error` field is NOT field-redactable** (documented limitation). (spec: Non-goals)

---

### Task 1: `redact` module — policy core, HMAC, render helper, global

**Files:**
- Modify: `Cargo.toml` (workspace) — add `hmac = "0.12"` to `[workspace.dependencies]`
- Modify: `rust-junosmcp-audit/Cargo.toml` — add `hmac` + `sha2` deps
- Create: `rust-junosmcp-audit/src/redact.rs`
- Modify: `rust-junosmcp-audit/src/lib.rs` — declare + re-export the module
- Test: inline `#[cfg(test)] mod tests` in `redact.rs`

**Interfaces:**
- Consumes: `crate::schema::AuditValue` (existing enum with `Display`).
- Produces:
  - `pub enum FieldTransform { Keep, Drop, Hmac }` (derives `Debug, Clone, Copy, PartialEq, Eq`)
  - `pub const REDACTABLE_FIELDS: &[&str]`
  - `pub struct AuditRedaction` (derives `Clone`; **manual** `Debug` that redacts the key)
  - `pub enum RedactError` (derives `Debug`; implements `std::fmt::Display` + `std::error::Error`)
  - `pub fn AuditRedaction::parse(map: &str, key_file: Option<&std::path::Path>) -> Result<AuditRedaction, RedactError>`
  - `pub fn AuditRedaction::apply(&self, field: &'static str, value: &str) -> Option<String>`
  - `pub fn render(redaction: Option<&AuditRedaction>, routers: &[String], metadata: &[(&'static str, AuditValue)]) -> (String, String)` → `(routers_string, metadata_string)`
  - `pub fn install(r: AuditRedaction)` / `pub fn active() -> Option<&'static AuditRedaction>`

- [ ] **Step 1: Add the workspace dependency**

In `Cargo.toml` under `[workspace.dependencies]`, next to `sha2 = "0.10"`, add:

```toml
hmac             = "0.12"
```

- [ ] **Step 2: Add deps to the audit crate**

In `rust-junosmcp-audit/Cargo.toml`, under `[dependencies]` add:

```toml
hmac               = { workspace = true }
sha2               = { workspace = true }
```

- [ ] **Step 3: Write the failing tests**

Create `rust-junosmcp-audit/src/redact.rs` with ONLY the test module first (it won't compile yet — that's the failing state):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::AuditValue;
    use std::io::Write;

    fn key_file(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn parse_valid_map_builds_policy() {
        let r = AuditRedaction::parse("host=drop, command=keep", None).unwrap();
        assert_eq!(r.apply("host", "1.2.3.4"), None);
        assert_eq!(r.apply("command", "show version"), Some("show version".to_string()));
        // Unlisted field defaults to keep.
        assert_eq!(r.apply("name", "r1"), Some("r1".to_string()));
    }

    #[test]
    fn parse_unknown_field_errors() {
        let err = AuditRedaction::parse("bogus=drop", None).unwrap_err();
        assert!(matches!(err, RedactError::UnknownField(f) if f == "bogus"));
    }

    #[test]
    fn parse_unknown_transform_errors() {
        let err = AuditRedaction::parse("host=scramble", None).unwrap_err();
        assert!(matches!(err, RedactError::UnknownTransform(t) if t == "scramble"));
    }

    #[test]
    fn parse_malformed_entry_errors() {
        let err = AuditRedaction::parse("host", None).unwrap_err();
        assert!(matches!(err, RedactError::MalformedEntry(_)));
    }

    #[test]
    fn parse_hmac_without_key_errors() {
        let err = AuditRedaction::parse("host=hmac", None).unwrap_err();
        assert!(matches!(err, RedactError::HmacKeyRequired));
    }

    #[test]
    fn parse_empty_key_file_errors() {
        let f = key_file(b"");
        let err = AuditRedaction::parse("host=hmac", Some(f.path())).unwrap_err();
        assert!(matches!(err, RedactError::HmacKeyEmpty));
    }

    #[test]
    fn apply_hmac_is_prefixed_and_deterministic() {
        let f = key_file(b"super-secret-key");
        let r = AuditRedaction::parse("host=hmac", Some(f.path())).unwrap();
        let a = r.apply("host", "1.2.3.4").unwrap();
        let b = r.apply("host", "1.2.3.4").unwrap();
        assert!(a.starts_with("hmac:"), "got {a}");
        assert_eq!(a, b, "hmac must be deterministic for equal input");
        assert_ne!(a, r.apply("host", "5.6.7.8").unwrap());
    }

    #[test]
    fn apply_hmac_differs_by_key() {
        let f1 = key_file(b"key-one");
        let f2 = key_file(b"key-two");
        let r1 = AuditRedaction::parse("host=hmac", Some(f1.path())).unwrap();
        let r2 = AuditRedaction::parse("host=hmac", Some(f2.path())).unwrap();
        assert_ne!(r1.apply("host", "1.2.3.4"), r2.apply("host", "1.2.3.4"));
    }

    #[test]
    fn render_none_is_passthrough() {
        let routers = vec!["r1".to_string(), "r2".to_string()];
        let meta = vec![("host", AuditValue::from("1.2.3.4")), ("count", AuditValue::from(3u64))];
        let (r, m) = render(None, &routers, &meta);
        assert_eq!(r, "r1,r2");
        assert_eq!(m, "host=1.2.3.4 count=3");
    }

    #[test]
    fn render_routers_hmac_is_per_name() {
        let f = key_file(b"k");
        let policy = AuditRedaction::parse("routers=hmac", Some(f.path())).unwrap();
        let routers = vec!["r1".to_string(), "r2".to_string()];
        let (r, _) = render(Some(&policy), &routers, &[]);
        let parts: Vec<&str> = r.split(',').collect();
        assert_eq!(parts.len(), 2, "per-name hmac preserves comma structure: {r}");
        assert!(parts[0].starts_with("hmac:") && parts[1].starts_with("hmac:"), "got {r}");
        assert_ne!(parts[0], parts[1]);
    }

    #[test]
    fn render_drop_omits_metadata_pair() {
        let policy = AuditRedaction::parse("host=drop", None).unwrap();
        let meta = vec![("host", AuditValue::from("1.2.3.4")), ("count", AuditValue::from(3u64))];
        let (_, m) = render(Some(&policy), &[], &meta);
        assert!(!m.contains("host="), "dropped field must be absent: {m}");
        assert!(m.contains("count=3"), "non-redacted field must survive: {m}");
    }

    #[test]
    fn render_routers_drop_yields_empty() {
        let policy = AuditRedaction::parse("routers=drop", None).unwrap();
        let routers = vec!["r1".to_string(), "r2".to_string()];
        let (r, _) = render(Some(&policy), &routers, &[]);
        assert_eq!(r, "");
    }

    #[test]
    fn debug_never_prints_key_bytes() {
        let f = key_file(b"TOPSECRETKEY");
        let r = AuditRedaction::parse("host=hmac", Some(f.path())).unwrap();
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("TOPSECRET"), "Debug leaked key: {dbg}");
    }

    #[test]
    fn install_then_active_returns_policy() {
        // NOTE: OnceLock is process-global; this is the ONLY test that touches it.
        let r = AuditRedaction::parse("host=drop", None).unwrap();
        install(r);
        assert!(active().is_some());
    }
}
```

Also add `tempfile` to `[dev-dependencies]` if not present (it already is, per `rust-junosmcp-audit/Cargo.toml`).

- [ ] **Step 4: Run tests to verify they fail**

Run: `cargo test -p rust-junosmcp-audit redact 2>&1 | tail -20`
Expected: FAIL — compile errors (`AuditRedaction`, `RedactError`, `render`, etc. not found).

- [ ] **Step 5: Write the module implementation**

Prepend the implementation above the test module in `rust-junosmcp-audit/src/redact.rs`:

```rust
//! Optional, off-by-default per-field redaction of audit metadata.
//!
//! An operator maps a closed set of audit fields to a transform:
//! `keep` (cleartext, default), `drop` (omit), or `hmac` (emit
//! `hmac:<hex>` = HMAC-SHA256 of the value under an operator-held key).
//! The policy is validated at startup and installed process-globally; the
//! `AuditScope` drop path reads it via [`active`] and [`render`].

use crate::schema::AuditValue;
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

/// Fields whose values may be transformed. Any other field named in a
/// policy is rejected at parse time. `caller` and structural fields
/// (result, duration_ms, counts, *_sha256, error, reason) are absent by
/// design and always emit cleartext.
pub const REDACTABLE_FIELDS: &[&str] =
    &["routers", "host", "name", "basename", "command", "pfe_command"];

/// The transform applied to a single field's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldTransform {
    /// Emit cleartext (default for any field not in the policy).
    Keep,
    /// Omit the field/pair entirely.
    Drop,
    /// Emit `hmac:<hex>` (HMAC-SHA256 under the configured key).
    Hmac,
}

/// A validated, installed redaction policy.
#[derive(Clone)]
pub struct AuditRedaction {
    policy: HashMap<&'static str, FieldTransform>,
    /// HMAC key bytes. `Some` iff at least one field maps to `Hmac`.
    key: Option<Vec<u8>>,
}

// Manual Debug: never print the key bytes (AuditConfig derives Debug).
impl std::fmt::Debug for AuditRedaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditRedaction")
            .field("policy", &self.policy)
            .field("key", &self.key.as_ref().map(|k| format!("<{} bytes redacted>", k.len())))
            .finish()
    }
}

/// Misconfiguration surfaced at startup (never at runtime).
#[derive(Debug)]
pub enum RedactError {
    UnknownField(String),
    UnknownTransform(String),
    MalformedEntry(String),
    HmacKeyRequired,
    HmacKeyUnreadable(String),
    HmacKeyEmpty,
}

impl std::fmt::Display for RedactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedactError::UnknownField(k) => write!(
                f,
                "unknown audit-redact field '{k}'; allowed: {}",
                REDACTABLE_FIELDS.join(", ")
            ),
            RedactError::UnknownTransform(t) => {
                write!(f, "unknown audit-redact transform '{t}'; allowed: keep, drop, hmac")
            }
            RedactError::MalformedEntry(e) => {
                write!(f, "malformed audit-redact entry '{e}'; expected field=transform")
            }
            RedactError::HmacKeyRequired => write!(
                f,
                "audit-redact requests hmac but no --audit-hmac-key-file was provided"
            ),
            RedactError::HmacKeyUnreadable(e) => write!(f, "audit hmac key file unreadable: {e}"),
            RedactError::HmacKeyEmpty => write!(f, "audit hmac key file is empty"),
        }
    }
}

impl std::error::Error for RedactError {}

impl AuditRedaction {
    /// Parse a `field=transform,field=transform` map and, if any field maps
    /// to `hmac`, load the key from `key_file`. Every field must be in
    /// [`REDACTABLE_FIELDS`] and every transform must be keep/drop/hmac.
    pub fn parse(map: &str, key_file: Option<&Path>) -> Result<Self, RedactError> {
        let mut policy = HashMap::new();
        let mut needs_key = false;
        for raw in map.split(',') {
            let entry = raw.trim();
            if entry.is_empty() {
                continue;
            }
            let (k, v) = entry
                .split_once('=')
                .ok_or_else(|| RedactError::MalformedEntry(entry.to_string()))?;
            let k = k.trim();
            let field = REDACTABLE_FIELDS
                .iter()
                .copied()
                .find(|f| *f == k)
                .ok_or_else(|| RedactError::UnknownField(k.to_string()))?;
            let transform = match v.trim().to_ascii_lowercase().as_str() {
                "keep" => FieldTransform::Keep,
                "drop" => FieldTransform::Drop,
                "hmac" => {
                    needs_key = true;
                    FieldTransform::Hmac
                }
                other => return Err(RedactError::UnknownTransform(other.to_string())),
            };
            policy.insert(field, transform);
        }
        let key = if needs_key {
            let path = key_file.ok_or(RedactError::HmacKeyRequired)?;
            let bytes = std::fs::read(path)
                .map_err(|e| RedactError::HmacKeyUnreadable(e.to_string()))?;
            if bytes.is_empty() {
                return Err(RedactError::HmacKeyEmpty);
            }
            Some(bytes)
        } else {
            None
        };
        Ok(Self { policy, key })
    }

    /// Apply the configured transform for `field` to `value`. Returns `None`
    /// when the field is dropped; `Some(rendered)` for keep/hmac. A field not
    /// in the policy defaults to keep.
    pub fn apply(&self, field: &'static str, value: &str) -> Option<String> {
        match self.policy.get(field).copied().unwrap_or(FieldTransform::Keep) {
            FieldTransform::Keep => Some(value.to_string()),
            FieldTransform::Drop => None,
            FieldTransform::Hmac => {
                let key = self
                    .key
                    .as_ref()
                    .expect("key present whenever any field maps to hmac");
                Some(format!("hmac:{}", hmac_hex(key, value.as_bytes())))
            }
        }
    }
}

/// HMAC-SHA256(key, msg) as lowercase hex.
fn hmac_hex(key: &[u8], msg: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let tag = mac.finalize().into_bytes();
    let mut out = String::with_capacity(tag.len() * 2);
    for byte in tag {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Render the `routers` and `metadata` strings with `redaction` applied.
/// `None` → cleartext, identical to the pre-redaction join. `routers` is
/// transformed per-name then re-joined so multi-router lines stay
/// correlatable; dropped router names are omitted.
pub fn render(
    redaction: Option<&AuditRedaction>,
    routers: &[String],
    metadata: &[(&'static str, AuditValue)],
) -> (String, String) {
    let Some(r) = redaction else {
        let routers = routers.join(",");
        let metadata = metadata
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        return (routers, metadata);
    };
    let routers = routers
        .iter()
        .filter_map(|name| r.apply("routers", name))
        .collect::<Vec<_>>()
        .join(",");
    let metadata = metadata
        .iter()
        .filter_map(|(k, v)| r.apply(k, &v.to_string()).map(|rendered| format!("{k}={rendered}")))
        .collect::<Vec<_>>()
        .join(" ");
    (routers, metadata)
}

static REDACTION: OnceLock<AuditRedaction> = OnceLock::new();

/// Install the process-global redaction policy. Idempotent: a second call is
/// a no-op (matches `init_tracing`'s try-init semantics).
pub fn install(r: AuditRedaction) {
    let _ = REDACTION.set(r);
}

/// The installed policy, or `None` when redaction is disabled.
pub fn active() -> Option<&'static AuditRedaction> {
    REDACTION.get()
}
```

Note: `r.apply(k, ...)` in `render` passes the metadata key `k: &'static str` (metadata is `Vec<(&'static str, AuditValue)>`), satisfying `apply`'s `&'static str` parameter.

- [ ] **Step 6: Declare and re-export the module**

In `rust-junosmcp-audit/src/lib.rs`, add `mod redact;` (after `mod init;`) and extend the re-export:

```rust
mod init;
mod redact;
mod schema;
mod scope;
pub mod testutil;

pub use init::{init_tracing, AuditConfig, AuditFormat};
pub use redact::{active, render, AuditRedaction, FieldTransform, RedactError, REDACTABLE_FIELDS};
pub use schema::{AuditOutcome, AuditValue};
pub use scope::AuditScope;
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cargo test -p rust-junosmcp-audit redact 2>&1 | tail -20`
Expected: PASS — all 13 `redact` tests green.

- [ ] **Step 8: Format, lint, commit**

Run: `cargo fmt && cargo clippy -p rust-junosmcp-audit 2>&1 | tail -5`
Expected: no warnings.

```bash
git add Cargo.toml Cargo.lock rust-junosmcp-audit/Cargo.toml rust-junosmcp-audit/src/redact.rs rust-junosmcp-audit/src/lib.rs
git commit -m "feat(#156): audit redaction policy core (keep/drop/hmac)"
```

---

### Task 2: Wire policy into `AuditConfig`, `init_tracing`, and the `Drop` emit path

**Files:**
- Modify: `rust-junosmcp-audit/src/init.rs:32-38` (AuditConfig), `:79-100` (init_tracing)
- Modify: `rust-junosmcp-audit/src/scope.rs:83-107` (Drop routers/metadata construction)
- Test: existing `scope.rs` capture tests must stay green (backward-compat); add one installed-path capture test guarded by the global.

**Interfaces:**
- Consumes: `crate::redact::{AuditRedaction, install, active, render}` from Task 1.
- Produces: `AuditConfig.redaction: Option<AuditRedaction>` field consumed by both binaries in Task 3.

- [ ] **Step 1: Add the field to `AuditConfig`**

In `rust-junosmcp-audit/src/init.rs`, extend the struct (note: `AuditConfig` derives `Debug, Clone`; `AuditRedaction`'s manual `Debug` keeps the key out of any debug output):

```rust
/// Audit / logging configuration.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    pub format: AuditFormat,
    /// When set, `target="audit"` events are also appended as JSON lines here.
    pub audit_log_file: Option<PathBuf>,
    /// When set, per-field redaction is applied to emitted audit events.
    pub redaction: Option<crate::redact::AuditRedaction>,
}
```

- [ ] **Step 2: Install the policy in `init_tracing`**

In `init_tracing`, after the `let _ = tracing_subscriber::registry()...try_init();` block (end of the function, before the closing brace at `init.rs:100`), add:

```rust
    if let Some(redaction) = cfg.redaction.clone() {
        crate::redact::install(redaction);
    }
```

- [ ] **Step 3: Update the existing `init.rs` test constructor(s)**

Any `AuditConfig { ... }` literal in `init.rs` tests must add `redaction: None`. (The current `json_line_written_to_audit_file_only` test builds the layer directly and does NOT construct `AuditConfig`, so no change is needed there — but grep to confirm: `rg -n "AuditConfig \{" rust-junosmcp-audit/src`.)

- [ ] **Step 4: Run the failing capture test first**

Add this test to the `#[cfg(test)] mod tests` in `rust-junosmcp-audit/src/scope.rs` (it exercises the Drop path through the global; place it as the ONLY test that installs a redaction policy):

```rust
#[test]
fn drop_applies_installed_redaction() {
    use crate::redact::{self, AuditRedaction};
    // Install a drop policy for `host`. OnceLock is process-global, so this is
    // the only scope test that installs redaction; other tests rely on None.
    redact::install(AuditRedaction::parse("host=drop", None).unwrap());
    let out = run_with_capture(|| {
        let mut a = AuditScope::new(None, "add_device", "add-device", vec!["r1".into()]);
        a.meta("host", "10.0.0.5");
        a.meta("name", "r1");
        a.succeed();
    });
    assert!(!out.contains("10.0.0.5"), "dropped host value must be absent: {out}");
    assert!(out.contains("name=r1"), "non-dropped field must survive: {out}");
}
```

Run: `cargo test -p rust-junosmcp-audit drop_applies_installed_redaction 2>&1 | tail -20`
Expected: FAIL — `AuditConfig`/Drop not yet reading the policy (compile error on `redaction` field, or assertion fails because Drop still joins cleartext).

- [ ] **Step 5: Rewrite the routers/metadata construction in `Drop`**

In `rust-junosmcp-audit/src/scope.rs`, replace the current construction (the three lines building `routers`, `router_count`, and `metadata` at the top of `impl Drop for AuditScope`) with a `render` call:

```rust
        let duration_ms = self.started.elapsed().as_millis() as u64;
        let router_count = self.routers.len() as u64;
        let (routers, metadata) =
            crate::redact::render(crate::redact::active(), &self.routers, &self.metadata);
```

Leave the `authorization` / outcome match and the `tracing::info!` emit unchanged — `routers` and `metadata` are now the redacted strings, `router_count` still counts the original routers.

- [ ] **Step 6: Run the new test + the full audit suite**

Run: `cargo test -p rust-junosmcp-audit 2>&1 | tail -20`
Expected: PASS — the new `drop_applies_installed_redaction` test passes AND all pre-existing scope capture tests (which never install a policy) still pass, proving byte-for-byte backward compat on the `None` path.

- [ ] **Step 7: Format, lint, commit**

Run: `cargo fmt && cargo clippy -p rust-junosmcp-audit 2>&1 | tail -5`
Expected: no warnings.

```bash
git add rust-junosmcp-audit/src/init.rs rust-junosmcp-audit/src/scope.rs
git commit -m "feat(#156): apply redaction policy in AuditScope drop path"
```

---

### Task 3: CLI flags + startup wiring for both binaries (fail-fast)

**Files:**
- Modify: `rust-junosmcp/src/cli.rs:130-132` (after `audit_log_file`)
- Modify: `rust-junosmcp/src/main.rs:22-26` (AuditConfig construction)
- Modify: `rust-srxmcp/src/cli.rs:113-114` (after `audit_log_file`)
- Modify: `rust-srxmcp/src/main.rs:26-30` (AuditConfig construction)

**Interfaces:**
- Consumes: `AuditConfig.redaction` (Task 2), `rust_junosmcp_audit::AuditRedaction::parse` (Task 1).
- Produces: nothing downstream (terminal wiring).

- [ ] **Step 1: Add the junos CLI flags**

In `rust-junosmcp/src/cli.rs`, immediately after the `audit_log_file` field (line 131), add:

```rust
    /// Per-field audit redaction, e.g. `routers=hmac,host=drop`.
    /// Fields: routers, host, name, basename, command, pfe_command.
    /// Transforms: keep, drop, hmac. Empty = disabled.
    #[arg(long, env = "JMCP_AUDIT_REDACT", default_value = "")]
    pub audit_redact: String,

    /// File containing the HMAC key used by any `=hmac` redaction. Required
    /// when audit-redact requests hmac. Path only; the key is never a flag/env value.
    #[arg(long, env = "JMCP_AUDIT_HMAC_KEY_FILE")]
    pub audit_hmac_key_file: Option<std::path::PathBuf>,
```

- [ ] **Step 2: Wire junos `main.rs` with fail-fast**

In `rust-junosmcp/src/main.rs`, replace the `AuditConfig` construction (lines 22-25) with:

```rust
    let redaction = if args.audit_redact.trim().is_empty() {
        None
    } else {
        Some(
            rust_junosmcp_audit::AuditRedaction::parse(
                &args.audit_redact,
                args.audit_hmac_key_file.as_deref(),
            )
            .map_err(|e| anyhow::anyhow!("invalid --audit-redact: {e}"))?,
        )
    };
    let audit_cfg = rust_junosmcp_audit::AuditConfig {
        format: rust_junosmcp_audit::AuditFormat::parse(&args.audit_format),
        audit_log_file: args.audit_log_file.clone(),
        redaction,
    };
    rust_junosmcp_audit::init_tracing(&audit_cfg);
```

This returns a non-zero exit (via `?` on the `Result<()>` main) with a clear message before the server binds. Confirm `anyhow` is in scope in `main.rs` (it is — `use anyhow::Result` / the fn returns `Result<()>`).

- [ ] **Step 3: Add the srx CLI flags**

In `rust-srxmcp/src/cli.rs`, immediately after the `audit_log_file` field (line 114), add the same two fields but with SRX env-var names:

```rust
    /// Per-field audit redaction, e.g. `routers=hmac,host=drop`.
    /// Fields: routers, host, name, basename, command, pfe_command.
    /// Transforms: keep, drop, hmac. Empty = disabled.
    #[arg(long, env = "JMCP_SRX_AUDIT_REDACT", default_value = "")]
    pub audit_redact: String,

    /// File containing the HMAC key used by any `=hmac` redaction. Required
    /// when audit-redact requests hmac. Path only; the key is never a flag/env value.
    #[arg(long, env = "JMCP_SRX_AUDIT_HMAC_KEY_FILE")]
    pub audit_hmac_key_file: Option<std::path::PathBuf>,
```

- [ ] **Step 4: Wire srx `main.rs` with fail-fast**

In `rust-srxmcp/src/main.rs`, replace the `AuditConfig` construction (lines 26-29) with the same pattern as Step 2:

```rust
    let redaction = if args.audit_redact.trim().is_empty() {
        None
    } else {
        Some(
            rust_junosmcp_audit::AuditRedaction::parse(
                &args.audit_redact,
                args.audit_hmac_key_file.as_deref(),
            )
            .map_err(|e| anyhow::anyhow!("invalid --audit-redact: {e}"))?,
        )
    };
    let audit_cfg = rust_junosmcp_audit::AuditConfig {
        format: rust_junosmcp_audit::AuditFormat::parse(&args.audit_format),
        audit_log_file: args.audit_log_file.clone(),
        redaction,
    };
    rust_junosmcp_audit::init_tracing(&audit_cfg);
```

If srx `main.rs` does not already return `anyhow::Result<()>`, confirm it does (`rg -n "fn main" rust-srxmcp/src/main.rs`); it uses the same `?`-on-Result pattern as junos.

- [ ] **Step 5: Build the whole workspace**

Run: `cargo build --workspace 2>&1 | tail -10`
Expected: Finished, no errors. (Both `AuditConfig` literals now compile with the new field.)

- [ ] **Step 6: Manual fail-fast smoke check**

Run: `cargo run -p rust-junosmcp -- --audit-redact 'bogus=drop' --transport stdio 2>&1 | head -5`
Expected: exits non-zero with `invalid --audit-redact: unknown audit-redact field 'bogus'; allowed: routers, host, name, basename, command, pfe_command`.

Run: `cargo run -p rust-junosmcp -- --audit-redact 'host=hmac' --transport stdio 2>&1 | head -5`
Expected: exits non-zero with `invalid --audit-redact: audit-redact requests hmac but no --audit-hmac-key-file was provided`.

- [ ] **Step 7: Format, lint, commit**

Run: `cargo fmt && cargo clippy --workspace 2>&1 | tail -5`
Expected: no warnings.

```bash
git add rust-junosmcp/src/cli.rs rust-junosmcp/src/main.rs rust-srxmcp/src/cli.rs rust-srxmcp/src/main.rs
git commit -m "feat(#156): --audit-redact / --audit-hmac-key-file flags for both binaries"
```

---

### Task 4: Documentation

**Files:**
- Modify: `docs/AUDIT.md` — add a "Field redaction" subsection under the audit-config docs; update the deferred per-field-encryption item.

**Interfaces:** none (docs only).

- [ ] **Step 1: Add the "Field redaction" subsection**

In `docs/AUDIT.md`, after the "File sink" / "Rotation & retention" material and before "SIEM / forwarding", add:

````markdown
### Field redaction

By default every audit field is emitted in cleartext. For deployments that treat device identifiers as sensitive, an optional per-field transform can `keep`, `drop`, or `hmac` a **closed set** of fields. Redaction is **off by default** — with no configuration the output is byte-for-byte unchanged.

| Flag | Env (junos / srx) | Meaning |
|------|-------------------|---------|
| `--audit-redact` | `JMCP_AUDIT_REDACT` / `JMCP_SRX_AUDIT_REDACT` | Comma-separated `field=transform` map. Empty = disabled. |
| `--audit-hmac-key-file` | `JMCP_AUDIT_HMAC_KEY_FILE` / `JMCP_SRX_AUDIT_HMAC_KEY_FILE` | Path to a file holding the HMAC key. Required if any field uses `hmac`. The key value is never a flag or env value. |

**Transforms:** `keep` (cleartext), `drop` (omit the field), `hmac` (emit `hmac:<hex>` = HMAC-SHA256 of the value under the key file's bytes). HMAC is deterministic, so a SIEM can still group events by a redacted identifier without learning it; it is keyed, so low-entropy values (IPs/hostnames) are not brute-force-reversible.

**Redactable fields (only these; anything else is a startup error):** `routers`, `host`, `name`, `basename`, `command`, `pfe_command`. The `routers` field is transformed per router name and re-joined (`hmac:<h1>,hmac:<h2>`); `router_count` stays cleartext. `caller` and all structural fields (`result`, `duration_ms`, `error`, etc.) are never redactable.

**Example** — HMAC the router names on every line and drop the device IP recorded by `add_device`:

```
rust-junosmcp \
  --audit-redact 'routers=hmac,host=drop' \
  --audit-hmac-key-file /etc/jmcp/audit-hmac.key \
  ...
```

**Startup validation:** an unknown field, an unknown transform, a malformed entry, `hmac` without a key file, or an unreadable/empty key file all abort startup with a clear message — redaction never silently downgrades.

**Limitation:** the free-text `error` field is bounded and secret-free by construction but may legitimately contain an identifier (e.g. `router 'r1' not found`). It is **not** field-redactable.
````

- [ ] **Step 2: Update the deferred item**

In the "Deferred Items" list, replace the per-field-encryption entry (item 3) with:

```markdown
3. **Per-field encryption** — sensitive metadata fields can be dropped or replaced with a keyed HMAC fingerprint via [Field redaction](#field-redaction). *Reversible* envelope encryption (recover the original from logs with a key) remains out of scope.
```

- [ ] **Step 3: Commit**

```bash
git add docs/AUDIT.md
git commit -m "docs(#156): document audit field redaction"
```

---

## Self-Review

**Spec coverage:**
- Transforms keep/drop/hmac + `hmac:<hex>` → Task 1 (apply/hmac_hex), Task 4 docs. ✅
- Closed redactable set + unknown-field startup error → Task 1 (parse/REDACTABLE_FIELDS), Task 3 (fail-fast), Task 4 docs. ✅
- `routers` per-name HMAC, `router_count` cleartext → Task 1 (render), Task 2 (Drop). ✅
- Fail-fast on all misconfig → Task 1 (RedactError), Task 3 (main.rs `?`). ✅
- Key from file only, never logged/Debug'd → Task 1 (manual Debug + test `debug_never_prints_key_bytes`), Task 3 (key-file path arg). ✅
- Global installed at init, no handler churn → Task 1 (install/active), Task 2 (init_tracing + render in Drop). ✅
- CLI/env map for both binaries → Task 3. ✅
- Off-by-default byte-compat → Task 2 Step 6 (existing capture tests green on None path). ✅
- Non-goals (no encryption, error not redactable, no tiers) → Task 4 docs. ✅
- Minimal deps (hmac only, no zeroize/hex) → Task 1 Steps 1-2, hmac_hex inline. ✅

**Placeholder scan:** No TBD/TODO; every code step shows complete code; every command shows expected output. ✅

**Type consistency:** `AuditRedaction`, `FieldTransform`, `RedactError`, `render(Option<&AuditRedaction>, &[String], &[(&'static str, AuditValue)]) -> (String, String)`, `apply(&self, &'static str, &str) -> Option<String>`, `install`/`active`, `AuditConfig.redaction: Option<AuditRedaction>` are used identically across Tasks 1-3. ✅
