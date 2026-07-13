# Design: Optional per-field redaction of sensitive audit metadata (#156)

- **Issue:** #156 — Optional per-field encryption for sensitive audit metadata
- **Date:** 2026-07-13
- **Status:** Approved (design), pending implementation plan
- **Follow-up from:** #132 (caller-attributed audit coverage, shipped in #152)

## Problem

The audit sink (#132/#152) redacts secrets *by construction*: it never logs
config bodies, rendered templates, command output, or credentials, and attaches
only allowlisted metadata. Some environments still treat **device identifiers**
(router names, IPs, hostnames) as sensitive and want them removed or obscured
before audit lines leave the process. Today every field is emitted in cleartext.

We add an **optional, off-by-default** per-field transform so operators can
`keep`, `drop`, or `hmac` a defined allowlist of audit fields.

## Non-goals

- **Reversible encryption.** No envelope encryption, key rotation, or nonce
  management. HMAC is one-way; SIEM correlation is preserved without
  recoverability. (The issue title says "encryption"; the accepted scope is
  drop/hash/keep with a keyed hash.)
- **Redacting identifiers inside the free-text `error` field.** `error` is
  bounded (≤512 chars) and secret-free by construction, but an error message may
  legitimately contain a router name or IP (e.g. `router 'r1' not found`). It is
  **not** field-redactable. Documented as a known limitation.
- **Per-tier / per-role / per-caller policies.** The policy is process-wide.
  (The rust-panosmcp "3-tier" model is a token-scope pattern, not a redaction
  mechanism; we reuse only its `sha256:<hex>`-style fingerprint convention,
  adapted to `hmac:<hex>`.)
- Transforming `caller` — attribution is the entire point of the audit trail.

## Approach

`FieldTransform ∈ { Keep, Drop, Hmac }`:

- **Keep** — emit cleartext (default for every field; no config → today's output
  byte-for-byte).
- **Drop** — omit the field/pair entirely from the emitted event.
- **Hmac** — emit `hmac:<hex>` where `<hex>` is lowercase hex of
  `HMAC-SHA256(key, value_bytes)`. Deterministic, so a SIEM can still group
  "all events for router X" without learning X; not brute-forceable for
  low-entropy inputs (IPs/hostnames) the way a plain unkeyed SHA-256 would be.

### Why keyed HMAC, not plain SHA-256

The protected fields are low-entropy (RFC1918 IPs, short hostnames). A plain
SHA-256 fingerprint of an IP is trivially reversible by hashing the whole
address space and matching. HMAC with an operator-held key defeats that while
staying deterministic for correlation. rust-panosmcp uses plain SHA-256 for
XPaths (higher entropy, non-secret); we deliberately diverge for identifiers.

### Redactable fields (closed set)

Only these keys may be named in the policy. Any other key → **startup error**
(prevents typos silently no-oping, and prevents transforming structural fields):

| Field | Location | Notes |
|-------|----------|-------|
| `routers` | top-level | Comma-joined router names; present on **every** line. HMAC is applied **per-name, then re-joined** (`hmac:<h1>,hmac:<h2>`) so per-router correlation survives. `Drop` replaces the whole field with empty. |
| `host` | metadata (`add_device`) | Device IP/hostname. |
| `name` | metadata (`add_device`) | Device name. |
| `basename` | metadata (`fetch_file`, `transfer_file`, `upgrade_junos`) | Filename. |
| `command` | metadata (`execute_junos_command`, `execute_junos_pfe_command`) | Operational command text. |
| `pfe_command` | metadata (`execute_junos_pfe_command`) | PFE command text. |

Never transformable: `caller`, `correlation_id`, `tool`, `router_count`,
`action`, `authorization`, `result`, `duration_ms`, `error_kind`, `error`,
`reason`, and all count/boolean/`*_sha256` metadata (already non-sensitive or
already hashed).

## Components

### New module: `rust-junosmcp-audit/src/redact.rs`

```rust
/// Per-field transform selected by the operator.
pub enum FieldTransform { Keep, Drop, Hmac }

/// The closed set of audit fields that may be redacted.
pub const REDACTABLE_FIELDS: &[&str] =
    &["routers", "host", "name", "basename", "command", "pfe_command"];

/// Installed, validated redaction policy.
pub struct AuditRedaction {
    policy: HashMap<&'static str, FieldTransform>, // keys ⊆ REDACTABLE_FIELDS
    key: Option<Vec<u8>>,                          // HMAC key bytes; Some iff any Hmac
}

pub enum RedactError {
    UnknownField(String),          // key ∉ REDACTABLE_FIELDS
    UnknownTransform(String),      // value ∉ {keep,drop,hmac}
    MalformedEntry(String),        // not `k=v`
    HmacKeyRequired,               // a field set to hmac but no --audit-hmac-key-file
    HmacKeyUnreadable(String),     // key file missing/unreadable
    HmacKeyEmpty,                  // key file present but empty
}

impl AuditRedaction {
    /// Parse a `k=v,k=v` map and (if any hmac) load the key file. Validates
    /// every field against REDACTABLE_FIELDS and every transform value.
    pub fn parse(map: &str, key_file: Option<&Path>) -> Result<Self, RedactError>;

    /// Apply the configured transform for `field` to `value`.
    /// Returns `None` when the field is dropped; `Some(rendered)` otherwise.
    /// A field not in the policy defaults to Keep (returns `Some(value)`).
    pub fn apply(&self, field: &'static str, value: &str) -> Option<String>;
}

// Process-global, installed once at startup, read in AuditScope::Drop.
pub fn install(r: AuditRedaction);         // OnceLock::set; second call is a no-op
pub fn active() -> Option<&'static AuditRedaction>;
```

Notes:
- Empty/absent `map` → `parse` returns an `AuditRedaction` with an empty policy
  (everything Keep) and no key. `install` of that is a no-op-equivalent (all
  fields Keep) — output identical to today.
- `map` grammar: comma-separated `field=transform`, whitespace trimmed,
  case-insensitive transform values. Duplicate keys: last wins.
- `apply` for `Hmac` uses `hmac::Hmac<sha2::Sha256>`; `key` is guaranteed
  `Some` whenever any policy entry is `Hmac` (enforced in `parse`).

### Wiring

- `AuditConfig` (`init.rs`) gains `pub redaction: Option<AuditRedaction>`.
- `init_tracing(cfg)` calls `redact::install(r)` when `cfg.redaction` is `Some`.
  Installation happens alongside subscriber init, once, at process start.
- `AuditScope::Drop` (`scope.rs`): before the `tracing::info!` emit, consult
  `redact::active()`:
  - `routers`: if policy has an entry, split the `Vec<String>` names, run each
    through `apply("routers", name)`, collect the `Some` values, re-join with
    `,`. (Per-name, so multi-router lines stay correlatable.) A `Drop` policy
    yields an empty `routers` string.
  - metadata: when building the joined `metadata` string, for each `(key, val)`
    pair whose `key ∈ REDACTABLE_FIELDS`, run `apply(key, &val.to_string())`;
    `None` omits the pair, `Some(v)` substitutes `key=v`. Non-redactable keys
    pass through unchanged.
  - When `active()` is `None`, the Drop path is unchanged (zero overhead beyond
    a single `OnceLock` load).
- CLI (`rust-junosmcp/src/cli.rs`, `rust-srxmcp/src/cli.rs`):
  - `--audit-redact` — `env JMCP_AUDIT_REDACT` (junos) / `JMCP_SRX_AUDIT_REDACT`
    (srx); default empty (disabled).
  - `--audit-hmac-key-file` — `env JMCP_AUDIT_HMAC_KEY_FILE` /
    `JMCP_SRX_AUDIT_HMAC_KEY_FILE`; a **path** only. The key value is never a
    CLI arg or env value (no-secrets-in-args/logs rule).
- `main.rs` (both binaries): call `AuditRedaction::parse(&args.audit_redact,
  args.audit_hmac_key_file.as_deref())`; on `Err`, print a clear message and
  exit non-zero **before** serving. On `Ok`, store `Some(r)` in `AuditConfig`
  (or `None` when the map is empty).

### Dependencies

- Add `hmac = "0.12"` to the workspace and to `rust-junosmcp-audit`.
- Reuse existing workspace `sha2 = "0.10"`.
- No `zeroize` (deps kept minimal). The key lives in a `Vec<u8>` for process
  lifetime and is never logged or serialized.

## Error handling

- All misconfiguration is a **startup** error via `RedactError`, surfaced in
  `main.rs` before the server binds — never a silent fallback. Specifically:
  unknown field, unknown transform, malformed entry, hmac requested without a
  key file, unreadable key file, empty key file.
- Runtime (`Drop`) never fails: `active()` is read-only; HMAC over in-memory
  bytes is infallible.

## Testing

Unit (`redact.rs`):
- `parse` valid map → correct policy; unknown field → `UnknownField`; unknown
  transform → `UnknownTransform`; `host=hmac` without key file →
  `HmacKeyRequired`; empty key file → `HmacKeyEmpty`.
- `apply`: `Keep` returns input; `Drop` returns `None`; `Hmac` returns
  `hmac:<hex>`, is deterministic for equal input, and differs for different
  keys.
- `routers` per-name rejoin: `["r1","r2"]` with `routers=hmac` →
  `hmac:<h1>,hmac:<h2>`; with `routers=drop` → empty.

Integration (capture harness, `scope.rs` tests via `run_with_capture`):
- Default (no install) → emitted line identical to pre-change (a golden field
  set).
- `host=drop` → the `host=` pair is absent from `metadata`.
- `routers=hmac` → `routers` value is `hmac:`-prefixed and `router_count`
  unchanged.

## Documentation

`docs/AUDIT.md`: new "Field redaction" subsection — the transform vocabulary,
the closed redactable-field set, the `--audit-redact` / `--audit-hmac-key-file`
flags (+ env vars), the `hmac:<hex>` format, key-file handling, and the
`error`-field limitation. Update the "Deferred Items" per-field-encryption entry
to point at the shipped redaction and note reversible encryption remains out of
scope.

## Rollout / compatibility

Fully backward compatible: absent config = today's behavior, byte-for-byte. No
schema version bump. SIEM parsers that key on field *names* are unaffected;
those that parse `routers`/`host` *values* must tolerate `hmac:<hex>` or a
dropped field once an operator opts in (documented).
