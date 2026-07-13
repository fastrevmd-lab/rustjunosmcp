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
pub const REDACTABLE_FIELDS: &[&str] = &[
    "routers",
    "host",
    "name",
    "basename",
    "command",
    "pfe_command",
];

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
            .field(
                "key",
                &self
                    .key
                    .as_ref()
                    .map(|k| format!("<{} bytes redacted>", k.len())),
            )
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
                write!(
                    f,
                    "unknown audit-redact transform '{t}'; allowed: keep, drop, hmac"
                )
            }
            RedactError::MalformedEntry(e) => {
                write!(
                    f,
                    "malformed audit-redact entry '{e}'; expected field=transform"
                )
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
            let bytes =
                std::fs::read(path).map_err(|e| RedactError::HmacKeyUnreadable(e.to_string()))?;
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
        match self
            .policy
            .get(field)
            .copied()
            .unwrap_or(FieldTransform::Keep)
        {
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
        .filter_map(|(k, v)| {
            r.apply(k, &v.to_string())
                .map(|rendered| format!("{k}={rendered}"))
        })
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
        assert_eq!(
            r.apply("command", "show version"),
            Some("show version".to_string())
        );
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
        let meta = vec![
            ("host", AuditValue::from("1.2.3.4")),
            ("count", AuditValue::from(3u64)),
        ];
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
        assert_eq!(
            parts.len(),
            2,
            "per-name hmac preserves comma structure: {r}"
        );
        assert!(
            parts[0].starts_with("hmac:") && parts[1].starts_with("hmac:"),
            "got {r}"
        );
        assert_ne!(parts[0], parts[1]);
    }

    #[test]
    fn render_drop_omits_metadata_pair() {
        let policy = AuditRedaction::parse("host=drop", None).unwrap();
        let meta = vec![
            ("host", AuditValue::from("1.2.3.4")),
            ("count", AuditValue::from(3u64)),
        ];
        let (_, m) = render(Some(&policy), &[], &meta);
        assert!(!m.contains("host="), "dropped field must be absent: {m}");
        assert!(
            m.contains("count=3"),
            "non-redacted field must survive: {m}"
        );
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
