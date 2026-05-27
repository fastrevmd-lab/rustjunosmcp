//! Redaction rules applied when `redact=true` (default) on
//! `collect_jtac_support_bundle`. Strips known-sensitive elements from
//! captured `get-configuration` and per-RPC XML payloads before they're
//! written into the on-device tarball.
//!
//! Locked rule list (Phase 3 design doc § "Redact rules"):
//! * `pre-shared-key` — IKE PSKs (`security ike policy ... pre-shared-key`)
//! * `secret` / `simple-password` / `encrypted-password` — local-user,
//!   RADIUS, TACACS, snmp-v3, IPsec-mfg secrets
//! * `community` under `snmp` — SNMP v1/v2c community strings
//! * `radius-server` `secret` — RADIUS shared-secret
//! * `tacplus-server` `secret` — TACACS+ shared-secret
//! * `hmac-key` — routing-options authentication-key HMAC
//!
//! The redaction is XML-element-name based — every matching element has
//! its text content replaced with `<REDACTED>` while preserving the XML
//! structure so JTAC can still see *where* a secret was configured.

/// Element names whose text content is replaced with `<REDACTED>`.
/// Matching is exact on the local element name (namespace-stripped).
pub const REDACT_ELEMENT_NAMES: &[&str] = &[
    "pre-shared-key",
    "secret",
    "simple-password",
    "encrypted-password",
    "community",
    "hmac-key",
];

/// Replacement string used in redacted element text.
pub const REDACTED_MARKER: &str = "<REDACTED>";

/// Redact known-sensitive element text content from an XML payload.
/// Returns the redacted XML string. If the input cannot be parsed,
/// returns the input unchanged (callers should treat parse failures as
/// non-fatal and log them).
///
/// Implementation lands in a follow-up commit during Task #13 — this
/// scaffold reserves the signature so callers can wire against it now.
pub fn redact_xml(input: &str) -> String {
    // TODO(task-13): roxmltree walk + quick-xml writer emitting REDACTED
    // text for any element in REDACT_ELEMENT_NAMES.
    let _ = REDACT_ELEMENT_NAMES;
    let _ = REDACTED_MARKER;
    input.to_string()
}
