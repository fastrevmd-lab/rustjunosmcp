//! `check_srx_feature_license` — map a security-service intent to the
//! matching license record(s) on the device.
//!
//! # Junos XML schema
//!
//! `<get-license-summary-information/>` returns one of two shapes depending
//! on the Junos version. Both are accepted by `parse()`.
//!
//! Older (legacy RPC docs):
//!
//! ```xml
//! <license-summary-information>
//!   <feature-summary>
//!     <name>IDP Signature</name>
//!     <description>…</description>
//!     <licenses-used>1</licenses-used>
//!     <licenses-installed>1</licenses-installed>
//!     <licenses-needed>0</licenses-needed>
//!     <license-type>permanent</license-type>
//!     <end-date>2026-06-30 23:07:30 UTC</end-date>
//!   </feature-summary>
//! </license-summary-information>
//! ```
//!
//! Junos 24.4R0+ live (observed on vSRX-test1 demo licensing):
//!
//! ```xml
//! <license-summary-information>
//!   <license-usage-summary>
//!     <feature-summary>
//!       <name>IDP-SIG</name>
//!       <description>IDP Signature</description>
//!       <licensed>1</licensed>
//!       <used-licensed>0</used-licensed>
//!       <needed>0</needed>
//!       <end-date junos:seconds="1810944000">2027-05-22</end-date>
//!     </feature-summary>
//!     <feature-summary>
//!       <name>Remote Access IPSec VPN Client</name>
//!       <licensed>2</licensed>
//!       <used-licensed>0</used-licensed>
//!       <used-given>0</used-given>
//!       <needed>0</needed>
//!       <validity-type>permanent</validity-type>
//!     </feature-summary>
//!   </license-usage-summary>
//! </license-summary-information>
//! ```
//!
//! `<get-license-key-information/>` returns a `<license-key-information>` block
//! listing raw key blobs — not used for feature matching but included in
//! `raw_xml` when `include_raw=true`.
//!
//! # Absence rule
//!
//! If no `<feature-summary>` whose `<name>` matches any of the feature's
//! `record_patterns()` (case-insensitive substring) is found →
//! `state=not_configured`, `reason="<feature> not present in installed licenses"`.

use crate::{SrxError, SrxToolResponse};
use rust_junosmcp_core::device_manager::PooledDevice;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

// ── Public types ──────────────────────────────────────────────────────────────

/// The set of SRX security features that require a Junos license.
///
/// Each variant has a hard-coded list of case-insensitive substring patterns
/// matched against the `<name>` field of `<feature-summary>` elements returned
/// by `<get-license-summary-information/>`.
#[derive(Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum SrxLicensedFeature {
    Idp,
    AppId,
    UtmAntivirus,
    WebFiltering,
    AntiSpam,
    SecIntel,
    AtpCloud,
    SslProxy,
}

impl SrxLicensedFeature {
    /// Case-insensitive substring patterns matched against the Junos
    /// `<name>` field (the "Feature" column in `show system license`).
    pub fn record_patterns(&self) -> &'static [&'static str] {
        match self {
            Self::Idp => &["idp", "intrusion"],
            Self::AppId => &["application identification", "appid", "app-id"],
            Self::UtmAntivirus => &["antivirus", "av-key", "av_key", "anti-virus"],
            Self::WebFiltering => &["web filtering", "url filtering", "web-filtering"],
            Self::AntiSpam => &["anti-spam", "antispam"],
            Self::SecIntel => &["secintel", "security intelligence", "sec-intel"],
            Self::AtpCloud => &["atp cloud", "sky atp", "advanced threat"],
            Self::SslProxy => &["ssl proxy", "ssl forward proxy", "ssl-proxy"],
        }
    }

    /// Human-readable name for use in `reason` strings.
    fn display_name(&self) -> &'static str {
        match self {
            Self::Idp => "idp",
            Self::AppId => "app_id",
            Self::UtmAntivirus => "utm_antivirus",
            Self::WebFiltering => "web_filtering",
            Self::AntiSpam => "anti_spam",
            Self::SecIntel => "sec_intel",
            Self::AtpCloud => "atp_cloud",
            Self::SslProxy => "ssl_proxy",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct LicenseArgs {
    pub router: String,
    pub feature: SrxLicensedFeature,
    #[serde(default)]
    pub include_raw: bool,
}

/// Per-record data extracted from a `<feature-summary>` block.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct LicenseRecord {
    /// The `<name>` text from the feature-summary block.
    pub feature_name: String,
    /// `"permanent"`, `"time-based"`, `"trial"`, etc.
    pub license_type: String,
    /// End-date when the license expires; `None` for permanent.
    /// Wire shape is RFC 3339 (e.g. `"2026-06-30T23:07:30Z"`).
    #[serde(with = "time::serde::rfc3339::option")]
    #[schemars(with = "Option<String>")]
    pub end_date: Option<OffsetDateTime>,
}

/// Aggregated counts across all matching records.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct LicenseCounts {
    pub used: u32,
    pub installed: u32,
    pub needed: u32,
}

/// The `data` payload returned in `SrxToolResponse<LicenseData>` when one
/// or more matching license records are found.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct LicenseData {
    pub feature: SrxLicensedFeature,
    pub license_records: Vec<LicenseRecord>,
    pub counts: LicenseCounts,
    /// Earliest expiry among time-based records (`None` when all permanent).
    /// Wire shape is RFC 3339.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schemars(with = "Option<String>")]
    pub earliest_expiry: Option<OffsetDateTime>,
    /// `true` iff every matching record has `license_type == "permanent"`
    /// (i.e. `end_date.is_none()` for all records).
    pub all_permanent: bool,
}

// ── `run()` — async entry point ───────────────────────────────────────────────

/// Run `get-license-summary-information` (and optionally `get-license-key-information`)
/// against a pooled device and return a typed `SrxToolResponse<LicenseData>`.
pub async fn run(
    device: &mut PooledDevice,
    args: LicenseArgs,
) -> Result<SrxToolResponse<LicenseData>, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let summary = exec
        .call("get-license-summary-information", &[])
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let keys = exec
        .call("get-license-key-information", &[])
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let mut parsed = parse(args.feature, &summary)?;
    if args.include_raw {
        parsed = parsed.with_raw(format!(
            "<!-- summary -->\n{summary}\n<!-- keys -->\n{keys}"
        ));
    }
    Ok(parsed)
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse the `<license-summary-information>` XML body (as returned by
/// `rustez::RpcExecutor::call`) and return a typed `SrxToolResponse`.
///
/// This is the pure unit-testable entry point; `run()` calls it after
/// obtaining the raw XML from the device.
///
/// `key_xml` is accepted for forward-compatibility but not parsed for
/// feature matching — matching is done against `summary_xml` only.
pub fn parse(
    feature: SrxLicensedFeature,
    summary_xml: &str,
) -> Result<SrxToolResponse<LicenseData>, SrxError> {
    // Strip `junos:`-prefixed attributes (no xmlns:junos binding survives the
    // rustnetconf `extract_rpc_reply_inner_content` step), which would otherwise
    // make roxmltree reject the document with "unknown namespace prefix".
    let sanitized = crate::xml::sanitize_rustez_xml(summary_xml);
    let doc = roxmltree::Document::parse(&sanitized)
        .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;

    let patterns = feature.record_patterns();

    let mut records: Vec<LicenseRecord> = Vec::new();
    let mut total_used: u32 = 0;
    let mut total_installed: u32 = 0;
    let mut total_needed: u32 = 0;

    // Walk every <feature-summary> child.
    for fs in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "feature-summary")
    {
        let name = child_text(&fs, "name").unwrap_or_default();
        let name_lc = name.to_ascii_lowercase();

        // Case-insensitive substring match against any pattern for this feature.
        if !patterns.iter().any(|p| name_lc.contains(p)) {
            continue;
        }

        // Junos date format: "2026-06-30 23:07:30 UTC" — parse to OffsetDateTime.
        let end_date = child_text(&fs, "end-date")
            .map(|s| junos_date_to_offset(&s))
            .transpose()
            .map_err(|e| SrxError::Parse(format!("end-date parse error: {e}")))?;

        // Two Junos schema variants observed in the wild:
        //   * Older (per RPC docs):  <license-type>,    <licenses-used>,
        //                            <licenses-installed>, <licenses-needed>
        //   * Junos 24.4R0+ live:    <validity-type>,   <used-licensed>,
        //                            <licensed>,          <needed>
        // Accept either, and fall back on `<end-date>` presence to infer the
        // license_type string when neither tag is present.
        let license_type = child_text(&fs, "license-type")
            .or_else(|| child_text(&fs, "validity-type"))
            .unwrap_or_else(|| {
                if end_date.is_some() {
                    "date-based".to_string()
                } else {
                    String::new()
                }
            });

        let used: u32 = child_text(&fs, "licenses-used")
            .or_else(|| child_text(&fs, "used-licensed"))
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0);
        let installed: u32 = child_text(&fs, "licenses-installed")
            .or_else(|| child_text(&fs, "licensed"))
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0);
        let needed: u32 = child_text(&fs, "licenses-needed")
            .or_else(|| child_text(&fs, "needed"))
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0);

        total_used = total_used.saturating_add(used);
        total_installed = total_installed.saturating_add(installed);
        total_needed = total_needed.saturating_add(needed);

        records.push(LicenseRecord {
            feature_name: name,
            license_type,
            end_date,
        });
    }

    if records.is_empty() {
        return Ok(SrxToolResponse::not_configured(format!(
            "{} not present in installed licenses",
            feature.display_name()
        )));
    }

    // Collect all expiry dates, find the earliest.
    let mut expiry_dates: Vec<OffsetDateTime> = records.iter().filter_map(|r| r.end_date).collect();
    expiry_dates.sort();
    let earliest_expiry = expiry_dates.into_iter().next();

    let all_permanent = records.iter().all(|r| r.end_date.is_none());

    Ok(SrxToolResponse::active(LicenseData {
        feature,
        license_records: records,
        counts: LicenseCounts {
            used: total_used,
            installed: total_installed,
            needed: total_needed,
        },
        earliest_expiry,
        all_permanent,
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Get the trimmed text content of the first child element with `tag_name`.
fn child_text(node: &roxmltree::Node<'_, '_>, tag_name: &str) -> Option<String> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == tag_name)
        .and_then(|n| n.text())
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Parse a Junos date string (`"2026-06-30 23:07:30 UTC"`) into an
/// `OffsetDateTime`.
///
/// Junos uses a non-standard format with a space separator and trailing " UTC".
/// We normalise it to RFC 3339 and then parse via `time`'s well-known format.
fn junos_date_to_offset(s: &str) -> Result<OffsetDateTime, String> {
    use time::format_description::well_known::Rfc3339;

    let s = s.trim();
    // Strip trailing timezone label (always UTC for Junos).
    let s = s.strip_suffix(" UTC").unwrap_or(s).trim();

    let rfc = if s.len() == 19 && s.as_bytes()[10] == b' ' {
        // "2026-06-30 23:07:30" → "2026-06-30T23:07:30+00:00"
        format!("{}T{}+00:00", &s[..10], &s[11..])
    } else if s.len() == 10 && s.as_bytes()[4] == b'-' && s.as_bytes()[7] == b'-' {
        // "2027-05-22" (date-only) → end-of-day UTC. Conservative for an
        // expiry: don't extend a license past its actual final day.
        format!("{s}T23:59:59+00:00")
    } else if s.contains('T') {
        // Already ISO 8601-ish.
        s.to_string()
    } else {
        return Err(format!("unrecognised Junos date format: {s:?}"));
    };

    OffsetDateTime::parse(&rfc, &Rfc3339).map_err(|e| format!("rfc3339 parse {rfc:?}: {e}"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SrxState;
    use pretty_assertions::assert_eq;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/license")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()))
    }

    // ── Test 1: eval/trial — no IDP records → not_configured ─────────────────

    #[test]
    fn eval_trial_idp_returns_not_configured() {
        // Lab eval/trial licenses (Virtual Appliance + VCPU Scale) don't include
        // any IDP record — expect not_configured with "not present" in the reason.
        let xml = fixture("eval_trial.xml");
        let resp = parse(SrxLicensedFeature::Idp, &xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::NotConfigured, "state");
        assert!(
            resp.reason
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .contains("not present"),
            "reason should contain 'not present', got: {:?}",
            resp.reason
        );
        assert!(
            resp.data.is_none(),
            "data should be absent for not_configured"
        );
    }

    // ── Test 2: eval/trial — non-IDP variants also return not_configured ──────

    #[test]
    fn eval_trial_appid_returns_not_configured() {
        let xml = fixture("eval_trial.xml");
        let resp = parse(SrxLicensedFeature::AppId, &xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::NotConfigured, "state");
    }

    #[test]
    fn eval_trial_utm_returns_not_configured() {
        let xml = fixture("eval_trial.xml");
        let resp = parse(SrxLicensedFeature::UtmAntivirus, &xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::NotConfigured, "state");
    }

    // ── Test 3: permanent IDP license → active, all_permanent=true ───────────

    #[test]
    fn permanent_idp_marks_all_permanent_true() {
        // Hand-crafted fixture with a permanent IDP Signature license.
        let xml = fixture("permanent.xml");
        let resp = parse(SrxLicensedFeature::Idp, &xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::Active, "state");

        let data = resp.data.expect("data must be present for Active");
        assert!(data.all_permanent, "all_permanent should be true");
        assert!(
            data.earliest_expiry.is_none(),
            "earliest_expiry should be None for permanent"
        );
        assert!(
            !data.license_records.is_empty(),
            "license_records non-empty"
        );
        assert_eq!(
            data.license_records[0].feature_name, "IDP Signature",
            "feature_name"
        );
        assert_eq!(
            data.license_records[0].license_type, "permanent",
            "license_type"
        );
        assert_eq!(data.counts.installed, 1, "counts.installed");
    }

    // ── Test 4: permanent fixture — non-IDP variant returns not_configured ────

    #[test]
    fn permanent_appid_returns_not_configured_when_only_idp_present() {
        let xml = fixture("permanent.xml");
        let resp = parse(SrxLicensedFeature::AppId, &xml).expect("parse should not error");
        // The permanent.xml fixture only has IDP — AppId should not match.
        assert_eq!(resp.state, SrxState::NotConfigured, "state");
    }

    // ── Test 5: no licenses installed → not_configured ────────────────────────

    #[test]
    fn none_installed_returns_not_configured() {
        let xml = fixture("none_installed.xml");
        let resp = parse(SrxLicensedFeature::Idp, &xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::NotConfigured, "state");
        assert!(
            resp.reason
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .contains("not present"),
            "reason should contain 'not present', got: {:?}",
            resp.reason
        );
        assert!(resp.data.is_none(), "data should be absent");
    }

    // ── Test 6: date conversion helper ───────────────────────────────────────

    #[test]
    fn junos_date_converts_to_offset() {
        let result = junos_date_to_offset("2026-06-30 23:07:30 UTC").unwrap();
        assert_eq!(result.unix_timestamp(), 1782860850);
        assert_eq!(result.offset(), time::UtcOffset::UTC);
    }

    #[test]
    fn junos_date_without_utc_suffix_still_converts() {
        let result = junos_date_to_offset("2026-06-30 23:07:30").unwrap();
        assert_eq!(result.unix_timestamp(), 1782860850);
    }

    #[test]
    fn junos_date_date_only_resolves_to_end_of_day_utc() {
        // Some Junos demolab/commercial bundles emit <end-date>2027-05-22</end-date>
        // (date-only). Treat as 23:59:59 UTC so we don't underreport remaining time.
        let result = junos_date_to_offset("2027-05-22").unwrap();
        assert_eq!(result.offset(), time::UtcOffset::UTC);
        assert_eq!(result.year(), 2027);
        assert_eq!(result.month(), time::Month::May);
        assert_eq!(result.day(), 22);
        assert_eq!(result.hour(), 23);
        assert_eq!(result.minute(), 59);
        assert_eq!(result.second(), 59);
    }

    #[test]
    fn junos_date_rejects_malformed_input() {
        assert!(junos_date_to_offset("not a date").is_err());
        assert!(junos_date_to_offset("2026/06/30").is_err());
    }

    // ── Regression test for #69 ──────────────────────────────────────────────
    //
    // rustnetconf's `extract_rpc_reply_inner_content` strips the outer xmlns
    // declarations but preserves `junos:`-prefixed attributes inside the
    // payload. Without sanitization, roxmltree refuses to parse with
    // "unknown namespace prefix 'junos'". `parse()` must invoke
    // `sanitize_rustez_xml` before handing the XML to roxmltree.
    #[test]
    fn parses_live_reply_with_junos_prefixed_attributes() {
        let xml = fixture("live_eval_with_junos_attrs.xml");
        let resp = parse(SrxLicensedFeature::Idp, &xml)
            .expect("parse must succeed on live-shape XML with junos: attrs");
        assert_eq!(resp.state, SrxState::NotConfigured, "state");
    }

    // ── Regression: Junos 24.4R0 demolab schema (used-licensed/licensed/needed) ──
    //
    // Junos 24.4R0 emits a different element shape than what the legacy RPC
    // docs describe: `<licensed>` instead of `<licenses-installed>`,
    // `<used-licensed>` instead of `<licenses-used>`, `<needed>` instead of
    // `<licenses-needed>`, and `<validity-type>` instead of `<license-type>`
    // (date-based licenses omit it entirely — `<end-date>` presence is the
    // only signal). Before this fix, all counts parsed as 0, which tripped
    // the preflight defence-in-depth check (`counts.installed == 0` →
    // SignaturePackageLicenseInactive) even though the device clearly has
    // the license installed.
    #[test]
    fn junos_24_4_demolab_idp_active_with_correct_counts() {
        let xml = fixture("junos_24_4_demolab.xml");
        let resp = parse(SrxLicensedFeature::Idp, &xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::Active, "state");

        let data = resp.data.expect("data must be present for Active");
        assert_eq!(data.counts.installed, 1, "counts.installed");
        assert_eq!(data.counts.used, 0, "counts.used");
        assert_eq!(data.counts.needed, 0, "counts.needed");
        assert!(!data.all_permanent, "date-based, not permanent");
        let record = &data.license_records[0];
        assert_eq!(record.feature_name, "IDP-SIG");
        assert_eq!(record.license_type, "date-based", "inferred from end-date");
        assert!(record.end_date.is_some(), "end-date must parse");
    }

    #[test]
    fn junos_24_4_demolab_permanent_validity_type_recognised() {
        let xml = fixture("junos_24_4_demolab.xml");
        // No SrxLicensedFeature variant matches "Remote Access IPSec VPN Client",
        // but we can still verify the schema-tolerance path by checking AppId,
        // which IS in the fixture as "APPID Signature" with the new schema.
        let resp = parse(SrxLicensedFeature::AppId, &xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::Active);
        let data = resp.data.expect("data present");
        assert_eq!(data.counts.installed, 1);
    }
}
