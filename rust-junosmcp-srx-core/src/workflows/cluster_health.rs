//! `validate_chassis_cluster_health` workflow (Phase 3).
//!
//! Runs the 8 cluster-scoped RPCs (capture-verified against Junos 24.4R1.9
//! on 2026-05-26 — see captures in `docs/superpowers/captures/phase3/`),
//! reuses the Phase 1B [`crate::workflows::cluster_status::parse`] for the
//! topology snapshot, and emits an ordered findings list rolled up into a
//! single [`Verdict`].
//!
//! Sub-RPCs run sequentially (strategy B) because the per-router pool lock
//! prevents concurrent acquisitions for the same device. Each sub-RPC is
//! tolerant of failure via the [`SubCall`] capture pattern: a single
//! missing RPC degrades only its own checks instead of aborting the
//! workflow.

use crate::xml::multi_re_split;
use crate::{SrxError, SrxToolResponse};
use rust_junosmcp_core::device_manager::PooledDevice;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClusterHealthArgs {
    #[serde(alias = "router_name")]
    pub router: String,
    #[serde(default)]
    pub include_raw: bool,
    /// Caller-supplied correlation token. If absent, `run()` mints
    /// `srxmcp-<uuid-v4>` and returns it in the response.
    #[serde(default)]
    pub request_id: Option<String>,
}

/// Per-check severity. Aggregated by [`Verdict::roll_up`] using
/// fail > warn > pass precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Pass,
    Warn,
    Fail,
}

/// Overall verdict for the cluster-health run. Derived from
/// `findings.iter().map(|f| f.severity).max()` with the precedence above.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Warn,
    Fail,
}

impl Verdict {
    /// Roll up an ordered findings list into a single verdict.
    pub fn roll_up<'a, I: IntoIterator<Item = &'a Finding>>(findings: I) -> Self {
        let mut worst = Verdict::Pass;
        for finding in findings {
            match (worst, finding.severity) {
                (_, Severity::Fail) => return Verdict::Fail,
                (Verdict::Pass, Severity::Warn) => worst = Verdict::Warn,
                _ => {}
            }
        }
        worst
    }
}

/// One ordered finding emitted by a single check. `check_id` is a stable
/// snake_case identifier; the closed set is enumerated in [`CHECK_IDS`].
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct Finding {
    pub check_id: String,
    pub severity: Severity,
    pub message: String,
    /// Optional structured detail (per-node values, RPC reply excerpts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

/// Closed set of `check_id` values emitted by this workflow.
pub const CHECK_IDS: &[&str] = &[
    "red_led",
    "disabled_secondary",
    "control_link_failure",
    "major_alarm",
    "minor_alarm",
    "recent_reboot",
    "version_skew",
];

/// Top-level response for `validate_chassis_cluster_health`. Wrapped in
/// [`SrxToolResponse`] by the workflow entry point so standalone devices
/// get the `NotConfigured` envelope instead.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ClusterHealthData {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    /// Effective request_id (caller-supplied or server-minted).
    pub request_id: String,
    /// Pass-through of the Phase 1B parser's structured cluster snapshot.
    /// Populated when the cluster_status RPC returned parseable data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_status: Option<crate::workflows::cluster_status::ClusterStatusData>,
}

// ── Sub-call capture ──────────────────────────────────────────────────────────

/// Per-RPC capture — `Ok(raw_xml)` on RPC success, `Err(reason)` if the
/// RPC itself errored or the reply was rejected. Mirrors the
/// `services_status::SubCall` pattern but keeps the raw XML for downstream
/// parsing (each check parses what it needs).
struct SubCall {
    raw: String,
    error: Option<String>,
}

impl SubCall {
    fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

async fn capture(exec: &mut rustez::rpc::RpcExecutor<'_>, rpc: &str) -> SubCall {
    match exec.call(rpc, &[]).await {
        Ok(xml) => SubCall {
            raw: xml,
            error: None,
        },
        Err(e) => SubCall {
            raw: String::new(),
            error: Some(format!("rpc error: {e}")),
        },
    }
}

// ── `run()` — async entry point ───────────────────────────────────────────────

/// Run the 8 cluster-health RPCs and emit a rolled-up verdict + findings.
///
/// Standalone devices (no chassis cluster configured) short-circuit to
/// `SrxState::NotConfigured` based on the same `<xnm:error>` detection
/// used by Phase 1B `cluster_status::parse`.
pub async fn run(
    device: &mut PooledDevice,
    args: ClusterHealthArgs,
) -> Result<SrxToolResponse<ClusterHealthData>, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    let request_id = args
        .request_id
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(mint_request_id);

    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    // 8 sequential captures. Order chosen to fail-fast on the cheapest RPC
    // first (cluster-status) so a standalone device returns quickly.
    let status = capture(&mut exec, "get-chassis-cluster-status").await;

    // Standalone short-circuit: reuse Phase 1B parser to detect the
    // <xnm:error>/<rpc-error> envelope.
    if status.is_ok() {
        let parsed = crate::workflows::cluster_status::parse(&status.raw)?;
        if matches!(parsed.state, crate::SrxState::NotConfigured) {
            let mut resp =
                SrxToolResponse::<ClusterHealthData>::not_configured("chassis cluster disabled");
            if args.include_raw {
                resp = resp.with_raw(status.raw);
            }
            return Ok(resp);
        }
    }

    let interfaces = capture(&mut exec, "get-chassis-cluster-interfaces").await;
    let info = capture(&mut exec, "get-chassis-cluster-information").await;
    let dp_stats = capture(&mut exec, "get-chassis-cluster-data-plane-statistics").await;
    let cl_stats = capture(&mut exec, "get-chassis-cluster-statistics").await;
    let software = capture(&mut exec, "get-software-information").await;
    let alarms = capture(&mut exec, "get-system-alarm-information").await;
    let uptime = capture(&mut exec, "get-system-uptime-information").await;

    // Re-parse cluster_status for the structured snapshot (already known OK).
    let cluster_status_resp = if status.is_ok() {
        crate::workflows::cluster_status::parse(&status.raw).ok()
    } else {
        None
    };
    let cluster_snapshot = cluster_status_resp.and_then(|r| match r.state {
        crate::SrxState::Active => r.data,
        crate::SrxState::NotConfigured | crate::SrxState::Error => None,
    });

    // Run all 7 checks in declaration order. Each check is tolerant of
    // its source RPC having errored (returns no findings + a synthetic
    // warn finding noting the data gap).
    let mut findings: Vec<Finding> = Vec::new();
    check_red_led(&info, &mut findings);
    check_disabled_secondary(cluster_snapshot.as_ref(), &mut findings);
    check_control_link_failure(&interfaces, &info, &mut findings);
    check_major_alarm(&alarms, &mut findings);
    check_minor_alarm(&alarms, &mut findings);
    check_recent_reboot(&uptime, &mut findings);
    check_version_skew(&software, &mut findings);

    let verdict = Verdict::roll_up(&findings);

    let data = ClusterHealthData {
        verdict,
        findings,
        request_id,
        cluster_status: cluster_snapshot,
    };

    let mut resp = SrxToolResponse::<ClusterHealthData>::active(data);
    if args.include_raw {
        // Concatenated raw dumps with section markers so the LLM (or a
        // human) can see exactly which RPC produced which envelope.
        resp = resp.with_raw(format!(
            "<!-- cluster-status -->\n{}\n<!-- cluster-interfaces -->\n{}\n<!-- cluster-information -->\n{}\n<!-- dp-stats -->\n{}\n<!-- cl-stats -->\n{}\n<!-- software -->\n{}\n<!-- alarms -->\n{}\n<!-- uptime -->\n{}",
            status.raw, interfaces.raw, info.raw, dp_stats.raw, cl_stats.raw, software.raw, alarms.raw, uptime.raw,
        ));
    }
    // dp_stats + cl_stats are captured for the raw dump only in v0.3.0;
    // they don't drive any check today. Future work: heartbeat-error +
    // counter-drift checks.
    let _ = (&dp_stats, &cl_stats);
    Ok(resp)
}

/// Mint a `srxmcp-<uuid-v4>` correlation token. Uses `uuid::Uuid::new_v4`
/// (random, no clock dependency — fine for correlation tokens).
fn mint_request_id() -> String {
    format!("srxmcp-{}", uuid::Uuid::new_v4())
}

// ── Checks ────────────────────────────────────────────────────────────────────

/// C1: red LED on any node → fail. Source RPC: `get-chassis-cluster-information`.
fn check_red_led(info: &SubCall, out: &mut Vec<Finding>) {
    if let Some(reason) = &info.error {
        out.push(synth_warn("red_led", "data_unavailable", reason));
        return;
    }
    let Ok(re_nodes) = multi_re_split(&info.raw) else {
        return;
    };
    for re in &re_nodes {
        let Ok(doc) = roxmltree::Document::parse(&re.inner_xml) else {
            continue;
        };
        for led in doc
            .descendants()
            .filter(|n| n.is_element() && n.tag_name().name() == "chassis-cluster-led-information")
        {
            let color = text_child(led, "current-led-color").unwrap_or_default();
            if color.eq_ignore_ascii_case("Red") {
                let node = text_child(led, "node-name").unwrap_or(re.re_name.clone());
                out.push(Finding {
                    check_id: "red_led".into(),
                    severity: Severity::Fail,
                    message: format!("node {node} cluster LED is Red"),
                    detail: Some(serde_json::json!({"node": node, "color": color})),
                });
            }
        }
    }
}

/// C2: any RG member with status `disabled` or `lost` → fail.
/// Source: parsed [`crate::workflows::cluster_status::ClusterStatusData`].
fn check_disabled_secondary(
    snapshot: Option<&crate::workflows::cluster_status::ClusterStatusData>,
    out: &mut Vec<Finding>,
) {
    let Some(snap) = snapshot else {
        out.push(synth_warn(
            "disabled_secondary",
            "data_unavailable",
            "cluster_status RPC produced no parseable snapshot",
        ));
        return;
    };
    for rg in &snap.redundancy_groups {
        for member in &rg.members {
            let lower = member.status.to_ascii_lowercase();
            if lower == "disabled" || lower == "lost" {
                out.push(Finding {
                    check_id: "disabled_secondary".into(),
                    severity: Severity::Fail,
                    message: format!(
                        "RG{} member {} is in state {}",
                        rg.group_id, member.node, member.status
                    ),
                    detail: Some(serde_json::json!({
                        "rg": rg.group_id,
                        "node": member.node,
                        "status": member.status,
                    })),
                });
            }
        }
    }
}

/// C3: control link / fabric link failure → fail. Sources: cluster-interfaces
/// (`fabric-link-child-interface-monitored-status=Down`) and
/// cluster-information (RG state-transition records mentioning "Control link
/// failure" or "Fabric link failure").
fn check_control_link_failure(interfaces: &SubCall, info: &SubCall, out: &mut Vec<Finding>) {
    let mut had_data = false;
    if interfaces.is_ok() {
        had_data = true;
        if let Ok(re_nodes) = multi_re_split(&interfaces.raw) {
            for re in &re_nodes {
                if let Ok(doc) = roxmltree::Document::parse(&re.inner_xml) {
                    for child in doc.descendants().filter(|n| {
                        n.is_element()
                            && n.tag_name().name() == "fabric-link-child-interface-monitored-status"
                    }) {
                        let val = child.text().unwrap_or_default().trim();
                        if val.eq_ignore_ascii_case("Down") {
                            let iface = child
                                .parent()
                                .and_then(|p| text_child(p, "fabric-link-child-interface-name"))
                                .unwrap_or_else(|| "?".into());
                            out.push(Finding {
                                check_id: "control_link_failure".into(),
                                severity: Severity::Fail,
                                message: format!(
                                    "fabric-link child interface {iface} monitored status Down on {}",
                                    re.re_name
                                ),
                                detail: Some(serde_json::json!({
                                    "node": re.re_name,
                                    "interface": iface,
                                })),
                            });
                        }
                    }
                }
            }
        }
    }
    if info.is_ok() {
        had_data = true;
        if let Ok(re_nodes) = multi_re_split(&info.raw) {
            for re in &re_nodes {
                if let Ok(doc) = roxmltree::Document::parse(&re.inner_xml) {
                    for rec in doc.descendants().filter(|n| {
                        n.is_element()
                            && n.tag_name().name() == "redundancy-group-state-transition-record"
                    }) {
                        // Junos 24.4 emits `<transition-reason>` (not the
                        // longer `redundancy-group-transition-reason`).
                        let reason = text_child(rec, "transition-reason").unwrap_or_default();
                        let lower = reason.to_ascii_lowercase();
                        if lower.contains("control link failure")
                            || lower.contains("fabric link failure")
                        {
                            out.push(Finding {
                                check_id: "control_link_failure".into(),
                                severity: Severity::Fail,
                                message: format!(
                                    "RG transition record on {}: {reason}",
                                    re.re_name
                                ),
                                detail: Some(serde_json::json!({
                                    "node": re.re_name,
                                    "reason": reason,
                                })),
                            });
                        }
                    }
                }
            }
        }
    }
    if !had_data {
        out.push(synth_warn(
            "control_link_failure",
            "data_unavailable",
            "neither cluster-interfaces nor cluster-information available",
        ));
    }
}

/// C4: any `alarm-class=Major` → fail. Source: `get-system-alarm-information`.
fn check_major_alarm(alarms: &SubCall, out: &mut Vec<Finding>) {
    iter_alarms(alarms, "Major", Severity::Fail, "major_alarm", out);
}

/// C5: any `alarm-class=Minor` → warn.
fn check_minor_alarm(alarms: &SubCall, out: &mut Vec<Finding>) {
    iter_alarms(alarms, "Minor", Severity::Warn, "minor_alarm", out);
}

fn iter_alarms(
    alarms: &SubCall,
    class_filter: &str,
    severity: Severity,
    check_id: &str,
    out: &mut Vec<Finding>,
) {
    if let Some(reason) = &alarms.error {
        // Only emit one data-unavailable finding for the whole alarm pair,
        // attributed to the first check that runs (Major).
        if check_id == "major_alarm" {
            out.push(synth_warn(check_id, "data_unavailable", reason));
        }
        return;
    }
    let Ok(re_nodes) = multi_re_split(&alarms.raw) else {
        return;
    };
    for re in &re_nodes {
        let Ok(doc) = roxmltree::Document::parse(&re.inner_xml) else {
            continue;
        };
        for alarm in doc
            .descendants()
            .filter(|n| n.is_element() && n.tag_name().name() == "alarm-detail")
        {
            let class = text_child(alarm, "alarm-class").unwrap_or_default();
            if !class.eq_ignore_ascii_case(class_filter) {
                continue;
            }
            let description = text_child(alarm, "alarm-description")
                .or_else(|| text_child(alarm, "alarm-short-description"))
                .unwrap_or_default();
            out.push(Finding {
                check_id: check_id.into(),
                severity,
                message: format!("{class} alarm on {}: {description}", re.re_name),
                detail: Some(serde_json::json!({
                    "node": re.re_name,
                    "class": class,
                    "description": description,
                })),
            });
        }
    }
}

/// C6: any node with uptime < 5 min → warn. Source:
/// `get-system-uptime-information` per-RE.
fn check_recent_reboot(uptime: &SubCall, out: &mut Vec<Finding>) {
    if let Some(reason) = &uptime.error {
        out.push(synth_warn("recent_reboot", "data_unavailable", reason));
        return;
    }
    let Ok(re_nodes) = multi_re_split(&uptime.raw) else {
        return;
    };
    for re in &re_nodes {
        let Ok(doc) = roxmltree::Document::parse(&re.inner_xml) else {
            continue;
        };
        for uptime_info in doc
            .descendants()
            .filter(|n| n.is_element() && n.tag_name().name() == "system-uptime-information")
        {
            // `uptime-information/up-time` carries `seconds` as an attribute
            // on the inner `<up-time seconds="123">…</up-time>` element.
            let seconds = uptime_info
                .descendants()
                .find(|n| n.is_element() && n.tag_name().name() == "up-time")
                .and_then(|n| n.attribute("seconds"))
                .and_then(|s| s.trim().parse::<u64>().ok());
            let Some(s) = seconds else {
                continue;
            };
            if s < 300 {
                out.push(Finding {
                    check_id: "recent_reboot".into(),
                    severity: Severity::Warn,
                    message: format!(
                        "{} uptime {s}s < 5 min; let it converge before destructive changes",
                        re.re_name
                    ),
                    detail: Some(serde_json::json!({
                        "node": re.re_name,
                        "uptime_seconds": s,
                    })),
                });
            }
        }
    }
}

/// C7: version skew across REs. Same train + maintenance → no finding;
/// same train different maintenance → warn; different train → fail.
/// Source: `get-software-information` per-RE.
fn check_version_skew(software: &SubCall, out: &mut Vec<Finding>) {
    if let Some(reason) = &software.error {
        out.push(synth_warn("version_skew", "data_unavailable", reason));
        return;
    }
    let Ok(re_nodes) = multi_re_split(&software.raw) else {
        return;
    };
    if re_nodes.len() < 2 {
        // Standalone or only one RE captured — nothing to compare.
        return;
    }
    // Collect (re_name, version-string).
    let mut versions: Vec<(String, String)> = Vec::new();
    for re in &re_nodes {
        if let Ok(doc) = roxmltree::Document::parse(&re.inner_xml) {
            let v = doc
                .descendants()
                .find(|n| n.is_element() && n.tag_name().name() == "junos-version")
                .and_then(|n| n.text())
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if !v.is_empty() {
                versions.push((re.re_name.clone(), v));
            }
        }
    }
    if versions.len() < 2 {
        return;
    }
    // Compare every pair against the first.
    let (base_name, base_ver) = &versions[0];
    let base_train = train_of(base_ver);
    for (re_name, ver) in versions.iter().skip(1) {
        if ver == base_ver {
            continue;
        }
        let other_train = train_of(ver);
        let severity = if base_train != other_train {
            Severity::Fail
        } else {
            Severity::Warn
        };
        out.push(Finding {
            check_id: "version_skew".into(),
            severity,
            message: format!("{base_name} runs {base_ver}, {re_name} runs {ver}"),
            detail: Some(serde_json::json!({
                "node_a": base_name,
                "version_a": base_ver,
                "node_b": re_name,
                "version_b": ver,
            })),
        });
    }
}

/// Junos train = leading `<major>.<minor>` where minor is the leading
/// digits only (e.g. `"24.4R1.9"` → `"24.4"`, `"22.4R3-S5.4"` → `"22.4"`).
/// Returns the original string when major/minor digits cannot be extracted.
fn train_of(version: &str) -> String {
    let mut parts = version.split('.');
    let major = parts.next().unwrap_or("");
    let minor_full = parts.next().unwrap_or("");
    let minor_digits: String = minor_full
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if major.is_empty() || minor_digits.is_empty() {
        version.to_string()
    } else {
        format!("{major}.{minor_digits}")
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Trimmed text of the first child element named `tag` under `parent`.
fn text_child(parent: roxmltree::Node<'_, '_>, tag: &str) -> Option<String> {
    parent
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == tag)
        .and_then(|n| n.text())
        .map(|t| t.trim().to_string())
}

/// Build a synthetic `warn` finding noting that the source RPC for a
/// given check was unavailable. `detail.code` is fixed to the supplied
/// reason category for downstream filtering.
fn synth_warn(check_id: &str, code: &str, reason: &str) -> Finding {
    Finding {
        check_id: check_id.into(),
        severity: Severity::Warn,
        message: format!("check {check_id} skipped: {reason}"),
        detail: Some(serde_json::json!({"code": code, "reason": reason})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_roll_up_precedence() {
        let pass_only = vec![mkf("a", Severity::Pass)];
        assert_eq!(Verdict::roll_up(&pass_only), Verdict::Pass);

        let pass_warn = vec![mkf("a", Severity::Pass), mkf("b", Severity::Warn)];
        assert_eq!(Verdict::roll_up(&pass_warn), Verdict::Warn);

        let warn_fail = vec![mkf("a", Severity::Warn), mkf("b", Severity::Fail)];
        assert_eq!(Verdict::roll_up(&warn_fail), Verdict::Fail);

        let empty: Vec<Finding> = vec![];
        assert_eq!(Verdict::roll_up(&empty), Verdict::Pass);
    }

    #[test]
    fn train_of_extracts_major_minor() {
        assert_eq!(train_of("24.4R1.9"), "24.4");
        assert_eq!(train_of("22.4R3-S5.4"), "22.4");
        assert_eq!(train_of("garbage"), "garbage");
    }

    fn mkf(id: &str, sev: Severity) -> Finding {
        Finding {
            check_id: id.into(),
            severity: sev,
            message: String::new(),
            detail: None,
        }
    }

    // ── Fixture-based check tests ─────────────────────────────────────────
    //
    // Source: docs/superpowers/captures/phase3/vSRX-test19-20-cluster/
    // (cluster, RG transitions include "Control link failure", node0 LED Red,
    // node1 alarms contain 1 Major + 2 Minor, node0 alarms 3 Minor).

    const INFO_CLUSTER: &str = include_str!(
        "../../../docs/superpowers/captures/phase3/vSRX-test19-20-cluster/\
         get-chassis-cluster-information.xml"
    );
    const ALARMS_CLUSTER: &str = include_str!(
        "../../../docs/superpowers/captures/phase3/vSRX-test19-20-cluster/\
         get-system-alarm-information.xml"
    );
    const SOFTWARE_CLUSTER: &str = include_str!(
        "../../../docs/superpowers/captures/phase3/vSRX-test19-20-cluster/\
         get-software-information.xml"
    );

    fn ok(raw: &str) -> SubCall {
        SubCall {
            raw: raw.to_string(),
            error: None,
        }
    }

    fn err(reason: &str) -> SubCall {
        SubCall {
            raw: String::new(),
            error: Some(reason.to_string()),
        }
    }

    #[test]
    fn red_led_check_detects_node0_red_in_fixture() {
        let mut findings = Vec::new();
        check_red_led(&ok(INFO_CLUSTER), &mut findings);
        // Fixture has Red on node0, Off on node1 → exactly one fail finding.
        let reds: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.check_id == "red_led")
            .collect();
        assert_eq!(
            reds.len(),
            1,
            "expected 1 red_led finding, got {findings:#?}"
        );
        assert_eq!(reds[0].severity, Severity::Fail);
        assert!(reds[0].message.contains("Red"), "{}", reds[0].message);
    }

    #[test]
    fn red_led_check_emits_synth_warn_when_info_unavailable() {
        let mut findings = Vec::new();
        check_red_led(&err("rpc error: timeout"), &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(findings[0].message.contains("red_led"));
    }

    #[test]
    fn major_alarm_check_finds_one_major_in_fixture() {
        let mut findings = Vec::new();
        check_major_alarm(&ok(ALARMS_CLUSTER), &mut findings);
        // Fixture: node1 has 1 Major (FPC 0 Hard errors).
        assert_eq!(findings.len(), 1, "got {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Fail);
        assert!(
            findings[0].message.contains("FPC 0"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn minor_alarm_check_finds_five_minors_in_fixture() {
        let mut findings = Vec::new();
        check_minor_alarm(&ok(ALARMS_CLUSTER), &mut findings);
        // Fixture: node0 has 3 Minor + node1 has 2 Minor = 5.
        assert_eq!(findings.len(), 5, "got {findings:#?}");
        for f in &findings {
            assert_eq!(f.severity, Severity::Warn);
        }
    }

    #[test]
    fn control_link_failure_check_detects_info_transition_reasons() {
        // interfaces unavailable → only the info path runs.
        let mut findings = Vec::new();
        check_control_link_failure(
            &err("rpc error: not available"),
            &ok(INFO_CLUSTER),
            &mut findings,
        );
        // Fixture: node1 has "Control link failure" transition reasons in
        // both RG0 and RG1 → ≥1 finding, all fail.
        let hits: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.check_id == "control_link_failure")
            .collect();
        assert!(
            !hits.is_empty(),
            "expected ≥1 control_link_failure finding, got {findings:#?}"
        );
        for f in &hits {
            assert_eq!(f.severity, Severity::Fail);
        }
    }

    #[test]
    fn version_skew_check_quiet_when_versions_match() {
        let mut findings = Vec::new();
        check_version_skew(&ok(SOFTWARE_CLUSTER), &mut findings);
        // Fixture: both REs run 24.4R1.9 → no findings.
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:#?}"
        );
    }

    #[test]
    fn standalone_short_circuit_via_cluster_status_parser() {
        // Sanity check that the standalone fixture parses as NotConfigured —
        // run() relies on this branch to skip the rest of the workflow.
        let raw = include_str!(
            "../../../docs/superpowers/captures/phase3/vSRX-test3-standalone/\
             get-chassis-cluster-status.xml"
        );
        let parsed = crate::workflows::cluster_status::parse(raw).expect("parse");
        assert!(matches!(parsed.state, crate::SrxState::NotConfigured));
    }
}
