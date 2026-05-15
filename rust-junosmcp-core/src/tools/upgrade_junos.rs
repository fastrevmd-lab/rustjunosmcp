//! `upgrade_junos` MCP tool. Upgrades a standalone Junos device by
//! staging an image via transfer_file, installing it with
//! `request system software add ... reboot`, waiting for NETCONF to
//! reopen, and verifying `show version` matches `target_version`.
//!
//! See docs/superpowers/specs/2026-05-15-upgrade-junos-design.md.
//! Cluster (ISSU) support deferred to v2.

/// Parse the version string from `show version | match Junos:` output.
/// Looks for a line of the form `Junos: <version>` (case-sensitive,
/// whitespace tolerant) and returns the version token. Returns `None`
/// when no `Junos:` line is present.
///
/// In cluster output (`node0:\n...Junos:...\nnode1:\n...Junos:...`)
/// the first match wins; cluster detection runs upstream of this and
/// refuses with `UpgradeClusterUnsupported`, so we never reach the
/// second-node case in the destructive path.
pub fn parse_junos_version(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Junos:") {
            let v = rest.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Detect whether `show chassis cluster status` reports an active
/// chassis cluster. The standalone vSRX response is either an error
/// line (`error: Chassis cluster is not enabled.`) or absent entirely;
/// the active-cluster response contains a `Cluster ID:` line and per-
/// node rows (`node0`, `node1`). We treat the presence of `Cluster ID:`
/// as the canonical signal.
pub fn detect_cluster_active(output: &str) -> bool {
    output.lines().any(|line| {
        let t = line.trim();
        t.starts_with("Cluster ID:")
    })
}

/// Detect an active commit-confirmed rollback window from
/// `show system commit` output. Junos prints `commit confirmed,
/// rollback in <N>m<S>s` while the window is open. Returns the
/// remaining time in seconds, or `None` if no active window.
pub fn detect_active_commit_confirmed(output: &str) -> Option<u64> {
    for line in output.lines() {
        let t = line.trim();
        let needle = "rollback in ";
        if let Some(idx) = t.find(needle) {
            let tail = &t[idx + needle.len()..];
            let token: String = tail.chars().take_while(|c| !c.is_whitespace()).collect();
            return parse_rollback_duration(&token);
        }
    }
    None
}

fn parse_rollback_duration(token: &str) -> Option<u64> {
    let mut total_secs: u64 = 0;
    let mut num: u64 = 0;
    let mut have_num = false;
    for c in token.chars() {
        if let Some(d) = c.to_digit(10) {
            num = num.checked_mul(10)?.checked_add(d as u64)?;
            have_num = true;
        } else if c == 'm' {
            if !have_num {
                return None;
            }
            total_secs = total_secs.checked_add(num.checked_mul(60)?)?;
            num = 0;
            have_num = false;
        } else if c == 's' {
            if !have_num {
                return None;
            }
            total_secs = total_secs.checked_add(num)?;
            num = 0;
            have_num = false;
        } else {
            return None;
        }
    }
    if have_num {
        return None;
    }
    Some(total_secs)
}

#[cfg(test)]
mod cluster_tests {
    use super::*;

    const STANDALONE_NOT_CONFIGURED: &str = "\
error: Chassis cluster is not enabled.";

    const ACTIVE_CLUSTER: &str = "\
Monitor Failure codes:
    CS  Cold Sync monitoring        FL  Fabric Connection monitoring
    GR  GRES monitoring             HW  Hardware monitoring

Cluster ID: 1
Node                  Priority Status         Preempt Manual   Monitor-failures

Redundancy group: 0 , Failover count: 1
node0                 100      primary        no      no       None
node1                 1        secondary      no      no       None
";

    #[test]
    fn not_configured_is_standalone() {
        assert!(!detect_cluster_active(STANDALONE_NOT_CONFIGURED));
    }

    #[test]
    fn active_cluster_detected() {
        assert!(detect_cluster_active(ACTIVE_CLUSTER));
    }

    #[test]
    fn empty_output_is_standalone() {
        assert!(!detect_cluster_active(""));
    }

    #[test]
    fn unrelated_output_is_standalone() {
        assert!(!detect_cluster_active(
            "Hostname: vsrx-test18\nJunos: 25.4R1.12"
        ));
    }
}

#[cfg(test)]
mod parse_version_tests {
    use super::*;

    #[test]
    fn parses_vsrx_version() {
        let s = "Hostname: vsrx-test18\nModel: vsrx\nJunos: 24.4R1.9\n";
        assert_eq!(parse_junos_version(s).as_deref(), Some("24.4R1.9"));
    }

    #[test]
    fn parses_filtered_line() {
        let s = "Junos: 25.4R1.12";
        assert_eq!(parse_junos_version(s).as_deref(), Some("25.4R1.12"));
    }

    #[test]
    fn parses_mx_dash_x_release() {
        // MX-series flex-x releases use a trailing -X qualifier.
        let s = "Junos: 22.4R3-S2.5";
        assert_eq!(parse_junos_version(s).as_deref(), Some("22.4R3-S2.5"));
    }

    #[test]
    fn returns_none_when_no_junos_line() {
        assert!(parse_junos_version("Hostname: x\nModel: vsrx\n").is_none());
    }

    #[test]
    fn returns_none_on_empty() {
        assert!(parse_junos_version("").is_none());
    }

    #[test]
    fn tolerates_extra_whitespace() {
        let s = "   Junos:    25.4R1.12   \n";
        assert_eq!(parse_junos_version(s).as_deref(), Some("25.4R1.12"));
    }

    #[test]
    fn picks_first_junos_line_in_cluster_output() {
        let s = "node0:\nHostname: a\nJunos: 22.4R3.10\n\nnode1:\nJunos: 22.4R3.10";
        assert_eq!(parse_junos_version(s).as_deref(), Some("22.4R3.10"));
    }
}

#[cfg(test)]
mod commit_confirmed_tests {
    use super::*;

    #[test]
    fn no_rollback_line_returns_none() {
        let s = "0   2026-05-14 11:00:00 UTC by root via cli\n";
        assert!(detect_active_commit_confirmed(s).is_none());
    }

    #[test]
    fn empty_returns_none() {
        assert!(detect_active_commit_confirmed("").is_none());
    }

    #[test]
    fn detects_rollback_minutes_and_seconds() {
        let s = "commit confirmed, rollback in 9m30s\n0   2026-05-14 ...";
        let got = detect_active_commit_confirmed(s);
        assert_eq!(got, Some(570), "9*60 + 30 = 570, got {got:?}");
    }

    #[test]
    fn detects_rollback_seconds_only() {
        let s = "commit confirmed, rollback in 45s";
        assert_eq!(detect_active_commit_confirmed(s), Some(45));
    }

    #[test]
    fn detects_rollback_minutes_only() {
        let s = "commit confirmed, rollback in 5m";
        assert_eq!(detect_active_commit_confirmed(s), Some(300));
    }
}

use std::collections::BTreeMap;

/// Per-command line-set diff. `added` = lines present in `post` but not
/// `pre`; `removed` = lines present in `pre` but not `post`. Order
/// follows first-seen in the source string. Whitespace-only lines are
/// ignored.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BaselineDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

/// Compute a per-command diff of baseline outputs. Commands present in
/// only one side are reported with the full content in the appropriate
/// `added` or `removed` list. Commands present in neither side are
/// absent from the result.
pub fn diff_baseline(
    pre: &BTreeMap<String, String>,
    post: &BTreeMap<String, String>,
) -> BTreeMap<String, BaselineDiff> {
    let mut out: BTreeMap<String, BaselineDiff> = BTreeMap::new();
    let mut keys: std::collections::BTreeSet<&String> = std::collections::BTreeSet::new();
    keys.extend(pre.keys());
    keys.extend(post.keys());
    for k in keys {
        let pre_lines: Vec<&str> = pre
            .get(k)
            .map(|s| s.lines().map(str::trim).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default();
        let post_lines: Vec<&str> = post
            .get(k)
            .map(|s| s.lines().map(str::trim).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default();
        let pre_set: std::collections::HashSet<&str> = pre_lines.iter().copied().collect();
        let post_set: std::collections::HashSet<&str> = post_lines.iter().copied().collect();
        let added: Vec<String> = post_lines
            .iter()
            .filter(|l| !pre_set.contains(*l))
            .map(|s| s.to_string())
            .collect();
        let removed: Vec<String> = pre_lines
            .iter()
            .filter(|l| !post_set.contains(*l))
            .map(|s| s.to_string())
            .collect();
        out.insert(k.clone(), BaselineDiff { added, removed });
    }
    out
}

#[cfg(test)]
mod diff_tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn empty_baselines_produce_empty_diff() {
        let pre: BTreeMap<String, String> = BTreeMap::new();
        let post: BTreeMap<String, String> = BTreeMap::new();
        let diff = diff_baseline(&pre, &post);
        assert!(diff.is_empty());
    }

    #[test]
    fn equal_outputs_have_empty_added_and_removed() {
        let mut pre = BTreeMap::new();
        pre.insert("show version".to_string(), "Junos: 24.4R1.9".to_string());
        let post = pre.clone();
        let diff = diff_baseline(&pre, &post);
        let d = &diff["show version"];
        assert!(d.added.is_empty());
        assert!(d.removed.is_empty());
    }

    #[test]
    fn added_line_appears_in_added() {
        let mut pre = BTreeMap::new();
        let mut post = BTreeMap::new();
        pre.insert("show alarms".into(), "no alarms".into());
        post.insert(
            "show alarms".into(),
            "no alarms\n1 alarms currently active".into(),
        );
        let diff = diff_baseline(&pre, &post);
        let d = &diff["show alarms"];
        assert_eq!(d.added, vec!["1 alarms currently active".to_string()]);
        assert!(d.removed.is_empty());
    }

    #[test]
    fn removed_line_appears_in_removed() {
        let mut pre = BTreeMap::new();
        let mut post = BTreeMap::new();
        pre.insert(
            "show interfaces".into(),
            "ge-0/0/0 up up\nge-0/0/1 up up".into(),
        );
        post.insert("show interfaces".into(), "ge-0/0/0 up up".into());
        let diff = diff_baseline(&pre, &post);
        let d = &diff["show interfaces"];
        assert!(d.added.is_empty());
        assert_eq!(d.removed, vec!["ge-0/0/1 up up".to_string()]);
    }

    #[test]
    fn whitespace_only_lines_ignored() {
        let mut pre = BTreeMap::new();
        let mut post = BTreeMap::new();
        pre.insert("c".into(), "a\n   \nb".into());
        post.insert("c".into(), "a\nb".into());
        let diff = diff_baseline(&pre, &post);
        assert!(diff["c"].added.is_empty());
        assert!(diff["c"].removed.is_empty());
    }

    #[test]
    fn commands_only_in_post_are_all_added() {
        let pre: BTreeMap<String, String> = BTreeMap::new();
        let mut post = BTreeMap::new();
        post.insert("new cmd".into(), "x\ny".into());
        let diff = diff_baseline(&pre, &post);
        assert_eq!(
            diff["new cmd"].added,
            vec!["x".to_string(), "y".to_string()]
        );
    }
}

// ---------------------------------------------------------------------------
// Preflight types + evaluator
// ---------------------------------------------------------------------------

/// Minimum free-disk headroom on top of `2 × image_size`. Junos install
/// needs working space for unpack + new partition; 2× is a safe rule of
/// thumb on top of the local image size, plus 32 MiB for slack.
pub const UPGRADE_DISK_HEADROOM_BYTES: u64 = 32 * 1024 * 1024;

/// Estimated outage duration baked into the ConfirmationRequired
/// payload. Derived from the 2026-05-14 vSRX-test18 timing (7 min
/// total = 420 s) with a small headroom margin.
pub const ESTIMATED_OUTAGE_SECONDS: u64 = 420;

/// Raw outputs + local image facts handed to the pure preflight
/// evaluator. Everything I/O happens upstream; this struct is the
/// boundary between "talk to the world" and "decide what to do".
#[derive(Debug, Clone)]
pub struct PreflightFacts {
    pub cluster_status_output: String,
    pub version_output: String,
    pub commit_output: String,
    pub storage_output: String,
    pub local_image_size: u64,
    pub local_image_sha256: [u8; 32],
    pub image_basename: String,
}

/// The decision the pure evaluator returns. Each variant maps to a
/// concrete handle() outcome: an error, a skip-success, a confirmation
/// payload, or "go ahead".
#[derive(Debug)]
pub enum PreflightDecision {
    ClusterUnsupported,
    UnparseableVersion,
    UnparseableStorage,
    AlreadyAtTarget { current_version: String },
    CommitConfirmedActive { rollback_secs: u64 },
    InsufficientDisk { free: u64, required: u64 },
    ConfirmationRequired(serde_json::Value),
    Proceed,
}

/// Pure preflight decision. Order of checks (each short-circuits):
/// 1. Cluster → refuse (highest priority — never proceed on cluster)
/// 2. Version parseable
/// 3. Already-at-target → skip-success
/// 4. Active commit-confirmed → refuse
/// 5. Storage parseable + disk headroom OK
/// 6. confirm=false → ConfirmationRequired
/// 7. else → Proceed
pub fn evaluate_preflight(
    facts: &PreflightFacts,
    args: &crate::tools::UpgradeJunosArgs,
) -> PreflightDecision {
    if detect_cluster_active(&facts.cluster_status_output) {
        return PreflightDecision::ClusterUnsupported;
    }
    let current_version = match parse_junos_version(&facts.version_output) {
        Some(v) => v,
        None => return PreflightDecision::UnparseableVersion,
    };
    if current_version == args.target_version {
        return PreflightDecision::AlreadyAtTarget { current_version };
    }
    if let Some(rollback_secs) = detect_active_commit_confirmed(&facts.commit_output) {
        return PreflightDecision::CommitConfirmedActive { rollback_secs };
    }
    let free = match crate::tools::transfer_file::parse_storage_free_bytes(&facts.storage_output) {
        Ok(b) => b,
        Err(_) => return PreflightDecision::UnparseableStorage,
    };
    let required = facts
        .local_image_size
        .saturating_mul(2)
        .saturating_add(UPGRADE_DISK_HEADROOM_BYTES);
    if free < required {
        return PreflightDecision::InsufficientDisk { free, required };
    }
    if !args.confirm {
        let payload = serde_json::json!({
            "code": "confirmation_required",
            "router": args.router_name,
            "current_version": current_version,
            "target_version": args.target_version,
            "image_basename": facts.image_basename,
            "image_size_bytes": facts.local_image_size,
            "device_var_free_bytes": free,
            "estimated_outage_seconds": ESTIMATED_OUTAGE_SECONDS,
            "preflight_blockers": [],
            "warning": "DESTRUCTIVE: this will install a new Junos image and REBOOT the device, causing an outage of approximately 5–7 minutes. Re-call with confirm=true to proceed."
        });
        return PreflightDecision::ConfirmationRequired(payload);
    }
    PreflightDecision::Proceed
}

#[cfg(test)]
mod preflight_tests {
    use super::*;

    fn args() -> crate::tools::UpgradeJunosArgs {
        crate::tools::UpgradeJunosArgs {
            router_name: "vsrx-test10".into(),
            source_path: "junos-25.4R1.12.tgz".into(),
            target_version: "25.4R1.12".into(),
            confirm: false,
            timeout: 900,
            reboot_wait_secs: 480,
        }
    }

    fn baseline_facts() -> PreflightFacts {
        PreflightFacts {
            cluster_status_output: "error: Chassis cluster is not enabled.".into(),
            version_output: "Junos: 24.4R1.9".into(),
            commit_output: "0   2026-05-14 ...\n".into(),
            storage_output: "\
Filesystem  Size Used Avail Capacity Mounted on
/dev/x      10G  2.1G 7.0G  23%      /.mount/var
"
            .into(),
            local_image_size: 1_000_000_000,
            local_image_sha256: [0; 32],
            image_basename: "junos-25.4R1.12.tgz".into(),
        }
    }

    #[test]
    fn refuses_cluster_device() {
        let mut f = baseline_facts();
        f.cluster_status_output = "Cluster ID: 1\nnode0 primary".into();
        let d = evaluate_preflight(&f, &args());
        assert!(matches!(d, PreflightDecision::ClusterUnsupported));
    }

    #[test]
    fn returns_already_at_target_when_version_matches() {
        let mut f = baseline_facts();
        f.version_output = "Junos: 25.4R1.12".into();
        let d = evaluate_preflight(&f, &args());
        match d {
            PreflightDecision::AlreadyAtTarget { current_version } => {
                assert_eq!(current_version, "25.4R1.12");
            }
            other => panic!("expected AlreadyAtTarget, got {other:?}"),
        }
    }

    #[test]
    fn refuses_active_commit_confirmed() {
        let mut f = baseline_facts();
        f.commit_output = "commit confirmed, rollback in 9m30s\n".into();
        let d = evaluate_preflight(&f, &args());
        match d {
            PreflightDecision::CommitConfirmedActive { rollback_secs } => {
                assert_eq!(rollback_secs, 570);
            }
            other => panic!("expected CommitConfirmedActive, got {other:?}"),
        }
    }

    #[test]
    fn refuses_insufficient_disk_for_2x_plus_headroom() {
        let mut f = baseline_facts();
        f.local_image_size = 4_000_000_000;
        let d = evaluate_preflight(&f, &args());
        match d {
            PreflightDecision::InsufficientDisk { free, required } => {
                assert!(free < required, "free={free} required={required}");
            }
            other => panic!("expected InsufficientDisk, got {other:?}"),
        }
    }

    #[test]
    fn returns_confirmation_required_when_confirm_false() {
        let f = baseline_facts();
        let d = evaluate_preflight(&f, &args());
        match d {
            PreflightDecision::ConfirmationRequired(payload) => {
                assert_eq!(payload["router"], "vsrx-test10");
                assert_eq!(payload["current_version"], "24.4R1.9");
                assert_eq!(payload["target_version"], "25.4R1.12");
                assert_eq!(payload["image_basename"], "junos-25.4R1.12.tgz");
                assert_eq!(payload["image_size_bytes"], 1_000_000_000);
                assert!(payload["warning"].as_str().unwrap().contains("DESTRUCTIVE"));
                assert!(payload["warning"].as_str().unwrap().contains("REBOOT"));
            }
            other => panic!("expected ConfirmationRequired, got {other:?}"),
        }
    }

    #[test]
    fn returns_proceed_when_confirm_true_and_everything_ok() {
        let f = baseline_facts();
        let mut a = args();
        a.confirm = true;
        let d = evaluate_preflight(&f, &a);
        assert!(matches!(d, PreflightDecision::Proceed));
    }

    #[test]
    fn unparseable_version_yields_proceed_block() {
        let mut f = baseline_facts();
        f.version_output = "garbage no junos line".into();
        let d = evaluate_preflight(&f, &args());
        assert!(matches!(d, PreflightDecision::UnparseableVersion));
    }

    #[test]
    fn check_order_cluster_before_already_at_target() {
        let mut f = baseline_facts();
        f.cluster_status_output = "Cluster ID: 1\n".into();
        f.version_output = "Junos: 25.4R1.12".into();
        let d = evaluate_preflight(&f, &args());
        assert!(matches!(d, PreflightDecision::ClusterUnsupported));
    }
}

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::inventory::AuthConfig;
use crate::tools::transfer_file::{sha256_file, validate_source_basename, TransferConfig};
use crate::tools::UpgradeJunosArgs;
use std::sync::Arc;

/// Tool-level config. Holds the shared `TransferConfig` so that:
/// - `transfer_file` and `upgrade_junos` use the same per-router locks
/// - staging dir + known hosts paths are configured in one place
/// - the mockable `ScpRunner` is reachable when this tool calls into
///   `transfer_file::handle` for the actual image push
#[derive(Clone)]
pub struct UpgradeConfig {
    pub transfer_cfg: TransferConfig,
}

async fn gather_facts(
    router: &str,
    dm: Arc<DeviceManager>,
    image_basename: String,
    local_size: u64,
    local_sha: [u8; 32],
) -> Result<PreflightFacts, JmcpError> {
    let mut dev = dm.open(router).await?;

    let cluster_status_output =
        run_probe(&mut dev, "show chassis cluster status", "cluster_probe").await?;
    let version_output =
        run_probe(&mut dev, "show version | match Junos:", "version_probe").await?;
    let commit_output = run_probe(&mut dev, "show system commit", "commit_probe").await?;
    let storage_output = run_probe(
        &mut dev,
        "show system storage no-forwarding",
        "storage_probe",
    )
    .await?;

    Ok(PreflightFacts {
        cluster_status_output,
        version_output,
        commit_output,
        storage_output,
        local_image_size: local_size,
        local_image_sha256: local_sha,
        image_basename,
    })
}

async fn run_probe(
    dev: &mut crate::device_manager::PooledDevice,
    command: &str,
    phase: &'static str,
) -> Result<String, JmcpError> {
    dev.cli(command)
        .await
        .map_err(|e| JmcpError::DeviceProbeFailed {
            phase: phase.into(),
            message: e.to_string(),
        })
}

pub async fn handle(
    args: UpgradeJunosArgs,
    dm: Arc<DeviceManager>,
    cfg: UpgradeConfig,
) -> Result<serde_json::Value, JmcpError> {
    let timeout = std::time::Duration::from_secs(args.timeout);
    tokio::time::timeout(timeout, run(args, dm, cfg))
        .await
        .map_err(|_| JmcpError::UpgradeOuterTimeout(timeout))?
}

async fn run(
    args: UpgradeJunosArgs,
    dm: Arc<DeviceManager>,
    cfg: UpgradeConfig,
) -> Result<serde_json::Value, JmcpError> {
    // 1. Basename validation (same allowlist as transfer_file).
    validate_source_basename(&args.source_path)?;

    // 2. Inventory lookup + auth check up front. We snapshot what we
    //    need so the borrow drops before any await on dm.open().
    {
        let inv = dm.inventory();
        let entry = inv.get(&args.router_name)?;
        match &entry.auth {
            AuthConfig::Password { .. } => {
                return Err(JmcpError::UnsupportedAuth(args.router_name.clone()));
            }
            AuthConfig::SshKey { .. } => {}
        }
    }

    // 3. Staged file checks (mirror transfer_file pre-flight).
    let local_path = cfg.transfer_cfg.staging_dir.join(&args.source_path);
    let meta = std::fs::symlink_metadata(&local_path).map_err(|_| {
        JmcpError::BadSourcePath(format!(
            "staged file not found or unreadable: {}",
            local_path.display()
        ))
    })?;
    if meta.file_type().is_symlink() {
        return Err(JmcpError::BadSourcePath(format!(
            "staged path is a symlink, refusing to follow: {}",
            local_path.display()
        )));
    }
    if !meta.is_file() {
        return Err(JmcpError::BadSourcePath(format!(
            "staged path is not a regular file: {}",
            local_path.display()
        )));
    }

    // 4. Acquire per-router transfer lock (shared with transfer_file).
    let _permit = cfg
        .transfer_cfg
        .transfer_locks
        .acquire(&args.router_name)
        .await;

    // 5. Local sha256 + size (streamed, blocks of 64 KiB).
    let (local_sha, local_size) = sha256_file(&local_path).await?;

    // 6. Gather NETCONF facts. Stub until Task 9 wires it up.
    let facts = gather_facts(
        &args.router_name,
        dm.clone(),
        args.source_path.clone(),
        local_size,
        local_sha,
    )
    .await?;

    // 7. Pure preflight decision.
    dispatch_preflight(&args, &facts, dm.clone(), &cfg).await
}

/// Translate a PreflightDecision into a handle() outcome. Task 9
/// stubs the Proceed arm; Tasks 10-11 fill in the destructive path.
async fn dispatch_preflight(
    args: &UpgradeJunosArgs,
    facts: &PreflightFacts,
    _dm: Arc<DeviceManager>,
    _cfg: &UpgradeConfig,
) -> Result<serde_json::Value, JmcpError> {
    match evaluate_preflight(facts, args) {
        PreflightDecision::ClusterUnsupported => Err(JmcpError::UpgradeClusterUnsupported {
            router: args.router_name.clone(),
        }),
        PreflightDecision::UnparseableVersion => Err(JmcpError::DeviceProbeFailed {
            phase: "version_parse".into(),
            message: "could not parse Junos version from `show version`".into(),
        }),
        PreflightDecision::UnparseableStorage => Err(JmcpError::DeviceProbeFailed {
            phase: "storage_parse".into(),
            message: "could not parse free bytes from `show system storage`".into(),
        }),
        PreflightDecision::AlreadyAtTarget { current_version } => Ok(serde_json::json!({
            "status": "already_at_target",
            "router": args.router_name,
            "current_version": current_version,
            "target_version": args.target_version,
            "message": "device already running target version; no action taken"
        })),
        PreflightDecision::CommitConfirmedActive { rollback_secs } => {
            Err(JmcpError::UpgradeCommitConfirmedActive {
                router: args.router_name.clone(),
                rollback_secs,
            })
        }
        PreflightDecision::InsufficientDisk { free, required } => {
            Err(JmcpError::InsufficientDisk {
                free,
                required,
                message: format!(
                    "device '{}' /var/tmp (install needs 2× image + 32 MiB headroom)",
                    args.router_name
                ),
            })
        }
        PreflightDecision::ConfirmationRequired(payload) => {
            Err(JmcpError::ConfirmationRequired { payload })
        }
        PreflightDecision::Proceed => Err(JmcpError::Validation(
            "destructive path not yet implemented (Task 10/11)".into(),
        )),
    }
}

#[cfg(test)]
mod handle_early_exit_tests {
    use super::*;
    use crate::device_manager::DeviceManager;
    use crate::inventory::Inventory;
    use crate::tools::{transfer_file::TransferLocks, UpgradeJunosArgs};
    use std::io::Write;
    use std::sync::Arc;

    fn cfg(dir: &std::path::Path) -> UpgradeConfig {
        UpgradeConfig {
            transfer_cfg: crate::tools::transfer_file::TransferConfig {
                staging_dir: dir.to_path_buf(),
                known_hosts_file: "/etc/jmcp/known_hosts".into(),
                scp_runner: crate::tools::transfer_file::MockScpRunner::ok(),
                transfer_locks: Arc::new(TransferLocks::default()),
            },
        }
    }

    /// Holds the inventory plus the temp key file so the key's lifetime
    /// covers the test (Inventory::load checks key existence at parse time).
    struct InvWithKey {
        inv: Arc<Inventory>,
        _key: tempfile::NamedTempFile,
        _json: tempfile::NamedTempFile,
    }

    fn build_inv(json_tmpl: &str) -> InvWithKey {
        let key = tempfile::NamedTempFile::new().unwrap();
        let key_path = key.path().to_string_lossy().to_string();
        let json = json_tmpl.replace("__KEY__", &key_path);
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        InvWithKey {
            inv,
            _key: key,
            _json: f,
        }
    }

    fn args(router: &str, source: &str) -> UpgradeJunosArgs {
        UpgradeJunosArgs {
            router_name: router.into(),
            source_path: source.into(),
            target_version: "25.4R1.12".into(),
            confirm: false,
            timeout: 10,
            reboot_wait_secs: 5,
        }
    }

    #[tokio::test]
    async fn rejects_bad_basename() {
        let dir = tempfile::tempdir().unwrap();
        let env = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"ssh_key","private_key_path":"__KEY__"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(env.inv.clone()));
        let r = handle(args("r1", "../etc/passwd"), dm, cfg(dir.path())).await;
        assert!(matches!(r, Err(crate::error::JmcpError::BadSourcePath(_))));
    }

    #[tokio::test]
    async fn unknown_router_propagates() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("img.tgz"), b"abc").unwrap();
        let env = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"ssh_key","private_key_path":"__KEY__"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(env.inv.clone()));
        let r = handle(args("nope", "img.tgz"), dm, cfg(dir.path())).await;
        assert!(matches!(r, Err(crate::error::JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn rejects_password_auth_before_transfer() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("img.tgz"), b"abc").unwrap();
        let env = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(env.inv.clone()));
        let r = handle(args("r1", "img.tgz"), dm, cfg(dir.path())).await;
        assert!(matches!(r, Err(crate::error::JmcpError::UnsupportedAuth(ref s)) if s == "r1"));
    }

    #[tokio::test]
    async fn rejects_missing_staged_file() {
        let dir = tempfile::tempdir().unwrap();
        let env = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"ssh_key","private_key_path":"__KEY__"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(env.inv.clone()));
        let r = handle(args("r1", "missing.tgz"), dm, cfg(dir.path())).await;
        assert!(matches!(r, Err(crate::error::JmcpError::BadSourcePath(_))));
    }
}
