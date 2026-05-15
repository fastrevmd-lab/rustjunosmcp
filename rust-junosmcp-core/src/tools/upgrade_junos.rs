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
