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
