//! Closed enum of `problem_type` values accepted by
//! `collect_jtac_support_bundle`, plus the per-type RPC + log file lists.
//!
//! Capture-verified against Junos 24.4R1.9 on 2026-05-26 — see
//! `docs/superpowers/specs/2026-05-26-srxmcp-phase-3-cluster-health-support-bundle-design.md`
//! § "`problem_type` enum" for the source-of-truth table and the RPC name
//! corrections that landed during verification.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Closed set of problem categories. Multi-select is handled by the caller
/// (orchestrator accepts `Vec<ProblemType>` and unions the additional
/// artefact lists).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProblemType {
    ChassisCluster,
    Vpn,
    TrafficLoss,
    IdpAppid,
    Routing,
    /// Catch-all — uses `request support information | save` directly.
    /// Short-circuits other selections when present in a multi-select array.
    Generic,
}

/// Universal-baseline RPCs run for every bundle regardless of `problem_type`.
/// The orchestrator MUST include these in every tarball.
pub const BASELINE_RPCS: &[&str] = &[
    "get-configuration",
    "get-software-information",
    "get-system-uptime-information",
    "get-system-alarm-information",
];

/// Universal-baseline log files copied for every bundle regardless of
/// `problem_type`.
pub const BASELINE_LOGS: &[&str] = &["/var/log/messages"];

impl ProblemType {
    /// RPCs to capture **in addition to** [`BASELINE_RPCS`] for this
    /// problem type. Each RPC is the bare element name (no inner XML);
    /// see [`Self::additional_rpcs_with_args`] for the few that need args.
    pub fn additional_rpcs(self) -> &'static [&'static str] {
        match self {
            ProblemType::ChassisCluster => &[
                "get-chassis-cluster-status",
                "get-chassis-cluster-information",
                "get-chassis-cluster-interfaces",
                "get-chassis-cluster-statistics",
                "get-chassis-cluster-control-plane-statistics",
                "get-chassis-cluster-data-plane-statistics",
                "get-system-alarm-information",
            ],
            ProblemType::Vpn => &[
                "get-ike-security-associations-information",
                "get-ipsec-statistics-information",
                "get-security-associations-information",
            ],
            ProblemType::TrafficLoss => &[
                // get-flow-session-information with inner `<summary/>` is
                // captured by `additional_rpcs_with_args`.
                "get-flow-session-information",
                "get-interface-information",
                "get-firewall-information",
            ],
            ProblemType::IdpAppid => &[
                "get-idp-security-package-information",
                "get-appid-package-version",
            ],
            ProblemType::Routing => &[
                "get-route-summary-information",
                "get-bgp-summary-information",
                "get-ospf-neighbor-information",
                "get-route-engine-information",
            ],
            // generic uses `request support information | save` instead of
            // an RPC list — orchestrator special-cases this.
            ProblemType::Generic => &[],
        }
    }

    /// Optional per-type RPCs that require inner XML args. Returned as
    /// `(rpc_name, inner_xml)` tuples. Capture-verified 2026-05-26.
    pub fn additional_rpcs_with_args(self) -> &'static [(&'static str, &'static str)] {
        match self {
            ProblemType::TrafficLoss => &[
                // Returns `<flow-session-summary-information>` —
                // `get-flow-session-summary-information` is UNKNOWN on 24.4R1.9.
                ("get-flow-session-information", "<summary/>"),
            ],
            _ => &[],
        }
    }

    /// Log files to copy **in addition to** [`BASELINE_LOGS`] for this
    /// problem type.
    pub fn additional_logs(self) -> &'static [&'static str] {
        match self {
            ProblemType::ChassisCluster => &["/var/log/chassisd", "/var/log/jsrpd"],
            ProblemType::Vpn => &["/var/log/kmd"],
            ProblemType::TrafficLoss => &[],
            ProblemType::IdpAppid => &["/var/log/idpd", "/var/log/appid"],
            ProblemType::Routing => &["/var/log/rpd"],
            ProblemType::Generic => &[],
        }
    }
}
