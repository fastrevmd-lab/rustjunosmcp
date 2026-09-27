//! `srx_resolve_application` — resolve a Junos application or
//! application-set name (including `junos-*` predefined defaults) to its
//! concrete protocol/port leaves.
//!
//! # RPC
//!
//! `get-configuration` with a hand-built subtree filter on `applications`
//! (user-defined) and `groups[name="junos-defaults"]/applications` (the
//! hidden-but-usually-readable group Junos ships predefined `junos-http`,
//! `junos-https`, etc. under), via
//! [`crate::workflows::config_fetch::get_configuration_subtree`].
//!
//! # `junos-defaults` visibility (MEC-53 §10 Q4 — live-confirmed negative)
//!
//! **Live-confirmed against `vsrx-ci` (2026-09-27, Junos 26.2R1.7)**: a
//! `get-configuration` filtered to `groups junos-defaults applications`
//! returned empty — the group is not exposed over NETCONF for the RPC user
//! available to this crate on this device. This is the spec's documented
//! negative case, now confirmed rather than hypothetical: the compiled-in
//! **static table** of the most common `junos-*` predefined applications
//! (below) is the primary source for predefined names on this class of
//! device, not a fallback of last resort. It is layered *under* whatever the
//! device does return, so a device that does expose the group (or overrides
//! a default) always wins. The static table is deliberately small (the
//! handful of defaults documented across Junos releases for decades);
//! anything not in it and not returned by the device resolves as not-found.
//!
//! # Junos XML schema (user-defined `<applications>` shape follows the
//! published schema; not independently live-verified — `vsrx-ci` has no
//! user-defined applications configured. The `<groups>` branch is confirmed
//! absent on this device per the above, so its shape is unverifiable here
//! and is included for completeness only.)
//!
//! ```xml
//! <configuration>
//!   <applications>
//!     <application>
//!       <name>my-app</name>
//!       <protocol>tcp</protocol>
//!       <destination-port>8443</destination-port>
//!     </application>
//!     <application-set>
//!       <name>my-set</name>
//!       <application><name>my-app</name></application>
//!       <application-set><name>other-set</name></application-set>
//!     </application-set>
//!   </applications>
//!   <groups>
//!     <name>junos-defaults</name>
//!     <applications>
//!       <application>
//!         <name>junos-http</name>
//!         <protocol>tcp</protocol>
//!         <destination-port>80</destination-port>
//!       </application>
//!     </applications>
//!   </groups>
//! </configuration>
//! ```

use crate::workflows::config_fetch::get_configuration_subtree;
use crate::workflows::resolve::{ConfigNode, resolve};
use crate::{SrxError, SrxToolResponse};
use rust_junosmcp_core::device_manager::PooledDevice;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cap on flattened, resolved application members. Application-sets are far
/// smaller than address-sets in practice.
pub const DEFAULT_APPLICATION_MEMBER_CAP: usize = 200;

const FILTER: &str = "<applications/><groups><name>junos-defaults</name><applications/></groups>";

// ── Public types ──────────────────────────────────────────────────────────────

/// Arguments for `srx_resolve_application`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = rust_junosmcp_core::schema_alias::router_name_alias)]
pub struct ApplicationResolveArgs {
    /// Device name (aliased as router_name).
    #[serde(alias = "router_name")]
    pub router: String,
    /// Application or application-set name to resolve.
    pub name: String,
    /// Include raw XML from device in response. Default false.
    #[serde(default)]
    pub include_raw: bool,
}

/// Whether the requested name is a single application or an application-set.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationKind {
    /// A single application entry.
    Application,
    /// A named set of applications (and/or other sets).
    ApplicationSet,
}

/// An inclusive port range. A single port is represented as `low == high`.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone, Copy)]
pub struct PortRange {
    /// Lower bound (inclusive).
    pub low: u16,
    /// Upper bound (inclusive).
    pub high: u16,
}

/// One flattened, resolved application leaf.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone)]
pub struct ResolvedApplication {
    /// Leaf application name.
    pub name: String,
    /// Protocol, e.g. `"tcp"`, `"udp"`, `"icmp"`.
    pub protocol: String,
    /// Source port match, if configured.
    pub source_port: Option<PortRange>,
    /// Destination port match, if configured.
    pub destination_port: Option<PortRange>,
    /// Session inactivity timeout in seconds, if configured.
    pub inactivity_timeout: Option<u32>,
}

/// Result of resolving an application or application-set name.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct ApplicationResolution {
    /// The name as requested by the caller.
    pub requested: String,
    /// Whether `requested` names a single application or a set.
    pub kind: ApplicationKind,
    /// Flattened, deduplicated leaves.
    pub members: Vec<ResolvedApplication>,
    /// True if `members` was cut short by [`DEFAULT_APPLICATION_MEMBER_CAP`].
    pub truncated: bool,
}

// ── `run()` — async entry point ───────────────────────────────────────────────

/// Fetch the applications configuration and resolve `args.name` within it.
pub async fn run(
    device: &mut PooledDevice,
    args: ApplicationResolveArgs,
) -> Result<SrxToolResponse<ApplicationResolution>, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    if args.name.trim().is_empty() {
        return Err(SrxError::InvalidInput("name must not be empty".into()));
    }
    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let reply = get_configuration_subtree(&mut exec, FILTER).await?;
    let mut parsed = parse(&args.router, &args.name, &reply)?;
    if args.include_raw {
        parsed = parsed.with_raw(reply);
    }
    Ok(parsed)
}

// ── Static junos-* defaults fallback ────────────────────────────────────────

/// Compiled-in fallback for the most common `junos-*` predefined
/// applications, used only when the device reply does not carry a readable
/// `junos-defaults` group (MEC-53 §10 Q4). These have been stable across
/// Junos releases for years; if a future release changes one, the live
/// config path (tried first) wins.
/// `(name, protocol, destination_port)` for one static `junos-*` default.
type JunosDefaultEntry = (&'static str, &'static str, Option<(u16, u16)>);

fn static_junos_defaults() -> HashMap<String, ConfigNode<ResolvedApplication>> {
    let entries: &[JunosDefaultEntry] = &[
        ("junos-http", "tcp", Some((80, 80))),
        ("junos-https", "tcp", Some((443, 443))),
        ("junos-ftp", "tcp", Some((21, 21))),
        ("junos-ssh", "tcp", Some((22, 22))),
        ("junos-smtp", "tcp", Some((25, 25))),
        ("junos-dns-udp", "udp", Some((53, 53))),
        ("junos-icmp-ping", "icmp", None),
    ];
    entries
        .iter()
        .map(|(name, protocol, port)| {
            (
                (*name).to_string(),
                ConfigNode::Leaf(ResolvedApplication {
                    name: (*name).to_string(),
                    protocol: (*protocol).to_string(),
                    source_port: None,
                    destination_port: port.map(|(low, high)| PortRange { low, high }),
                    inactivity_timeout: None,
                }),
            )
        })
        .collect()
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse a `get-configuration` reply body and resolve `name`. Pure,
/// unit-testable entry point.
pub fn parse(
    router: &str,
    name: &str,
    reply_xml: &str,
) -> Result<SrxToolResponse<ApplicationResolution>, SrxError> {
    let re_nodes = crate::xml::multi_re_split(reply_xml)?;
    let Some(node) = re_nodes.iter().find(|n| !contains_rpc_error(&n.inner_xml)) else {
        return Ok(SrxToolResponse::not_configured(
            "no node returned applications configuration without an error",
        ));
    };

    let mut map = parse_applications(&node.inner_xml)?;

    // Layer the static junos-* fallback under (not over) whatever the device
    // actually returned — a live definition always wins.
    for (k, v) in static_junos_defaults() {
        map.entry(k).or_insert(v);
    }

    let kind = match map.get(name) {
        Some(ConfigNode::Leaf(_)) => ApplicationKind::Application,
        Some(ConfigNode::Set(_)) => ApplicationKind::ApplicationSet,
        None => {
            return Err(SrxError::ResolutionNameNotFound {
                router: router.to_string(),
                name: name.to_string(),
                book: "applications".to_string(),
            });
        }
    };

    let (leaves, truncated) = resolve(
        router,
        &map,
        name,
        "applications",
        DEFAULT_APPLICATION_MEMBER_CAP,
    )?;
    let members = leaves.into_iter().map(|(_, v)| v).collect();

    Ok(SrxToolResponse::active(ApplicationResolution {
        requested: name.to_string(),
        kind,
        members,
        truncated,
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn contains_rpc_error(xml: &str) -> bool {
    xml.contains("<rpc-error>") || xml.contains("<nc:rpc-error>")
}

fn child_text(node: &roxmltree::Node<'_, '_>, tag_name: &str) -> Option<String> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == tag_name)
        .and_then(|n| n.text())
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Parse a single port value: `"80"` or `"1024-65535"`.
fn parse_port_range(text: &str) -> Result<PortRange, SrxError> {
    if let Some((lo, hi)) = text.split_once('-') {
        let low: u16 = lo
            .trim()
            .parse()
            .map_err(|_| SrxError::Parse(format!("invalid port range: {text}")))?;
        let high: u16 = hi
            .trim()
            .parse()
            .map_err(|_| SrxError::Parse(format!("invalid port range: {text}")))?;
        Ok(PortRange { low, high })
    } else {
        let p: u16 = text
            .trim()
            .parse()
            .map_err(|_| SrxError::Parse(format!("invalid port: {text}")))?;
        Ok(PortRange { low: p, high: p })
    }
}

fn parse_application_leaf(
    app_node: &roxmltree::Node<'_, '_>,
    name: String,
) -> Result<ResolvedApplication, SrxError> {
    let protocol = child_text(app_node, "protocol")
        .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "application/protocol"))?;
    let source_port = child_text(app_node, "source-port")
        .map(|t| parse_port_range(&t))
        .transpose()?;
    let destination_port = child_text(app_node, "destination-port")
        .map(|t| parse_port_range(&t))
        .transpose()?;
    let inactivity_timeout = child_text(app_node, "inactivity-timeout")
        .map(|t| {
            t.parse::<u32>()
                .map_err(|_| SrxError::Parse(format!("invalid inactivity-timeout: {t}")))
        })
        .transpose()?;
    Ok(ResolvedApplication {
        name,
        protocol,
        source_port,
        destination_port,
        inactivity_timeout,
    })
}

fn parse_applications_container(
    container: &roxmltree::Node<'_, '_>,
    map: &mut HashMap<String, ConfigNode<ResolvedApplication>>,
) -> Result<(), SrxError> {
    for child in container.children().filter(|n| n.is_element()) {
        match child.tag_name().name() {
            "application" => {
                let name = child_text(&child, "name").ok_or_else(|| {
                    SrxError::schema_mismatch("get-configuration", "application/name")
                })?;
                let leaf = parse_application_leaf(&child, name.clone())?;
                map.insert(name, ConfigNode::Leaf(leaf));
            }
            "application-set" => {
                let name = child_text(&child, "name").ok_or_else(|| {
                    SrxError::schema_mismatch("get-configuration", "application-set/name")
                })?;
                let mut members = Vec::new();
                for m in child.children().filter(|n| n.is_element()) {
                    match m.tag_name().name() {
                        "application" | "application-set" => {
                            if let Some(n) = child_text(&m, "name") {
                                members.push(n);
                            }
                        }
                        _ => {}
                    }
                }
                map.insert(name, ConfigNode::Set(members));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Walk the `<configuration>` document for `<applications>` (user-defined)
/// and `<groups name="junos-defaults"><applications>` (predefined, if the
/// device exposes it).
fn parse_applications(
    config_xml: &str,
) -> Result<HashMap<String, ConfigNode<ResolvedApplication>>, SrxError> {
    let sanitized = crate::xml::sanitize_rustez_xml(config_xml);
    let doc = roxmltree::Document::parse(&sanitized)
        .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;

    let mut map = HashMap::new();

    for apps in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "applications")
    {
        parse_applications_container(&apps, &mut map)?;
    }

    for group in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "groups")
    {
        let is_junos_defaults = child_text(&group, "name").as_deref() == Some("junos-defaults");
        if !is_junos_defaults {
            continue;
        }
        for apps in group
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "applications")
        {
            parse_applications_container(&apps, &mut map)?;
        }
    }

    Ok(map)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SrxState;
    use pretty_assertions::assert_eq;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/resolve_application")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()))
    }

    #[test]
    fn junos_predefined_resolves_from_live_group() {
        let xml = fixture("junos_https_live.xml");
        let resp = parse("r1", "junos-https", &xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.kind, ApplicationKind::Application);
        assert_eq!(
            data.members[0].destination_port,
            Some(PortRange {
                low: 443,
                high: 443
            })
        );
    }

    #[test]
    fn junos_predefined_falls_back_to_static_table_when_group_absent() {
        // No <groups> element at all in this fixture — junos-defaults is not
        // exposed by the device (MEC-53 §10 Q4 negative case).
        let xml = "<configuration><applications/></configuration>";
        let resp = parse("r1", "junos-http", xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.members[0].protocol, "tcp");
        assert_eq!(
            data.members[0].destination_port,
            Some(PortRange { low: 80, high: 80 })
        );
    }

    #[test]
    fn user_defined_single_application() {
        let xml = fixture("user_defined_single.xml");
        let resp = parse("r1", "internal-billing-api", &xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.members[0].protocol, "tcp");
        assert_eq!(
            data.members[0].destination_port,
            Some(PortRange {
                low: 8443,
                high: 8443
            })
        );
    }

    #[test]
    fn two_level_application_set_flattens() {
        let xml = fixture("nested_set.xml");
        let resp = parse("r1", "outer-set", &xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.kind, ApplicationKind::ApplicationSet);
        let names: Vec<_> = data.members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["app1"]);
    }

    #[test]
    fn mixed_predefined_and_user_defined_set() {
        let xml = fixture("mixed_set.xml");
        let resp = parse("r1", "mixed-set", &xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        let names: Vec<_> = data.members.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"app1"));
        assert!(names.contains(&"junos-https"));
    }

    #[test]
    fn icmp_application_has_no_ports() {
        let xml = fixture("icmp_application.xml");
        let resp = parse("r1", "custom-icmp", &xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.members[0].protocol, "icmp");
        assert!(data.members[0].source_port.is_none());
        assert!(data.members[0].destination_port.is_none());
    }

    #[test]
    fn cyclic_application_set_is_rejected() {
        let xml = fixture("cyclic_set.xml");
        let err = parse("r1", "set-a", &xml).expect_err("cycle must error");
        assert!(matches!(err, SrxError::ResolutionCycle { .. }), "{err}");
    }

    #[test]
    fn unknown_name_errors() {
        let xml = "<configuration><applications/></configuration>";
        let err = parse("r1", "totally-unknown-app", xml).expect_err("must error");
        assert!(
            matches!(err, SrxError::ResolutionNameNotFound { .. }),
            "{err}"
        );
    }

    #[test]
    fn state_is_active_not_not_configured_for_static_fallback_only() {
        let xml = "<configuration><applications/></configuration>";
        let resp = parse("r1", "junos-ssh", xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::Active);
    }
}
