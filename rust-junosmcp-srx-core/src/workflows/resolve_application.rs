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

/// A port match: either a numeric single port/range, or a named service
/// reference (Percy M7, MEC-83). Junos accepts a symbolic port name (e.g.
/// referencing a service alias) in the same slot as a numeric port/range;
/// the original parser only accepted digits and errored on anything else —
/// and because that parse ran eagerly for *every* application in the
/// config, one application anywhere using a named port broke every
/// unrelated `srx_resolve_application` lookup.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PortSpec {
    /// A numeric single port or range.
    Numeric(PortRange),
    /// A named/symbolic port value that isn't a plain number.
    Named {
        /// The raw configured value.
        name: String,
    },
}

/// Where a resolved application entry came from (Percy M7, MEC-83).
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationSource {
    /// Read from the device's own configuration.
    Device,
    /// Not present on the device; filled from this crate's compiled-in
    /// `junos-*` defaults table (see module docs).
    BuiltinTable,
}

/// One flattened, resolved application leaf.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone)]
pub struct ResolvedApplication {
    /// Leaf application name. For a multi-`term` application, this is
    /// `"{application-name}#{term-name}"` — Percy M7 (MEC-83): each term is
    /// its own independent match (protocol/ports/ICMP fields), so folding
    /// them into one entry would silently union or overwrite criteria that
    /// Junos evaluates as alternatives.
    pub name: String,
    /// Protocol, e.g. `"tcp"`, `"udp"`, `"icmp"`.
    pub protocol: String,
    /// Source port match, if configured.
    pub source_port: Option<PortSpec>,
    /// Destination port match, if configured.
    pub destination_port: Option<PortSpec>,
    /// Session inactivity timeout in seconds, if configured.
    pub inactivity_timeout: Option<u32>,
    /// ICMP type, if `protocol` is `"icmp"`/`"icmp6"` and configured.
    pub icmp_type: Option<u8>,
    /// ICMP code, if `protocol` is `"icmp"`/`"icmp6"` and configured.
    pub icmp_code: Option<u8>,
    /// `false` if this application (or its `term`) is `inactive` in the
    /// configuration. Inactivity of an enclosing application-set is not
    /// reflected here.
    pub active: bool,
    /// Whether this entry came from the device or the compiled-in fallback
    /// table (MEC-53 §10 Q4) — the static `junos-*` table is otherwise
    /// indistinguishable from real device data.
    pub source: ApplicationSource,
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

fn static_junos_defaults<'a>() -> HashMap<String, ConfigNode<ApplicationLeaf<'a>>> {
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
                ConfigNode::Leaf(ApplicationLeaf::Static(ResolvedApplication {
                    name: (*name).to_string(),
                    protocol: (*protocol).to_string(),
                    source_port: None,
                    destination_port: port
                        .map(|(low, high)| PortSpec::Numeric(PortRange { low, high })),
                    inactivity_timeout: None,
                    icmp_type: None,
                    icmp_code: None,
                    active: true,
                    source: ApplicationSource::BuiltinTable,
                })),
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
    let mut node = None;
    for re_node in &re_nodes {
        let sanitized = crate::xml::sanitize_rustez_xml(&re_node.inner_xml);
        let probe = roxmltree::Document::parse(&sanitized)
            .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;
        if let Some((tag, message)) = crate::xml::rpc_error_parts(&probe) {
            if tag == "not-configured" {
                continue;
            }
            // Percy M5 (MEC-83): a real per-node error must not be silently
            // read as "no applications configured".
            return Err(SrxError::Rpc {
                tag,
                severity: "error".into(),
                message,
            });
        }
        node = Some(re_node);
        break;
    }
    let Some(node) = node else {
        return Ok(SrxToolResponse::not_configured(
            "no node returned applications configuration without an error",
        ));
    };

    let sanitized = crate::xml::sanitize_rustez_xml(&node.inner_xml);
    let doc = roxmltree::Document::parse(&sanitized)
        .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;

    // Percy M7 (MEC-83): the map holds an unparsed reference to each
    // device-sourced `<application>` element rather than eagerly parsing
    // every one up front. Eager parsing meant one application anywhere in
    // the config that this parser couldn't fully model (a `term`, a named
    // port, …) made `parse_applications` return `Err`, which broke *every*
    // unrelated lookup — "parse only the nodes the walk reaches".
    let mut map: HashMap<String, ConfigNode<ApplicationLeaf<'_>>> = HashMap::new();
    collect_applications(&doc, &mut map)?;

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
    let mut members = Vec::new();
    for (_, leaf) in leaves {
        match leaf {
            ApplicationLeaf::Static(a) => members.push(a),
            // Parsed here, lazily, only because the walk actually reached
            // this application (Percy M7, MEC-83).
            ApplicationLeaf::Device(app_node) => {
                members.extend(parse_application_node(&app_node)?);
            }
        }
    }

    Ok(SrxToolResponse::active(ApplicationResolution {
        requested: name.to_string(),
        kind,
        members,
        truncated,
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn child_text(node: &roxmltree::Node<'_, '_>, tag_name: &str) -> Option<String> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == tag_name)
        .and_then(|n| n.text())
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// `true` if `node` carries Junos's `inactive="inactive"` deactivation
/// attribute.
fn is_inactive(node: &roxmltree::Node<'_, '_>) -> bool {
    node.attribute("inactive") == Some("inactive")
}

/// Parse a port value. A plain number or `"low-high"` becomes
/// [`PortSpec::Numeric`]; anything else (a named/symbolic port) becomes
/// [`PortSpec::Named`] rather than an error (Percy M7, MEC-83) — see the
/// `PortSpec` doc comment for why this must never fail.
fn parse_port_spec(text: &str) -> PortSpec {
    if let Some((lo, hi)) = text.split_once('-')
        && let (Ok(low), Ok(high)) = (lo.trim().parse::<u16>(), hi.trim().parse::<u16>())
    {
        return PortSpec::Numeric(PortRange { low, high });
    }
    if let Ok(p) = text.trim().parse::<u16>() {
        return PortSpec::Numeric(PortRange { low: p, high: p });
    }
    PortSpec::Named {
        name: text.trim().to_string(),
    }
}

/// Core match fields shared by the whole-application and per-`term` parse
/// paths (protocol, ports, ICMP type/code, inactivity-timeout).
struct ApplicationFields {
    protocol: String,
    source_port: Option<PortSpec>,
    destination_port: Option<PortSpec>,
    inactivity_timeout: Option<u32>,
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
}

/// Children of an `<application>` (or one of its `<term>`s) this parser
/// understands. Percy R3 (MEC-378): anything else — `rpc-program-number`,
/// `application-protocol` (ALG), `uuid`, … — narrows or changes the match
/// in ways this tool can't represent, so the application fails closed
/// instead of reading as a plain protocol/port match. The lazy parse keeps
/// that failure scoped to lookups that actually reach this application.
const KNOWN_APPLICATION_CHILDREN: &[&str] = &[
    "name",
    "description",
    "protocol",
    "source-port",
    "destination-port",
    "inactivity-timeout",
    "icmp-type",
    "icmp-code",
    "icmp6-type",
    "icmp6-code",
];

fn reject_unknown_children(
    node: &roxmltree::Node<'_, '_>,
    extra_allowed: &[&str],
) -> Result<(), SrxError> {
    for child in node.children().filter(|n| n.is_element()) {
        let tag = child.tag_name().name();
        if !KNOWN_APPLICATION_CHILDREN.contains(&tag) && !extra_allowed.contains(&tag) {
            return Err(SrxError::Parse(format!(
                "unrecognised application child <{tag}>: refusing to report this \
                 application rather than silently drop a match criterion"
            )));
        }
    }
    Ok(())
}

/// Parse a `u8` ICMP field, accepting it under either its ICMPv4 or ICMPv6
/// tag. Both present is ambiguous and fails closed.
fn parse_icmp_field(
    node: &roxmltree::Node<'_, '_>,
    v4_tag: &str,
    v6_tag: &str,
) -> Result<Option<u8>, SrxError> {
    match (child_text(node, v4_tag), child_text(node, v6_tag)) {
        (Some(_), Some(_)) => Err(SrxError::Parse(format!(
            "application has both <{v4_tag}> and <{v6_tag}>"
        ))),
        (Some(t), None) | (None, Some(t)) => t
            .parse::<u8>()
            .map(Some)
            .map_err(|_| SrxError::Parse(format!("invalid {v4_tag}/{v6_tag}: {t}"))),
        (None, None) => Ok(None),
    }
}

/// Parse one application-shaped node's core match fields. Shared by the
/// whole-application and per-`term` parse paths.
fn parse_application_fields(node: &roxmltree::Node<'_, '_>) -> Result<ApplicationFields, SrxError> {
    reject_unknown_children(node, &[])?;
    let protocol = child_text(node, "protocol")
        .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "application/protocol"))?;
    let source_port = child_text(node, "source-port").map(|t| parse_port_spec(&t));
    let destination_port = child_text(node, "destination-port").map(|t| parse_port_spec(&t));
    let inactivity_timeout = child_text(node, "inactivity-timeout")
        .map(|t| {
            t.parse::<u32>()
                .map_err(|_| SrxError::Parse(format!("invalid inactivity-timeout: {t}")))
        })
        .transpose()?;
    let icmp_type = parse_icmp_field(node, "icmp-type", "icmp6-type")?;
    let icmp_code = parse_icmp_field(node, "icmp-code", "icmp6-code")?;
    Ok(ApplicationFields {
        protocol,
        source_port,
        destination_port,
        inactivity_timeout,
        icmp_type,
        icmp_code,
    })
}

/// Parse one device `<application>` element into one or more
/// [`ResolvedApplication`] entries. Percy M7 (MEC-83): an application with
/// one or more `<term>` children (each an independent protocol/port match,
/// same shape as a firewall filter term) expands into one entry per term
/// instead of the original parser's hard requirement for top-level
/// `<protocol>`/ports, which made any `term`-based application fail to
/// parse — and, before the lazy-parse fix above, fail *every* lookup.
fn parse_application_node(
    app_node: &roxmltree::Node<'_, '_>,
) -> Result<Vec<ResolvedApplication>, SrxError> {
    let name = child_text(app_node, "name")
        .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "application/name"))?;
    let app_active = !is_inactive(app_node);

    let terms: Vec<_> = app_node
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "term")
        .collect();

    if terms.is_empty() {
        let fields = parse_application_fields(app_node)?;
        return Ok(vec![ResolvedApplication {
            name,
            protocol: fields.protocol,
            source_port: fields.source_port,
            destination_port: fields.destination_port,
            inactivity_timeout: fields.inactivity_timeout,
            icmp_type: fields.icmp_type,
            icmp_code: fields.icmp_code,
            active: app_active,
            source: ApplicationSource::Device,
        }]);
    }

    // Only `term`s (plus name/description) may sit beside each other at the
    // top level of a term-based application; anything else fails closed.
    for child in app_node.children().filter(|n| n.is_element()) {
        let tag = child.tag_name().name();
        if !matches!(tag, "name" | "description" | "term") {
            return Err(SrxError::Parse(format!(
                "unrecognised child <{tag}> beside <term> in application '{name}'"
            )));
        }
    }
    let mut out = Vec::with_capacity(terms.len());
    for term in terms {
        let term_name = child_text(&term, "name").ok_or_else(|| {
            SrxError::schema_mismatch("get-configuration", "application/term/name")
        })?;
        let fields = parse_application_fields(&term)?;
        out.push(ResolvedApplication {
            name: format!("{name}#{term_name}"),
            protocol: fields.protocol,
            source_port: fields.source_port,
            destination_port: fields.destination_port,
            inactivity_timeout: fields.inactivity_timeout,
            icmp_type: fields.icmp_type,
            icmp_code: fields.icmp_code,
            active: app_active && !is_inactive(&term),
            source: ApplicationSource::Device,
        });
    }
    Ok(out)
}

/// One entry in the name→node map built from device configuration, before
/// the per-application fields are parsed (see `ApplicationLeaf` docs).
enum ApplicationLeaf<'a> {
    /// A device `<application>` element, parsed lazily.
    Device(roxmltree::Node<'a, 'a>),
    /// A pre-parsed static `junos-*` fallback entry.
    Static(ResolvedApplication),
}

impl Clone for ApplicationLeaf<'_> {
    fn clone(&self) -> Self {
        match self {
            Self::Device(n) => Self::Device(*n),
            Self::Static(a) => Self::Static(a.clone()),
        }
    }
}

fn collect_applications_container<'a>(
    container: &roxmltree::Node<'a, 'a>,
    map: &mut HashMap<String, ConfigNode<ApplicationLeaf<'a>>>,
) -> Result<(), SrxError> {
    for child in container.children().filter(|n| n.is_element()) {
        match child.tag_name().name() {
            "application" => {
                let name = child_text(&child, "name").ok_or_else(|| {
                    SrxError::schema_mismatch("get-configuration", "application/name")
                })?;
                map.insert(name, ConfigNode::Leaf(ApplicationLeaf::Device(child)));
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
fn collect_applications<'a>(
    doc: &'a roxmltree::Document<'a>,
    map: &mut HashMap<String, ConfigNode<ApplicationLeaf<'a>>>,
) -> Result<(), SrxError> {
    for apps in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "applications")
    {
        collect_applications_container(&apps, map)?;
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
            collect_applications_container(&apps, map)?;
        }
    }

    Ok(())
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
            Some(PortSpec::Numeric(PortRange {
                low: 443,
                high: 443
            }))
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
            Some(PortSpec::Numeric(PortRange { low: 80, high: 80 }))
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
            Some(PortSpec::Numeric(PortRange {
                low: 8443,
                high: 8443
            }))
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

    #[test]
    fn unrelated_lookup_unaffected_by_term_and_named_port_applications_elsewhere() {
        // Percy M7 (MEC-83): before the fix, `parse_applications` eagerly
        // parsed *every* `<application>` in the config up front — a
        // `term`-based application or a named (non-numeric) port anywhere
        // in the reply made the whole call return `Err`, so an unrelated
        // simple TCP application couldn't be resolved either. The walk must
        // only parse the node(s) it actually reaches.
        let xml = fixture("unrelated_lookup_with_term_application_elsewhere.xml");
        let resp = parse("r1", "simple-tcp", &xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.members.len(), 1);
        assert_eq!(
            data.members[0].destination_port,
            Some(PortSpec::Numeric(PortRange {
                low: 8080,
                high: 8080
            }))
        );
    }

    #[test]
    fn term_application_expands_to_one_entry_per_term() {
        let xml = fixture("unrelated_lookup_with_term_application_elsewhere.xml");
        let resp = parse("r1", "multi-term-app", &xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.members.len(), 2);
        assert_eq!(data.members[0].name, "multi-term-app#t1");
        assert_eq!(data.members[0].protocol, "tcp");
        assert_eq!(
            data.members[0].destination_port,
            Some(PortSpec::Numeric(PortRange {
                low: 8000,
                high: 8000
            }))
        );
        assert_eq!(data.members[1].name, "multi-term-app#t2");
        assert_eq!(data.members[1].protocol, "udp");
    }

    #[test]
    fn named_port_resolves_instead_of_erroring() {
        // Percy M7 (MEC-83): a symbolic destination-port value must become
        // `PortSpec::Named`, not a parse error.
        let xml = fixture("unrelated_lookup_with_term_application_elsewhere.xml");
        let resp = parse("r1", "named-port-app", &xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(
            data.members[0].destination_port,
            Some(PortSpec::Named {
                name: "ssh".to_string()
            })
        );
    }

    #[test]
    fn icmp_type_and_code_are_parsed() {
        let xml = fixture("icmp_application.xml");
        let resp = parse("r1", "custom-icmp", &xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.members[0].icmp_type, Some(8));
        assert_eq!(data.members[0].icmp_code, Some(0));
    }

    #[test]
    fn icmp6_type_is_parsed_not_dropped() {
        // Percy R3 (MEC-378): an echo-only ICMPv6 application must not read
        // as "all of ICMPv6" because <icmp6-type> was ignored.
        let xml = "<configuration><applications><application>\
            <name>v6-echo</name><protocol>icmp6</protocol>\
            <icmp6-type>128</icmp6-type><icmp6-code>0</icmp6-code>\
            </application></applications></configuration>";
        let resp = parse("r1", "v6-echo", xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.members[0].protocol, "icmp6");
        assert_eq!(data.members[0].icmp_type, Some(128));
        assert_eq!(data.members[0].icmp_code, Some(0));
    }

    #[test]
    fn unrecognised_application_child_fails_closed() {
        // Percy R3 (MEC-378): rpc-program-number / application-protocol
        // (ALG) change the match; silently dropping them made the
        // application look like a plain protocol/port match.
        for extra in [
            "<rpc-program-number>100003</rpc-program-number>",
            "<application-protocol>ftp</application-protocol>",
        ] {
            let xml = format!(
                "<configuration><applications><application>\
                 <name>odd</name><protocol>tcp</protocol>\
                 <destination-port>2049</destination-port>{extra}\
                 </application></applications></configuration>"
            );
            let err = parse("r1", "odd", &xml).expect_err("must fail closed");
            assert!(matches!(err, SrxError::Parse(_)), "{extra}: {err}");
        }
    }

    #[test]
    fn unrecognised_child_in_term_or_beside_terms_fails_closed() {
        let in_term = "<configuration><applications><application><name>t</name>\
            <term><name>a</name><protocol>tcp</protocol><alg>x</alg></term>\
            </application></applications></configuration>";
        assert!(parse("r1", "t", in_term).is_err());
        let beside = "<configuration><applications><application><name>t</name>\
            <application-protocol>ftp</application-protocol>\
            <term><name>a</name><protocol>tcp</protocol></term>\
            </application></applications></configuration>";
        assert!(parse("r1", "t", beside).is_err());
    }

    #[test]
    fn per_node_permission_denied_errors_instead_of_reporting_not_configured() {
        // Percy M5 (MEC-83): both cluster nodes returning a real rpc-error
        // must surface as an error, not silently report applications as
        // absent.
        let xml = fixture("clustered_permission_denied.xml");
        let err = parse("r1", "junos-https", &xml).expect_err("must not report not_configured");
        assert!(matches!(err, SrxError::Rpc { .. }), "{err}");
        assert!(err.to_string().contains("access-denied"), "{err}");
    }
}
