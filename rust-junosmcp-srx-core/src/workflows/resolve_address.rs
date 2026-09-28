//! `srx_resolve_address` — resolve a Junos address or address-set name
//! (global or zone-scoped, arbitrarily nested) to its concrete leaf values.
//!
//! # Deterministic core
//!
//! There is no Junos RPC that "resolves" an address-set — resolution is a
//! config-time concept. Asking the device to interpret set membership on our
//! behalf would introduce exactly the model/device ambiguity this project
//! avoids; instead the address-book **configuration** is fetched once and
//! nesting is resolved ourselves, deterministically, in Rust (see
//! [`crate::workflows::resolve`]).
//!
//! # RPC
//!
//! `get-configuration` with a hand-built subtree filter on
//! `security/address-book` (global) and `security/zones/security-zone/address-book`
//! (every zone), via [`crate::workflows::config_fetch::get_configuration_subtree`] —
//! `rustez::rpc::RpcExecutor::call()` only supports flat key/value args, so the
//! envelope is built by hand, the same technique `support_bundle::collect_per_type`
//! already uses.
//!
//! # Junos XML schema
//!
//! **Live-confirmed against `vsrx-ci` (2026-09-27, Junos 26.2R1.7)** via
//! `show configuration security address-book | display xml`: the global
//! `<security><address-book><name>...</name><address><name>...</name>
//! <ip-prefix>...</ip-prefix></address></address-book></security>` shape
//! below matches the real device reply exactly (the security hierarchy also
//! carries a `junos-es` YANG namespace in the real reply; parsing matches on
//! local element name only, via `roxmltree`, so the namespace doesn't
//! matter). The zone-scoped path (`zones/security-zone/address-book`) and
//! `address-set`/`range-address`/`wildcard-address`/`dns-name` shapes were
//! not independently live-verified — `vsrx-ci` has no zone-scoped or nested
//! address-book configured — and follow Juniper's published schema.
//!
//! ```xml
//! <configuration>
//!   <security>
//!     <address-book>
//!       <name>global</name>
//!       <address><name>host1</name><ip-prefix>10.0.0.1/32</ip-prefix></address>
//!       <address>
//!         <name>range1</name>
//!         <range-address>
//!           <name>10.0.0.10</name>
//!           <range-address-upper><name>10.0.0.20</name></range-address-upper>
//!         </range-address>
//!       </address>
//!       <address><name>wc1</name><wildcard-address><name>10.0.0.0/255.255.0.0</name></wildcard-address></address>
//!       <address><name>dns1</name><dns-name><name>example.com</name></dns-name></address>
//!       <address-set>
//!         <name>set1</name>
//!         <address><name>host1</name></address>
//!         <address-set><name>set2</name></address-set>
//!       </address-set>
//!     </address-book>
//!     <zones>
//!       <security-zone>
//!         <name>trust</name>
//!         <address-book>
//!           <address><name>trustnet</name><ip-prefix>192.168.1.0/24</ip-prefix></address>
//!         </address-book>
//!       </security-zone>
//!     </zones>
//!   </security>
//! </configuration>
//! ```

use crate::workflows::config_fetch::get_configuration_subtree;
use crate::workflows::resolve::{ConfigNode, resolve};
use crate::{SrxError, SrxToolResponse};
use ipnet::IpNet;
use rust_junosmcp_core::device_manager::PooledDevice;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Cap on flattened, resolved address-book members. A nested set exploding
/// past this is itself worth surfacing via `truncated`, not silently cut off.
pub const DEFAULT_ADDRESS_MEMBER_CAP: usize = 1000;

const FILTER: &str = "<security><address-book/><zones><security-zone><address-book/></security-zone></zones></security>";

// ── Public types ──────────────────────────────────────────────────────────────

/// Arguments for `srx_resolve_address`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = rust_junosmcp_core::schema_alias::router_name_alias)]
pub struct AddressResolveArgs {
    /// Device name (aliased as router_name).
    #[serde(alias = "router_name")]
    pub router: String,
    /// Address or address-set name to resolve.
    pub name: String,
    /// Zone whose address-book to search. Omit to search the global address-book.
    #[serde(default)]
    pub zone: Option<String>,
    /// Include raw XML from device in response. Default false.
    #[serde(default)]
    pub include_raw: bool,
}

/// Which address-book scope a name was resolved against.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AddressScope {
    /// The device's global address-book.
    Global,
    /// A zone's own address-book — either the zone's inline `address-book`
    /// stanza, or a separately named, top-level address-book `attach`ed to
    /// this zone (Percy M6, MEC-83: the original parser only ever
    /// recognised the book literally named `"global"` plus each zone's own
    /// inline book, so any other named top-level book — the common
    /// `attach { zone ...; }` shape — was silently invisible).
    Zone {
        /// Zone name.
        zone: String,
        /// Which book actually matched: the zone's own inline book, or the
        /// name of a top-level book attached to it.
        book: String,
    },
}

/// Whether the requested name is a single address or an address-set.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum AddressKind {
    /// A single address entry.
    Address,
    /// A named set of addresses (and/or other sets).
    AddressSet,
}

/// Concrete value of a resolved address leaf.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone)]
#[serde(tag = "value_kind", rename_all = "snake_case")]
pub enum AddressValue {
    /// An `ip-prefix` entry.
    Prefix {
        /// The prefix.
        #[schemars(with = "String")]
        prefix: IpNet,
    },
    /// A `range-address` entry.
    Range {
        /// Range start (inclusive).
        start: IpAddr,
        /// Range end (inclusive).
        end: IpAddr,
    },
    /// A `wildcard-address` entry, e.g. `10.0.0.0/255.255.0.0`. Not parsed
    /// into a prefix — Junos wildcard masks are not always contiguous.
    Wildcard {
        /// Raw `address/wildcard-mask` string.
        address: String,
    },
    /// A `dns-name` entry. Returned as-is; this tool never performs its own
    /// DNS resolution (no speculative behaviour, no non-deterministic output).
    Dns {
        /// Hostname.
        name: String,
    },
}

/// One flattened, resolved address leaf.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone)]
pub struct ResolvedAddress {
    /// Leaf address name.
    pub name: String,
    /// Leaf value.
    pub value: AddressValue,
    /// `false` if this address's own `<address>` element is `inactive` in
    /// the configuration (Percy H3, MEC-83 — applied here for the same
    /// reason as NAT rules: a deactivated object must not read the same as
    /// a live one). Does not track deactivation of an enclosing
    /// address-set on the resolution path.
    pub active: bool,
}

/// Result of resolving an address or address-set name.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct AddressResolution {
    /// The name as requested by the caller.
    pub requested: String,
    /// Which address-book scope it was resolved against.
    pub scope: AddressScope,
    /// Whether `requested` names a single address or a set.
    pub kind: AddressKind,
    /// Flattened, deduplicated leaves.
    pub members: Vec<ResolvedAddress>,
    /// True if `members` was cut short by [`DEFAULT_ADDRESS_MEMBER_CAP`].
    pub truncated: bool,
}

// ── `run()` — async entry point ───────────────────────────────────────────────

/// Fetch the address-book configuration and resolve `args.name` within it.
pub async fn run(
    device: &mut PooledDevice,
    args: AddressResolveArgs,
) -> Result<SrxToolResponse<AddressResolution>, SrxError> {
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
    let mut parsed = parse(&args.router, &args.name, args.zone.as_deref(), &reply)?;
    if args.include_raw {
        parsed = parsed.with_raw(reply);
    }
    Ok(parsed)
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse a `get-configuration` reply body and resolve `name` within the
/// requested scope. Pure, unit-testable entry point.
pub fn parse(
    router: &str,
    name: &str,
    zone: Option<&str>,
    reply_xml: &str,
) -> Result<SrxToolResponse<AddressResolution>, SrxError> {
    let re_nodes = crate::xml::multi_re_split(reply_xml)?;
    let mut node = None;
    for re_node in &re_nodes {
        let sanitized = crate::xml::sanitize_rustez_xml(&re_node.inner_xml);
        let doc = roxmltree::Document::parse(&sanitized)
            .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;
        if let Some((tag, message)) = crate::xml::rpc_error_parts(&doc) {
            if tag == "not-configured" {
                continue;
            }
            // Percy M5 (MEC-83): a real per-node error (e.g. permission
            // denied) must not be silently read as "no address-book
            // configured" — that hides addresses the device actually has.
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
            "no node returned address-book configuration without an error",
        ));
    };

    let books = parse_address_books(&node.inner_xml)?;

    let (map, scope, book_label): (
        &HashMap<String, ConfigNode<ResolvedAddress>>,
        AddressScope,
        String,
    ) = match zone {
        Some(z) => match books.resolve_zone(z) {
            Some((book_name, m)) => (
                m,
                AddressScope::Zone {
                    zone: z.to_string(),
                    book: book_name.clone(),
                },
                format!("address-book '{book_name}' (zone '{z}')"),
            ),
            None => {
                return Ok(SrxToolResponse::not_configured(format!(
                    "zone '{z}' has no address-book configured (no inline book, no book \
                         attached to it, and no global book)"
                )));
            }
        },
        None => {
            if books.global.is_empty() {
                return Ok(SrxToolResponse::not_configured(
                    "no global address-book configured",
                ));
            }
            (
                &books.global,
                AddressScope::Global,
                "global address-book".to_string(),
            )
        }
    };

    let kind = match map.get(name) {
        Some(ConfigNode::Leaf(_)) => AddressKind::Address,
        Some(ConfigNode::Set(_)) => AddressKind::AddressSet,
        None => {
            return Err(SrxError::ResolutionNameNotFound {
                router: router.to_string(),
                name: name.to_string(),
                book: book_label,
            });
        }
    };

    let (leaves, truncated) = resolve(router, map, name, &book_label, DEFAULT_ADDRESS_MEMBER_CAP)?;
    let members = leaves.into_iter().map(|(_, v)| v).collect();

    Ok(SrxToolResponse::active(AddressResolution {
        requested: name.to_string(),
        scope,
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

fn parse_address_value(addr_node: &roxmltree::Node<'_, '_>) -> Result<AddressValue, SrxError> {
    if let Some(prefix) = child_text(addr_node, "ip-prefix") {
        let net: IpNet = prefix
            .parse()
            .map_err(|_| SrxError::Parse(format!("invalid ip-prefix: {prefix}")))?;
        return Ok(AddressValue::Prefix { prefix: net });
    }
    if let Some(range_node) = addr_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "range-address")
    {
        let start = child_text(&range_node, "name")
            .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "range-address/name"))?;
        let upper_node = range_node
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "range-address-upper")
            .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "range-address-upper"))?;
        let end = child_text(&upper_node, "name").ok_or_else(|| {
            SrxError::schema_mismatch("get-configuration", "range-address-upper/name")
        })?;
        let start_ip: IpAddr = start
            .parse()
            .map_err(|_| SrxError::Parse(format!("invalid range start: {start}")))?;
        let end_ip: IpAddr = end
            .parse()
            .map_err(|_| SrxError::Parse(format!("invalid range end: {end}")))?;
        return Ok(AddressValue::Range {
            start: start_ip,
            end: end_ip,
        });
    }
    if let Some(wc_node) = addr_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "wildcard-address")
    {
        let address = child_text(&wc_node, "name").ok_or_else(|| {
            SrxError::schema_mismatch("get-configuration", "wildcard-address/name")
        })?;
        return Ok(AddressValue::Wildcard { address });
    }
    if let Some(dns_node) = addr_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "dns-name")
    {
        let name = child_text(&dns_node, "name")
            .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "dns-name/name"))?;
        return Ok(AddressValue::Dns { name });
    }
    Err(SrxError::schema_mismatch(
        "get-configuration",
        "address value (ip-prefix|range-address|wildcard-address|dns-name)",
    ))
}

fn parse_address_book(
    book_node: &roxmltree::Node<'_, '_>,
) -> Result<HashMap<String, ConfigNode<ResolvedAddress>>, SrxError> {
    let mut map = HashMap::new();
    for child in book_node.children().filter(|n| n.is_element()) {
        match child.tag_name().name() {
            "address" => {
                let name = child_text(&child, "name").ok_or_else(|| {
                    SrxError::schema_mismatch("get-configuration", "address/name")
                })?;
                let value = parse_address_value(&child)?;
                let active = child.attribute("inactive") != Some("inactive");
                map.insert(
                    name.clone(),
                    ConfigNode::Leaf(ResolvedAddress {
                        name,
                        value,
                        active,
                    }),
                );
            }
            "address-set" => {
                let name = child_text(&child, "name").ok_or_else(|| {
                    SrxError::schema_mismatch("get-configuration", "address-set/name")
                })?;
                let mut members = Vec::new();
                for m in child.children().filter(|n| n.is_element()) {
                    match m.tag_name().name() {
                        "address" | "address-set" => {
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
    Ok(map)
}

/// All address-book configuration parsed from a `get-configuration` reply,
/// split by scope. Percy M6 (MEC-83): the original parser only recognised
/// the book literally named `"global"` and each zone's own inline book — a
/// separately named, top-level book `attach`ed to a zone (the common
/// `security address-book corp-book { ...; attach { zone trust; } }` shape)
/// was parsed into neither map and so was completely invisible.
struct AddressBooks {
    /// The implicit book named `"global"` (or unnamed) — visible everywhere.
    global: HashMap<String, ConfigNode<ResolvedAddress>>,
    /// Each zone's own inline `<security-zone><address-book>` (unnamed).
    zone_inline: HashMap<String, HashMap<String, ConfigNode<ResolvedAddress>>>,
    /// Other top-level named books, keyed by book name.
    named_books: HashMap<String, HashMap<String, ConfigNode<ResolvedAddress>>>,
    /// zone -> name of a top-level book `attach`ed to it.
    attach: HashMap<String, String>,
}

impl AddressBooks {
    /// Resolve which book to search for `zone`, in the order Junos itself
    /// applies: the zone's own inline book, then a top-level book attached
    /// to it, then the implicit global book. Returns `(book_label, map)`.
    fn resolve_zone(
        &self,
        zone: &str,
    ) -> Option<(String, &HashMap<String, ConfigNode<ResolvedAddress>>)> {
        if let Some(m) = self.zone_inline.get(zone) {
            return Some((format!("{zone} (zone-inline)"), m));
        }
        if let Some(book_name) = self.attach.get(zone)
            && let Some(m) = self.named_books.get(book_name)
        {
            return Some((book_name.clone(), m));
        }
        if !self.global.is_empty() {
            return Some(("global".to_string(), &self.global));
        }
        None
    }
}

/// Walk the full `<configuration>` document and split address-books by scope.
fn parse_address_books(config_xml: &str) -> Result<AddressBooks, SrxError> {
    let sanitized = crate::xml::sanitize_rustez_xml(config_xml);
    let doc = roxmltree::Document::parse(&sanitized)
        .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;

    let mut global: HashMap<String, ConfigNode<ResolvedAddress>> = HashMap::new();
    let mut named_books: HashMap<String, HashMap<String, ConfigNode<ResolvedAddress>>> =
        HashMap::new();
    let mut attach: HashMap<String, String> = HashMap::new();

    for security in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "security")
    {
        for book in security
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "address-book")
        {
            let book_name = child_text(&book, "name").unwrap_or_default();
            if book_name == "global" || book_name.is_empty() {
                global.extend(parse_address_book(&book)?);
                continue;
            }
            for attach_node in book
                .children()
                .filter(|n| n.is_element() && n.tag_name().name() == "attach")
            {
                for zone_node in attach_node
                    .children()
                    .filter(|n| n.is_element() && n.tag_name().name() == "zone")
                {
                    if let Some(zone_name) = zone_node.text().map(|t| t.trim().to_string()) {
                        attach.insert(zone_name, book_name.clone());
                    }
                }
            }
            named_books.insert(book_name, parse_address_book(&book)?);
        }
    }

    let mut zone_inline: HashMap<String, HashMap<String, ConfigNode<ResolvedAddress>>> =
        HashMap::new();
    for zone_node in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "security-zone")
    {
        let zone_name = child_text(&zone_node, "name")
            .ok_or_else(|| SrxError::schema_mismatch("get-configuration", "security-zone/name"))?;
        if let Some(book) = zone_node
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "address-book")
        {
            zone_inline.insert(zone_name, parse_address_book(&book)?);
        }
    }

    Ok(AddressBooks {
        global,
        zone_inline,
        named_books,
        attach,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SrxState;
    use pretty_assertions::assert_eq;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/resolve_address")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()))
    }

    #[test]
    fn flat_global_address_resolves_to_itself() {
        let xml = fixture("flat_global.xml");
        let resp = parse("r1", "host1", None, &xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::Active);
        let data = resp.data.expect("data present");
        assert_eq!(data.kind, AddressKind::Address);
        assert_eq!(data.scope, AddressScope::Global);
        assert_eq!(data.members.len(), 1);
        assert_eq!(data.members[0].name, "host1");
        assert_eq!(
            data.members[0].value,
            AddressValue::Prefix {
                prefix: "10.0.0.1/32".parse().unwrap()
            }
        );
        assert!(!data.truncated);
    }

    #[test]
    fn zone_scoped_address_resolves() {
        let xml = fixture("zone_scoped.xml");
        let resp = parse("r1", "trustnet", Some("trust"), &xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::Active);
        let data = resp.data.expect("data present");
        assert_eq!(
            data.scope,
            AddressScope::Zone {
                zone: "trust".into(),
                book: "trust (zone-inline)".into(),
            }
        );
        assert_eq!(data.members[0].name, "trustnet");
    }

    #[test]
    fn two_level_nested_set_flattens() {
        let xml = fixture("nested_set.xml");
        let resp = parse("r1", "outer-set", None, &xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(data.kind, AddressKind::AddressSet);
        let names: Vec<_> = data.members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["host1", "net1"]);
    }

    #[test]
    fn mixed_set_of_addresses_and_sets() {
        let xml = fixture("mixed_set.xml");
        let resp = parse("r1", "mixed-set", None, &xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        let names: Vec<_> = data.members.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"host1"));
        assert!(names.contains(&"net1"));
    }

    #[test]
    fn range_address_parses_start_and_end() {
        let xml = fixture("range_address.xml");
        let resp = parse("r1", "range1", None, &xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(
            data.members[0].value,
            AddressValue::Range {
                start: "10.0.0.10".parse().unwrap(),
                end: "10.0.0.20".parse().unwrap(),
            }
        );
    }

    #[test]
    fn wildcard_address_kept_as_string() {
        let xml = fixture("wildcard_address.xml");
        let resp = parse("r1", "wc1", None, &xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(
            data.members[0].value,
            AddressValue::Wildcard {
                address: "10.0.0.0/255.255.0.0".into()
            }
        );
    }

    #[test]
    fn dns_name_address_not_resolved_locally() {
        let xml = fixture("dns_name_address.xml");
        let resp = parse("r1", "dns1", None, &xml).expect("parse should not error");
        let data = resp.data.expect("data present");
        assert_eq!(
            data.members[0].value,
            AddressValue::Dns {
                name: "example.com".into()
            }
        );
    }

    #[test]
    fn cyclic_set_is_rejected_not_looped() {
        let xml = fixture("cyclic_set.xml");
        let err = parse("r1", "set-a", None, &xml).expect_err("cycle must error, not loop");
        assert!(matches!(err, SrxError::ResolutionCycle { .. }), "{err}");
    }

    #[test]
    fn missing_global_address_book_is_not_configured() {
        let xml = "<configuration/>";
        let resp = parse("r1", "anything", None, xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::NotConfigured);
    }

    #[test]
    fn missing_zone_is_not_configured() {
        // No global book, no inline zone book, no attached book anywhere —
        // genuinely nothing to search.
        let xml = "<configuration/>";
        let resp = parse("r1", "host1", Some("no-such-zone"), xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::NotConfigured);
    }

    #[test]
    fn unconfigured_zone_falls_back_to_global_book() {
        // Percy M6 (MEC-83): the `"global"` book is implicitly visible in
        // every zone, including one Junos has no explicit knowledge of
        // (unlike a named, `attach`ed book, which requires a matching
        // zone) — so a zone with no inline or attached book, but a
        // populated global book, must still resolve against it rather than
        // reporting not_configured.
        let xml = fixture("flat_global.xml");
        let resp =
            parse("r1", "host1", Some("no-such-zone"), &xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::Active);
        let data = resp.data.expect("data present");
        assert_eq!(
            data.scope,
            AddressScope::Zone {
                zone: "no-such-zone".into(),
                book: "global".into(),
            }
        );
    }

    #[test]
    fn attached_named_book_is_resolved_for_its_zone() {
        // Percy M6 (MEC-83): a top-level address-book named something other
        // than "global", attached to a zone via `attach { zone trust; }`,
        // must resolve when that zone is queried — before the fix this
        // shape was parsed into neither the global map nor any zone map,
        // so it was completely invisible and the zone read as
        // not_configured.
        let xml = fixture("attached_named_book.xml");
        let resp = parse("r1", "h1", Some("trust"), &xml).expect("parse should not error");
        assert_eq!(resp.state, SrxState::Active);
        let data = resp.data.expect("data present");
        assert_eq!(
            data.scope,
            AddressScope::Zone {
                zone: "trust".into(),
                book: "corp-book".into(),
            }
        );
        assert_eq!(data.members[0].name, "h1");
    }

    #[test]
    fn per_node_permission_denied_errors_instead_of_reporting_not_configured() {
        // Percy M5 (MEC-83): both cluster nodes returning a real rpc-error
        // (not "not-configured") must surface as an error, not silently
        // report the address-book as absent.
        let xml = fixture("clustered_permission_denied.xml");
        let err = parse("r1", "host1", None, &xml).expect_err("must not report not_configured");
        assert!(matches!(err, SrxError::Rpc { .. }), "{err}");
        assert!(err.to_string().contains("access-denied"), "{err}");
    }

    #[test]
    fn unknown_name_in_existing_book_errors() {
        let xml = fixture("flat_global.xml");
        let err = parse("r1", "ghost", None, &xml).expect_err("must error");
        assert!(
            matches!(err, SrxError::ResolutionNameNotFound { .. }),
            "{err}"
        );
    }
}
