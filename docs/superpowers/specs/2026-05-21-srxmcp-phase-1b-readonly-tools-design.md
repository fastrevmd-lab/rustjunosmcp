# `rust-srxmcp` Phase 1B — Read-only SRX status tools (v0.1.0)

**Date:** 2026-05-21
**Status:** Approved design — ready for implementation planning
**Repo:** `RustJunosMCP`
**Related:**
- `docs/superpowers/specs/2026-05-20-srx-mcp-strategy-design.md` — overall SRX endpoint strategy
- `docs/superpowers/specs/2026-05-20-srxmcp-phase-1a-scaffold-design.md` — Phase 1A scaffolding (shipped as `srxmcp-v0.0.1`)
- `SRX_RUSTJUNOSMCP_CAPABILITY_GAPS.md` — gap analysis, command references

## Goal

Populate the empty `rust-srxmcp-core` placeholder with four typed, read-only
SRX status tools. Bump the `rust-srxmcp` tool surface from 1 (`srxmcp_status`)
to 5. Ship as `srxmcp-v0.1.0`.

## Non-goals

- Write-path tools (IDP/AppID package management, cluster operations, upgrade).
  Those land in v0.2.0+ per the strategy doc's phased delivery table.
- Polling/wait helpers. Phase 1B tools are single-shot RPCs; `polling.rs`
  arrives with the first write tool.
- Audit log integration. All v0.1.0 tools are read-only.
- UTM, SecIntel, ATP Cloud, web filtering, anti-spam, SSL proxy sub-features
  beyond what `get_srx_security_services_status` reports as a sub-`state`.
  Full lifecycle tools for those features are out of scope (see strategy doc).

## Architecture

`rust-srxmcp-core` gains one workflow module per tool plus three small
shared modules (`error.rs`, `absence.rs`, `xml.rs`). Each workflow exposes a
single public `async fn run(&PooledDevice, args) -> Result<SrxToolResponse<T>, SrxError>`.

The four tools reuse `rust-junosmcp-core`'s `DeviceManager` + session pool
unchanged — no new SSH sessions per call, no new transport code. The
`rustnetconf` crate already pulls in `quick-xml`, which Phase 1B uses
directly for parsing.

### Crate layout (post-Phase 1B)

```text
rust-srxmcp-core/
├── src/
│   ├── lib.rs                       # pub uses for workflows + types
│   ├── error.rs                     # SrxError taxonomy
│   ├── xml.rs                       # multi_re_split(), find_child(), text_of()
│   ├── absence.rs                   # SrxState enum + helpers
│   └── workflows/
│       ├── mod.rs
│       ├── license.rs               # check_srx_feature_license + SrxLicensedFeature
│       ├── services_status.rs      # get_srx_security_services_status
│       ├── cluster_status.rs      # get_chassis_cluster_status
│       └── vpn_report.rs           # vpn_lifecycle_report
├── tests/
│   └── fixtures/
│       ├── license/                 # see Testing section
│       ├── services_status/
│       ├── cluster_status/
│       └── vpn_report/
└── Cargo.toml
```

`rust-srxmcp/src/server.rs` adds four `#[tool]` methods on `JmcpSrxHandler`
next to the existing `srxmcp_status`.

## Shared types

### `SrxToolResponse<T>` — uniform envelope

Every tool returns the same envelope. The `state` field is the LLM's branch
point between "device has this feature, here is the data" and "device does
not have this feature configured."

```rust
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct SrxToolResponse<T> {
    pub state: SrxState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_xml: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SrxState { Active, NotConfigured }
```

Invariants:
- `state == Active` ⇒ `data.is_some() && reason.is_none()`
- `state == NotConfigured` ⇒ `data.is_none() && reason.is_some()`
- `raw_xml` is independent: populated iff the caller passed `include_raw == true`.

Transport, parse, and schema-mismatch failures surface as MCP errors (RFC
6750/6749-aligned, matching the existing `rust-junosmcp` convention). They
never appear inside `SrxToolResponse`.

### `xml::multi_re_split` — multi-RE envelope helper

Junos wraps RPC replies from clustered devices in
`<multi-routing-engine-results><multi-routing-engine-item><re-name>node0</re-name>…`.
Standalone devices omit the wrapper. `multi_re_split` flattens this:

```rust
pub fn multi_re_split(root: &Element) -> Vec<(&str, &Element)>;
```

Clustered devices yield `[("node0", inner), ("node1", inner)]`. Standalone
devices yield a one-element vec keyed by `""`. Every workflow parser
operates on the per-node `inner` element and never has to know about the
envelope.

Lab evidence (captured 2026-05-21): `vSRX-test19-20` is a real chassis
cluster (Cluster ID 1, node0 primary / node1 secondary, RG 0+1 healthy);
the other five vSRX are standalone. Multiple commands (`show chassis
cluster status`, `show security ike sa`, `show services
application-identification version`, `show security idp
security-package-version`) confirm the `node0:` / `node1:` prefix pattern
on clustered devices.

### `absence::SrxState` helpers

```rust
pub fn active<T>(data: T) -> SrxToolResponse<T> { … }
pub fn not_configured<T>(reason: impl Into<String>) -> SrxToolResponse<T> { … }
pub fn with_raw<T>(resp: SrxToolResponse<T>, raw: String) -> SrxToolResponse<T> { … }
```

## The four tools

### Tool 1 — `check_srx_feature_license`

**Intent:** map a security-service intent (IDP, AppID, …) to the underlying
license artifact(s) so the LLM can answer "is this device entitled to run
IDP?" without parsing the raw license dump.

| | |
|---|---|
| NETCONF RPCs | `<get-license-summary-information/>`, `<get-license-key-information/>` |
| Input | `router: String`, `feature: SrxLicensedFeature`, `include_raw: bool = false` |
| `data` shape | `{feature, license_records: Vec<LicenseRecord>, counts: {used, installed, needed}, earliest_expiry: Option<DateTime>, all_permanent: bool}` |

```rust
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SrxLicensedFeature {
    Idp, AppId, UtmAntivirus, WebFiltering,
    AntiSpam, SecIntel, AtpCloud, SslProxy,
}
```

Each enum variant has a hard-coded list of license-record names it matches
against (kept in `workflows/license.rs`'s `feature_record_names()` map).
The match is case-insensitive substring against the `Feature` column.

**Absence rule:** if no license record matches the enum's mapping →
`state=not_configured` with `reason="<feature> not present in installed
licenses"`. The lab's eval/trial vSRX licenses (`Virtual Appliance`,
`VCPU Scale`, `Remote Access IPSec VPN Client`, `Remote Access Standard`)
will not match any `SrxLicensedFeature` variant, so all four lab calls
against `feature=Idp` etc. correctly return `state=not_configured` —
this is the intended behavior, not a bug.

### Tool 2 — `get_srx_security_services_status`

**Intent:** one call that says "what security services are active on this
device and what are their package versions / health?" The LLM uses it to
decide whether to recommend AppID/IDP updates, ATP enrollment, etc.

| | |
|---|---|
| NETCONF RPCs (concurrent via `tokio::try_join!`) | `<get-idp-security-package-version/>`, `<get-appid-application-version/>`, `<get-utm-anti-virus-status/>`, `<get-secintel-feed-summary/>`, `<get-atp-cloud-info/>` |
| Input | `router: String`, `include_raw: bool = false` |
| `data` shape | `{nodes: Vec<NodeServicesStatus>}` |

```rust
pub struct NodeServicesStatus {
    pub re_name: String, // "" for standalone, "node0"/"node1" for clusters
    pub idp:       SubServiceStatus<IdpInfo>,
    pub appid:     SubServiceStatus<AppIdInfo>,
    pub utm_av:    SubServiceStatus<UtmAvInfo>,
    pub secintel:  SubServiceStatus<SecIntelInfo>,
    pub atp_cloud: SubServiceStatus<AtpCloudInfo>,
}

pub struct SubServiceStatus<T> {
    pub state: SrxState,
    pub data: Option<T>,
    pub reason: Option<String>,
}
```

**Sub-service absence rule:** each sub-RPC is independently classified.
If a sub-RPC returns `application='not-configured'` or its equivalent
"feature not licensed" error, that sub-service's `state=not_configured`.
The parent call's `state` is `active` as long as the RPC channel works
at all (i.e. the device responded to at least one of the five sub-RPCs).

If **all five** sub-RPCs return `not-configured`, the parent call's
`state=not_configured` with `reason="no SRX security services
configured on this device"`.

**Lab expectations:** test10 returns `idp.state=active` with empty
versions (`Attack database version: N/A`) and `appid.state=active` with
`version: 0`. UTM/SecIntel/ATP likely all return `not_configured` on
vSRX. test19-20 returns the same content under each of `node0` and
`node1`.

### Tool 3 — `get_chassis_cluster_status`

**Intent:** the cluster topology + health snapshot, ready to feed into
chassis-cluster lifecycle work in v0.5.0.

| | |
|---|---|
| NETCONF RPC | `<get-chassis-cluster-status-information/>` |
| Input | `router: String`, `include_raw: bool = false` |
| `data` shape | `{cluster_id, nodes: Vec<ClusterNode>, redundancy_groups: Vec<RedundancyGroup>}` |

```rust
pub struct ClusterNode {
    pub name: String,        // "node0" / "node1"
    pub priority: u16,
    pub status: String,      // "primary" / "secondary" / "hold" / "lost" / "ineligible"
    pub monitor_failures: Vec<String>, // e.g. ["IF", "IP"], empty when "None"
}

pub struct RedundancyGroup {
    pub group_id: u16,
    pub failover_count: u32,
    pub members: Vec<RgMember>,
}

pub struct RgMember {
    pub node: String,            // "node0" / "node1"
    pub priority: u16,
    pub status: String,
    pub preempt: bool,
    pub manual: bool,
    pub monitor_failures: Vec<String>,
}
```

**Absence rule:** the RPC returns either an empty payload or a
`<rpc-error>` with `application='not-configured'` on standalone devices.
Both map to `state=not_configured`, `reason="chassis cluster disabled"`.

**Lab expectations:** test19-20 returns `state=active` with `cluster_id=1`,
two nodes (node0 priority 200 primary, node1 priority 100 secondary),
RG 0 and RG 1 both healthy, no monitor failures. The other five vSRX
return `state=not_configured`.

### Tool 4 — `vpn_lifecycle_report`

**Intent:** one call that correlates IKE (Phase 1) and IPsec (Phase 2)
state for VPN troubleshooting. Lets the LLM say "tunnel X is up but its
IPsec SA expires in 4 minutes" without two separate calls.

| | |
|---|---|
| NETCONF RPCs (concurrent) | `<get-ike-security-associations-information/>`, `<get-security-associations-information/>` |
| Input | `router: String`, `peer: Option<String>` (filter by remote IP), `tunnel: Option<String>` (filter by tunnel/st0 name), `include_raw: bool = false` |
| `data` shape | `{nodes: Vec<NodeVpnReport>}` |

```rust
pub struct NodeVpnReport {
    pub re_name: String,
    pub ike_sas: Vec<IkeSa>,
    pub ipsec_sas: Vec<IpsecSa>,
    pub correlations: Vec<VpnCorrelation>,
}

pub struct IkeSa {
    pub index: u64,
    pub remote_address: String,
    pub state: String,                  // "UP" / "MATURE" / "INITIATING" / …
    pub mode: String,                   // "Main" / "Aggressive"
    pub initiator_cookie: String,
    pub responder_cookie: String,
    pub lifetime_remaining_seconds: u64,
}

pub struct IpsecSa {
    pub tunnel_id: u32,
    pub name: Option<String>,           // e.g. "st0.0"
    pub gateway: String,
    pub inbound_spi: String,
    pub outbound_spi: String,
    pub lifetime_remaining_seconds: u64,
    pub lifetime_remaining_kilobytes: Option<u64>,
}

pub struct VpnCorrelation {
    pub ike_sa_index: u64,
    pub ipsec_sa_tunnel_ids: Vec<u32>,
}
```

**Correlation logic:** group IPsec SAs by `gateway` (remote address) and
match to IKE SAs by `remote_address`. Each `VpnCorrelation` is one IKE SA
plus the IPsec SAs that share its remote.

**Filters:** `peer` filters both IKE and IPsec sets by remote-address
substring match. `tunnel` filters the IPsec set by name substring. Filters
apply **before** correlation, so empty filters never produce orphan
correlations.

**Absence rule:** `state=active` whenever both RPCs succeed, even if both
arrays are empty (no active SAs is a valid VPN state — e.g. configured
but currently down). Only `application='not-configured'` on **both** RPCs
maps to `state=not_configured`, `reason="security ike/ipsec stanza
absent"`.

**Lab expectations (after Appendix A setup):** test10 returns
`state=active` with 1 IKE SA, 1 IPsec SA (lifetime ~3600s), 1 correlation
pointing at test11's IP. Other four standalone devices return
`state=active` with empty arrays.

## Data flow

```
client (LLM/CLI)
  │ HTTP POST /mcp + Bearer
  ▼
rust-srxmcp axum router
  │ rust-junosmcp-auth::tower::auth_layer → CallerCtx in request extensions
  ▼
rmcp dispatch → JmcpSrxHandler::<tool>
  │ rmcp::wrapper::Parameters<T> → typed args
  ▼
rust-srxmcp-core::workflows::<tool>::run(&PooledDevice, args)
  │ DeviceManager::get(router) → PooledDevice (reuses existing pool)
  ▼
device.rpc(RpcPayload::Xml("<get-…-information/>"))
  │ rustnetconf NETCONF <rpc>…</rpc> over the existing SSH session
  ▼
raw reply XML (String)
  │ xml::multi_re_split(root)
  │ per-node parsers produce typed structs
  │ absence detector inspects RPC error tag or content
  ▼
SrxToolResponse<T>
  │ serde_json → CallToolResult { content: [Text { text: <json> }] }
  ▼
client
```

### Invariants

1. **Pool reuse.** Each tool acquires a `PooledDevice` via the shared
   `DeviceManager`. Idle-timeout, keepalive, reaper behavior carries over
   unchanged from rust-junosmcp.
2. **One RPC per logical call where possible.** Cluster/license/vpn issue
   1–2 RPCs each. `services_status` fans out up to 5 sub-RPCs via
   `tokio::try_join!`; rustnetconf serializes them on the channel but
   await points keep the executor responsive.
3. **Absence detection runs against parsed XML**, never against text
   markers. Detection rule: missing top-level child + `<rpc-error>` with
   `<error-tag>application/not-configured</error-tag>` ⇒
   `state=not_configured`.
4. **`include_raw` is opt-in.** Default response excludes the raw XML.
   When `include_raw=true`, parsing still runs (so structured fields are
   always present) and the raw reply is moved into `raw_xml`.
5. **No write path.** None of the four tools open the config DB. The
   `rustez` 0.10.1 config-DB-open guard is observed but never tripped.

## Error handling

### `SrxError` taxonomy (`rust-srxmcp-core/src/error.rs`)

```rust
#[derive(thiserror::Error, Debug)]
pub enum SrxError {
    #[error("transport: {0}")]
    Transport(#[from] rust_junosmcp_core::DeviceError),

    #[error("rpc error: {tag} ({severity}) — {message}")]
    Rpc { tag: String, severity: String, message: String },

    #[error("xml parse: {0}")]
    Parse(String),

    #[error("schema mismatch in {rpc}: missing required element <{element}>")]
    SchemaMismatch { rpc: &'static str, element: &'static str },

    #[error("invalid input: {0}")]
    InvalidInput(String),
}
```

Variants split by what the operator can do about them:

| Variant | Cause | Operator action |
|---|---|---|
| `Transport` | SSH/NETCONF channel failure | Retry; check device reachability |
| `Rpc` | Junos `<rpc-error>` not classified as absence (e.g. permission denied) | Fix device-side config / token |
| `Parse` | Malformed XML, unexpected schema | File a bug with the captured raw XML |
| `SchemaMismatch` | RPC succeeded but reply shape unknown | Patch parser; ship a new fixture |
| `InvalidInput` | Empty router, unknown enum value | Fix caller args |

### MCP wire mapping

| Outcome | Wire response |
|---|---|
| RPC succeeds, content present | `CallToolResult { state: active, data, …}` |
| RPC succeeds, content absent / `application=not-configured` | `CallToolResult { state: not_configured, reason, …}` |
| RPC `<rpc-error>` with any other tag | `ErrorData::Rpc(…)` |
| Transport / parse / schema-mismatch | `ErrorData::Transport / Parse / SchemaMismatch` |
| Bad input | `ErrorData::InvalidInput` |

### Timeouts

Each tool uses the `PooledDevice`'s existing `rpc_timeout` (default 1
hour, settable via `POOL_RPC_TIMEOUT` env). The MCP per-call `timeout`
parameter remains the upper bound. `services_status`'s parallel sub-RPCs
share that single bound; if total elapsed exceeds it the workflow
returns `SrxError::Transport(DeviceError::Timeout)`.

### Partial-cluster failures

When a clustered device has one node down, the multi-RE envelope still
contains the live node's payload but the dead node may appear as
`<re-name>node1</re-name>…<rpc-error>…</rpc-error>`. The parser treats
per-node `<rpc-error>` as a per-node `state=not_configured` with
`reason="node unreachable"`. The tool-level `state` stays `active` as
long as at least one node responded with content.

### No audit log

All four tools are read-only and don't touch the config DB. The
existing `rust-junosmcp-core` audit logger is not wired into Phase 1B.
Audit integration lands with the first write tool in v0.2.0.

## Testing

### Unit tests — fixture-driven, deterministic

Each tool's `tests/fixtures/<tool>/` directory holds captured raw
NETCONF XML replies. Each parser test reads a fixture, invokes the
workflow's parse function directly (no SSH, no async runtime), and
asserts the resulting `SrxToolResponse<T>` matches an expected JSON
snapshot.

**Required fixtures:**

| Tool | Fixtures |
|---|---|
| `check_srx_feature_license` | (1) eval/trial license like the lab; (2) permanent license; (3) no installed feature licenses → `state=not_configured` |
| `get_srx_security_services_status` | (1) standalone, AppID=0, IDP=N/A (lab today); (2) clustered with both nodes responding; (3) one sub-RPC errors with `not-configured` |
| `get_chassis_cluster_status` | (1) standalone → `state=not_configured`; (2) lab cluster (test19-20 today): both nodes primary/secondary, RG 0+1 healthy; (3) failover state: one node down → per-node `state=not_configured` inside an otherwise active response |
| `vpn_lifecycle_report` | (1) no SAs (lab today); (2) active route-based tunnel (post-Appendix-A); (3) IKE present but IPsec absent (Phase-2 down); (4) `not-configured` (security stanza absent) |

All fixtures live in-repo, redacted of any secrets (the lab has none,
but the precedent matters for future hardware fixtures).

### Integration test — one live smoke per tool

`rust-srxmcp/tests/live_smoke.rs`, gated behind `#[ignore]`. Pulls
endpoint URL + token from `JMCP_SRX_LIVE_URL` and `JMCP_SRX_LIVE_TOKEN`.
Each test:

1. Calls the tool against a known device:
   - license / services_status → `vSRX-test10`
   - cluster_status → `vSRX-test19-20` (real cluster)
   - vpn_report → `vSRX-test10` (VPN peer per Appendix A)
2. Asserts `state` matches expectation.
3. Round-trips `include_raw=true` and asserts the raw string parses as
   valid XML.

Run manually as part of release sign-off:
`cargo test --test live_smoke -- --ignored`.

### TDD ordering (per tool)

1. Capture raw RPC reply from a lab device into a fixture file.
2. Write a failing parser test against the fixture.
3. Implement the parser to make it pass.
4. Repeat for the next fixture / state.
5. Wire the workflow function into `rust-srxmcp/src/server.rs` as a
   `#[tool]` method.
6. Add a workflow-level test that mocks `PooledDevice` (or splits the
   parse function so the test can drive it without I/O).
7. Manual live smoke against the LXC 601 deployment.

Coverage target: every variant of `SrxState` and every documented
sub-service has at least one passing fixture-based test before the
tool ships.

### CI

No changes to `.github/workflows/ci.yml`. Phase 1A's expanded fmt +
clippy package lists already cover `rust-srxmcp-core` and `rust-srxmcp`.
The `#[ignore]`d live smoke test is not picked up by CI.

## Sequencing and release

Phase 1B = one PR per tool, four total, all merged before tagging
`srxmcp-v0.1.0`. Order recommended:

1. **`get_chassis_cluster_status`** — simplest RPC, real lab smoke
   target (test19-20), exercises the multi-RE envelope and `SrxState`
   round-trip end-to-end. Good first integration milestone.
2. **`check_srx_feature_license`** — exercises the closed enum +
   absence rule; no multi-RE complications.
3. **`get_srx_security_services_status`** — exercises the concurrent
   sub-RPC pattern with `tokio::try_join!` and per-sub-service
   `SubServiceStatus<T>`. Most code volume.
4. **`vpn_lifecycle_report`** — requires the lab tunnel from Appendix A
   to be live before fixture (2) can be captured; defer to last so the
   tunnel work doesn't block the other three tools.

Each PR follows the existing repo workflow: feat branch → CI green →
two-stage review (spec compliance, then code quality) → rebase-merge →
deploy to LXC 601 → smoke. The tag `srxmcp-v0.1.0` lands after all
four are merged and smoked.

## Deployment

Same procedure as Phase 1A (LXC 601, scp + pct push, `systemctl
restart rust-srxmcp.service`). Pre-deploy check: stop the unit before
`pct push` to avoid `Text file busy` (per the existing memory note).
Post-deploy check: `rust-srxmcp --version` reports `0.1.0`.

No new env vars, no new ports, no changes to `/etc/jmcp/*`.

## Risks and tradeoffs

| Risk | Mitigation |
|---|---|
| Junos schema drift between versions (RPC reply fields renamed) | `SchemaMismatch` error carries the RPC name and missing element; new fixture + parser patch is a one-PR fix. |
| Optional sub-RPCs in `services_status` returning unfamiliar error tags on hardware SRX | Fixture (3) covers `not-configured`; if hardware uses a different tag, add to the absence detector's tag list. |
| Lab tunnel drift after Appendix A is applied | Capture the tunnel-up fixture (vpn fixture 2) immediately after configuring, before any other config change. |
| Schema differences between vSRX and hardware SRX for cluster output | Out of Phase 1B scope; if found, fix the parser to be schema-tolerant (treat missing optional fields as `None` rather than `SchemaMismatch`). |
| Increased token volume per tool response on clustered devices (× nodes) | `include_raw=false` default keeps responses small; per-node breakdown is necessary for cluster semantics anyway. |

## Out of scope

Same as the strategy doc:
- Write-path tools (IDP/AppID install, cluster operations, support
  bundle, flow trace, cluster upgrade)
- Cross-process pool sharing with `rust-junosmcp`
- Per-endpoint bearer token scoping
- UTM/SecIntel/ATP Cloud lifecycle tools beyond status reporting
- Republishing `rust-srxmcp-core` to crates.io

## Success criteria

- All four tools shipped, registered in `rust-srxmcp/src/server.rs`,
  visible via `tools/list` over MCP at `:30032`.
- Every tool has at least three fixture-driven unit tests covering
  `state=active`, `state=not_configured`, and at least one schema or
  filter edge case.
- Live smoke against the lab returns `state=active` for the expected
  tool/device pairs (cluster_status → test19-20; vpn_report → test10
  post-Appendix-A; license/services_status → test10).
- `rust-junosmcp` v0.6.2 on `:30031` remains healthy throughout
  deploy. No regression in the generic endpoint.
- Tag `srxmcp-v0.0.1` artifacts continue to build identically — the
  Phase 1B work does not touch any of the v0.0.1 surfaces other than
  bumping `rust-srxmcp-core`'s and `rust-srxmcp`'s `version` to
  `0.1.0`.

---

## Appendix A — Lab IPsec tunnel for `vpn_lifecycle_report` fixture (2)

Configure a route-based site-to-site IPsec tunnel between `vSRX-test10`
and `vSRX-test11` to give `vpn_lifecycle_report` an "active" smoke
target. Both ends must be applied and committed together.

### Inputs (fill in from `/etc/jmcp/devices.json` on LXC 601)

- `TEST10_IP` — outside / external IP of vSRX-test10
- `TEST11_IP` — outside / external IP of vSRX-test11
- `EXT_IFACE` — outside interface name on both devices (commonly `ge-0/0/0.0`)
- Inside-tunnel network: `192.0.2.0/30`
  - test10's `st0.0` address: `192.0.2.1/30`
  - test11's `st0.0` address: `192.0.2.2/30`

### `vSRX-test10` configuration

```text
set security ike proposal P1-AES256-SHA256-DH14 authentication-method pre-shared-keys
set security ike proposal P1-AES256-SHA256-DH14 dh-group group14
set security ike proposal P1-AES256-SHA256-DH14 authentication-algorithm sha-256
set security ike proposal P1-AES256-SHA256-DH14 encryption-algorithm aes-256-cbc
set security ike proposal P1-AES256-SHA256-DH14 lifetime-seconds 28800

set security ike policy IKE-POL-TEST11 mode main
set security ike policy IKE-POL-TEST11 proposals P1-AES256-SHA256-DH14
set security ike policy IKE-POL-TEST11 pre-shared-key ascii-text "lab-test10-test11-psk"

set security ike gateway GW-TEST11 ike-policy IKE-POL-TEST11
set security ike gateway GW-TEST11 address <TEST11_IP>
set security ike gateway GW-TEST11 external-interface <EXT_IFACE>
set security ike gateway GW-TEST11 version v2-only

set security ipsec proposal P2-AES256-SHA256 protocol esp
set security ipsec proposal P2-AES256-SHA256 authentication-algorithm hmac-sha-256-128
set security ipsec proposal P2-AES256-SHA256 encryption-algorithm aes-256-cbc
set security ipsec proposal P2-AES256-SHA256 lifetime-seconds 3600

set security ipsec policy IPSEC-POL-TEST11 perfect-forward-secrecy keys group14
set security ipsec policy IPSEC-POL-TEST11 proposals P2-AES256-SHA256

set security ipsec vpn VPN-TEST11 bind-interface st0.0
set security ipsec vpn VPN-TEST11 ike gateway GW-TEST11
set security ipsec vpn VPN-TEST11 ike ipsec-policy IPSEC-POL-TEST11
set security ipsec vpn VPN-TEST11 establish-tunnels immediately

set interfaces st0 unit 0 family inet address 192.0.2.1/30
set security zones security-zone vpn-zone interfaces st0.0

set routing-options static route 192.0.2.0/30 next-hop st0.0
```

### `vSRX-test11` configuration

Mirror image — same proposals, same policy names, swap `TEST10_IP`/`TEST11_IP`,
swap `st0.0` address to `192.0.2.2/30`, point gateway at `<TEST10_IP>`.

### Bring-up & verify

```text
test10> show security ike security-associations
test10> show security ipsec security-associations
```

Expected after both ends commit:
- 1 IKE SA in `UP`/`MATURE` state with remote = `<TEST11_IP>`
- 1 IPsec SA, tunnel id > 0, lifetime ~3600 s

Capture the raw NETCONF reply (`<get-ike-security-associations-information/>`
and `<get-security-associations-information/>`) into
`rust-srxmcp-core/tests/fixtures/vpn_report/active.xml` for fixture (2).

### Teardown (optional)

The tunnel can be left up indefinitely — it doesn't interfere with
other lab work. If teardown is desired, `delete security ike` +
`delete security ipsec` + `delete interfaces st0` + `delete routing-options
static route 192.0.2.0/30` on both ends.
