# SRX MCP Endpoint Strategy

**Date:** 2026-05-20
**Status:** Approved design — ready for implementation planning
**Repo:** `RustJunosMCP`
**Related:** `SRX_RUSTJUNOSMCP_CAPABILITY_GAPS.md`

## Problem

`rust-junosmcp` is a strong generic Junos MCP bridge but cannot drive SRX-specific
workflows as typed, validated, stateful operations. Operators can run the raw
commands today, but there is no first-class tool for IDP/AppID signature lifecycle,
chassis cluster operations, VPN health, flow tracing, ATP/SecIntel, support
bundles, or cluster-aware upgrades. The capability gaps document identifies ~27
candidate workflows.

Adding all of these to the existing `rust-junosmcp` binary would:

1. Push the tool surface past ~25 tools, where LLM tool selection accuracy degrades.
2. Bloat the generic Junos MCP for users who don't operate SRX devices.
3. Mix domains — generic Junos primitives vs SRX-specific workflows — that
   evolve at different velocities.

## Decision

Add a second, **opt-in** MCP binary `rust-srxmcp` to the same Cargo workspace.
It reuses the existing `rust-junosmcp-core` transport, auth, pool, and inventory
infrastructure via a path dependency and exposes only SRX-specific workflows on
its own HTTP endpoint (`:30032` by default). Users who do not manage SRX devices
build, deploy, and run nothing extra.

## Architectural choices and rationale

### Why two binaries in one workspace, not one bloated binary

- LLM tool budget. Going from 14 → 24+ tools on one endpoint degrades selection.
- Two independent tool surfaces let clients mount only what each project needs
  in `.mcp.json`.
- Generic Junos work and SRX work have different release cadences.

### Why one workspace, not a sidecar repo

- All the heavy infrastructure (auth, session pool, NETCONF transport,
  `transfer_file`, staging, blocklist, audit log) already lives in
  `rust-junosmcp-core`. Reusing it via a path dep is cheaper and lower-risk than
  republishing crates and managing version drift across two repos.
- The upstream-parity goal for `rust-junosmcp` (relative to
  `juniper/junos-mcp-server`) is no longer strict, so co-locating SRX code in
  the same repo is acceptable.

### Why asymmetric reuse, not a shared `mcp-shared` crate

- `rust-junosmcp-core` already contains the right primitives. Splitting it
  into a third "shared" crate is a non-trivial refactor of v0.5.10 with
  regression risk. The refactor can happen later, when symmetry is actually
  needed.
- `rust-srxmcp-core` depends on `rust-junosmcp-core`; nothing in
  `rust-junosmcp-core` depends on `rust-srxmcp-core`. Generic users compile
  zero SRX code.

### Why opt-in via `default-members`, not a Cargo feature flag

- Feature flags would force `rust-junosmcp` itself to know about SRX
  (`--features srx`), which leaks the SRX surface into the generic crate.
- `default-members` cleanly excludes the SRX crates from `cargo build` /
  `cargo test` without args. `cargo build --workspace` opts into everything.
- Release artifacts are produced independently per binary.

## Workspace layout

```text
RustJunosMCP/
├── Cargo.toml                    # workspace root
├── rust-junosmcp/                # existing generic binary
├── rust-junosmcp-core/           # existing shared lib (no SRX deps)
├── rust-srxmcp/                  # NEW — opt-in SRX binary
└── rust-srxmcp-core/             # NEW — opt-in SRX workflow lib
```

Workspace `Cargo.toml`:

```toml
[workspace]
members = [
    "rust-junosmcp",
    "rust-junosmcp-core",
    "rust-srxmcp",
    "rust-srxmcp-core",
]
default-members = [
    "rust-junosmcp",
    "rust-junosmcp-core",
]
resolver = "2"
```

Generic users running `cargo build` get exactly what they get today. SRX
operators run `cargo build --workspace` or `cargo build -p rust-srxmcp`.

## Components

### Existing — reused unchanged

`rust-junosmcp-core` provides everything `rust-srxmcp` needs:

- `DeviceManager` + session pool
- `Inventory` loading from `/etc/jmcp/devices.json`
- `AuthLayer` (bearer token, RFC 6750 + RFC 6749 error bodies)
- NETCONF transport via `rustnetconf`
- `transfer_file` + staging directory + safe-basename rules
- Blocklist filter
- Audit logger
- SIGHUP hot-reload

### New crate `rust-srxmcp-core`

```text
rust-srxmcp-core/
├── src/
│   ├── lib.rs
│   ├── workflows/
│   │   ├── mod.rs
│   │   ├── license.rs                 # check_srx_feature_license
│   │   ├── services_status.rs         # get_srx_security_services_status
│   │   ├── cluster_status.rs          # get_chassis_cluster_status
│   │   ├── cluster_health.rs          # validate_chassis_cluster_health
│   │   ├── vpn_report.rs              # vpn_lifecycle_report
│   │   ├── idp_package.rs             # manage_idp_security_package
│   │   ├── appid_package.rs           # manage_appid_signature_package
│   │   ├── support_bundle.rs          # collect_jtac_support_bundle
│   │   ├── flow_trace.rs              # run_flow_trace
│   │   └── cluster_upgrade.rs         # upgrade_srx_chassis_cluster
│   ├── parsers/
│   │   ├── mod.rs
│   │   ├── idp_version.rs
│   │   ├── appid_version.rs
│   │   ├── ike_sa.rs
│   │   ├── ipsec_sa.rs
│   │   ├── cluster.rs
│   │   ├── license.rs
│   │   └── services.rs
│   ├── precheck.rs                    # license/cluster/version preconditions
│   └── polling.rs                     # generic poll-with-timeout for status RPCs
└── Cargo.toml                         # path dep on rust-junosmcp-core
```

Parsers prefer Junos XML RPC output (`<rpc>...<format>xml</format></rpc>`)
where available; fall back to text parsing for commands that don't emit
structured output.

### New binary `rust-srxmcp`

```text
rust-srxmcp/
├── src/
│   ├── main.rs        # server bootstrap, mirrors rust-junosmcp/src/main.rs
│   └── server.rs      # SERVER_TOOLS list of 10 SRX tools
└── Cargo.toml         # path deps: rust-srxmcp-core, rust-junosmcp-core
```

Environment:

- `JMCP_SRX_HTTP_PORT` — default `30032`
- `JMCP_TOKENS_PATH` — shared with `rust-junosmcp`, default `/etc/jmcp/tokens.json`
- `JMCP_DEVICES_PATH` — shared, default `/etc/jmcp/devices.json`
- Other env vars (audit log path, blocklist, staging dir) — same as generic

## Tool surface (v0.1.0 target)

Read-only (Phase 1):

1. `check_srx_feature_license(router, feature)` — maps license entitlement to feature.
2. `get_srx_security_services_status(router)` — summary of IDP/AppID/UTM/SecIntel/ATP.
3. `get_chassis_cluster_status(router)` — RG state, node priorities, control/fabric links.
4. `vpn_lifecycle_report(router, peer?, tunnel?)` — IKE + IPsec SA correlation.

Multi-step write (Phases 2–3):

5. `manage_idp_security_package(router, action, version?, offline_package?)`
6. `manage_appid_signature_package(router, action, version?)`
7. `validate_chassis_cluster_health(router)`
8. `collect_jtac_support_bundle(router, problem_type, include_logs, redact)`

Destructive (Phases 4–5):

9. `run_flow_trace(router, source, destination?, duration_seconds, flags, auto_cleanup)`
10. `upgrade_srx_chassis_cluster(router, image, target_version, mode, confirm)`

All destructive tools follow the existing two-call confirm pattern from
`upgrade_junos`, use commit-confirmed where applicable, log to the audit trail,
and clean up on failure.

## Calls made inside the design

- **`fetch_file` is a generic primitive, not SRX-specific.** It ships in
  `rust-junosmcp` v0.6.0 (Phase 0). Workflows that need fetched files (support
  bundle, PKI export, packet captures, generated CSRs) document or chain through
  it from the SRX endpoint.
- **Naming:** `rust-srxmcp` binary, `rust-srxmcp-core` lib. Mirrors existing.
- **Port:** `:30032` by default, configurable via `JMCP_SRX_HTTP_PORT`.
- **Container:** Same LXC 601, second systemd unit `rust-srxmcp.service`. Both
  reload via `systemctl kill -s HUP`. Shared `/etc/jmcp/`.
- **Auth:** Same `tokens.json` and bearer token across both endpoints.
  Per-endpoint scoping deferred until there is a concrete need.
- **Versioning:** `rust-srxmcp` starts at `0.1.0`, independent of
  `rust-junosmcp` version. Git tags become endpoint-prefixed:
  `junosmcp-v0.6.0`, `srxmcp-v0.1.0`.
- **Repo name:** Stays `RustJunosMCP`. README adds an "Optional: SRX endpoint"
  section.

## Sequencing (phased delivery)

Each phase = one PR + one release + one LXC 601 deploy.

| Phase | Scope | Release |
|---|---|---|
| 0 | `fetch_file` in generic endpoint. Unlocks support bundle / PKI export later. | `rust-junosmcp` v0.6.0 |
| 1 | Workspace scaffolding, new crates, new binary, new systemd unit, 4 read-only tools (license, services_status, cluster_status, vpn_report). | `rust-srxmcp` v0.1.0 |
| 2 | IDP + AppID lifecycle. The original motivating use case. | `rust-srxmcp` v0.2.0 |
| 3 | Cluster health validation + support bundle collection. | `rust-srxmcp` v0.3.0 |
| 4 | Flow trace with packet-filter guardrails, commit-confirm, auto cleanup. | `rust-srxmcp` v0.4.0 |
| 5 | Chassis cluster upgrade (ISSU / ICU / separate-node). | `rust-srxmcp` v0.5.0 |

## Deployment model

### Default install (no SRX)

Unchanged. Operators deploy `rust-junosmcp` to LXC 601 as today. One systemd
unit, one port, one binary. Zero awareness of `rust-srxmcp`.

### Optional SRX install

1. Build: `cargo build --release -p rust-srxmcp` (or pull the
   `rust-srxmcp-vA.B.C-linux-x86_64.tar.gz` release artifact).
2. Copy binary to `/usr/local/bin/rust-srxmcp` inside LXC 601.
3. Install `systemd/rust-srxmcp.service` (new file in repo).
4. `systemctl enable --now rust-srxmcp.service`.
5. Mount in client `.mcp.json` as a separate server:
   ```json
   {
     "mcpServers": {
       "rust-junosmcp": {"type":"http","url":"http://192.168.1.194:30031/mcp"},
       "rust-srxmcp":   {"type":"http","url":"http://192.168.1.194:30032/mcp"}
     }
   }
   ```

Operators who don't need SRX simply never do steps 1–5.

## CI changes

- `cargo fmt -- --check` already runs across the workspace — unchanged.
- Add `cargo test --workspace` to ensure SRX code doesn't rot when default
  builds skip it.
- Release workflow gains a second matrix entry that builds and uploads
  `rust-srxmcp` artifacts whenever an `srxmcp-v*` tag is pushed. Generic
  releases (`v*` or `junosmcp-v*` tags) skip the SRX build.

## Risks and tradeoffs

| Risk | Mitigation |
|---|---|
| Two SSH pools to the same device when both endpoints run | Accept the duplication. Each binary has its own `DeviceManager`. Cross-process pool sharing is a deferred concern. |
| `devices.json` SIGHUP race between two processes | Both reload independently; the file is atomic and read-only at runtime. Test both processes receive SIGHUP cleanly. |
| Tool name collisions if a tool should exist on both endpoints | SRX endpoint exposes only SRX tools. Clients mount both servers and pick the right tool. No name aliasing inside one binary. |
| Workspace CI matrix complexity | Single addition: `cargo test --workspace`. Release tag prefixes are documented. |
| Drift between `rust-srxmcp-core` and `rust-junosmcp-core` interfaces | Path dep inside one workspace means breaking changes show up immediately in `cargo check`. |

## Out of scope

- The remaining 17 workflows from the capability gaps document (UTM AV, web
  filtering, anti-spam, SecIntel, ATP Cloud enrollment, dynamic feeds, SSL
  proxy, full PKI, license install, policy CRUD, NAT analysis, flow session
  query, rescue/snapshot, log export, RPM/IP monitoring, routing health,
  MPLS/EVPN, PFE bundles). These are candidates for `rust-srxmcp` v0.6.0+.
- Cross-process session pool sharing.
- Per-endpoint bearer token scoping.
- Republishing `rust-junosmcp-core` to crates.io as a third-party-consumable
  shared library. (Stays a workspace-internal crate.)
- Extracting a third `mcp-shared` crate. Deferred until symmetry is needed.

## Success criteria

- Generic users who do not build SRX crates have **zero** SRX-related compile
  time, binary size, or runtime overhead.
- All 10 SRX tools shipped across phases 1–5 with structured outputs and
  documented safety guardrails.
- Each phase deploys to LXC 601 with no regression in the generic
  `rust-junosmcp` endpoint.
- Operators can run SRX-only or generic-only deployments cleanly. Both
  together work without resource conflicts.

## Source notes

- `SRX_RUSTJUNOSMCP_CAPABILITY_GAPS.md` — gap analysis, command references.
- `rust-junosmcp/src/server.rs` — current 14-tool registry to mirror.
- `rust-junosmcp-core/src/tools/*.rs` — primitives to reuse.
- Memory: `rust_junosmcp_container_601.md` — LXC 601 deploy procedure.
- Memory: `v0_5_10_released.md` — current release baseline.
