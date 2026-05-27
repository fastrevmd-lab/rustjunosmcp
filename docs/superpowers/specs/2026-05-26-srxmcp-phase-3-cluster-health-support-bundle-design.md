# srxmcp Phase 3 — Cluster health validation + JTAC support bundle

**Status:** scope locked + RPC-captured + eng-reviewed 2026-05-26
**Release target:** single `srxmcp-v0.3.0` — both tools ship together. Eng-review concluded the two tools share too little code to justify the v0.2.0/v0.2.1-style split, and `validate_*`'s `chassis_cluster` problem_type artefacts dovetail with `collect_*` so they're complementary.
**Builds on:** `srxmcp-v0.2.1` (signature-package primitives, `[code=...]` error vocabulary), `rust-junosmcp` v0.6.0 (`fetch_file` device → LXC 601 primitive)
**Strategy doc:** [`2026-05-20-srx-mcp-strategy-design.md`](2026-05-20-srx-mcp-strategy-design.md) — Phase 3 row

## Why

Phase 1B's `get_chassis_cluster_status` answers *"is the cluster healthy
right now?"* in a snapshot. Phase 3 turns that into two operator workflows:

1. **`validate_chassis_cluster_health`** — opinionated pre-change check. Folds
   together cluster status, interface monitoring, RG failover history, control-
   and fabric-link state, and node-pair version skew into a single
   pass/warn/fail verdict. Run before any destructive change (signature install,
   image upgrade, RG move) so the operator gets a single yes/no with a list of
   blockers instead of a wall of XML.
2. **`collect_jtac_support_bundle`** — drive the device to assemble its own
   tarball at `/var/tmp/srxmcp-<request_id>.tgz` (via `request support
   information | save …` for `generic`, or per-`problem_type` RPC + log
   capture for the scoped types), then return the *device-side* path. The
   caller chains the existing `rust-junosmcp` v0.6.0 `fetch_file` to pull
   that tarball off the device into LXC 601's staging dir, and pulls again
   onto their own workstation via whatever transport their MCP client
   supports. **Phase 3 ships no LXC → caller primitive** (none exists today
   and adding one is out of scope).

These are still all read-only from the device's perspective — Phase 3 ships
zero destructive verbs. That keeps the lab acceptance plan tractable.

## Scope decisions (locked in brainstorming pass 2026-05-26)

| Decision | Choice | Rationale |
|---|---|---|
| `validate_chassis_cluster_health` verdict shape | **`pass` / `warn` / `fail` single status + ordered `findings: []`** | Simple for LLM consumers to reason over; per-finding `severity` + `evidence` blocks carry the per-check detail |
| Standalone SRX behaviour | **`state=not_configured`** | Symmetric with Phase 1B's `get_chassis_cluster_status`; the tool name implies cluster, standalone callers should use the Phase 1B surface |
| Bundle collection mechanism | **Operator-selectable `problem_type` accepts a single value OR an array** for chained-symptom cases (e.g. `["chassis_cluster", "vpn"]`). Drives per-type artefact list. | Matches strategy-doc signature; multi-select keeps "VPN flapping after a cluster failover" workflows in one tool call. Cheap to add now, expensive to retrofit. |
| Bundle delivery to caller | **Bundle is generated *on-device* at `/var/tmp/srxmcp-<request_id>.tgz`; tool returns the device-side path and the caller chains `fetch_file` (device → LXC 601).** From LXC 601, caller transports to their workstation by whatever means their MCP client supports — Phase 3 does NOT introduce an LXC→caller primitive. | Matches `fetch_file`'s actual contract (device → LXC). Sidesteps MCP response-size limits without inventing a new primitive. |
| Per-`problem_type` `get-configuration` baseline | **Every `problem_type` row implicitly includes `get-configuration` (running config).** Cannot be opted out. | Universal JTAC ask; omitting it is the single most operator-visible mistake. |
| `redact` arg semantics | **On/off boolean, default `true`.** Initial redaction rule list (committed in `support_bundle/redact.rs`): `pre-shared-key` values from `kmd` logs; `secret` / `simple-password` / `encrypted-password` in `get-configuration`; SNMP community strings; RADIUS shared-secrets; HMAC keys in `security ipsec` config. | Lock the rule list at design time so the smoke test has something concrete to assert. Future expansion goes through the same rules file. |
| Per-router lock | **No per-router lock; per-router *staging-key* lock instead.** Concurrent `collect_jtac_support_bundle` calls against the same router serialize on a `Semaphore` keyed by `(router, "support_bundle")` to avoid `/var/tmp/srxmcp-*.tgz` collisions on the device and racing scp pulls into LXC 601 staging. Distinct from Phase 2's `TransferLocks`. | Two callers can validate the same router concurrently (cheap RPCs). Two callers cannot collect at once (device-side `request support information` is itself serialized by mgd). |
| Topology scope | **`validate_*` cluster-only (standalone → `state=not_configured`); `collect_*` works on both** | Matches the tool names and strategy-doc intent |
| `validate` long-form output | **Findings + per-check `evidence` block; `include_raw=true` adds full RPC XML dumps** | Lets the LLM act without re-querying. Raw dumps stay opt-in to keep the default response small |
| Staging dir env vars | **`JMCP_SRX_STAGING_DIR` (default `/var/lib/rust-srxmcp/staging/bundles/`) + `JMCP_SRX_STAGING_MAX_BYTES` (default `500 MiB`)**. **No conflict** with `rust-junosmcp`'s existing `--staging-dir` flag (default `/var/lib/jmcp/staging`, no env var) — different binary, different directory. | Symmetric with `rust-junosmcp` staging conventions, but distinct path so the two binaries don't fight for the same disk budget. |
| Stale-bundle cleanup | **LRU eviction inside `JMCP_SRX_STAGING_MAX_BYTES`** when staging a new bundle would exceed cap. No background reaper, no scheduled prune. Bundle files retain mtime; eviction order is oldest-mtime-first. | Bounded disk usage without a daemon. Operators can `rm` manually if they want eager cleanup. |
| Async on-device RPCs | **`request support information` runs via the standard NETCONF RPC with the per-call `timeout` budget (default `1800`, cap `3600`).** No async / polling protocol in v0.3.0 — the call is a single long RPC. Operators on real hardware (SRX1500/4600) where this can run 5-15 min should pass an explicit `timeout` and be aware that `rmcp` client-detach (issue #44) can drop the response mid-flight without the device-side daemon noticing. Tarball remains on the device for a subsequent `fetch_file` even if the MCP response is lost. | Avoids inventing a polling protocol; relies on the bundle persisting on-device so client-disconnect is recoverable. |
| Release slicing | **Single release: `srxmcp-v0.3.0` ships both tools.** | Eng review concluded the v0.3.0/v0.3.1 split would be cargo-culting Phase 2 — the two tools share little code, and `validate_*`'s output complements `collect_*`'s `chassis_cluster` artefacts. |

## Tool surface (target)

Two new MCP tools added inline to `JmcpSrxHandler` in
`rust-srxmcp/src/server.rs` via `#[tool_router]` / `#[tool]`, growing the
surface from 8 to 10 tools.

### `validate_chassis_cluster_health`

| Arg | Type | Required | Notes |
|---|---|---|---|
| `router` | string | yes | Must exist in inventory |
| `request_id` | string | no | Caller-supplied correlation token; if absent, server mints `srxmcp-<uuid>` and returns it in the response. Same `request_id` is logged in audit lines (see § "Request-ID correlation"). |
| `include_raw` | bool | no | Append per-check raw RPC dumps |
| `timeout` | u64 | no | Outer per-call budget (default `120`, cap `300`) |

Returns `SrxToolResponse<ClusterHealthData>` with `state=active` / `state=not_configured`. `ClusterHealthData` carries verdict + ordered findings + the effective `request_id`.

### `collect_jtac_support_bundle`

| Arg | Type | Required | Notes |
|---|---|---|---|
| `router` | string | yes | Inventory router |
| `problem_type` | string \| string[] | yes | Closed enum value, or array of values for multi-symptom cases. Closed set in § "`problem_type` enum". |
| `request_id` | string | no | Same correlation token semantics as `validate_*`. Drives the device-side filename `/var/tmp/srxmcp-<request_id>.tgz`. |
| `include_logs` | bool | no | Default `true`; gates `/var/log/*` archival |
| `redact` | bool | no | Default `true`; strips fields listed in § "Scope decisions / `redact` arg semantics" |
| `max_log_bytes_per_file` | u64 | no | Default `10 MiB`; per-log-file size cap when archiving |
| `max_log_files` | u32 | no | Default `5`; latest-N rotated copies of each log series (e.g. `messages`, `messages.0.gz`, …) |
| `timeout` | u64 | no | Outer per-call budget (default `1800`, cap `3600`). `request support information` on real SRX hardware can run 5-15 min. |

**Response shape (success):**

```json
{
  "state": "active",
  "router": "vsrx-test19-20",
  "request_id": "srxmcp-7e2c…",
  "bundle": {
    "device_path": "/var/tmp/srxmcp-7e2c.tgz",
    "bytes": 12842156,
    "sha256": "ab12…",
    "problem_types": ["chassis_cluster", "vpn"]
  },
  "next_step": "fetch_file router=vsrx-test19-20 source=/var/tmp/srxmcp-7e2c.tgz"
}
```

The caller then issues `fetch_file` against the **`rust-junosmcp`** endpoint (port 30031), not `rust-srxmcp`, since `fetch_file` is a generic-Junos primitive. This is documented in the tool description so the LLM picks the right endpoint.

## RPC capture (live, 2026-05-26 against Junos 24.4R1.9)

Captured replies committed under `docs/superpowers/captures/phase3/`:
- `vSRX-test19-20-cluster/` — chassis cluster, currently degraded (node1 disabled, control-link failure, "Red" LED) — real non-pass data
- `vSRX-test3-standalone/` — standalone vSRX, returns `<xnm:error>` for all cluster-scoped RPCs

### Locked RPC set for `validate_chassis_cluster_health`

| RPC | Envelope | Use |
|---|---|---|
| `get-chassis-cluster-status` | `<chassis-cluster-status>` (Phase 1B shape) | RG status, node priorities — **reuse Phase 1B parser** |
| `get-chassis-cluster-interfaces` | `<chassis-cluster-interface-statistics>` | Control link Up/Down, fabric link `dataplane-interface-status`, reth status, `interface-monitoring` block |
| `get-chassis-cluster-information` | `<multi-routing-engine-results>` per-RE → `<chassis-cluster-information>` | Per-RG `redundancy-group-state-transition-record` (failover history), `chassis-cluster-led-information`, `chassis-cluster-monitoring-failure-information` |
| `get-chassis-cluster-data-plane-statistics` | `<chassis-cluster-data-plane-statistics>` | Fabric-link counter drift across nodes |
| `get-chassis-cluster-statistics` | `<chassis-cluster-statistics>` | Heartbeat sent/received/errors |
| `get-software-information` (per-RE on cluster) | `<multi-routing-engine-results>` → `<software-information>` | Version skew detection across REs. **Skew mapping:** different train (e.g. `22.4` vs `24.4`) → `fail`; same train different maintenance (`24.4R1` vs `24.4R2`) → `warn`; identical → no finding. |
| `get-system-alarm-information` (per-RE on cluster) | `<multi-routing-engine-results>` → `<alarm-information>` | `alarm-class` (`Minor`/`Major`) drives finding severities; `Major` → `fail`, `Minor` → `warn` |
| `get-system-uptime-information` (per-RE on cluster) | `<multi-routing-engine-results>` → `<system-uptime-information>` | Per-node uptime + last-reboot reason. **Severity:** uptime < 5 min → `warn` ("node recently rebooted; let it converge before destructive changes"); reboot-reason `Power Loss` or `Watchdog` on a node currently primary → `warn`. Added per eng-review recommendation. |

**Dropped from the candidate list:**
- `get-chassis-cluster-control-plane-statistics` — returns the **identical** `<chassis-cluster-statistics>` envelope as `get-chassis-cluster-statistics` on Junos 24.4R1.9. Calling both is redundant. Keep only `get-chassis-cluster-statistics`.
- `get-alarm-information` — chassis-only subset of `get-system-alarm-information`; system is the superset.

### `problem_type` enum (closed set; multi-select allowed)

**Universal baseline — included in every bundle regardless of `problem_type`:**
- `get-configuration` (running config) — the universal JTAC ask
- `get-software-information`
- `get-system-uptime-information`
- `get-system-alarm-information`
- `/var/log/messages` (latest, subject to `max_log_files` / `max_log_bytes_per_file`)

Per-type artefacts are added **on top of** the baseline:

| Value | Additional RPCs | Additional log files | Notes |
|---|---|---|---|
| `chassis_cluster` | All 7 RPCs from validate set above | `/var/log/chassisd`, `/var/log/jsrpd` | Reuse the validate capture set as data input |
| `vpn` | `get-ike-security-associations-information`, `get-ipsec-statistics-information`, `get-security-associations-information` | `/var/log/kmd` | Capture-verify 2026-05-26: `get-ike-active-peer*` and `get-ipsec-security-associations-information` UNKNOWN on Junos 24.4R1.9; `get-security-associations-information` returns the IPsec SA envelope so the set is complete. `ipsec-key-management` rolled into `kmd` on 24.4R1. |
| `traffic_loss` | `get-flow-session-information` (inner `<summary/>`), `get-flow-session-information` (full), `get-interface-information`, `get-firewall-information` | flowd traces if enabled | Capture-verify: `get-flow-session-summary-information` UNKNOWN — use `get-flow-session-information<summary/>` which returns `<flow-session-summary-information>`. `get-firewall-policer-information` / `get-policy-hit-count` UNKNOWN — `get-firewall-information` lists configured filters; per-counter detail needs an explicit `<countername>` arg and is out of scope for the bundle. |
| `idp_appid` | `get-idp-security-package-information`, `get-appid-package-version` | `/var/log/idpd`, `/var/log/appid` | Capture-verify: matches Phase 2 source names. `get-idp-policy-version`, `get-idp-security-package-version`, `get-appid-status`, `get-appid-application-package-version` are ALL UNKNOWN on 24.4R1.9. Optional add: `get-idp-policy-template-information` (templates list). |
| `routing` | `get-route-summary-information`, `get-bgp-summary-information`, `get-ospf-neighbor-information`, `get-route-engine-information` | `/var/log/rpd` | Capture-verify: all 4 confirmed against test10 + test19-20. |
| `generic` | `request-support-information` (full Junos tech-support) | — | Catch-all; on-device `request support information | save /var/tmp/srxmcp-<request_id>.tgz` produces the tarball directly. Baseline RPCs are run separately and added to the tarball. |

**Multi-select behaviour:** `problem_type: ["chassis_cluster", "vpn"]` runs the union of additional artefacts (deduped) on top of the universal baseline. `generic` short-circuits — if present in the array, only the `generic` path runs and other values are ignored (since `request support information` is a superset).

**Verification complete (2026-05-26):** all per-`problem_type` RPC names above were live-probed against the lab via raw NETCONF subsystem on Junos 24.4R1.9 (vSRX-test10 for vpn/traffic/routing/support, vSRX-test3 for idp_appid, vSRX-test19-20 for routing baseline). Captures live in `docs/superpowers/captures/phase3-v2/`. Five RPC name corrections were applied inline before code lands (see table notes). One legitimate gap remains: IKE "active peer" has no working RPC on 24.4R1.9 — `get-ike-security-associations-information` covers the same operational data and is the IKE source-of-truth for the bundle.

### Resolved RPC questions

- **`request support information` output path:** writes to stdout XML by default. To stage on-device for fetch, use the CLI form `request support information | save /var/tmp/srxmcp-<request_id>.tgz` (gzipped). Pull via `fetch_file` afterwards. Bundle persists on-device across `rmcp` client-disconnect (issue #44), so a lost MCP response is recoverable by re-issuing `fetch_file` with the known `request_id`.
- **`request system snapshot` on vSRX:** out of scope — vSRX is a single read-write filesystem, snapshot concept doesn't map. Phase 3 doesn't try to call it.
- **Bundle size on vSRX:** to be measured during v0.3.0 implementation; staging cap of 500 MiB is conservative for vSRX and a sane upper bound for the few SRX1500-class devices in the lab.
- **`show log <file>` XML equivalent:** no native RPC. Log archival uses scp via the existing `fetch_file` primitive (Phase 0), called from inside `collect_jtac_support_bundle`'s implementation per-log-file before assembling the tarball on-device.

## Architecture & modules

Mirroring Phase 2's `signature_package/` shared submodule pattern:

```
rust-srxmcp-core/src/workflows/
    cluster_status.rs          (existing — Phase 1B)
    cluster_health.rs          (new — wraps Phase 1B parser + adds checks)
    support_bundle.rs          (new — orchestrates per-`problem_type` collection)
    support_bundle/            (new submodule for shared primitives)
        artefacts.rs           (per-artefact capture: RPC, log path, file fetch)
        staging.rs             (writes to /var/lib/rust-srxmcp/staging/bundles/)
        redact.rs              (strips known-sensitive fields if `redact=true`)
        problem_type.rs        (enum + per-type artefact list)
```

`SrxLicensedFeature` doesn't apply here (no license preflight needed for read-only diagnostic RPCs). Note: `collect_jtac_support_bundle` IS audit-logged (it costs MB of disk + minutes of device time), but does NOT take a license preflight — the asymmetry vs Phase 2's destructive tools is deliberate, see § "Error & audit envelope" / § "Request-ID correlation".

**Staging directory:** Phase 3 introduces `JMCP_SRX_STAGING_DIR` (default `/var/lib/rust-srxmcp/staging/bundles/`) on the LXC 601 side. **No conflict** with `rust-junosmcp`'s existing `--staging-dir` flag (default `/var/lib/jmcp/staging`, no env var) — different binary, different directory, no shared writer. The two binaries do share the LXC 601 disk so `JMCP_SRX_STAGING_MAX_BYTES` (default 500 MiB) caps `rust-srxmcp`'s own slice.

## Lab acceptance plan

Live smokes against LXC 601:30032, `#[ignore]`d by default. The cluster
target `vSRX-test19-20` is **currently degraded** (node1 disabled, control-
link failure, "Red" LED) — that is *better* test data than a clean cluster
for the v0.3.0 release gate since it exercises every failure-path the
parser will emit. Healthy-cluster smokes are explicit `#[ignore]` gaps
until the lab is healed.

### Standalone smoke target: `vSRX-test3` (.220)

- `bundle_generic_returns_device_path_and_sha256`
- `bundle_vpn_excludes_cluster_rpcs`
- `bundle_redact_strips_known_psk_token` (asserts at least one configured PSK is absent from the redacted bundle; uses a known-injected dummy value)
- `bundle_multi_select_unions_artefacts` (asserts `problem_type: ["vpn", "routing"]` includes both kmd and rpd logs)
- `validate_returns_not_configured_on_standalone`

### Cluster smoke target: `vSRX-test19-20` (.241) — degraded state is the test fixture

Release-gate smokes (must pass):

- `validate_flags_red_led_as_fail` — captured: `<current-led-color>Red</current-led-color>` on node0
- `validate_flags_disabled_secondary_as_fail` — captured: node1 RG `disabled` with `Control link failure` transition reason
- `validate_flags_control_link_failure_as_fail` — captured: `<fabric-link-child-interface-monitored-status>Down</fabric-link-child-interface-monitored-status>`
- `validate_flags_major_alarm_as_fail` — captured: node1 `FPC 0 Hard errors` (`alarm-class=Major`)
- `validate_flags_minor_alarm_as_warn` — captured: license expiry alarms (`alarm-class=Minor`)
- `validate_flags_recent_reboot_as_warn` — fixture-driven (synthesize `<system-uptime-information>` with uptime < 5min)
- `bundle_chassis_cluster_captures_both_nodes` — runs `request support information` on the device, asserts both `node0` and `node1` artefacts present
- `bundle_includes_running_config` — asserts `get-configuration` reply present in every bundle regardless of `problem_type` (universal baseline)

Healthy-state smokes (`#[ignore]` with documented gap):

- `validate_returns_pass_on_healthy_cluster` — currently impossible against the lab; revisit when `vSRX-test19-20` is healed

### Anticipated lab gaps

- **No healthy cluster available right now.** `vSRX-test19-20` is degraded and `vSRX-test1` is a degenerate 1-node cluster. Bringing node1 back requires Proxmox-side work (re-enable VM, fix control-link MAC/vlan, wait for RG0 stabilization). Tracked as a Phase 3 lab task, not a code blocker.
- **Real SRX hardware bundle size.** vSRX bundles will be small (~10-50 MB); real SRX1500/4600 bundles can hit 200-300 MB. The 500 MiB cap holds for the lab; operators on real hardware can override via `JMCP_SRX_STAGING_MAX_BYTES`.
- **`request support information` runtime.** ~30-90 s on vSRX; 5-15 min on real hardware. Smokes will time-bound to vSRX numbers; real-hardware operators must pass an explicit `timeout`.

## Error & audit envelope

Read-only tools, but `collect_jtac_support_bundle` writes MB to disk +
runs minutes of device time and should be audit-logged for capacity +
forensic reasons:

- `tracing::info!(target = "audit", request_id = %rid, ...)` on bundle start, completion, AND every per-artefact failure (so post-mortems can reconstruct what was skipped and why).
- `tracing::info!(target = "audit", request_id = %rid, ...)` on every `validate_chassis_cluster_health` call — eng review flagged that the chained workflow (validate → collect → fetch) needs forensic continuity even though `validate_*` is itself read-only. Same `request_id` flows through all three calls.
- Error vocabulary: reuse the `[code=...]`-bracketed style from Phase 2.

### Request-ID correlation

Both Phase 3 tools accept an optional `request_id` argument. If omitted,
the server mints `srxmcp-<uuid-v7>` and returns it in the response. The
same `request_id` is:

- Logged in every `target="audit"` line emitted by the tool
- Used as the on-device tarball basename (`/var/tmp/srxmcp-<request_id>.tgz`)
- Expected to be passed to a subsequent `fetch_file` call by the operator/LLM so the three-call chain (validate → collect → fetch) is grep-able in audit logs

This closes the Phase 2 deferred concern that single-tool `request_id` is
useless without cross-tool propagation.

### New error variants

- `BundleStagingFull` — staging dir over `JMCP_SRX_STAGING_MAX_BYTES` after LRU eviction would still not free enough space
- `BundleStagingEvicted` — non-fatal: indicates which older bundle(s) were evicted to make room
- `BundleRpcSubsetFailed` — some artefacts collected, some failed; bundle returned with `partial=true` and a per-artefact error map
- `BundlePerRouterContention` — another `collect_*` call is in flight against this router (staging-key lock held); caller should retry
- `ClusterHealthCheckTimeout` — per-check timeout (distinct from outer timeout)
- `BundleConfigCaptureFailed` — `get-configuration` failed; bundle generation aborts because the universal-baseline guarantee cannot be honoured

## Out of scope (Phase 3)

Locked here so the design doesn't grow:

- **No destructive verbs.** Bundle collection is read-only-from-the-device;
  staging is local to the LXC container.
- **No LXC 601 → caller transport primitive.** `fetch_file` covers device → LXC 601. Getting the bundle from LXC 601 to the operator's workstation is whatever transport their MCP client supports (typically a follow-up scp). Inventing an `download_staged_file` tool is deferred unless an operational need surfaces.
- **No bundle decryption / introspection.** The tool stages a tarball; it does not unpack, parse, or summarize it. "What's in the bundle?" is a hypothetical future tool.
- **No background bundle reaper / scheduled prune.** LRU eviction happens *at write time*, not on a timer.
- **No async / polling protocol for `request support information`.** Single long RPC bounded by `timeout`. If it exceeds the budget the operator can re-fetch the on-device tarball via `fetch_file` (it persists across MCP client-disconnect).
- **No remediation guidance.** `validate_*` returns findings; suggesting fixes
  is the LLM's job, not the tool's.
- **No proactive monitoring loop.** Operator-initiated only.
- **No bundle upload to JTAC.** That's a manual step the operator takes
  against the staged path.
- **No cross-router bundle aggregation.** One router per call. Multi-`problem_type` IS supported (single router, multiple symptom buckets).
- **No automatic interface-monitor recovery.** Phase 3 reports state, not fixes it.
- **No `redact` levels.** Boolean only; rule list locked in design. Levels can come in v0.3.x patch if a real need surfaces.

## Appendix A — Cluster-information XML schema (live capture 2026-05-26)

Captured from `vSRX-test19-20` (currently degraded). Full file:
`docs/superpowers/captures/phase3/vSRX-test19-20-cluster/get-chassis-cluster-information.xml`.

```xml
<multi-routing-engine-results>
  <multi-routing-engine-item>
    <re-name>node0</re-name>
    <chassis-cluster-information>
      <chassis-cluster-redundancy-group-information>
        <redundancy-group-list>
          <redundancy-group-id>0</redundancy-group-id>
          <redundancy-group-status>primary</redundancy-group-status>
          <redundancy-group-weight>255</redundancy-group-weight>
          <redundancy-group-state-transition-record>
            <transition-time>May 24 15:31:20</transition-time>
            <from-state>hold</from-state>
            <to-state>secondary</to-state>
            <transition-reason>Hold timer expired</transition-reason>
          </redundancy-group-state-transition-record>
          <!-- ... repeating records per RG ... -->
        </redundancy-group-list>
        <!-- ... repeating <redundancy-group-list> per RG ... -->
      </chassis-cluster-redundancy-group-information>
      <chassis-cluster-led-information>
        <current-led-color>Red</current-led-color>
        <last-change-reason>Peer node: node1 is disabled</last-change-reason>
      </chassis-cluster-led-information>
      <chassis-cluster-monitoring-failure-information>
        <monitoring-failure-title>Failure Information:</monitoring-failure-title>
        <fabric-link-failure-information>
          <fabric-link-interface-status>
            <fabric-link-interface-index>0</fabric-link-interface-index>
            <fabric-link-child-interface-status>
              <fabric-link-child-interface-name>ge-0/0/3</fabric-link-child-interface-name>
              <fabric-link-child-interface-physical-status>Up</fabric-link-child-interface-physical-status>
              <fabric-link-child-interface-monitored-status>Down</fabric-link-child-interface-monitored-status>
            </fabric-link-child-interface-status>
          </fabric-link-interface-status>
        </fabric-link-failure-information>
      </chassis-cluster-monitoring-failure-information>
    </chassis-cluster-information>
  </multi-routing-engine-item>
  <!-- ... next RE ... -->
</multi-routing-engine-results>
```

Notes:
- `<chassis-cluster-monitoring-failure-information>` only present when failures are active — its absence on a node means that node has no current monitor failures.
- LED color taxonomy from observed data: `Green` / `Yellow` / `Red` / `Off`. `Red` → finding severity `fail`; `Yellow` → `warn`; `Off` on the secondary node typically means the node is disabled (not lit), correlate with `redundancy-group-status=disabled`.
- `<transition-time>` is *month day HH:MM:SS* with no year — operator-facing strings only, do not parse to `OffsetDateTime`.

## Appendix B — Standalone error envelope

```xml
<nc:rpc-reply xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" ...>
  <xnm:error xmlns="http://xml.juniper.net/xnm/1.1/xnm" xmlns:xnm="http://xml.juniper.net/xnm/1.1/xnm">
    <parse/>
    <source-daemon>jsrpd</source-daemon>
    <message>error: Chassis cluster is not enabled</message>
  </xnm:error>
</nc:rpc-reply>
```

Detect via the existing Phase 1B `sanitize_rustez_xml` + `<xnm:error>` parse path → return `SrxToolResponse { state: not_configured, .. }`.

---

## Next steps before implementation

1. ✅ **Brainstorming pass** — scope locked 2026-05-26 (§ "Scope decisions").
2. ✅ **Live RPC capture pass** — 9 RPCs captured against `vSRX-test19-20` (cluster) and `vSRX-test3` (standalone); committed under `docs/superpowers/captures/phase3/`. RPC set in § "RPC capture" trimmed to the 8 non-redundant calls (7 original + `get-system-uptime-information` added per eng review).
3. ✅ **Eng review** — pass v2 incorporated 2026-05-26. Three blockers fixed inline (bundle delivery mechanics rewritten to on-device tarball + `fetch_file` device → LXC; `get-configuration` added to universal baseline; lab acceptance plan reframed around the degraded `vSRX-test19-20` capture data). Multi-select `problem_type`, request_id correlation, stale-bundle LRU, async-RPC handling, and redact rule list all locked.
4. ✅ **Pre-implementation capture-verify pass** — completed 2026-05-26. All 6 `problem_type` RPC sets probed via raw NETCONF against test10 / test3 / test19-20; captures in `docs/superpowers/captures/phase3-v2/`. Five RPC names corrected inline in the `problem_type` table. `get-system-storage-information` → `get-system-storage` for the storage health probe.
5. **Implementation v0.3.0 (single release)** — both tools together:
   - `validate_chassis_cluster_health`: reuse Phase 1B `cluster_status` parser; new `cluster_health` workflow module calls the 8 RPCs concurrently and emits ordered findings.
   - `collect_jtac_support_bundle`: new `support_bundle/` submodule with `artefacts.rs`, `staging.rs`, `redact.rs`, `problem_type.rs`. On-device tarball assembled via `request support information | save` for `generic`, or per-type RPC + log capture for scoped types. Returns device-side path; documents the `fetch_file` chain.
   - Live smokes against the degraded `vSRX-test19-20` as release-gate; healthy-cluster smokes `#[ignore]` with documented gap.
6. **Tag `srxmcp-v0.3.0`** when smokes pass + memory note + GitHub release.
