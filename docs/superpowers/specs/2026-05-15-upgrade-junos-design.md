# `upgrade_junos` MCP tool — design spec

- **Date:** 2026-05-15
- **Author:** brainstorm with operator + Claude
- **Status:** approved, ready for implementation-plan
- **Target release:** v0.5.0
- **Tool count:** 13 → 14

## Background

The manual vSRX upgrade workflow (proven 2026-05-14 on vSRX-test18:
24.4R1.9 → 25.4R1.12, ~7 min total) is captured in the
`junos_upgrade_manual_workflow.md` memory entry. It is six MCP/SCP
steps the operator currently runs by hand. This spec formalizes those
steps into a single MCP tool, `upgrade_junos`, for **standalone**
Junos devices.

Cluster devices (chassis cluster — `node0/node1`) are **out of scope
for v1**. A separate `upgrade_junos_cluster` tool (ISSU / unified
ISSU / node-by-node) is on the v2 roadmap.

The reliability primitives this tool depends on already exist:

- `transfer_file` (v0.4.0, hardened in v0.4.1): SCP push with sha256
  pre/post verify, idempotent skip, ASCII-allowlist source-path
  validation, scrubbed scp stderr, per-router `TransferLocks` semaphore.
- `rustez 0.10.1` `POOL_RPC_TIMEOUT=1h` (v0.4.1 deploy on 2026-05-14):
  long-running `request system software add … reboot` RPCs no longer
  hit the old 30s timeout.
- Session pool reconnects cleanly through device reboot (proven v0.3.0).

## Goals

1. One MCP call, one router, one image → upgraded standalone Junos
   device with structured pre/post baseline diff.
2. Make the destructive nature **load-bearing in the protocol**: a
   reboot cannot happen without the caller explicitly passing
   `confirm: true`.
3. Forward-only: any failure returns a structured error with diagnostics;
   the operator decides whether to investigate, manually roll back, or
   accept the partial state.
4. Idempotent: repeating the same call when the device is already at
   `target_version` is free (skip, no destructive action).
5. Compose cleanly with existing per-router serialization
   (`TransferLocks`).

## Non-goals (v1)

- Chassis cluster upgrades (ISSU, unified ISSU, node-by-node).
- Auto-rollback on post-verify failure.
- Force-reboot when device is already at `target_version`.
- Image fetched from external URL (operator pre-stages via `transfer_file`).
- Multi-router fan-out (caller-side loop is fine; per-router lock
  prevents accidental same-router parallelism).
- Pre-baseline-blocking on alarms or core dumps (informational only —
  often the *reason* for the upgrade).

## Tool surface

| Arg | Type | Required | Notes |
|---|---|---|---|
| `router_name` | string | yes | Must exist in inventory |
| `source_path` | string | yes | Basename in staging dir; validated by `validate_source_basename` (ASCII allowlist `[A-Za-z0-9._-]`) |
| `target_version` | string | yes | E.g. `"25.4R1.12"`; exact-match post-install assertion |
| `confirm` | bool | yes | Must be `true` to perform destructive workflow; defaults to `false` and tool refuses with `ConfirmationRequired` |
| `timeout` | u64 | no | Per-call outer timeout in seconds; default `900` (15 min); cap `3600` |
| `reboot_wait_secs` | u64 | no | Max wall-clock budget for NETCONF to reopen after install; default `480` (8 min) |

MCP tool description (registered in `server.rs`):

> DESTRUCTIVE: installs a new Junos image and REBOOTS the device. Outage
> ~5-7 min. Requires `confirm=true` to proceed; first call with
> `confirm=false` returns a `ConfirmationRequired` error containing the
> upgrade plan (current version, target version, image, free disk,
> estimated outage). v1 supports standalone devices only; chassis
> clusters are refused.

## Two-call confirmation protocol

### Call 1 — `confirm: false` (or omitted)

The tool runs the **read-only pre-flight** phase only, then returns a
`ConfirmationRequired` JSON-RPC error with the upgrade plan:

```json
{
  "code": "confirmation_required",
  "router": "vsrx-test18",
  "current_version": "24.4R1.9",
  "target_version": "25.4R1.12",
  "image_basename": "junos-vsrx-x86-64-25.4R1.12.tgz",
  "image_size_bytes": 1395728384,
  "device_var_free_bytes": 7516192768,
  "estimated_outage_seconds": 420,
  "preflight_blockers": [],
  "warning": "DESTRUCTIVE: this will install a new Junos image and REBOOT the device, causing an outage of approximately 5–7 minutes. Re-call with confirm=true to proceed."
}
```

If the device is already at `target_version`, call 1 returns
**success** with `status: "already_at_target"` (no confirmation needed
— no destructive work to do):

```json
{
  "status": "already_at_target",
  "router": "vsrx-test18",
  "current_version": "25.4R1.12",
  "target_version": "25.4R1.12",
  "message": "device already running target version; no action taken"
}
```

If pre-flight finds a hard blocker (cluster, insufficient disk, active
commit-confirmed window, unknown router, missing staged file, password-only
auth), call 1 fails with the specific structured error — never reaches
the `ConfirmationRequired` prompt.

### Call 2 — same args + `confirm: true`

Runs the **full destructive workflow**. Pre-flight is re-executed in
call 2 so that a blocker that materialized between calls (e.g., disk
filled, commit-confirmed window opened) is still caught before
anything destructive happens.

## Workflow phases (destructive path, `confirm: true`)

Linear, no parallelism, no rollback. Each phase has a defined failure
mode that aborts the rest. The entire workflow runs inside
`tokio::time::timeout(args.timeout, ...)`.

### Phase 0 — Pre-flight

1. Inventory lookup → `UnknownRouter` on miss.
2. Auth check (must be SSH-key, not password) → `UnsupportedAuth` on
   miss (mirrors `transfer_file`).
3. Open pooled NETCONF session → `DeviceProbeFailed { phase: "preflight" }`
   on miss.
4. `show chassis cluster status` → if active cluster
   (`Cluster ID` present and not `Not configured`) → `UpgradeClusterUnsupported`.
5. `show version | match Junos:` → parse current version. If
   `== target_version` → return `{status: "already_at_target", …}`,
   **exit successfully without doing anything destructive**.
6. `show system commit | match "rollback"` → if active commit-confirmed
   window → `UpgradeCommitConfirmedActive { router, rollback_secs }`.
7. Local sha256 + size of staged image (streamed via
   `sha256_file`, ~3-5 s for a 1.3 GB image; reused from `transfer_file`).
8. `show system storage no-forwarding` → parse free `/var` bytes via
   `parse_storage_free_bytes` (reused from `transfer_file`). Require
   `≥ 2 × image_size + MIN_FREE_HEADROOM_BYTES` → `InsufficientDisk`
   on miss. Junos install needs working room for unpack + new
   partition, typically ~2× image size.

### Phase 1 — Baseline capture (informational)

One batched run of these six commands; output stashed as
`pre_baseline: HashMap<String, String>`:

- `show version`
- `show interfaces terse | except "\.[0-9]+ "`
- `show route summary`
- `show security flow session summary`
- `show system alarms`
- `show system core-dumps no-forwarding`

No blocking on output; pure capture.

### Phase 2 — Transfer

Call `transfer_file::handle(...)` internally with:

- same `router_name`, `source_path`
- `force: false`, `verify: true`
- generous internal `timeout` (default 600 s)

Reuses the existing `TransferLocks` `Arc` (shared via `UpgradeConfig`)
so a concurrent caller-initiated `transfer_file` to the same router is
serialized correctly. `transfer_file`'s idempotent skip means a
re-pushed identical image short-circuits.

Errors from `transfer_file` (`ScpFailed`, `ConnectTimeout`,
`VerifyMismatch`, `DestExistsDiffers`, `TransferOuterTimeout`,
`InsufficientDisk`) bubble up unchanged.

### Phase 3 — Install + reboot

Single CLI command via the pooled session:

```
request system software add /var/tmp/<basename> no-copy reboot
```

The RPC will resolve in one of three ways:

- **Returns with install output before reboot fires** — happy path.
  Stdout captured into `install_stdout`.
- **Session drops mid-stream** when reboot kicks in — caught as
  `rustez` connection-closed error; treated as **expected**, not a
  failure. `install_stdout` empty.
- **Hits `POOL_RPC_TIMEOUT`** (1 h from v0.4.1) — treated as
  `UpgradeInstallTimeout { router, elapsed }`.

Record `install_started_at` timestamp. Drop the dead session from the
pool before Phase 4 (rustez session-pool handles this on transient
errors already).

### Phase 4 — Wait for NETCONF to reopen

NETCONF-only retry loop (no ICMP, no TCP-22 probing — they add
container-capability requirements for marginal diagnostic value):

- Initial sleep: 30 s (device is definitely still rebooting).
- Then attempt `dm.open(router)` every 15 s.
- Each attempt has its own 10 s connect deadline.
- Wall-clock budget: `reboot_wait_secs` (default 480 s).
- On budget exceeded → `UpgradeRebootTimeout { router, waited_secs }`.
- First successful open → record `device_back_at` timestamp, continue.

### Phase 5 — Post-verify (hard gate)

`show version | match Junos:` → parse → must equal `target_version`.

Mismatch returns `UpgradePostVerifyMismatch { router, expected,
observed, baseline_diff }` carrying the partial baseline diff
gathered so far.

### Phase 6 — Post-baseline capture (informational)

Same six commands as Phase 1; output stashed as `post_baseline`.

### Phase 7 — Build response

Diff `pre_baseline` vs `post_baseline` per command (simple
key-by-key line-set diff; `added` / `removed` string lists). Return
success.

## Response shapes

### `upgraded` (Phase 7 success)

```json
{
  "status": "upgraded",
  "router": "vsrx-test18",
  "from_version": "24.4R1.9",
  "to_version": "25.4R1.12",
  "image_basename": "junos-vsrx-x86-64-25.4R1.12.tgz",
  "image_sha256": "ba7816bf...",
  "elapsed_seconds": 423,
  "phase_timings": {
    "preflight_secs": 4,
    "transfer_secs": 84,
    "install_secs": 218,
    "reboot_wait_secs": 112,
    "postverify_secs": 5
  },
  "pre_baseline": {
    "show version": "...",
    "show interfaces terse | except \"\\.[0-9]+ \"": "...",
    "...": "..."
  },
  "post_baseline": { "...": "..." },
  "baseline_diff": {
    "show interfaces terse | except \"\\.[0-9]+ \"": {
      "added":   ["lo0   up  up"],
      "removed": []
    },
    "show system alarms": {
      "added":   ["1 alarms currently active"],
      "removed": []
    }
  }
}
```

### `already_at_target` (skip path)

Returned from call 1 or call 2 when current version already matches.
Shown earlier under "Call 1".

## Error taxonomy

New `JmcpError` variants, each with `[code=<snake>]` tag in `Display`
per existing convention:

| Variant | Code tag | Phase | When |
|---|---|---|---|
| `ConfirmationRequired { payload }` | `confirmation_required` | 0 | Call without `confirm: true` |
| `UpgradeClusterUnsupported { router }` | `cluster_unsupported` | 0 | `show chassis cluster status` reports active cluster |
| `UpgradeCommitConfirmedActive { router, rollback_secs }` | `commit_confirmed_active` | 0 | Active rollback window |
| `UpgradeInstallTimeout { router, elapsed }` | `install_timeout` | 3 | Install RPC hit `POOL_RPC_TIMEOUT` without session drop |
| `UpgradeRebootTimeout { router, waited_secs }` | `reboot_timeout` | 4 | NETCONF never reopened within `reboot_wait_secs` |
| `UpgradePostVerifyMismatch { router, expected, observed, baseline_diff }` | `postverify_mismatch` | 5 | `show version` ≠ `target_version` |
| `UpgradeOuterTimeout(Duration)` | `upgrade_outer_timeout` | any | Outer `args.timeout` expired |

Reused / existing errors (no new variants):

- `UnknownRouter`, `InsufficientDisk`, `UnsupportedAuth`,
  `BadSourcePath`, `DeviceProbeFailed` — surfaced as-is.
- `ConnectTimeout`, `ScpFailed`, `VerifyMismatch`,
  `DestExistsDiffers`, `TransferOuterTimeout` — bubbled up from
  `transfer_file::handle`.

## File layout

Mirrors `transfer_file.rs` shape:

- `rust-junosmcp-core/src/tools/upgrade_junos.rs` — new module
  - `pub struct UpgradeConfig { transfer_cfg: TransferConfig, ... }`
    — shares the same `Arc<TransferLocks>` as `TransferConfig`
  - `pub async fn handle(args, dm, cfg) -> Result<Value, JmcpError>`
    — orchestrates phases 0-7
  - Pure helpers (unit-testable without a device):
    - `parse_junos_version(&str) -> Option<String>`
    - `detect_cluster_active(&str) -> bool`
    - `detect_active_commit_confirmed(&str) -> Option<u64>`
    - `diff_baseline(pre: &Map, post: &Map) -> Map<String, BaselineDiff>`
- `rust-junosmcp-core/src/tools/mod.rs` — add `UpgradeJunosArgs`
  struct + `pub mod upgrade_junos`
- `rust-junosmcp-core/src/error.rs` — add 7 new variants from above
- `rust-junosmcp/src/server.rs` — register `upgrade_junos` as MCP
  tool with the description from "Tool surface" above
- `rust-junosmcp/src/main.rs` — build `UpgradeConfig` once at startup,
  share `TransferLocks` `Arc` with `TransferConfig`

## Concurrency

Reuses the existing `TransferLocks` per-router semaphore from v0.4.1.
The lock is acquired in Phase 0 immediately after the read-only
pre-flight passes and before any destructive work, released on drop at
end of `handle()`. A `transfer_file` and an `upgrade_junos` targeting
the same router serialize against each other through this shared lock;
different routers proceed in parallel.

## Testing strategy

### Unit tests (pure helpers, no device)

- `parse_junos_version` — happy path, missing match, vSRX + MX format
  variants, whitespace tolerance.
- `detect_cluster_active` — `node0/node1` output (active) vs single-
  node output vs `Not configured`.
- `detect_active_commit_confirmed` — `show system commit` with rollback
  line vs without; rollback seconds parsing.
- `diff_baseline` — added / removed / equal cases per command, multi-
  command diff, ordering stability.
- All 7 new error variants — `Display` includes the `[code=…]` tag
  per the existing convention (see `transfer_file::scp_unit_tests`).

### `handle()` validation tests (mocked, no NETCONF)

Reuse the `MockScpRunner` pattern + a (to-be-added) mock device
trait or in-process `cli` stub:

- `confirm_false_returns_confirmation_required`
- `already_at_target_skips_destructive_path`
- `cluster_device_refused_before_transfer`
- `commit_confirmed_active_refused_before_transfer`
- `unknown_router_propagates`
- `password_auth_refused_before_transfer`
- `insufficient_disk_refused_before_transfer`

### Live integration test (lab only, not CI)

- Gated behind env var `JMCP_LIVE_UPGRADE_TARGET=<router_name>` and
  `JMCP_LIVE_UPGRADE_IMAGE=<basename>` and
  `JMCP_LIVE_UPGRADE_TARGET_VERSION=<version>`.
- Runs full Phase 0-7 against vSRX-test18 (or any standalone vSRX in
  lab inventory).
- Smoke check only; skipped unless env vars set.
- Expected runtime: ~7-10 min.

### CI

- `cargo fmt -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace` (mocked tests only; no live device)

## Out of scope for v1 (deferred to v2)

- **Cluster device upgrades** (ISSU / unified ISSU / node-by-node) →
  separate `upgrade_junos_cluster` tool on the v2 roadmap. The
  cluster-detection helper (`detect_cluster_active`) will be reused
  by both tools.
- **Force-reboot at already-installed target version** — would need a
  separate `reboot_junos` tool; YAGNI for v1.
- **Image fetched from external URL** — operator pre-stages via
  `transfer_file`.
- **Auto-rollback on post-verify mismatch** — operator's call; manual
  `request system software rollback` from console or out-of-band SSH.
- **Multi-router fan-out** — caller-side loop is sufficient;
  `TransferLocks` already serializes per-router.
- **Pre-baseline-blocking on alarms / core dumps** — informational
  only; alarms may be benign or the very reason for the upgrade.

## Memory updates (after release)

- `junos_upgrade_manual_workflow.md` → annotate as superseded by
  `upgrade_junos` tool for standalone devices; retain for cluster +
  reference.
- New project memory: `upgrade_junos_v1.md` — args, response shape,
  error codes, release tag.
- New roadmap memory: `upgrade_junos_cluster_v2_roadmap.md` — ISSU
  plan, cluster-detection helper reuse, scoping rationale.

## Open questions

None — all design decisions resolved during brainstorm
(see Q1-Q9 in the brainstorm transcript).
