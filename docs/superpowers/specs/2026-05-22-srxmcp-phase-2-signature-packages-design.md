# srxmcp Phase 2 — IDP + AppID signature-package lifecycle

**Status:** design, eng-reviewed 2026-05-25
**Release split:**
- `srxmcp-v0.2.0` — IDP (`manage_idp_security_package`) only
- `srxmcp-v0.2.1` — AppID (`manage_appid_signature_package`) reusing the shared `signature_package/` submodule landed in v0.2.0

**Builds on:** `srxmcp-v0.1.1` (read-only tools), `rust-junosmcp` v0.5.4+ (`tracing::info!(target = "audit", ...)` pattern), `upgrade_junos` (two-call confirm reference implementation)
**Strategy doc:** [`2026-05-20-srx-mcp-strategy-design.md`](2026-05-20-srx-mcp-strategy-design.md) — Phase 2 row

## Why

Phase 2 is the original motivating use case for the SRX MCP project: managing
SRX signature-package lifecycle (IDP and Application Identification) through
the LLM-driven MCP surface, so operators can keep these packages current without
hand-running Junos CLI sequences.

The read-only surface from Phase 1B (`get_srx_security_services_status`) tells
the operator *what version is installed*. Phase 2 lets the operator *change
which version is installed*, with the same two-call confirmation pattern that
`upgrade_junos` already uses for Junos image installs.

## Scope decisions (made in brainstorming, locked here)

| Decision | Choice | Rationale |
|---|---|---|
| Package source | **Online** (`https://signatures.juniper.net`) only | All test vSRX devices will be licensed; offline path adds plumbing (staging dir, checksum validation) that has no testable lab story for this release |
| IDP action verbs | `check_server`, `download_and_install`, `rollback` | Convenience-centric; hides the Junos-internal download→install split that's rarely operator-useful |
| AppID action verbs | `check_server`, `download_and_install`, `uninstall` | Mirrors IDP but uses honest verb names — AppID has no preserved previous-package state to roll back to |
| Confirmation pattern | Two-call confirm on every destructive verb | Symmetric with `upgrade_junos`; pre-flight plan is genuinely useful even for `rollback` (TOCTOU window where previous-package state could change) |
| Topology | Standalone **and** chassis cluster | Junos handles cluster sync automatically for signature packages; pre-flight surfaces per-node state |
| Tool granularity | Two MCP tools (one per service) | AppID's verb set differs in semantics; merging would force conditional schemas |

## Tool surface

Two new MCP tools added inline to `JmcpSrxHandler` in
`rust-srxmcp/src/server.rs` via the existing `#[tool_router]` /
`#[tool]` pattern, growing the surface from 5 to 7 tools.

### `manage_idp_security_package`

| Arg | Type | Required | Notes |
|---|---|---|---|
| `router` | string | yes | Must exist in inventory; pre-flight resolves to standalone or cluster |
| `action` | enum | yes | `check_server` \| `download_and_install` \| `rollback` |
| `version` | string | no | Pin to specific package version (e.g. `"3714"`); applies only to `download_and_install`; default = whatever `check-server` reports as latest |
| `confirm` | bool | no | Required for `download_and_install` and `rollback`; ignored for `check_server` |
| `timeout` | u64 | no | Per-call outer budget in seconds; default `600` (10 min), cap `1800` (30 min) |
| `include_raw` | bool | no | Append raw RPC replies to response (debugging) |

### `manage_appid_signature_package`

Identical args; `action` enum is `check_server` \| `download_and_install` \|
`uninstall`. `version` arg accepts the bare-integer AppID version strings
(e.g. `"3458"`).

### MCP tool descriptions (registered string)

For `manage_idp_security_package`:

> DESTRUCTIVE on the `download_and_install` and `rollback` actions: changes
> which IDP signature package is active. No reboot, no data-plane outage,
> brief IDP processing pause (~30-90s per node). Read-only on `check_server`.
> Destructive actions require `confirm=true` to proceed; first call with
> `confirm=false` returns a `confirmation_required` error containing the
> install plan (current/target versions per node, license state, estimated
> duration).

For `manage_appid_signature_package`: identical wording substituting
"Application Identification" for "IDP" and noting that `uninstall` does not
preserve a rollback target (next install requires a fresh download).

## Two-call confirmation protocol

Same shape as `upgrade_junos`. Documented per verb.

### `check_server` (no confirmation)

Pure read-only — issues `check-server` RPC, returns the published-latest
version plus the current installed version per node. Always single-call.
Not audited. Response shape:

```json
{
  "router": "vsrx-test10",
  "service": "idp",
  "topology": "standalone",
  "latest_version": "3714",
  "nodes": [
    { "re_name": "", "current_package_version": "3712(4.1)" }
  ],
  "update_available": true
}
```

For a cluster, `nodes` carries one entry per RE.

### `download_and_install` call 1 — `confirm: false`

Runs read-only pre-flight only. If all blockers clear and `current != target`,
returns `confirmation_required`:

```json
{
  "code": "confirmation_required",
  "router": "vsrx-test19-20",
  "action": "download_and_install",
  "service": "idp",
  "topology": "chassis_cluster",
  "nodes": [
    { "re_name": "node0", "current_package_version": "3712(4.1)", "current_detector_version": "12.6.180200620_v6" },
    { "re_name": "node1", "current_package_version": "3712(4.1)", "current_detector_version": "12.6.180200620_v6" }
  ],
  "target_package_version": "3714",
  "target_source": "latest_from_check_server",
  "estimated_package_size_bytes": 287309824,
  "estimated_install_duration_seconds": 90,
  "preflight_blockers": [],
  "warning": "Will download IDP signature package 3714 from signatures.juniper.net and install on both cluster nodes. Brief IDP processing pause (~30-90s per node); no data-plane outage. Re-call with confirm=true to proceed."
}
```

`target_source` is one of:
- `"latest_from_check_server"` — `version` arg was absent; target = check-server's reply
- `"pinned"` — `version` arg was present; target = arg value, with a separate `latest_from_check_server` field added for reference

### `download_and_install` already-at-target short-circuit

If every node's `current_package_version` equals the resolved target, call 1
returns **success** with `status: "already_at_target"` — no
`confirmation_required`:

```json
{
  "status": "already_at_target",
  "router": "vsrx-test10",
  "service": "idp",
  "current_package_version": "3714(4.1)",
  "target_package_version": "3714",
  "message": "device already running target version; no action taken"
}
```

Matches `upgrade_junos`'s short-circuit pattern.

### `rollback` call 1 — `confirm: false`

Pre-flight reads device-stored rollback target. Returns `confirmation_required`:

```json
{
  "code": "confirmation_required",
  "router": "vsrx-test10",
  "action": "rollback",
  "service": "idp",
  "topology": "standalone",
  "current_package_version": "3714(4.1)",
  "rollback_target_version": "3712(4.1)",
  "preflight_blockers": [],
  "warning": "Will revert IDP signature package from 3714 to 3712. Brief IDP processing pause (~30s); no data-plane outage. Re-call with confirm=true to proceed."
}
```

### `uninstall` (AppID only) call 1 — `confirm: false`

```json
{
  "code": "confirmation_required",
  "router": "vsrx-test10",
  "action": "uninstall",
  "service": "appid",
  "topology": "standalone",
  "current_package_version": "3458",
  "preflight_blockers": [],
  "warning": "Will uninstall the active AppID signature package. There is no preserved previous-package state; a subsequent download_and_install will be required to restore protection. Re-call with confirm=true to proceed."
}
```

Warning text is deliberately heavier than `rollback` to make the asymmetry
explicit.

### Pre-flight blockers (return structured error, not confirmation prompt)

Each blocker is a hard refusal — call 1 fails with the specific
`SrxError` variant, no `confirmation_required` is emitted:

| Blocker | Error variant | Applies to |
|---|---|---|
| Unknown router | `InvalidInput` | all actions |
| Feature license not active | `SignaturePackageLicenseInactive` | all destructive actions |
| `signatures.juniper.net` unreachable | `SignaturePackageServerUnreachable` | `check_server`, `download_and_install` |
| No rollback target available | `SignaturePackageNoRollbackTarget` | `rollback` only |
| Cluster topology not synchronized | `SignaturePackageClusterDesynced` | destructive actions on clusters |

An active commit-confirmed window is **not** a blocker. Sig-package install is
an operational RPC (`request security idp security-package install`) — it
writes binaries to `/var/db/idpd/` without transiting the candidate-config /
commit pipeline. Unlike `upgrade_junos`, there is no interaction between the
two codepaths in `mgd`. When detected, pre-flight emits
`tracing::warn!(target = "audit", event = "sigpkg_commit_confirmed_window_active", ...)`
so the audit trail captures the unusual condition, then proceeds.

### Call 2 — same args + `confirm: true`

Per-router lock acquired FIRST (before pre-flight re-runs), so pre-flight
result is fresh at the moment the destructive RPC fires. Pre-flight then
re-runs under the lock as the TOCTOU guard — license could have lapsed,
latest version on Juniper's side could have advanced, cluster could have
desynced between call 1 and call 2. Destructive workflow proceeds linearly.

### Per-router lock

Same `TransferLocks` machinery `upgrade_junos` and `transfer_file` share
(`tokio::sync::Semaphore`-per-router map in
`rust-junosmcp-core/src/tools/transfer_file.rs`, the
`OwnedSemaphorePermit` released on drop). Keyed on router name. Prevents
two concurrent destructive ops on the same device (whether IDP, AppID,
or junos image upgrade).

**Ordering:** acquired BEFORE call 2 pre-flight re-runs, released on drop
after post-install verification. Matches `upgrade_junos` (see
`rust-junosmcp-core/src/tools/upgrade_junos.rs:577`). Lock-first closes
the TOCTOU window where two operators could both pass pre-flight against
the same router and then queue for the destructive RPC with stale
pre-flight results — under lock-first the second operator's pre-flight
runs after the first releases, so it sees current state.

## Workflow phases (destructive path, `confirm: true`)

### IDP `download_and_install`

1. **Acquire per-router lock** (`TransferLocks::acquire(router)` — see D4).
2. **Open NETCONF session** via existing `DeviceManager::open` (pooled).
3. **Pre-flight (re-execute call 1 pre-flight under the lock)** — reject before touching state if anything changed.
4. **Audit:** write `phase=preflight_passed`.
5. **Download** — fire `request-idp-security-package-download` (RPC name; XML CLI equivalent). Get async job-id back.
6. **Poll** — call `get-idp-security-package-download-status` every 5s up to `timeout - elapsed`. Terminate on `done` / `error` / poll-timeout.
7. **Audit:** write `phase=download_complete`.
8. **Install** — fire `request-idp-security-package-install`. Get async job-id back.
9. **Poll** — call `get-idp-security-package-install-status` every 5s up to remaining budget.
10. **Audit:** write `phase=install_complete`.
11. **Verify** — read `get-idp-security-package-information` per node; assert installed version matches the target. Mismatch → `SignaturePackageVerificationFailed`.
12. **Audit:** write `phase=verified` (terminal success) or `phase=failed` with error detail.

### IDP `rollback`

1-4. Same as above (lock, session, pre-flight, audit `preflight_passed`).
5. **Rollback** — fire `request-idp-security-package-rollback`. Synchronous on Junos's side; no poll needed.
6. **Audit:** write `phase=install_complete` (overloaded — semantics are "active-version change committed").
7. **Verify** — read `get-idp-security-package-information`; assert installed version matches the rollback target.
8. **Audit:** write `phase=verified` or `phase=failed`.

### AppID workflows

Same shape as IDP, substituting the AppID RPC names. `uninstall` uses
`request-services-application-identification-uninstall` and verifies by
reading `get-appid-package-version` and asserting the package field is empty
or `"0"`.

## Architecture & modules

Builds on the existing `rust-srxmcp-core` layout. Adds two workflow modules,
one shared primitive submodule, and one MCP-handler entry per tool.

### New files in `rust-srxmcp-core/`

```text
rust-srxmcp-core/src/
├── workflows/
│   ├── idp_package.rs                # manage_idp_security_package — verb dispatch + per-verb run()
│   ├── appid_package.rs              # manage_appid_signature_package — verb dispatch + per-verb run()
│   └── signature_package/            # shared primitives (new submodule)
│       ├── mod.rs                    # re-exports + the public SignaturePackagePlan type
│       ├── preflight.rs              # license check, cluster topology, internet reachability, commit-confirmed audit warn
│       ├── poll.rs                   # async poll-with-timeout for download/install status RPCs
│       └── plan.rs                   # confirmation-plan JSON shape + already_at_target detection
```

### Changes in `rust-srxmcp/`

No new files. Two new `#[tool]` methods are added inline to
`JmcpSrxHandler` in `rust-srxmcp/src/server.rs`, matching the inline
pattern used by the five Phase 1B tools:

- `manage_idp_security_package` — args validation; dispatches to `workflows::idp_package::run`
- `manage_appid_signature_package` — args validation; dispatches to `workflows::appid_package::run`

The `instructions` string returned by `ServerHandler::get_info()` is
updated to mention both new tools alongside the existing list. No
`SERVER_TOOLS` constant exists today; tool registration happens via the
`#[tool_router]` macro on the `impl` block.

### `signature_package/` submodule responsibilities

Roughly 60% of the workflow logic between IDP and AppID is shared:

| Concern | Location | Shape |
|---|---|---|
| License pre-flight | `signature_package/preflight.rs::license_active(router, feature)` | Reuses `workflows::license::run` internally via Rust call (not via re-entrant MCP call) |
| Cluster topology read | `signature_package/preflight.rs::cluster_topology(router)` | Reuses `workflows::cluster_status` similarly |
| Internet reachability | `signature_package/preflight.rs::signatures_server_reachable(exec)` | Runs the service-specific `check-server` RPC and classifies the result |
| Commit-confirmed audit warn | `signature_package/preflight.rs::detect_commit_confirmed(exec)` | Non-blocking — emits `tracing::warn!(target = "audit", ...)` if a window is open, then returns Ok. Reuses parser from `upgrade_junos`'s `detect_active_commit_confirmed`. |
| Poll loop | `signature_package/poll.rs::poll_until_done<F, T>` | Generic async loop calling caller-supplied status closure every 5s; terminates on closure-returned terminal state or outer timeout |
| Plan envelope | `signature_package/plan.rs::ConfirmationPlan` | Serialize impl produces the JSON shape from the Section 2 examples; constructors per verb |

### What is NOT shared

The RPC dispatch tables are hard-coded per workflow module:

- `idp_package.rs` knows the IDP RPC names (`get-idp-security-package-information`, `request-idp-security-package-check-server`, `request-idp-security-package-download`, `get-idp-security-package-download-status`, `request-idp-security-package-install`, `get-idp-security-package-install-status`, `request-idp-security-package-rollback`)
- `appid_package.rs` knows the AppID equivalents (`get-appid-package-version`, `request-services-application-identification-download`, `request-services-application-identification-status`, `request-services-application-identification-install`, `request-services-application-identification-uninstall`)

Generalizing the RPC table would force a trait or enum that adds indirection
without clarifying anything — when an RPC name changes (Junos 25.x deprecation,
for instance), the diff should be localized to one file, not split across a
registry definition and a usage site.

### Internal helpers are NOT re-entrant MCP calls

`license_active(router, feature)` and `cluster_topology(router)` are Rust
function calls into the existing workflow modules' `parse()` and `run()`
entry points — not bearer-token-authenticated MCP round-trips. This avoids
the auth overhead and keeps the audit log focused on operator-initiated
calls.

## Error & audit envelope

### New `SrxError` variants (added to `rust-srxmcp-core/src/error.rs`)

| Variant | JSON `code` | Semantics |
|---|---|---|
| `SignaturePackageConfirmationRequired { router, plan }` | `confirmation_required` | Call 1 of two-call confirm — `plan` is the JSON object documented above |
| `SignaturePackageLicenseInactive { router, feature }` | `license_inactive` | Pre-flight: feature license absent or expired |
| `SignaturePackageServerUnreachable { router, detail }` | `signatures_server_unreachable` | Pre-flight: `check-server` RPC failed |
| `SignaturePackageNoRollbackTarget { router }` | `no_rollback_target` | `rollback` requested but device has no preserved previous package |
| `SignaturePackageClusterDesynced { router, state }` | `cluster_desynced` | Cluster topology not `synchronized` |
| `SignaturePackageDownloadFailed { router, detail }` | `download_failed` | Async download poll terminated in failure state |
| `SignaturePackageInstallFailed { router, detail }` | `install_failed` | Async install poll terminated in failure state |
| `SignaturePackageVerificationFailed { router, expected, got }` | `post_install_version_mismatch` | Post-install version read doesn't match target |
| `SignaturePackagePollTimeout { router, action, elapsed_secs }` | `poll_timeout` | Outer `timeout` arg exceeded while download/install still in progress |

All variants flow through the existing `JsonRpcError` machinery — same
envelope shape as `upgrade_junos`'s errors. Each carries the router name.

### Audit log entries

Emitted via `tracing::info!(target = "audit", ...)` — same pattern
`upgrade_junos` uses (see `rust-junosmcp/src/server.rs` and the
`upgrade_audit_guard_tests` module). The structured fields below are
attached as tracing key-values so any subscriber (the default
`tracing_subscriber` JSON layer, `journalctl -u rust-srxmcp`, or a
downstream log shipper) renders the same payload. One entry per
destructive operation phase transition; `check_server` is not audited.

Field shape, as it would render through the JSON subscriber:

```json
{
  "ts": "2026-05-22T14:23:01.482Z",
  "tool": "manage_idp_security_package",
  "router": "vsrx-test10",
  "action": "download_and_install",
  "service": "idp",
  "caller": "claude-code-mch-2026-05-20",
  "request_id": "req-7f3c2e",
  "phase": "preflight_passed",
  "current_version": "3712(4.1)",
  "target_version": "3714"
}
```

If structured JSONL on disk is desired in the future, the operator wires
a file-rotating tracing layer — that's an infra decision separate from
this tool's audit shape.

Phase transitions:

| Phase | Written when |
|---|---|
| `preflight_passed` | Call 2 pre-flight cleared, lock acquired, about to fire first destructive RPC |
| `download_complete` | Async download poll terminated in success |
| `install_complete` | Async install / rollback / uninstall poll terminated in success |
| `verified` | Post-install version read matches target — terminal success |
| `failed` | Terminal failure at any point, with `error_code` and `error_detail` fields appended |

### `caller` field

Populated from `CallerCtx` (the bearer-token middleware sets it on the
request extensions — same machinery `upgrade_junos` uses).

### What is NOT audited

- `check_server` calls (read-only, high-frequency)
- Pre-flight read RPCs called internally during a destructive op
- Call 1 of two-call confirm (`confirm: false`) — operator hasn't committed yet

## Lab acceptance plan

### Manual pre-flight (one-time, before tagging v0.2.0)

1. **License verification.** On all 6 vSRX devices, confirm IDP + AppID
   licenses are active and capture their `end-date`:

   ```
   show system license | match "IDP Signature"
   show system license | match "Application"
   ```

   Document the per-device `end-date` in the v0.2.0 release notes so we
   know when smoke tests will start failing in the future.

2. **Internet egress verification.** Confirm `signatures.juniper.net` is
   reachable from at least `vSRX-test10`:

   ```
   show services application-identification status detail | match server
   ```

   If egress is blocked at the homelab firewall, document the explicit
   allowlist rule that was added.

3. **Baseline capture.** Snapshot current `package_version` for IDP and
   AppID on every device. This becomes the expected starting state for the
   live smoke runs.

### Smoke test surface (added to `rust-srxmcp/tests/live_smoke.rs`)

Tests are `#[ignore]`d and run with
`cargo test --test live_smoke -p rust-srxmcp -- --ignored --test-threads=1`.
Same `JMCP_SRX_LIVE_URL` / `JMCP_SRX_LIVE_TOKEN` env mechanism the existing
4 smoke tests use.

#### v0.2.0 release (IDP — 7 tests)

| Test | Verb / args | Target | Asserts |
|---|---|---|---|
| `idp_check_server_returns_latest_version` | `check_server` | `vSRX-test10` | response has `latest_version` field with non-empty value |
| `idp_download_and_install_call1_returns_plan` | `download_and_install` (no confirm) | `vSRX-test10` | response is `confirmation_required` with populated `target_package_version` and zero `preflight_blockers` |
| `idp_download_and_install_call2_succeeds` | `download_and_install` (confirm=true) | `vSRX-test10` | success; post-install `get-idp-security-package-information` reports installed version matches the target |
| `idp_already_at_target_short_circuits` | `download_and_install` (confirm=false, no `version`) immediately after the previous test | `vSRX-test10` | response is success with `status: "already_at_target"`, no `confirmation_required` emitted |
| `idp_version_pin_accepts_explicit` | `download_and_install` (confirm=false, `version` arg = known older version) | `vSRX-test10` | response is `confirmation_required` with `target_source: "pinned"` and the explicit version echoed |
| `idp_rollback_after_install_restores_previous` | `rollback` (confirm=true) | `vSRX-test10` | success; post-rollback version matches the version that was current before the install test |
| `idp_cluster_install_syncs_both_nodes` | `download_and_install` (confirm=true) | `vSRX-test19-20` | success; both `node0` and `node1` report the installed version |

(The two new tests — `idp_already_at_target_short_circuits` and
`idp_version_pin_accepts_explicit` — close gaps T1 and T2 raised in the
eng review.)

#### v0.2.1 release (AppID — 5 tests, added when AppID lands)

| Test | Verb / args | Target | Asserts |
|---|---|---|---|
| `appid_check_server_returns_latest_version` | `check_server` | `vSRX-test10` | response has `latest_version` field |
| `appid_download_and_install_call1_returns_plan` | `download_and_install` (no confirm) | `vSRX-test10` | confirmation_required emitted |
| `appid_download_and_install_call2_succeeds` | `download_and_install` (confirm=true) | `vSRX-test10` | success; post-install `get-appid-package-version` reports target version |
| `appid_uninstall_clears_package` | `uninstall` (confirm=true) | `vSRX-test10` | success; post-uninstall `get-appid-package-version` reports empty or `"0"` |
| `appid_cluster_install_syncs_both_nodes` | `download_and_install` (confirm=true) | `vSRX-test19-20` | success; both nodes report installed version |

### Test ordering

Tests 3 and 4 in each set are stateful — they assume "before test 3 the
device is on version A, after test 3 it's on version B, after test 4 it's
back on a known state." `--test-threads=1` is required.

If `signatures.juniper.net` only publishes one current version (so we can't
test "newer than current"), test 3 is preceded by a manual rollback to
deliberately go behind, then `download_and_install` brings the device
forward. This is documented in the test file as a pre-condition.

### Negative paths NOT covered by live smoke

Unit-tested with fixtures, not live-tested:

- `license_inactive` — synthetic fixture; revoking a license to test it would be hostile to lab uptime
- `signatures_server_unreachable` — synthetic fixture; firewall-blocking the SRX to test it requires homelab network changes
- `cluster_desynced` — synthetic fixture; parser regression covered
- `no_rollback_target` — synthetic fixture; would require destroying a device's rollback state to live-test

Each lives under `rust-srxmcp-core/tests/fixtures/signature_package/` with a
parser regression test in `signature_package/preflight.rs`.

### Release gate

- `srxmcp-v0.2.0` tag is cut only after all 7 IDP live smoke tests pass
  green against LXC 601:30032 with the licensed vSRX devices.
- `srxmcp-v0.2.1` tag is cut only after all 5 AppID live smoke tests
  pass green on top of the IDP suite (12 smokes total once AppID lands).

Same release-gate rule v0.1.0 and v0.1.1 used.

## Out of scope (deferred)

- **AppID tool (`manage_appid_signature_package`).** Deferred to
  `srxmcp-v0.2.1`. v0.2.0 ships only IDP. AppID reuses the
  `signature_package/` submodule unchanged; only the workflow module and
  the inline `#[tool]` registration are added in v0.2.1.
- **Offline package install path.** No `offline_package` arg, no staging-dir
  integration. Operators who need this can chain `transfer_file` + a manual
  Junos CLI command for now; a `manage_idp_security_package_offline`
  follow-up is plausible if a real operational need emerges.
- **Policy-template management.** IDP supports policy templates separately
  from the signature package (`request security idp security-package
  policy-templates`). Not in v0.2.0.
- **Detector engine updates.** IDP detector is bundled with the signature
  package; the AppID detector is updated separately and is not exposed by
  Phase 2.
- **Scheduled / unattended runs.** v0.2.0 is operator-initiated only. No
  cron, no policy-driven "auto-update when newer is available."
- **`request_id` correlation across tools.** The audit log entries carry
  `request_id` but cross-tool correlation (e.g. "find every audit entry for
  the same MCP request") is out of scope — v0.2.0 just sets the field per
  call.
