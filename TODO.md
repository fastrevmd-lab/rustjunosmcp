# RustJunosMCP TODO

This file tracks review recommendations that are not individual defect findings.
Security, correctness, deployment, and audit defects are tracked as GitHub issues
and should not be duplicated as implementation checklists here.

## Review Findings Tracked As Issues

- [x] [#125](https://github.com/fastrevmd-lab/rustjunosmcp/issues/125)
  Validate support-bundle request IDs before path construction (critical).
- [x] [#126](https://github.com/fastrevmd-lab/rustjunosmcp/issues/126)
  Guarantee candidate cleanup and surface cleanup failures (high).
- [x] [#127](https://github.com/fastrevmd-lab/rustjunosmcp/issues/127)
  Make the published container support SCP file tools (high).
- [x] [#128](https://github.com/fastrevmd-lab/rustjunosmcp/issues/128)
  Repair and test LXC and systemd packaging (high).
- [x] [#129](https://github.com/fastrevmd-lab/rustjunosmcp/issues/129)
  Bind destructive confirmations to server-issued plans (high).
- [x] [#130](https://github.com/fastrevmd-lab/rustjunosmcp/issues/130)
  Filter `get_router_list` by caller router scope (medium).
- [x] [#131](https://github.com/fastrevmd-lab/rustjunosmcp/issues/131)
  Add HTTP resource and session limits (medium).
- [x] [#132](https://github.com/fastrevmd-lab/rustjunosmcp/issues/132)
  Complete caller-attributed audit coverage (medium).
- [x] [#133](https://github.com/fastrevmd-lab/rustjunosmcp/issues/133)
  Update `anyhow` to 1.0.103 for RUSTSEC-2026-0190
  (minor/informational).

Post-0.8.0 hardening issues, all closed and shipped in `0.8.0`:
[#147](https://github.com/fastrevmd-lab/rustjunosmcp/issues/147) per-router
in-flight limits, [#148](https://github.com/fastrevmd-lab/rustjunosmcp/issues/148)
per-token session caps,
[#149](https://github.com/fastrevmd-lab/rustjunosmcp/issues/149) Prometheus
`/metrics`, [#150](https://github.com/fastrevmd-lab/rustjunosmcp/issues/150)
per-token RPS rate limiting,
[#151](https://github.com/fastrevmd-lab/rustjunosmcp/issues/151) session-cap
overshoot race, [#153](https://github.com/fastrevmd-lab/rustjunosmcp/issues/153)
native journald audit sink,
[#154](https://github.com/fastrevmd-lab/rustjunosmcp/issues/154) audit log
rotation, [#155](https://github.com/fastrevmd-lab/rustjunosmcp/issues/155)
`error_kind` taxonomy,
[#156](https://github.com/fastrevmd-lab/rustjunosmcp/issues/156) per-field audit
redaction, and
[#163](https://github.com/fastrevmd-lab/rustjunosmcp/issues/163) the unified
Junos/SRX server.

The one open tracking issue is
[#110](https://github.com/fastrevmd-lab/rustjunosmcp/issues/110): `russh`
0.61.2 pulls prerelease (`-rc`) crypto into the SSH transport. Revisit when
0.61.x stabilizes.

## Now: Protocol And Product Quality

- [ ] Return MCP `structuredContent` for tool results instead of encoding JSON
  only inside text content. Publish and test an `outputSchema` for every stable
  tool response.
- [ ] Add accurate MCP tool annotations for read-only, destructive, idempotent,
  and open-world behavior. Treat annotations as client guidance, not security
  enforcement.
- [ ] Filter tool discovery by the caller's authorized tool scopes so clients do
  not plan calls they cannot execute.
- [ ] Make sensitive configuration redaction the default. Require a separate,
  narrowly granted scope for raw configuration and document which fields are
  always suppressed.
- [ ] Add explicit health, readiness, and build-information endpoints. Readiness
  should cover inventory/token parsing and required local runtime dependencies,
  without opening a session to every device.
- [ ] Publish a stable error catalog for all tools, including whether each error
  is retryable and which failures can leave device-side state behind.
- [ ] Perform a documentation truth pass:
  - Correct stale SRX version, tool-count, and generic Junos port statements.
  - Document the actual token and inventory reload behavior for the unified server.
  - Remove obsolete v0.1/v0.2 packaging caveats and the stale `rmcp 0.x` comment.
  - Add a supported deployment and feature matrix for stdio, HTTP, TLS,
    container, LXC, Junos, and SRX modes.
- [ ] Declare and test the minimum supported Rust version with
  `workspace.package.rust-version`; add missing crate descriptions, keywords,
  categories, and documentation links before publishing crates.
- [ ] Finish dependency policy tooling. The `security` workflow (#168) already
  runs `cargo-audit` for advisories and yanked crates plus `cargo-deny check
  bans sources` for duplicate versions, sources, and accidental git
  dependencies. Still missing: a checked-in `deny.toml` (the action currently
  runs on defaults, so the policy is implicit and unreviewable) and a `licenses`
  check. Resolve the currently yanked transitive AES release (`aes 0.9.0`) when
  its dependency chain permits a focused update.

## Next 1-3 Months: Operations And Safety

- [ ] Add MCP progress notifications, cancellation checkpoints, and resumable
  operation state for upgrades, signature-package changes, file transfers, and
  JTAC bundle collection. Evaluate MCP task support where client interoperability
  is mature enough.
- [ ] Define durable operation IDs and status lookup for long-running work so a
  client disconnect does not make the final outcome unknowable.
- [ ] Add an explicit confirmed-commit lifecycle: return a commit ID and deadline,
  provide a dedicated confirmation tool, expose pending confirmed commits, and
  make rollback state observable.
- [ ] Replace plaintext inventory passwords with credential references. Support
  SSH agent/key providers first, then environment/file secret providers and a
  documented interface for external secret managers.
- [ ] Add configurable command and configuration policy profiles for read-only
  NOC, operator, network engineer, and administrator roles. Prefer allowlists for
  high-risk environments and log the exact policy decision.
- [ ] Implement the support-bundle staging quota rather than the current LRU
  stub. Stream hashes and archive creation to bound memory and disk usage, and
  expose quota/eviction metrics.
- [ ] Add OpenTelemetry-compatible traces and metrics for MCP request latency,
  device connection pooling, NETCONF RPC duration, retries, timeouts, queueing,
  transfer throughput, and destructive workflow outcomes.
- [ ] Add token expiry, last-used timestamps, rotation overlap, and revocation
  observability. Document when static bearer tokens are appropriate and define a
  path toward standard OAuth/OIDC for shared deployments.
- [ ] Refactor the largest modules along existing workflow boundaries:
  - `transfer_file.rs` (about 2,419 lines): validation, path policy, SCP process,
    checksum, staging, and response mapping.
  - `idp_package.rs` (about 1,918 lines): discovery, planning, confirmation,
    execution, polling, parsing, and audit.
  - `upgrade_junos.rs` (about 1,647 lines): preflight, transfer, install,
    reboot/reconnect, verification, and rollback.
  - `appid_package.rs` (about 1,537 lines): discovery, planning, execution,
    polling, parsing, and audit.
- [ ] Keep refactors behavior-preserving: add characterization and failure-path
  tests before moving code, and avoid a generic framework shared by workflows
  with materially different device semantics.

## Next 3-6 Months: Release And Scale

- [ ] Build a reproducible benchmark harness for the public performance claims.
  Record device/topology, command mix, concurrency, warm/cold pool state,
  response sizes, percentiles, failures, and the compared implementation/commit.
- [ ] Add end-to-end fixtures for NETCONF and SCP fault injection: malformed XML,
  RPC errors, slow responses, disconnects, cancellation, host-key changes,
  partial loads, cleanup failures, checksum mismatch, and reconnect after reboot.
- [ ] Maintain a tested Junos/SRX compatibility matrix covering supported
  releases, standalone/clustered SRX, authentication modes, and the RPC variants
  used by each tool.
- [ ] Add parser and policy fuzzing/property tests for XML normalization, command
  filters, configuration blocklists, path validation, manifest handling, and
  scope evaluation.
- [ ] Harden releases with checksums, SBOMs, signed images/artifacts, provenance
  attestations, pinned CI actions/base-image digests, and a documented
  vulnerability-response process.
- [ ] Publish multi-architecture container images and test `linux/amd64` and
  `linux/arm64` rather than relying on Apple Silicon emulation.
- [ ] Add release gates that install the produced archive/image and exercise
  `initialize`, `tools/list`, one read-only call, authorization denial, graceful
  shutdown, and upgrade/rollback fixture paths.
- [ ] Define the high-availability model before adding replicas: token reload
  propagation, session ownership, operation leases, durable operation state,
  audit ordering, and safe behavior during partitions or process restarts.
- [ ] Add a versioned public API compatibility policy for tool names, input and
  output schemas, stable error codes, deprecation windows, and migration notes.

## Ongoing Engineering Hygiene

- [ ] Add architecture decision records for transport security, token/scopes,
  device pooling, destructive-operation coordination, subprocess use, and
  credential storage.
- [ ] Require tests for every fixed review issue, including a negative test that
  demonstrates the original failure and an end-to-end test where practical.
- [ ] Keep release notes aligned with actual ports, tools, transports, and
  security defaults; automate checks for generated CLI help and tool counts.
- [ ] Track upstream `rustEZ`, `rustnetconf`, `rmcp`, and `russh` compatibility in
  one place and remove stale dependency comments when upgrades land.
- [ ] Review log fields and sample output before every release to ensure tokens,
  passwords, private keys, raw sensitive configuration, and support-bundle
  contents cannot be emitted accidentally.
