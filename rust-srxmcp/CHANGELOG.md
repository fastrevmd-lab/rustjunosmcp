# Changelog — rust-srxmcp

All notable changes to the `rust-srxmcp` crate are recorded in this file.
The generic `rust-junosmcp` binary has its own changelog and version line
(`v0.6.x` at the time of this writing).

This project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-05-21

Phase 1B — read-only SRX status tools.

### Added
- `get_chassis_cluster_status` — chassis-cluster topology + RG health.
- `check_srx_feature_license` — closed-enum feature → license-record mapping.
- `get_srx_security_services_status` — IDP/AppID/UTM-AV/SecIntel/ATP-Cloud per node.
- `vpn_lifecycle_report` — correlated IKE + IPsec view with optional `peer`/`tunnel` filters.
- `rust-srxmcp-core` populated with shared `SrxError`, `SrxToolResponse<T>`, `multi_re_split`, `sanitize_rustez_xml`, and one workflow module per tool.
- Fixture-driven unit tests covering `state=active`, `state=not_configured`, partial-cluster, and per-sub-service absence cases.
- `tests/live_smoke.rs` — `#[ignore]`d smoke test per tool against LXC 601.

### Changed
- Tool surface 1 → 5 (`srxmcp_status` + four new tools).
- `JmcpSrxHandler` now holds an `Arc<DeviceManager>` so workflows can acquire pooled NETCONF sessions.

### Notes
- `rust-junosmcp` and `rust-srxmcp` continue to ship independent versions. `rust-junosmcp` remains at its current `0.6.x` line.

## [0.0.1] — 2026-05-20

Phase 1A scaffolding release. Establishes the second MCP binary in the
workspace alongside `rust-junosmcp` without changing any existing
behaviour.

### Added
- New workspace crates `rust-srxmcp` (binary) and `rust-srxmcp-core`
  (placeholder for Phase 1B SRX workflow logic).
- New shared `rust-junosmcp-auth` crate containing the bearer-token tower
  middleware and `CallerCtx` extension, relocated from
  `rust-junosmcp/src/`. Both binaries now share one auth implementation.
- New `rust-junosmcp-core::bootstrap` module with `init_tracing`,
  `load_inventory`, and `build_host_key_policy` helpers used by both
  binaries.
- `srxmcp_status` MCP tool — diagnostic-only, returns crate version,
  process uptime, and the caller's authenticated scope.
- `packaging/systemd/rust-srxmcp.service` — independent systemd unit with
  the same hardening directives as `rust-junosmcp.service`. Default port
  **30032**.
- CI: format and clippy gates expanded to cover the new crates.

### Changed
- Workspace `default-members` set to the three `rust-junosmcp*` crates so
  plain `cargo build` / `cargo test` remain byte-for-byte unchanged.
- Per-crate `version` fields: `rust-junosmcp*` stay on `0.6.2`,
  `rust-srxmcp*` start at `0.0.1`. The workspace-wide `package.version`
  was removed.

### Security
- No new attack surface beyond what `rust-junosmcp` already exposes.
  Same bearer-token model, same allowlisted scopes, same SIGHUP-driven
  reload semantics.
