# Changelog — rust-srxmcp

All notable changes to the `rust-srxmcp` crate are recorded in this file.
The generic `rust-junosmcp` binary has its own changelog and version line
(`v0.6.x` at the time of this writing).

This project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.1] — 2026-05-26

Phase 2 continuation — AppID signature-package lifecycle. Adds the sibling
of `manage_idp_security_package` for the Application Identification engine.
Tool surface 7 → 8.

### Added
- `manage_appid_signature_package` — three actions: `check_server`
  (read-only — returns installed + latest version from
  signatures.juniper.net), `download_and_install` (downloads + installs
  the latest or a pinned `version`), and `uninstall` (removes the
  currently-installed application package and protocol bundle). Both
  destructive actions use the same two-call confirmation protocol IDP
  introduced in v0.2.0.
- New error variant `SignaturePackageNoUninstallTarget` for the case where
  `uninstall` is called against a device that has no AppID package
  currently installed.
- 14 new XML fixtures captured live from vSRX-test3 (Junos 24.4R1) and
  22 fixture-driven unit tests covering the new parsers, plan builders,
  and async-status detection logic.
- Five new `#[ignore]`d live smokes against LXC 601:30032 in
  `tests/live_smoke.rs` — `appid_check_server_returns_latest_version`,
  `appid_download_and_install_call1_returns_plan`,
  `appid_uninstall_call1_returns_plan`, `appid_uninstall_call2_succeeds`,
  and `appid_cluster_install_syncs_both_nodes` (cluster smoke shipped
  `#[ignore]` per task scope; gracefully accepts a lab-gap error today).

### RPC contract (live capture 2026-05-26 against vSRX-test3, Junos 24.4R1)
- All AppID RPCs are **flat single-element** (no composite parent+child
  like IDP's `<request-idp-security-package-download><check-server/></...>`).
- Names use the `request-appid-application-package-*` prefix, not
  `request-services-application-identification-*` (which was the original
  design-doc guess — that CLI namespace does not exist as an RPC).
- The check-server envelope is `<apppack-server-status>` with a free-text
  `<apppack-server-status-detail>`, distinct from the
  `<apppack-download-status>` envelope used by the download workflow.
- Async-status responses use plain-English token vocabulary
  (`Downloaded`/`Installed`/`Uninstalled` for terminal-success; substring
  "failed" for terminal-failure), not IDP's `Done;`/`Failed;` markers.
- `get-appid-package-version` reports `<version-detail>` as `"0"`
  post-uninstall on Junos 24.4R1 — `normalize_version_text` treats `"0"`,
  `""`, and `"N/A"` as equivalent absence markers.

### Lab gaps (documented, not blocking)
- `vSRX-test3` cannot reach `signatures.juniper.net` from the homelab;
  `check_server` and the destructive download path emit
  `signatures_server_unreachable` until egress is fixed. Smokes
  graceful-degrade to accept that error.
- The cluster smoke (`vSRX-test19-20`) requires a clustered+AppID-licensed
  pair the lab does not currently have; the smoke accepts a `license_inactive`
  or transport error in the interim.

### Changed
- Tool surface 7 → 8.
- Server `instructions` string lists `manage_appid_signature_package`
  alongside `manage_idp_security_package`.

### Notes
- The two-call confirmation protocol, per-router transfer locks, license
  preflight, cluster topology detection, commit-confirmed audit warn, and
  `[code=...]`-bracketed error vocabulary all reuse the
  `workflows::signature_package` primitives shipped in v0.2.0.
- Verified live against LXC 601:30032 (5/5 AppID smokes pass; uninstall
  call2 successfully removed the package from vSRX-test3 on first run).

## [0.1.2] — 2026-05-26

Bugfix release. License XML parser now accepts the date-only `<end-date>`
shape that several Junos demolab + commercial bundles emit on the wire
(`<end-date>2027-05-22</end-date>`). Pre-fix, every IDP-licensed lab box
returned `xml parse: end-date parse error: unrecognised Junos date format`
from `check_srx_feature_license`, masking real licenses as parse failures
and blocking Phase 2 signature-package smoke work.

### Fixed
- `license::junos_date_to_offset` accepts the 10-char `YYYY-MM-DD` shape
  in addition to the long-form `YYYY-MM-DD HH:MM:SS UTC`. Date-only inputs
  resolve to 23:59:59 UTC of the named day (conservative for an expiry —
  midnight UTC could underreport remaining time by a day in eastern
  timezones). Verified live against vSRX-twin, vSRX-test1/2/3/4, vSRX-mm-B,
  vSRX-Production via `/etc/jmcp/devices.json` on LXC 601:30032.

### Operational note
- Confirms a separate latent gap (not fixed in this release): `rust-srxmcp`
  reads `/etc/jmcp/devices.json` once at startup; SIGHUP only reloads the
  token store. Editing the inventory therefore requires a full service
  restart until a `reload_devices` analogue is added (tracked separately
  as a Phase 1 polish item).

## [0.1.1] — 2026-05-21

Live-smoke follow-up to v0.1.0. Fixes the three runtime bugs discovered
on LXC 601 immediately after the v0.1.0 deploy (issues #68/#69/#70).

### Fixed
- `get_chassis_cluster_status` (#68): switch RPC name from
  `get-chassis-cluster-status-information` to `get-chassis-cluster-status`.
  The previous name produced `[OperationFailed] syntax error` on vSRX 24.4;
  verified via Junos's own `| display xml rpc` introspection on
  `show chassis cluster status`.
- `check_srx_feature_license` (#69): `license::parse()` now sanitises the
  reply through `xml::sanitize_rustez_xml` before handing it to roxmltree.
  Live replies carry `junos:seconds` / `junos:style` attributes whose
  `xmlns:junos` declaration is stripped by rustnetconf's
  `extract_rpc_reply_inner_content`; without sanitisation roxmltree refused
  the document with `unknown namespace prefix 'junos'`.
- `get_srx_security_services_status` (#70): refactor `run()` so a failing
  sub-RPC degrades only its own slot to `state=not_configured` instead of
  aborting the entire tool with `?`. vSRX 24.4 returns syntax `rpc-error`
  for `get-secintel-feed-summary`; the previous fail-fast design surfaced
  that as a top-level transport error and lost the IDP/AppID/UTM/ATP
  results that were already available.

### Added
- `live_eval_with_junos_attrs.xml` fixture mirroring the actual rustnetconf
  output (post `extract_rpc_reply_inner_content`) so future regressions of
  #69 are caught by `cargo test`.
- `per_node()` helper + `SubCall` capture in `services_status` plus three
  unit tests covering the new degradation paths (Err → not_configured,
  Ok-but-missing-index → not_configured, Ok-with-payload → parser).

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
