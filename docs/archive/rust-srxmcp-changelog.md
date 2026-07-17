# Changelog — rust-srxmcp

> Historical changelog for the former standalone `rust-srxmcp` binary.
> Version 0.8.0 merged this server into `rust-junosmcp`; current changes are
> recorded in the repository root `CHANGELOG.md`.

All notable changes to the `rust-srxmcp` crate are recorded in this file.
The generic `rust-junosmcp` binary has its own changelog and version line
(`v0.6.x` at the time of this writing).

This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **#150 - optional per-token request-rate limiting.** Both streamable-HTTP
  endpoints can enforce a continuously refilled token bucket for each exact
  authenticated token name using configurable whole-number RPS and burst
  knobs. The limiter is disabled by default; exhaustion returns stable `429`
  JSON with `Retry-After`, runs before existing concurrency/session gates, and
  exports the bounded `token_rate` limit metric without caller labels.

- **#153 - native journald audit sink.** Both binaries can opt into direct,
  structured journald fan-out with `--audit-journald`; only `target="audit"`
  events are routed, fields use a stable `AUDIT_` namespace, and an unavailable
  journal fails startup instead of silently dropping the configured sink.

- **#149 - Prometheus HTTP metrics.** Streamable HTTP can now expose an
  opt-in, unauthenticated `/metrics` route with bounded-label active-session,
  resource-limit, tool-duration, and reaper metrics. The route shares the
  configured listener/TLS but bypasses MCP auth and limits, so deployments must
  protect it with network controls.

- **#148 - per-token MCP session caps.** Streamable HTTP now limits each exact
  bearer-token name to 16 live sessions by default (`0` disables), with atomic
  initialize admission, stable `token_session_cap` 503 responses, token isolation,
  and capacity returned on close or reap.

- **#147 - per-router HTTP concurrency limits.** Both streamable-HTTP endpoints
  now cap concurrent work per exact router name at 4 by default (`0` disables),
  with immediate `503` + `Retry-After: 1` load shedding. Multi-router calls hold
  one slot per unique target, and destructive calls count once while waiting for
  or holding the existing cross-process device lease.

### Fixed

- **#151 - strict global MCP session caps.** Concurrent initialize requests can
  no longer leave live sessions beyond the tracked global cap. A race loser is
  closed without cancellation leaks and receives the existing `session_cap`
  `503` with `Retry-After: 1`; ordinary session-manager failures remain `500`.
- **#129 stage 2 - cross-process destructive-operation races.** Junos upgrades
  and destructive SRX IDP/AppID package actions now hold the same kernel-backed
  per-device file lease across locked preflight and execution. Lease waits are
  bounded, cancellation-aware for upgrades, and audited with one correlation
  ID. The kernel releases leases on process exit/crash; persistent lock files
  retain last-owner metadata and are never used as the lock-state authority.
- **#129 stage 1 - destructive signature-package confirmation bypass.**
  IDP and AppID previews now issue 256-bit, five-minute, one-time confirmation
  tokens. Execution binds the token to the authenticated caller, inventory
  endpoint, router, action, target, and normalized plan; re-runs preflight
  under the process-local device lock; rejects material drift; and carries the
  preview correlation ID through execution audit phases. Bare `confirm=true`,
  expired, replayed, tampered, and wrong-caller tokens fail closed. Stage 2
  will replace the process-local lock with a cross-process device lease.
- **#125 - support-bundle path traversal through caller-controlled IDs.**
  Caller `request_id` values are now short ASCII correlation labels only;
  filesystem paths use an independent server-minted UUID. Router, request,
  RPC artefact, and device-log components are validated before path creation.
  Staging rejects symlink escapes, creates tarballs without following existing
  destinations, and removes scratch or partial archive files on every error.

## [0.3.6] — 2026-06-05

Security follow-up to [0.3.5]: closes two redaction gaps found by a live
JTAC-bundle smoke test against a real device.

### Fixed
- **#91 — `redact_xml` was a no-op on real `get-configuration` captures,
  leaking root password hashes.** Live Junos `get-configuration` replies open
  with `<configuration … junos:changed-seconds="…" junos:changed-localtime="…">`
  whose `junos:` attribute prefix is **undeclared** (no `xmlns:junos`).
  `roxmltree` rejects the unbound prefix, so the well-formedness gate failed and
  `redact_xml` returned the **entire config verbatim** — shipping root and local
  `encrypted-password` `$6$…` hashes and the SNMP `community` in the clear, with
  the bundle manifest still reporting `redacted:false`. The unit tests passed
  only because they used cleanly-namespaced fixtures, not live device output.
  The gate now also accepts the namespace-sanitized form
  (`crate::xml::sanitize_rustez_xml`, which strips undeclared `junos:` attrs),
  while redaction still runs over the original input (quick-xml treats
  `junos:foo` as an opaque attribute name). Genuinely malformed XML is still
  returned unchanged.
- **#92 — a `set` config statement echoed mid-line escaped log redaction.**
  `redact_log_text`'s set-context only fired when a line *started* with `set `
  or contained the `set:` audit marker. A `UI_CMDLINE_READ_LINE` syslog echoes
  the raw RPC command mid-line (`… load-configuration set snmp community VALUE
  authorization read-only`), where the bare community value carried no other
  config signal and slipped through. Set-context is now decided per key by
  `set_statement_precedes`, which trips when a whole-word `set` token precedes
  the key and every token between is a config identifier — catching the mid-line
  echo while leaving prose like "we set the secret aside" untouched (the
  intervening stopword "the" suppresses the match).

## [0.3.5] — 2026-06-05

Security follow-up to [0.3.4]: extends redaction to plain-text log lines.

### Fixed
- **#89 — secrets embedded in plain-text log *lines* shipped in the clear.**
  The [0.3.4] `redact_xml` pass only scrubs XML element text; the `/var/log/*`
  files archived since #82 are not well-formed XML, so they failed the
  `roxmltree` gate and were emitted **verbatim** inside JTAC bundles even with
  `redact=true` (the default). A PSK/password echoed in a config-change log, an
  SNMP `community` in a trace, or credentials in a debug trace still leaked.
  Now non-XML artefacts are routed through a new conservative, line-oriented
  redactor (`redact_log_text`, dispatched by `redact_log_artefact`) that scrubs
  the same `REDACT_ELEMENT_NAMES` surface in config-style log syntax —
  `key=value`, `key "value"`, a format qualifier (`ascii-text` /
  `hexadecimal` / `plain-text` / `encrypted`), `key value;`, a bare Junos crypt
  hash (`$9$…`), and bare values on `set …` lines — replacing the value with
  `<REDACTED>` and tripping the per-artefact `redacted` flag. Bare prose
  mentions of a key name (no config signal) are left untouched to avoid false
  positives. No new crate dependency.

## [0.3.4] — 2026-06-05

Security fix for JTAC support-bundle redaction.

### Fixed
- **#85 — `redact_xml` was a no-op stub, leaking secrets despite
  `redact=true` (the default).** `collect_jtac_support_bundle` shipped
  PSKs, `secret`/`simple-password`/`encrypted-password`, SNMP `community`,
  and `hmac-key` values **in the clear** inside every bundle artefact (the
  `get-configuration` RPC capture, the generic `request support
  information` payload, and the `/var/log/*` files added in #82). The
  manifest's `redacted` flags never tripped. Now implemented: input is
  gated on `roxmltree` well-formedness, then streamed through `quick-xml`
  replacing the text content of any element whose namespace-stripped local
  name is in `REDACT_ELEMENT_NAMES` with `<REDACTED>`, preserving element
  structure so JTAC can still see *where* a secret was configured. On parse
  failure the input is returned unchanged (callers treat that as
  non-fatal).

### Known limitation
- Redaction is XML-element based, so secrets embedded in plain-text log
  *lines* still pass through unchanged (a log file fails the XML
  well-formedness gate and is emitted verbatim). A text-pattern pass for
  log lines is tracked separately in #85.

## [0.3.3] — 2026-06-02

Implements JTAC support-bundle log archival (the per-type path's last gap).

### Added
- **#82 — `/var/log/*` archival in the per-type bundle path.** With
  `include_logs:true` (the default), each baseline + per-problem-type log
  is now pulled inline via `file show <path>` over the same pooled
  `command` RPC used for the RPC captures, then staged into
  `logs/<device-path>` inside the tarball with a real `sha256` +
  `bytes_in_tarball`. Previously every log artefact was an empty
  placeholder carrying `error: "log archival not implemented in v0.3.0
  (tracked for v0.3.1)"`. The `fetch_file` SCP primitive cannot serve the
  log dir (it only pulls basenames out of `/var/tmp`), and CLI pipe
  modifiers (`| save`, `| last`) are silently ignored over the NETCONF
  `command` RPC — verified live — so the inline `file show` capture is the
  correct mechanism.
  - `max_log_bytes_per_file` (default 10 MiB) now enforces a real size cap:
    the inline payload is truncated at a UTF-8 char boundary and the
    artefact records `error: "truncated to max_log_bytes_per_file=N"`.
  - `max_log_files` (default 5) now enforces a real count cap: logs beyond
    the cap are recorded as skip markers
    (`error: "skipped: max_log_files=N reached"`) so JTAC sees what was
    omitted.
  - Per-log failures (`file show` transport error, or a Junos
    `error: …`-prefixed reply for an absent/unreadable file) degrade to a
    per-artefact `error` instead of failing the whole bundle.
  - New `truncate_to_char_boundary` helper + unit test.

### Known limitation
- `redact_xml` is still a no-op stub (returns input unchanged), so
  `redact=true` does not yet scrub secrets from any bundle artefact —
  RPC, generic, or log. Redaction is wired through the log path for parity
  so logs are scrubbed automatically once the stub is implemented. Tracked
  separately in #85.

## [0.3.2] — 2026-06-02

Bugfix for the `generic` JTAC support-bundle path.

### Fixed
- **#81 — `collect_jtac_support_bundle` generic path reported success but
  produced no file.** The generic path issued
  `request support information | save /var/tmp/srxmcp-<rid>.tgz` over the
  NETCONF `command` RPC and reported `state=active` with `bytes=0`,
  `sha256=""`, and an empty artefact list. The `| save <path>` redirection
  is **not honoured** over the `command` RPC — the full tech-support text
  is returned INLINE and nothing is written on-device, so the advertised
  `fetch_file` next-step always failed (`No such file or directory`). The
  generic path now runs `request support information` (no `| save`),
  captures the inline payload, applies redaction when `redact=true`, writes
  it into the per-router LXC staging scratch dir, and assembles a real
  tarball — identical to the per-type path. The response now reports
  `location=lxc_staging` with a non-zero `bytes`, a real `sha256`, and one
  `request support information` artefact. A new shared `finalize_lxc_bundle`
  helper backs both the generic and per-type tails (manifest write + tar +
  digest). Adds one regression test asserting the generic finalize yields a
  non-empty, hashed `lxc_staging` bundle.

## [0.3.1] — 2026-06-02

Cosmetic patch for the Phase 3 JTAC support-bundle path builders.

### Fixed
- **#79 — bundle filenames double-prefixed `srxmcp-`.** `mint_request_id`
  already returns `srxmcp-<uuid>`, but `bundle_tarball_path`,
  `bundle_manifest_path`, and `device_tarball_path` each prepended a second
  `srxmcp-`, producing names like
  `…/vSRX-test10/srxmcp-srxmcp-<uuid>.tgz` (and `/var/tmp/srxmcp-srxmcp-<uuid>.tgz`
  on-device). A new `request_id_stem` helper strips any single leading
  `srxmcp-` before the builders prepend one, so the prefix appears exactly
  once. Robust across server-minted IDs, bare caller IDs, and already-prefixed
  caller IDs. The `request_id` value reported in responses/manifests is
  unchanged (`srxmcp-<uuid>`); only the on-disk filename normalizes. The
  bundle manifest schema string stays `srxmcp-support-bundle-v0.3.0` (no
  structural change). Adds two regression tests in
  `support_bundle::staging`.

### Security
- Bumped transitive `russh` 0.60.2 → 0.60.3 and `russh-cryptovec`
  0.59.0 → 0.60.3 in `Cargo.lock` to clear RUSTSEC-2026-0154 (unbounded
  32-bit allocation) and RUSTSEC-2026-0153 (unchecked `CryptoVec`
  allocation/growth). Pulled in via `rustnetconf` → `rustez`; patch-level
  bump, no API change.

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
