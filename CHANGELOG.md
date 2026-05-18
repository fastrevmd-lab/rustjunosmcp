# Changelog

All notable user-facing changes are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.2] — TBD

Security audit response. Six findings from the internal code review
(`SECURITY_CODE_REVIEW_REPORT.md`, RJMCP-SEC-001..006) are now fixed.
No breaking changes to the MCP wire protocol, but two operator-facing
defaults change — see **Changed** below.

### Fixed (security)

- **SEC-001** — `KNOWN_TOOLS` drift. `transfer_file`,
  `list_staged_files`, and `upgrade_junos` were missing from the auth
  allowlist (the `tool:*` bearer-token scope check). A new drift
  test (`known_tools_matches_server_tools`) now asserts
  `KNOWN_TOOLS == SERVER_TOOLS` so future tool additions cannot bypass
  RBAC by omission.
- **SEC-002** — Drop YAML support in `render_and_apply_j2_template`'s
  `vars_content`. The crate depended on `serde_yml`, which carries an
  unmaintained-yaml advisory. `vars_content` is now strict JSON only.
  Callers that were passing YAML must convert to JSON; the `vars_file`
  path was already JSON.
- **SEC-003** — Centralised inventory validation. Username and
  private-key path fields are now validated on `add_device` and on
  inventory load — rejects spaces, leading dashes, control characters,
  and other shell-metacharacter classes that could be smuggled into an
  SSH argv. Helpers live in `rust-junosmcp-core::inventory::validation`
  so `add_device` and `Inventory::validate` share one source of truth.
- **SEC-004** — `transfer_file` / `upgrade_junos` now default to
  `StrictHostKeyChecking=yes`. Previously the server used TOFU
  (`accept-new`) on first contact, which silently pinned any host key
  presented during the first transfer. A new flag,
  `--ssh-accept-new-host-keys`, restores the old behaviour for lab
  bring-up. A helper script, `scripts/scan-known-hosts.sh`, drives
  `ssh-keyscan` against `devices.json` and writes the pinned file
  atomically.
- **SEC-005** — `reload_devices` `file_name` argument is now restricted
  to a relative basename inside the `--device-mapping` directory.
  Absolute paths, `..` traversal, and symlinks whose target escapes
  the inventory directory are all rejected with
  `InventoryInvalid`. Errors carry the original arg verbatim for
  debugging.
- **SEC-006** — Drop the `rustls-pemfile` crate (flagged unmaintained
  upstream). PEM parsing now uses `rustls-pki-types` directly
  (`CertificateDer::pem_slice_iter`, `PrivateKeyDer::from_pem_slice`),
  which ships in-tree with rustls 0.23.

### Changed

- **Default SSH host-key policy is now strict.** Operators who used
  the v0.5.x server against a fresh fleet without first pre-populating
  `known_hosts` will see `transfer_file` / `upgrade_junos` fail with
  the `known_hosts_missing` error code. Two recovery paths: (a) run
  `scripts/scan-known-hosts.sh --inventory /etc/jmcp/devices.json`
  before first use, or (b) start the server with
  `--ssh-accept-new-host-keys` for one-shot lab bring-up.
- **`render_and_apply_j2_template` rejects YAML in `vars_content`.**
  The schema documents `vars_content` as JSON; YAML was previously
  accepted as a best-effort fallback. Callers should switch to JSON
  (or use `vars_file`, which is unchanged).

### Tooling

- Workspace version bumped to `0.5.2`.
- New helper script: `scripts/scan-known-hosts.sh`.

## [0.5.1] — TBD

Bugfix release for the v0.5.0 `upgrade_junos` / `transfer_file` storage
preflight on older Junos layouts.

### Fixed

- **`parse_storage_free_bytes` on vSRX 24.x single-mount layout** (#36).
  v0.5.0's parser required a row whose `Mounted on` column was `/var`
  or `/.mount/var`. vSRX 24.x reports `/var` as a directory inside the
  root `/.mount` filesystem rather than as its own mount, so the
  parser fell through with `device_probe_failed (phase=storage_parse)`
  and blocked every upgrade originating from 24.x. The parser now
  records the `/.mount` row's `Avail` as a fallback and returns it
  when no dedicated `/var` row is found. Order of preference for the
  modern layout is unchanged: `/var` > `/.mount/var` > `/.mount`.

### Tooling

- Workspace version bumped to `0.5.1`.

## [0.5.0] — TBD

Feature release: new `upgrade_junos` MCP tool brings the standalone
vSRX upgrade workflow into the tool surface. Tool count 13 → 14.

### Added

- **`upgrade_junos` tool** — single MCP call automates the proven
  standalone vSRX upgrade workflow: pre-baseline → transfer →
  install + reboot → wait for NETCONF → post-verify → post-baseline
  → response. Two-call confirm protocol: first call returns a
  `ConfirmationRequired` JSON-RPC error carrying the full upgrade
  plan (current version, target version, image, free disk,
  estimated outage); operator re-calls with `confirm=true` to
  perform the destructive workflow. Reuses the v0.4.1
  `TransferLocks` semaphore so transfer_file + upgrade_junos
  serialize per-router. Cluster (ISSU) devices are auto-detected
  and refused — separate v2 tool planned.
- 7 new structured `JmcpError` variants:
  `ConfirmationRequired`, `UpgradeClusterUnsupported`,
  `UpgradeCommitConfirmedActive`, `UpgradeInstallTimeout`,
  `UpgradeRebootTimeout`, `UpgradePostVerifyMismatch`,
  `UpgradeOuterTimeout`. All follow the `[code=<snake>]` Display
  convention.

### Tooling

- Workspace version bumped to `0.5.0`.

## [0.4.1] — 2026-05-15

Security + hardening release. No tool API changes; one server-side
response-header change for unauthenticated requests, plus a new response
field on `list_staged_files`.

### Security

- **RFC 6750 bearer challenges on every 401** — the streamable-HTTP
  endpoint now always returns a `WWW-Authenticate: Bearer ...` header on
  `401 Unauthorized`. Wrong-token rejections include
  `error="invalid_token"` per RFC 6750 §3.1 so clients can distinguish
  bearer rejection from an OAuth-discovery prompt (avoids
  `~/.claude/.credentials.json` corruption from clients that retry as
  OAuth on a bare 401). (#27, PR #28)
- **`transfer_file` source-path allowlist tightened** —
  `validate_source_basename` previously rejected `/`, `\`, `..`, leading
  `.`, and >255 bytes but accepted NUL bytes, ASCII control characters,
  shell metacharacters, and arbitrary Unicode (including RTL overrides
  and homoglyph scripts). Now restricts to `[A-Za-z0-9._-]`. Junos image
  / config artifacts are plain ASCII so this is non-restrictive in
  practice. (#26 L2, PR #30)
- **`scp` stderr scrubbed in `ScpFailed` errors** — absolute filesystem
  paths and IPv4 addresses are redacted to `<path>` / `<host>` before
  the error is surfaced to the MCP caller. Diagnostic text is
  preserved. Closes a path/host leak surface in multi-tenant setups.
  (#26 L1, PR #31)

### Reliability

- **`list_staged_files` capped at 256 entries** — `read_staging_dir`
  previously walked every regular file and computed sha256 on each
  (~3 s/GB), producing slow + large responses when an operator dumped
  thousands of files into staging. Now caps at
  `STAGING_DIR_MAX_ENTRIES = 256` (sorted by name, deterministic
  truncation, sha256 skipped for excess files). Response gains two new
  fields: `staged_files_truncated: bool` and
  `staged_files_total_found: usize`. (#26 L5, PR #32)
- **Per-router serialization for `transfer_file`** — new `TransferLocks`
  process-wide map of `Arc<Semaphore(1)>` keyed by router name. Prevents
  a confused or buggy caller from exhausting a device's `/var/tmp` or
  session pool via fan-out. Different routers proceed in parallel; same
  router serializes. Junos serializes on its side anyway, so this caps
  client-side fan-out. (#26 L4, PR #33)

### Operability

- **Actionable EACCES message on `tokens.json`** — when the running
  process can't read the tokens file due to permissions, the server now
  surfaces the file owner uid + mode and the running process's uid plus
  a `sudo -u <service-user>` / `chown` hint. Previously the operator
  saw a bare `Permission denied (os error 13)` with no pointer at the
  underlying ownership mismatch. README also gained a note in the
  "Mint a token" section about running token subcommands as the service
  user. (#22 / #23, PR #29)

### Tooling

- Workspace version bumped to `0.4.1`.

## [0.4.0]

Initial release of the `transfer_file` + `list_staged_files` MCP tools.
See PR #25 for details.
