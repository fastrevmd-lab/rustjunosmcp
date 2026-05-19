# Changelog

All notable user-facing changes are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.7] — 2026-05-18

Fixes a latent bug exposed (but not introduced) by v0.5.6: every
NETCONF op command failed with `transport error: connection failed:
SSH connect to <ip>:22 failed: Unknown server key`. Root cause —
`DeviceManager` built the `rustez::Device` without ever calling
`.host_key_verification(...)`, so it inherited the rustnetconf 0.11+
default of `RejectAll` (fail-closed). v0.5.5 had the same bug; it was
just unobserved until a live op command was run after the dep bump.

### Fixed

- **NETCONF SSH host-key policy is now wired through.** `DeviceManager`
  carries a `HostKeyVerification` policy (new field) applied to every
  fresh `Device` connect. Production posture mirrors scp:
  - default → `HostKeyVerification::KnownHosts(args.known_hosts_file)`
    (strict; reuses the pre-existing `/etc/jmcp/known_hosts` file that
    was already populated for scp).
  - `--ssh-accept-new-host-keys` → `HostKeyVerification::AcceptAll`
    (lab/TOFU mode; same flag that already toggles scp behavior).
  - No new CLI surface.

### Added

- `DeviceManager::with_host_key_policy(HostKeyVerification) -> Self` —
  fluent setter for the new policy field. Default for the bare
  `::new()` / `::with_path()` constructors remains `AcceptAll` so the
  ~40 unit-test call sites keep working without plumbing.
- `rust_junosmcp_core::HostKeyVerification` re-export (from rustez 0.12)
  so the binary crate doesn't need its own rustez dep.

### Verification

- 323 unit tests pass (2 new: default-policy + setter coverage).
- `cargo clippy --workspace --all-targets -- -D warnings` and
  `cargo fmt --check` are clean.
- Live smoke test against vSRX-test10 from LXC 601 after deploy.

### Tooling

- Workspace version bumped to `0.5.7`.

## [0.5.6] — 2026-05-18

Dependency bump. `rustez 0.11.0 → 0.12.0` pulls in `rustnetconf 0.11
→ 0.12`. Additive only — no caller code in this repo changes.

### Added (upstream surface)

- **`HostKeyVerification::KnownHosts(PathBuf)`** is now re-exported by
  rustez (from `rustnetconf 0.12`). Callers may point at an OpenSSH
  `known_hosts` file instead of pinning a single fingerprint at the
  NETCONF layer. RustJunosMCP does not yet opt in to NETCONF host-key
  verification (tracked as a follow-up); scp host-key pinning via
  `known_hosts` remains strict since v0.5.2.

### Fixed (upstream)

- Stale rustez doc comments on `DeviceBuilder::host_key_verification`
  and Python `Device.__init__` corrected — they now reflect the
  `RejectAll` default introduced in `rustnetconf 0.11`.

### Verification

- `cargo audit` against the post-bump `Cargo.lock` reports **zero
  advisories** across 397 crates.
- 321 unit tests pass; `cargo clippy --workspace --all-targets --
  -D warnings` and `cargo fmt --check` are clean.

### Tooling

- Workspace version bumped to `0.5.6`.

## [0.5.5] — TBD

Dependency bump. `rustez 0.10.1 → 0.11.0` pulls in `rustnetconf 0.10
→ 0.11`. Backward-compatible at the API level — no caller code in
this repo changes.

### Security

- **rustez 0.11.0 inherits these upstream fixes** (per the rustEZ
  0.10.1 → 0.11.0 audit cycle):
  - **RZ-SEC-001** — `DeviceBuilder::host_key_verification()` is now
    available for opt-in NETCONF SSH host-key pinning. Default is
    unchanged (`AcceptAll` with warning) for backward compatibility.
    RustJunosMCP does **not** yet opt in to fingerprint pinning at
    the NETCONF layer; tracked as a follow-up. (Note: scp host-key
    pinning via `known_hosts` is already strict since v0.5.2.)
  - **RZ-SEC-002** — RUSTSEC-2023-0071 (rsa timing side-channel) is
    documented as an accepted/tracked risk in the rustEZ CI ignore
    list. No change to RustJunosMCP exposure.
  - **RZ-SEC-003** — rustez now closes the auto-opened config DB on
    load failure, preventing a leaked lock if a config load errors
    after the DB was opened on the caller's behalf. RustJunosMCP's
    `apply_junos_config` / template-render tools inherit the fix
    transparently.
  - **RZ-QUAL-001 / RZ-QUAL-002** — workspace package-drift CI check
    and `rb_id` forwarding through `diff()`. No user-visible change
    here, but reduces the risk of future rustez regressions affecting
    our `diff_against_rollback` tool.

### Verification

- `cargo audit` against the post-bump `Cargo.lock` reports **zero
  advisories** across 397 crates.
- 321 unit tests pass; live `upgrade_junos` integration test passes;
  `cargo clippy --workspace --all-targets -- -D warnings` and
  `cargo fmt --check` are clean.

### Tooling

- Workspace version bumped to `0.5.5`.

## [0.5.4] — TBD

Server-side correctness pass for the long-running `upgrade_junos`
tool. No new tools or wire-protocol changes; two bug fixes and one
observability gap closed.

### Fixed

- **`upgrade_junos.args.timeout` now actually constrains the transfer
  phase** (#42). Previously the inner call to `transfer_file::handle`
  used a hard-coded 600 s timeout regardless of the operator-supplied
  `args.timeout` (default 900 s). Raising the outer budget had no
  effect on the longest phase, so large-image transfers on slow links
  hit a phantom 600 s cap. The inner call now uses `args.timeout`; the
  outer `tokio::time::timeout(args.timeout, run(…))` remains the wall
  bound, so `UpgradeOuterTimeout` fires as documented.

### Added

- **`audit tool="upgrade_junos"` log line on every result path** (#42).
  `upgrade_junos` previously had no audit logging in the server-layer
  wrapper, so operators could not distinguish "tool errored" from
  "client disconnected mid-call" from "tool never ran." It now emits
  the same `audit` shape as `transfer_file` / `list_staged_files` on
  Ok, Err, and HTTP-cancellation paths. Cancellation lands via a
  `Drop`-based guard with `outcome="cancelled"`.

### Note

- rmcp 0.8.5's streamable-HTTP transport already emits SSE `:`
  keep-alive comments at 15 s intervals (`sse_keep_alive` default).
  SSE-aware clients should hold the response stream open for the full
  `args.timeout`. The original #42 symptom — `upgrade_junos` appearing
  to hang ~6 min — was a curl `--max-time` wall-clock cap on the
  smoke harness, not a server-side hang. Operators driving
  `upgrade_junos` from curl must set `--max-time` ≥ `args.timeout`.

### Tooling

- Workspace version bumped to `0.5.4`.

## [0.5.3] — TBD

Bugfix release for the `transfer_file` / `upgrade_junos` pre-transfer
checksum probe against Junos 24.x devices.

### Fixed

- **`parse_checksum_output` rejected Junos 24.x missing-file output**
  (#40). The probe (`file checksum sha-256 /var/tmp/<name>`) returns
  `sha256: (sha256: /var/tmp/<name>: No such file or directory) = directory`
  on 24.x when the destination is absent, instead of the older
  `error: stat: /var/tmp/<name>: No such file or directory` form. The
  parser only recognized the older form, so the probe failed with
  `validation error: unable to parse checksum output`, aborting the
  transfer **before any scp was attempted**. Any line containing
  `No such file or directory` is now treated as the missing-file
  signal regardless of prefix; the success format (trailing 64-char
  hex digest) is unambiguous.

### Tooling

- Workspace version bumped to `0.5.3`.

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
