# RustJunosMCP repository instructions

## Purpose and architecture

This Rust workspace implements one Junos and SRX MCP server:

- `rust-junosmcp/` is the unified Junos/SRX MCP server.
- `rust-junosmcp-core/` owns device I/O, base tools, and HTTP limits.
- `rust-junosmcp-srx-core/` owns optional SRX workflows.
- `rust-junosmcp-auth/` is the auth security boundary.
- `rust-junosmcp-audit/` is the audit/compliance boundary.

Inventory mutation, file transfer, configuration load and commit, upgrades,
support bundles, and package lifecycle tools are high risk.

## Setup and development

- Install the golden workstation baseline and run `just setup`.
- Use the pinned `rust-toolchain.toml`; commit `Cargo.lock` with dependency
  changes. `just dev` shows the local server CLI without contacting a device.
- Keep MCP schemas, annotations, auth scopes, timeouts, and audit behavior
  compatible or document the break in the changelog.

## Required checks

- Offline: `just fmt`, `just lint`, `just test`, and `just guard`.
- `just integration` is the only target for ignored real-device tests and
  requires `CONFIRM_LAB_INTEGRATION=yes`.
- `just e2e` performs offline CLI help checks.
- Run `just security` and `just release-check` before handoff.

## Generated files and dependencies

- Do not hand-edit `Cargo.lock`, generated schemas, package archives, or build
  output. Keep `devices-template.json` and `tokens-template.json` secret-free.
- Review new dependencies for maintenance, license, crypto, and attack surface.

## Secrets and device safety

- Never commit device inventories, bearer tokens, SSH keys, fetched files,
  private configurations, support bundles, or generated certificates.
- Read-only facts/config/diff are the default. Writes require validated target,
  exact diff, approval, confirmed commit/rollback protection, and verification.
- Never run upgrades or real-device tests against production.

## Completion evidence

Report files changed, commands/results, schema or behavior compatibility,
skipped real-device checks, and remaining risk.
