# Contributing to rust-junosmcp

Thanks for considering a contribution. rust-junosmcp is a [Model Context
Protocol](https://modelcontextprotocol.io/) server for Juniper Junos and SRX
devices, written in Rust — part of the [mechub](https://github.com/fastrevmd-lab)
family of open-source, self-hosted network-security automation tooling. It's
built on [rustnetconf](https://github.com/mechubsec/rustnetconf) and
[rustEZ](https://github.com/mechubsec/rustez), and shares the `mecmcp`
crate family (auth, transport, runtime, policy, audit, etc.) with sibling
mechub MCP servers.

## Before you start

- Check open issues and PRs first — someone may already be working on it.
- For anything larger than a small fix, open an issue to discuss the approach
  before writing code. It saves everyone a rewrite.
- This project follows one hard rule across the whole mechub fleet:
  **deterministic code decides, a model may explain, a human approves.**
  Nothing you contribute should let an LLM or other model output directly
  drive a device action (a config load, a commit, an upgrade, a package
  push). Models may draft, summarize, or explain; deterministic code decides.

## Workspace layout

This is a Cargo workspace (`resolver = "2"`) with four members:

- `rust-junosmcp` — the unified Junos/SRX MCP server binary.
- `rust-junosmcp-core` — device I/O, the core Junos tools, and HTTP limits.
- `rust-junosmcp-auth` — the auth security boundary.
- `rust-junosmcp-srx-core` — optional SRX security workflows (enabled by
  default, but not part of `[workspace] default-members`, so a plain
  `cargo build`/`cargo test` from the workspace root without `--workspace`
  or `-p` will skip it — CI and the commands below always pass `--workspace`
  or explicit `-p` flags).

Read-only tools (facts, config, diffs) are the default surface. Inventory
mutation, file transfer, configuration load/commit, upgrades, support
bundles, and package-lifecycle tools are treated as high-risk and reviewed
accordingly (see `AGENTS.md` for the full list).

## Build and test

```sh
cargo build --workspace
cargo test --workspace
```

Junos-only (no SRX) feature builds, which CI also runs:

```sh
cargo build -p rust-junosmcp --no-default-features --locked
cargo build -p rust-junosmcp --no-default-features --features tls --locked
cargo test -p rust-junosmcp --no-default-features --locked
```

Format and lint, both required to pass in CI (`.github/workflows/ci.yml`):

```sh
cargo fmt -p rust-junosmcp-core -p rust-junosmcp -p rust-junosmcp-auth -p rust-junosmcp-srx-core -- --check
cargo clippy -p rust-junosmcp-core -p rust-junosmcp -p rust-junosmcp-auth -p rust-junosmcp-srx-core --all-targets -- -D warnings
```

Dependency and secret-scanning checks, both required to pass in CI
(`.github/workflows/security.yml`):

```sh
cargo audit
cargo deny check bans sources
```

If you have [`just`](https://github.com/casey/just) installed, `just setup`,
`just fmt`, `just lint`, `just test`, and `just guard` (lint + test) wrap the
same commands; see the `justfile` for the full list of recipes, including
`just security` (runs `trivy` locally) and `just release-check`.

### Lab / real-device integration tests

`just integration` runs `cargo test -p rust-junosmcp-core --test
integration_real_device -- --ignored`. It is gated behind
`CONFIRM_LAB_INTEGRATION=yes` and is **not** run in hosted CI — skip it
unless you have lab access to a real (non-production) Junos/SRX device.
Never point it at a production device, and never commit real hostnames,
credentials, serials, or device output captured from a real-device run.
`devices-template.json` and `tokens-template.json` must stay secret-free —
they're templates, not real inventory.

## Dependencies

New dependencies, and version bumps that touch `deny.toml`'s allow-list, get
reviewed for maintenance status, license, and attack surface. The `mecmcp-*`
crates are pinned to a git tag (`mechubsec/mecmcp`) rather than
crates.io; all of them must move together to the same tag in one PR — mixing
tags produces two incompatible copies of shared types in the dependency
graph (see the comment in `Cargo.toml`).

## Commit and PR conventions

- Match the existing commit style: `type(scope): summary` (`fix(audit):`,
  `feat(server):`, `build(deps):`, `chore(release):`, etc.) — see `git log`
  for examples.
- Keep PRs focused on one change. A bug fix doesn't need a drive-by refactor
  riding along.
- Fill out the PR template, including the exact commands you ran to verify
  the change.
- All contributions land as a pull request against `main` for human review —
  there is no direct-push path to `main`. By opening a pull request, you're
  agreeing your contribution is licensed under this repository's
  [MIT license](LICENSE).

## Review process

Every pull request goes through a security review and a code review, then an
independent test run, before anything merges. Only a maintainer merges —
contributors, including anyone with write access, should not merge their own
PR. CI (build, test, clippy, fmt, `cargo audit`, `cargo deny`, secret
scanning) must be green first.

## Reporting a vulnerability

Please don't open a public issue for a security vulnerability — see
[SECURITY.md](SECURITY.md) for how to report one privately.

## Fixtures and test data

Never commit real device inventories, hostnames, serial numbers,
credentials, bearer tokens, SSH keys, generated certificates, or support
bundles — synthetic or sanitized fixtures only. If you find real data
already committed anywhere in this repo, don't add to it — report it
privately instead (see [SECURITY.md](SECURITY.md)).
