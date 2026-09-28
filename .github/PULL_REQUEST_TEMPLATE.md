## Summary

<!-- What does this PR do, and why? -->

## Changes

<!-- Bullet list of what changed -->

## Verification

<!-- Exact commands you ran and their result. "Should work" is not verification. -->

```sh

```

## Checklist

- [ ] `cargo fmt -p rust-junosmcp-core -p rust-junosmcp -p rust-junosmcp-auth -p rust-junosmcp-srx-core -- --check` passes
- [ ] `cargo clippy -p rust-junosmcp-core -p rust-junosmcp -p rust-junosmcp-auth -p rust-junosmcp-srx-core --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` (and the `--no-default-features` builds, if relevant) pass
- [ ] Tests added or updated for this change, and they fail against the old code
- [ ] `cargo audit` and `cargo deny check bans sources` are clean, or any new advisory/exception is called out below
- [ ] This touches a device-facing config/command path (inventory, file transfer, config load/commit, upgrade, support bundle, package lifecycle): **yes / no** — if yes, explain how the existing safety gates (validated target, exact diff, confirmed commit/rollback) are preserved
- [ ] Any new or changed fixtures/test data are synthetic — no real hostnames, serials, credentials, tokens, keys, or device output
- [ ] No new telemetry, analytics, or outbound network call added
- [ ] If this touches a path that can act on a device or informs one: deterministic code decides, not a model output

## Anything you're unsure about

<!-- Flag it here rather than hoping review catches it -->
