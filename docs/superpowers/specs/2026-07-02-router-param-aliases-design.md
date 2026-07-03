# Router-param aliases (#104)

**Issue:** #104 — inconsistent router param name across tools (router_name vs routers vs router)
**Date:** 2026-07-02
**Status:** Approved design

## Problem

The target-router parameter is named inconsistently across tools: junos single-router tools use `router_name` (string), `execute_junos_command_batch` uses `routers` (list), and srx tools use `router`. An LLM's first call to a not-yet-seen tool guesses the wrong key and gets an opaque deserialize error, e.g. `missing field 'routers'` after (reasonably) passing `router_name` — a wasted round-trip on every new tool.

## Decision: additive serde aliases (non-breaking)

Add `#[serde(alias = …)]` so every router-target field accepts the common names. No field renames (backward-compatible with existing callers and advertised schemas). The batch list field additionally accepts a single string (coerced to a one-element list).

**Accepted-name set:**
- Single-router fields → accept **`router`** and **`router_name`**.
- Batch list field (`routers`) → accept **`router`**, **`router_name`**, **`routers`**, and a **string-or-list** value.

## Components

### junos — `rust-junosmcp-core/src/tools/mod.rs`

The 12 single-router `router_name` fields — `ExecuteCommandArgs`, `GetConfigArgs`, `ConfigDiffArgs`, `GatherFactsArgs`, `LoadCommitArgs`, `CommitCheckArgs`, `ExecutePfeArgs`, `TemplateArgs` (`Option`), `TransferFileArgs`, `FetchFileArgs`, `ListStagedFilesArgs` (`Option`), `UpgradeJunosArgs` — each gains `#[serde(alias = "router")]`.

`ExecuteBatchArgs.routers: Vec<String>` gains `#[serde(alias = "router", alias = "router_name", deserialize_with = "string_or_vec")]`. A small helper:

```rust
/// Deserialize a `Vec<String>` from either a JSON string (→ one-element vec)
/// or a JSON array of strings. Lets `routers`/`router`/`router_name` accept a
/// single router name as well as a list.
fn string_or_vec<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where D: serde::Deserializer<'de> {
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum OneOrMany { One(String), Many(Vec<String>) }
    Ok(match OneOrMany::deserialize(d)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
    })
}
```

The JSON schema stays `array<string>` — schemars reads the field's declared type (`Vec<String>`), independent of serde's `deserialize_with`; the tool description notes a single string is also accepted. (If schemars rejects a field with `deserialize_with` and no matching `schemars` attr, add `#[schemars(with = "Vec<String>")]` — resolve at build time.)

### srx — `rust-srxmcp-core/src/workflows/*`

The ~10 `router: String` arg structs — `SupportBundleArgs`, `ServicesStatusArgs`, `ClusterHealthArgs`, `ClusterStatusArgs`, `VpnLifecycleArgs`, `LicenseArgs`, `IdpPackageArgs`, `AppidPackageArgs`, and the `signature_package/plan` arg struct(s) — each `router` field gains `#[serde(alias = "router_name")]`. (`router` is already the primary; adding `router_name` matches junos so either resolves.)

### Tool descriptions

Where practical, append to the router param's description (or the tool description) a note: "router param accepts `router` or `router_name`" (batch: "…or `routers`; a single name or a list"). Low priority; the aliases are the functional fix.

## Testing

Serde round-trip unit tests (pure, no device):
- Each single-router struct deserializes identically from `{"router_name":"r1"}` **and** `{"router":"r1"}`.
- `ExecuteBatchArgs` deserializes from `{"routers":["a","b"]}`, `{"routers":"a"}` (→ `["a"]`), `{"router":"a"}`, `{"router_name":"a"}`.
- An srx arg struct deserializes from both `{"router":"r1"}` and `{"router_name":"r1"}`.
- Existing arg-default/required tests still pass (aliases are additive; the primary name still works).

Gates: `cargo test --workspace` 0 failures; `cargo fmt -- --check` + `cargo clippy --workspace` clean.

## Out of scope

- No field renames (backward-compatible).
- No custom top-level deserialize-error rewriting — the aliases remove the reported friction (YAGNI).
- No change to tool behavior, routing, or the tool surface.

## Risks

1. `deserialize_with` + `schemars` derive interaction on `ExecuteBatchArgs.routers` — if schemars errors, add `#[schemars(with = "Vec<String>")]`. Guarded by the build.
2. A future tool that legitimately means something different by `router` vs `router_name` would be surprised by the alias — none exist today; all these fields mean "the target router(s)".
