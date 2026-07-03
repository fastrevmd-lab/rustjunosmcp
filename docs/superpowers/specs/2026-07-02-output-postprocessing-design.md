# Command output post-processing: caps + pipe honoring

**Issues:** #106 (max_lines/max_bytes output cap), #105 (dropped `| last N` / `| count` pipe modifiers)
**Date:** 2026-07-02
**Status:** Approved design

## Problem

Junos operational commands can return very large output. Two related failures observed during a live enterprise build:

- **#105:** `execute_junos_command` passes the command **verbatim** to rustez's `run_cli`, which translates CLI → NETCONF and **drops** trailing output-limiting pipe modifiers. `show log messages | match outbound | last 10` applied `| match` but dropped `| last 10`; `… | count` returned the full table instead of a count. The dropped modifiers are exactly the ones a caller adds to bound output.
- **#106:** Even with correct pipes, some commands legitimately return a lot (`show system connections`, `show route`, `show log …`). Oversized responses (66–97 KB) tripped the MCP client token budget **three times** in one session.

There is no MCP-native way to bound a single command's output.

## Design

A single pure function post-processes the `run_cli` string before it is returned, wired into all three command-execution tools. Default-off — behavior is unchanged unless a new arg is set or the command carries a recognized trailing pipe.

### New module: `rust-junosmcp-core/src/output.rs`

```rust
/// Post-process operational-command output: honor the trailing `| count` /
/// `| last N` pipe modifiers that rustez drops in NETCONF translation (#105),
/// then apply optional size caps (#106). Pure; no I/O.
pub fn process_output(
    command: &str,
    raw: String,
    max_lines: Option<u32>,
    max_bytes: Option<u32>,
    tail: bool,
) -> String
```

Order of operations:

1. **Honor trailing pipe modifiers (#105).** Parse the pipe segments of `command` and, if the **last** recognized output-limiting modifier is one of these, apply it to `raw`:
   - `| count` → replace the whole output with `Count: <N> lines\n` where N is the line count of `raw` (matches Junos's own `| count` format).
   - `| last <N>` → keep only the last N lines of `raw`.
   Only these two are honored (the reported cases). `| match` / `| except` / etc. are left to rustez (which already applies them). Applied automatically — the caller placed the pipe intentionally. If both appear (`… | last 5 | count`), apply in left-to-right order (last then count). If N is missing/unparseable, the modifier is ignored (leave `raw` as-is).

2. **Apply explicit caps (#106)**, in this order, after step 1:
   - `max_bytes`: if the (post-step-1) output exceeds `max_bytes`, truncate to at most `max_bytes` on a UTF-8 char boundary and append `\n… (truncated, <omitted> bytes omitted)`.
   - `max_lines`: if the output has more than `max_lines` lines, keep the first N (or the **last** N when `tail == true`) and append `\n… (truncated, <M> more lines)`.
   Both are `Option`; when `None`, that cap is skipped. When both `None` and no honored pipe, `process_output` returns `raw` unchanged.

Rationale for order: honor the caller's own pipe intent first; the explicit caps are a belt-and-suspenders ceiling on top.

### New tool args

Add to `ExecuteCommandArgs`, `ExecuteBatchArgs`, `ExecutePfeArgs` (in `rust-junosmcp-core/src/tools/mod.rs`):

```rust
/// Cap output to at most N lines (head; use `tail` for the last N).
#[serde(default)]
pub max_lines: Option<u32>,
/// Hard byte cap on returned output.
#[serde(default)]
pub max_bytes: Option<u32>,
/// With `max_lines`, keep the LAST N lines instead of the first N.
#[serde(default)]
pub tail: bool,
```

### Wiring

- `execute_command::handle` — replace `Ok(json!(result))` with
  `Ok(json!(process_output(&args.command, result, args.max_lines, args.max_bytes, args.tail)))`.
- `batch::handle` — apply `process_output(cmd, value, args.max_lines, args.max_bytes, args.tail)` to each successful per-command `value` before assembling the per-router result array. (Batch runs multiple commands; each command string is available per entry, so per-command pipe honoring works.)
- `pfe::handle` — apply `process_output(&args.pfe_command, result, args.max_lines, args.max_bytes, args.tail)` to the PFE output.
- Update the three `#[tool(description=…)]` strings in `server.rs` to mention `max_lines` / `max_bytes` / `tail`.

## Testing

Unit tests on `process_output` (pure — no device, no network):
- `| count` → exactly `Count: <N> lines` for a known N; empty output → `Count: 0 lines`.
- `| last 10` on 25 lines → last 10 lines, order preserved.
- `show foo | match x | last 3` — since rustez already applied `| match`, `raw` is the matched text; assert last 3 lines of `raw` returned (post-process only applies `last`).
- `max_lines=5` head → first 5 + `… (truncated, N more lines)`; with `tail=true` → last 5.
- `max_bytes=100` → ≤100 bytes on a char boundary (multibyte-safe) + `… (truncated, N bytes omitted)`.
- All-None + no honored pipe → `raw` returned byte-identical (passthrough).
- Interaction: `| last 20` then `max_lines=5` → 5 lines (cap applies after pipe honoring).
- `| count` present + `max_lines=1` → the single `Count:` line unaffected by the cap.

Plus the existing execute/batch/pfe handler tests must still pass (args gain optional fields; default-off preserves behavior).

Gates: `cargo test --workspace` 0 failures; `cargo fmt -- --check` + `cargo clippy` clean.

## Out of scope / follow-ups

- The **deep #105 fix** — rustez honoring pipe modifiers during CLI→NETCONF translation — stays a rustez concern. This in-repo post-process is the mitigation. A separate rustez tracking issue may be filed.
- Only `| count` and `| last N` are honored client-side. `| except`, `| trim`, etc. are not reimplemented (YAGNI; not reported).
- No change to `render_and_apply_j2_template` or config tools (they don't return chatty operational output).
- No live deploy required for correctness (pure logic + handler wiring), but a post-merge deploy + smoke is reasonable since it touches the three highest-traffic tools.

## Risks

1. Auto-honoring `| count`/`| last N` changes what a piped command returns (by design — it's what the caller asked). Guarded by unit tests; only triggers on those two trailing modifiers.
2. Pipe parsing must be robust to whitespace and quoting (`| last  10`, trailing spaces). The parser trims and matches case-insensitively on the modifier keyword; a malformed/unknown modifier is ignored (output unchanged), never an error.
3. `max_bytes` must cut on a char boundary to avoid producing invalid UTF-8.
