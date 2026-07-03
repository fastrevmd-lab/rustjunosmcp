# Command output post-processing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound command output — honor trailing `| count` / `| last N` that rustez drops (#105) and add optional `max_lines`/`max_bytes`/`tail` caps (#106) — across the three command-execution tools.

**Architecture:** One pure function `process_output` in a new `rust-junosmcp-core/src/output.rs`, unit-tested in isolation, then wired into `execute_command`, `batch`, and `pfe` handlers. Default-off: unchanged behavior unless a new arg is set or the command carries a recognized trailing pipe.

**Tech Stack:** Rust, serde/schemars (tool args), no new dependencies.

## Global Constraints

- New module `rust-junosmcp-core/src/output.rs`; register `pub mod output;` in `rust-junosmcp-core/src/lib.rs`.
- Signature: `pub fn process_output(command: &str, raw: String, max_lines: Option<u32>, max_bytes: Option<u32>, tail: bool) -> String`.
- Pipe honoring (auto, not opt-in): trailing `| count` → replace output with `Count: <N> lines\n`; `| last <N>` → keep last N lines. Other modifiers (`match`/`except`/…) are skipped (rustez already applied them). Unparseable N → modifier ignored (output unchanged).
- Caps order: `max_bytes` first (truncate to ≤ cap on a UTF-8 char boundary, append `\n… (truncated, <omitted> bytes omitted)`), then `max_lines` (first N, or last N when `tail == true`, append `\n… (truncated, <M> more lines)`). Each `Option`; `None` skips that cap.
- New args on `ExecuteCommandArgs`, `ExecuteBatchArgs`, `ExecutePfeArgs`: `max_lines: Option<u32>`, `max_bytes: Option<u32>`, `tail: bool`, all `#[serde(default)]`.
- Default-off (all `None`/`false`, no honored pipe) → `process_output` returns `raw` unchanged; existing behavior preserved.
- `cargo test --workspace` 0 failures; `cargo fmt -- --check` + `cargo clippy` clean.

---

### Task 1: `output.rs` — `process_output` + unit tests (TDD)

**Files:**
- Create: `rust-junosmcp-core/src/output.rs`
- Modify: `rust-junosmcp-core/src/lib.rs` (add `pub mod output;`)

**Interfaces:**
- Produces: `pub fn process_output(command: &str, raw: String, max_lines: Option<u32>, max_bytes: Option<u32>, tail: bool) -> String`.

- [ ] **Step 1: Register the module**

In `rust-junosmcp-core/src/lib.rs`, add after `pub mod inventory;` (keep alphabetical-ish ordering — place after `pub mod helpers;`):

```rust
pub mod output;
```

- [ ] **Step 2: Write the failing tests**

Create `rust-junosmcp-core/src/output.rs` with the test module first (implementation stubs come next step). Put this at the bottom of the file:

```rust
#[cfg(test)]
mod tests {
    use super::process_output;

    fn none() -> Option<u32> { None }

    #[test]
    fn passthrough_when_all_off() {
        let raw = "line1\nline2\nline3".to_string();
        assert_eq!(process_output("show foo", raw.clone(), none(), none(), false), raw);
    }

    #[test]
    fn count_pipe_reports_line_count() {
        let raw = "a\nb\nc\n".to_string();
        assert_eq!(process_output("show x | count", raw, none(), none(), false), "Count: 3 lines\n");
    }

    #[test]
    fn count_pipe_on_empty_is_zero() {
        assert_eq!(process_output("show x | count", String::new(), none(), none(), false), "Count: 0 lines\n");
    }

    #[test]
    fn last_pipe_keeps_last_n_lines() {
        let raw = (1..=25).map(|n| n.to_string()).collect::<Vec<_>>().join("\n");
        let out = process_output("show x | last 10", raw, none(), none(), false);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 10);
        assert_eq!(lines.first().copied(), Some("16"));
        assert_eq!(lines.last().copied(), Some("25"));
    }

    #[test]
    fn last_pipe_after_match_applies_to_already_filtered_text() {
        // rustez already applied `| match`; raw is the matched text. We only apply `last`.
        let raw = "m1\nm2\nm3\nm4".to_string();
        let out = process_output("show x | match m | last 2", raw, none(), none(), false);
        assert_eq!(out.lines().collect::<Vec<_>>(), vec!["m3", "m4"]);
    }

    #[test]
    fn last_pipe_unparseable_n_is_ignored() {
        let raw = "a\nb".to_string();
        assert_eq!(process_output("show x | last", raw.clone(), none(), none(), false), raw);
    }

    #[test]
    fn max_lines_head_with_marker() {
        let raw = (1..=10).map(|n| n.to_string()).collect::<Vec<_>>().join("\n");
        let out = process_output("show x", raw, Some(5), none(), false);
        assert!(out.starts_with("1\n2\n3\n4\n5"), "got: {out}");
        assert!(out.contains("… (truncated, 5 more lines)"), "got: {out}");
    }

    #[test]
    fn max_lines_tail_keeps_last_n() {
        let raw = (1..=10).map(|n| n.to_string()).collect::<Vec<_>>().join("\n");
        let out = process_output("show x", raw, Some(3), none(), true);
        let body: Vec<&str> = out.lines().filter(|l| !l.contains("truncated")).collect();
        assert_eq!(body, vec!["8", "9", "10"]);
    }

    #[test]
    fn max_bytes_cuts_on_char_boundary() {
        // Multibyte char (é = 2 bytes) straddling the cap must not split.
        let raw = "aéb".to_string(); // bytes: 'a'(1) 'é'(2) 'b'(1) = 4 bytes
        let out = process_output("show x", raw, none(), Some(2), false);
        // cap=2 lands mid-'é'; must back off to a boundary (keep just "a").
        assert!(out.starts_with('a'));
        assert!(!out.starts_with("aé"), "must not include a split char: {out}");
        assert!(out.contains("bytes omitted"), "got: {out}");
    }

    #[test]
    fn max_bytes_passthrough_when_under_cap() {
        let raw = "short".to_string();
        assert_eq!(process_output("show x", raw.clone(), none(), Some(1000), false), raw);
    }

    #[test]
    fn pipe_then_cap_interaction() {
        // `| last 20` keeps 20; then max_lines=5 head caps to 5 with marker.
        let raw = (1..=30).map(|n| n.to_string()).collect::<Vec<_>>().join("\n");
        let out = process_output("show x | last 20", raw, Some(5), none(), false);
        let body: Vec<&str> = out.lines().filter(|l| !l.contains("truncated")).collect();
        assert_eq!(body.len(), 5);
        // last 20 of 1..=30 = 11..=30; head 5 = 11,12,13,14,15
        assert_eq!(body, vec!["11", "12", "13", "14", "15"]);
    }
}
```

- [ ] **Step 3: Run — verify it fails to compile (no `process_output` yet)**

Run: `cargo test -p rust-junosmcp-core output:: 2>&1 | tail -10`
Expected: FAIL — `process_output` not found.

- [ ] **Step 4: Implement `process_output`**

Prepend to `rust-junosmcp-core/src/output.rs` (above the test module):

```rust
//! Post-process operational-command output: honor the trailing `| count` /
//! `| last N` pipe modifiers that rustez drops in NETCONF translation (#105),
//! then apply optional size caps (#106). Pure — no I/O.

/// See module docs. Order: honor pipe modifiers → byte cap → line cap.
/// Returns `raw` unchanged when nothing applies.
pub fn process_output(
    command: &str,
    raw: String,
    max_lines: Option<u32>,
    max_bytes: Option<u32>,
    tail: bool,
) -> String {
    let piped = apply_pipe_modifiers(command, raw);
    let byte_capped = apply_byte_cap(piped, max_bytes);
    apply_line_cap(byte_capped, max_lines, tail)
}

/// Apply the trailing `| count` / `| last N` modifiers rustez drops. Other
/// modifiers (`match`, `except`, …) were already applied upstream, so they are
/// skipped here. Modifiers are applied left-to-right.
fn apply_pipe_modifiers(command: &str, raw: String) -> String {
    let mut segments = command.split('|');
    let _base = segments.next(); // the command itself
    let mut out = raw;
    for seg in segments {
        let seg = seg.trim();
        let lower = seg.to_ascii_lowercase();
        if lower == "count" {
            let n = out.lines().count();
            out = format!("Count: {n} lines\n");
        } else if let Some(rest) = lower.strip_prefix("last") {
            if let Ok(n) = rest.trim().parse::<usize>() {
                let lines: Vec<&str> = out.lines().collect();
                let start = lines.len().saturating_sub(n);
                out = lines[start..].join("\n");
                if !out.is_empty() {
                    out.push('\n');
                }
            }
            // unparseable N → leave `out` unchanged
        }
        // any other modifier: already applied by rustez → skip
    }
    out
}

/// Truncate to at most `max_bytes` on a UTF-8 char boundary, appending a marker.
fn apply_byte_cap(s: String, max_bytes: Option<u32>) -> String {
    let Some(cap) = max_bytes.map(|c| c as usize) else {
        return s;
    };
    if s.len() <= cap {
        return s;
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let omitted = s.len() - end;
    let mut out = s[..end].to_string();
    out.push_str(&format!("\n… (truncated, {omitted} bytes omitted)"));
    out
}

/// Keep the first `max_lines` lines (or the last N when `tail`), with a marker.
fn apply_line_cap(s: String, max_lines: Option<u32>, tail: bool) -> String {
    let Some(cap) = max_lines.map(|c| c as usize) else {
        return s;
    };
    let lines: Vec<&str> = s.lines().collect();
    if lines.len() <= cap {
        return s;
    }
    let more = lines.len() - cap;
    let kept: Vec<&str> = if tail {
        lines[lines.len() - cap..].to_vec()
    } else {
        lines[..cap].to_vec()
    };
    let mut out = kept.join("\n");
    out.push_str(&format!("\n… (truncated, {more} more lines)"));
    out
}
```

- [ ] **Step 5: Run — verify tests pass**

Run: `cargo test -p rust-junosmcp-core output:: 2>&1 | tail -15`
Expected: all 11 tests PASS.

- [ ] **Step 6: fmt + clippy + commit**

Run: `cargo fmt && cargo fmt -- --check && cargo clippy -p rust-junosmcp-core 2>&1 | tail -3`

```bash
git add rust-junosmcp-core/src/output.rs rust-junosmcp-core/src/lib.rs
git commit -m "feat(core): output post-processing (pipe honoring + size caps) (#105, #106)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_019mPwHV2n6YmBTd5j8HcAAJ"
```

---

### Task 2: Wire `process_output` into the three command tools + new args

**Files:**
- Modify: `rust-junosmcp-core/src/tools/mod.rs` (add 3 args to `ExecuteCommandArgs`, `ExecuteBatchArgs`, `ExecutePfeArgs` + arg-default tests)
- Modify: `rust-junosmcp-core/src/tools/execute_command.rs`, `rust-junosmcp-core/src/tools/batch.rs`, `rust-junosmcp-core/src/tools/pfe.rs`
- Modify: `rust-junosmcp/src/server.rs` (tool descriptions)

**Interfaces:**
- Consumes: `crate::output::process_output` (Task 1).

- [ ] **Step 1: Add the args to the three structs**

In `rust-junosmcp-core/src/tools/mod.rs`, add these three fields to `ExecuteCommandArgs`, `ExecuteBatchArgs`, and `ExecutePfeArgs` (before each struct's closing brace):

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

- [ ] **Step 2: Add arg-default tests in `mod.rs`**

In the `#[cfg(test)] mod tests` block of `mod.rs`, add:

```rust
#[test]
fn execute_command_output_caps_default_off() {
    let v = serde_json::json!({"router_name":"r1","command":"show version"});
    let a: ExecuteCommandArgs = serde_json::from_value(v).unwrap();
    assert!(a.max_lines.is_none());
    assert!(a.max_bytes.is_none());
    assert!(!a.tail);
}

#[test]
fn execute_command_accepts_output_caps() {
    let v = serde_json::json!({"router_name":"r1","command":"show log messages","max_lines":50,"max_bytes":8192,"tail":true});
    let a: ExecuteCommandArgs = serde_json::from_value(v).unwrap();
    assert_eq!(a.max_lines, Some(50));
    assert_eq!(a.max_bytes, Some(8192));
    assert!(a.tail);
}

#[test]
fn batch_and_pfe_accept_output_caps() {
    let b: ExecuteBatchArgs = serde_json::from_value(serde_json::json!({
        "routers":["r1"],"commands":["show version"],"max_lines":10
    })).unwrap();
    assert_eq!(b.max_lines, Some(10));
    let p: ExecutePfeArgs = serde_json::from_value(serde_json::json!({
        "router_name":"r1","fpc_target":"fpc0","pfe_command":"show jnh 0 stats","max_bytes":4096
    })).unwrap();
    assert_eq!(p.max_bytes, Some(4096));
}
```

- [ ] **Step 3: Run — verify the new arg tests pass, old ones still pass**

Run: `cargo test -p rust-junosmcp-core tools::tests 2>&1 | tail -12`
Expected: new tests PASS; the pre-existing default tests (e.g. `execute_command_defaults_timeout`) still PASS (adding optional `#[serde(default)]` fields does not break them).

- [ ] **Step 4: Wire `execute_command.rs`**

In `rust-junosmcp-core/src/tools/execute_command.rs`, change the final return (currently `Ok(json!(result))`) to:

```rust
    let processed = crate::output::process_output(
        &args.command,
        result,
        args.max_lines,
        args.max_bytes,
        args.tail,
    );
    Ok(json!(processed))
```

- [ ] **Step 5: Wire `pfe.rs`**

In `rust-junosmcp-core/src/tools/pfe.rs`, change the final block (currently `Ok(json!({ "fpc_target": fpc_target, "output": result }))`) to post-process `result` first:

```rust
    let output = crate::output::process_output(
        &args.pfe_command,
        result,
        args.max_lines,
        args.max_bytes,
        args.tail,
    );
    Ok(json!({
        "fpc_target": fpc_target,
        "output": output,
    }))
```

- [ ] **Step 6: Wire `batch.rs` (post-collection pass)**

In `rust-junosmcp-core/src/tools/batch.rs`, `handle()` builds `let final_results: Vec<RouterResult> = …;` then `Ok(serde_json::to_value(final_results)?)`. Make `final_results` mutable and post-process each successful command's value before serializing. Replace `let final_results` with `let mut final_results` and insert before the `Ok(serde_json::to_value(...))`:

```rust
    // Apply per-command output post-processing (pipe honoring + caps).
    for rr in &mut final_results {
        for co in &mut rr.commands {
            if let Some(v) = co.value.take() {
                co.value = Some(crate::output::process_output(
                    &co.command,
                    v,
                    args.max_lines,
                    args.max_bytes,
                    args.tail,
                ));
            }
        }
    }
    Ok(serde_json::to_value(final_results)?)
```

(`CommandOutcome` has public `command: String` and `value: Option<String>` fields — confirmed in batch.rs.)

- [ ] **Step 7: Update tool descriptions in `server.rs`**

In `rust-junosmcp/src/server.rs`, append to the `#[tool(description=…)]` strings for `execute_junos_command`, `execute_junos_command_batch`, and `execute_junos_pfe_command` a sentence like: `Supports optional max_lines/max_bytes/tail output caps, and honors trailing '| last N' / '| count'.` Keep each description a single string literal.

- [ ] **Step 8: Build + full core + workspace**

Run: `cargo test -p rust-junosmcp-core 2>&1 | tail -6 && cargo test --workspace 2>&1 | grep -E "FAILED|error\[" || echo "workspace clean"`
Expected: core suite passes (incl. existing execute/batch/pfe handler tests — default-off preserves their behavior); 0 workspace failures.

- [ ] **Step 9: fmt + clippy + commit**

Run: `cargo fmt && cargo fmt -- --check && cargo clippy --workspace 2>&1 | tail -3`

```bash
git add rust-junosmcp-core/src/tools/mod.rs rust-junosmcp-core/src/tools/execute_command.rs rust-junosmcp-core/src/tools/batch.rs rust-junosmcp-core/src/tools/pfe.rs rust-junosmcp/src/server.rs
git commit -m "feat: wire output caps + pipe honoring into command tools (#105, #106)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_019mPwHV2n6YmBTd5j8HcAAJ"
```

---

## Self-Review

**Spec coverage:**
- `output.rs` with `process_output` (pipe honoring + caps) → Task 1. ✔
- `| count` → `Count: N lines`; `| last N`; skip other modifiers; unparseable ignored → Task 1 Step 4 `apply_pipe_modifiers` + tests. ✔
- `max_bytes` char-boundary cut + marker; `max_lines` head/tail + marker; Option/default-off → Task 1 Step 4 + tests. ✔
- New args on the 3 structs (`#[serde(default)]`) → Task 2 Step 1 + default tests. ✔
- Wire into execute/batch/pfe → Task 2 Steps 4-6. ✔
- Tool descriptions updated → Task 2 Step 7. ✔
- Behavior unchanged when off → covered by passthrough test (Task 1) + existing handler tests passing (Task 2 Step 8). ✔

**Placeholder scan:** No TBD/TODO; all code blocks complete; exact commands with expected output.

**Type consistency:** `process_output(&str, String, Option<u32>, Option<u32>, bool) -> String` defined in Task 1 and called identically in all three handlers (Task 2). New args `max_lines: Option<u32>`, `max_bytes: Option<u32>`, `tail: bool` named identically in the structs and the call sites (`args.max_lines`, `args.max_bytes`, `args.tail`; batch uses `co.command`/`co.value`).

**Risk note for implementer:** (1) `apply_pipe_modifiers` must NOT treat a `|` inside a `match`/`except` regex argument (`| match up|count`, `| match "a|b"`) as a modifier — that would silently corrupt output (return a count / truncate) rather than no-op. Split on the Junos boundary `" | "` (space-pipe-space) and honor only the **trailing run** of recognized `count`/`last N` modifiers. (Corrected after the final review found the naive bare-`|` split mis-fired on regex alternations.) (2) The byte-cap marker adds bytes beyond `max_bytes`; that's intentional (marker is meta). (3) Keep each `server.rs` tool description a single string literal — don't break it across concatenated literals in a way that changes the advertised text.
