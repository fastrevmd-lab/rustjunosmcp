# quick-xml 0.41 in rust-srxmcp-core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade `rust-srxmcp-core` to quick-xml 0.41 (+ the now-published sibling crates) to clear RUSTSEC-2026-0194/-0195, and close the `Event::GeneralRef` redaction gap the upgrade introduces.

**Architecture:** Two dependency bumps (`quick-xml 0.36→0.41` direct in `rust-srxmcp-core`; `rustez 0.12.0→0.12.1` in the workspace) + `cargo update` remove all pre-0.41 quick-xml. The only code change is in `redact.rs`: quick-xml 0.38+ streams XML entities as separate `Event::GeneralRef` events instead of folding them into `Text`, so the redaction loop must suppress `GeneralRef` under a redacted element (else a fragment leaks) while still round-tripping entities on the non-redacted path.

**Tech Stack:** Rust, quick-xml 0.41, rustez 0.12.1 / rustnetconf 0.12.3 (crates.io), roxmltree.

## Global Constraints

- `Cargo.toml:23` (workspace): `rustez = "0.12.0"` → `"0.12.1"`.
- `rust-srxmcp-core/Cargo.toml:18`: `quick-xml = "0.36"` → `"0.41"`.
- After `cargo update`: `Cargo.lock` MUST contain no `quick-xml` version `< 0.41.0` (neither 0.36.2 nor 0.37.5), and `rustnetconf >= 0.12.3`, `rustez = 0.12.1`.
- `REDACTED_MARKER = "<REDACTED>"`; `REDACT_ELEMENT_NAMES = ["pre-shared-key","secret","simple-password","encrypted-password","community","hmac-key"]` (verbatim, do not change).
- `redact_xml`: under `redact_depth > 0`, `Event::Text`/`CData`/**`GeneralRef`** are all suppressed and collapse to a SINGLE `REDACTED_MARKER` per contiguous run; on the non-redacted path `GeneralRef` MUST round-trip (re-emit `&name;`), preserving element values that contain `&`/`<`/`>`.
- Acceptance gate: `cargo audit` reports no RUSTSEC-2026-0194/-0195; `cargo test --workspace` 0 failures; `cargo fmt -- --check` clean.
- quick-xml 0.40 raised MSRV to 1.79 — the toolchain must be ≥ 1.79.
- Deploy target: container ct601 on node **pve2** (`pve2.mechub.org`), `rust-srxmcp.service` at `:30032`; its unit already carries `--allowed-host 192.168.1.194`.

---

### Task 1: Dependency bump — quick-xml 0.41 + sibling crates, audit clean

**Files:**
- Modify: `Cargo.toml:23` (workspace `rustez`), `rust-srxmcp-core/Cargo.toml:18` (`quick-xml`)
- Touch: `Cargo.lock`

**Interfaces:**
- Consumes: published `rustez 0.12.1`, `rustnetconf 0.12.3` (crates.io).
- Produces: a workspace on quick-xml 0.41 that builds and passes existing tests; `redact.rs` still compiles unchanged (the `GeneralRef` security fix is Task 2).

- [ ] **Step 1: Confirm toolchain ≥ 1.79**

Run: `rustc --version`
Expected: `1.79.0` or newer (quick-xml 0.40+ MSRV). If older, stop and report — the bump needs a newer toolchain.

- [ ] **Step 2: Bump the versions**

In `Cargo.toml` (workspace root), change line 23:
```toml
rustez       = "0.12.1"
```
In `rust-srxmcp-core/Cargo.toml`, change line 18:
```toml
quick-xml          = "0.41"
```

- [ ] **Step 3: Update the lockfile**

Run: `cargo update -p quick-xml -p rustez -p rustnetconf 2>&1 | tail -20`
Expected: `rustez v0.12.1`, `rustnetconf v0.12.3` (or newer), quick-xml resolves to `0.41.0`. If a transitive still pins an old quick-xml, run a broad `cargo update` and inspect.

- [ ] **Step 4: Verify no pre-0.41 quick-xml remains**

Run: `grep -A1 '^name = "quick-xml"' Cargo.lock | grep version`
Expected: only `version = "0.41.0"` (or higher) — NO `0.36.2`, NO `0.37.5`. If an old version lingers, find its source with `cargo tree -i quick-xml@<ver>` and resolve (a sibling that still pins old quick-xml would mean the wrong published version resolved).

- [ ] **Step 5: Build + existing tests**

Run: `cargo build --workspace && cargo test --workspace 2>&1 | tail -15`
Expected: compiles (redact.rs/xml.rs need no edits — they never call the removed `unescape`), 0 test failures. The existing redaction tests don't exercise entities-under-redaction yet, so they pass; Task 2 adds those.

- [ ] **Step 6: cargo audit — the acceptance gate**

Run: `cargo audit 2>&1 | tail -20`
Expected: **no RUSTSEC-2026-0194, no RUSTSEC-2026-0195** (and RUSTSEC-2026-0189 still absent). Remaining `anyhow` (RUSTSEC-2026-0190) + yanked `aes` are pre-existing warnings, out of scope — exit code 0. Record the output in the report.

- [ ] **Step 7: fmt + commit**

Run: `cargo fmt && cargo fmt -- --check`
```bash
git add Cargo.toml rust-srxmcp-core/Cargo.toml Cargo.lock
git commit -m "build(deps): quick-xml 0.36->0.41, rustez 0.12.1, rustnetconf 0.12.3 (#103)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_019mPwHV2n6YmBTd5j8HcAAJ"
```

---

### Task 2: Close the GeneralRef redaction gap in `redact.rs`

**Files:**
- Modify: `rust-srxmcp-core/src/workflows/support_bundle/redact.rs` — the `redact_xml` reader loop (currently ~lines 71-112) + tests module (~line 357)

**Interfaces:**
- Consumes: Task 1's quick-xml 0.41 (`Event::GeneralRef` now exists).
- Produces: `redact_xml(&str) -> String` with `GeneralRef` handled — no signature change.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `redact.rs`:

```rust
#[test]
fn redacts_entity_split_secret_to_single_marker() {
    // quick-xml 0.41 streams `abc&amp;def` as Text("abc"), GeneralRef("amp"),
    // Text("def"). Under redaction the entity must NOT leak through, and the
    // split value must collapse to exactly one marker.
    let xml = "<config><pre-shared-key>abc&amp;def</pre-shared-key></config>";
    let out = redact_xml(xml);
    assert!(!out.contains('&'), "entity fragment leaked from redacted element: {out}");
    assert!(!out.contains("abc"), "secret fragment leaked: {out}");
    assert!(!out.contains("def"), "secret fragment leaked: {out}");
    assert_eq!(
        out.matches(REDACTED_MARKER).count(),
        1,
        "split redacted value must collapse to a single marker: {out}"
    );
    // Structure preserved.
    assert!(out.contains("<pre-shared-key>") && out.contains("</pre-shared-key>"), "structure lost: {out}");
}

#[test]
fn non_redacted_entity_round_trips() {
    // A non-secret element containing an entity must be preserved verbatim
    // (GeneralRef must re-emit &amp; on the passthrough path).
    let xml = "<config><name>edge &amp; core</name></config>";
    let out = redact_xml(xml);
    assert!(out.contains("&amp;"), "entity not round-tripped on non-redacted path: {out}");
    assert!(out.contains("edge") && out.contains("core"), "text lost: {out}");
    assert!(!out.contains(REDACTED_MARKER), "unexpected redaction: {out}");
}
```

- [ ] **Step 2: Run — verify failure**

Run: `cargo test -p rust-srxmcp-core redacts_entity_split_secret_to_single_marker non_redacted_entity_round_trips 2>&1 | tail -20`
Expected: `redacts_entity_split_secret_to_single_marker` FAILS (pre-fix, the `GeneralRef` hits the catch-all and `&amp;` is written verbatim and/or two markers appear). `non_redacted_entity_round_trips` may already pass if quick-xml's `write_event` re-emits `GeneralRef` — if it FAILS, Step 3's non-redacted handling is required.

- [ ] **Step 3: Implement the fix**

In `rust-srxmcp-core/src/workflows/support_bundle/redact.rs`, replace the state declarations + reader loop inside `redact_xml`. Add a `redacted_run` flag and a `GeneralRef` arm. The state block (currently ~lines 71-72) becomes:

```rust
    let mut matched_stack: Vec<bool> = Vec::new();
    let mut redact_depth: usize = 0;
    // True once a REDACTED marker has been emitted for the current contiguous
    // run of redacted text/entity events. Reset at each element boundary so a
    // value split across Text/GeneralRef events (quick-xml 0.38+) collapses to
    // a single marker instead of repeating it.
    let mut redacted_run = false;
```

And the `loop { match reader.read_event() { ... } }` body becomes:

```rust
    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let matched = REDACT_ELEMENT_NAMES
                    .iter()
                    .any(|name| e.local_name().as_ref() == name.as_bytes());
                if writer.write_event(Event::Start(e)).is_err() {
                    return input.to_string();
                }
                if matched {
                    redact_depth += 1;
                }
                matched_stack.push(matched);
                redacted_run = false;
            }
            Ok(Event::End(e)) => {
                if writer.write_event(Event::End(e)).is_err() {
                    return input.to_string();
                }
                if matched_stack.pop().unwrap_or(false) {
                    redact_depth = redact_depth.saturating_sub(1);
                }
                redacted_run = false;
            }
            // Under redaction, replace text and SUPPRESS entity references
            // (GeneralRef). Without the GeneralRef arm an entity inside a
            // redacted secret would fall through to the catch-all and be
            // written verbatim (partial leak). Collapse the whole run to one
            // marker via `redacted_run`.
            Ok(Event::Text(_)) | Ok(Event::CData(_)) | Ok(Event::GeneralRef(_))
                if redact_depth > 0 =>
            {
                if !redacted_run {
                    if writer
                        .write_event(Event::Text(BytesText::new(REDACTED_MARKER)))
                        .is_err()
                    {
                        return input.to_string();
                    }
                    redacted_run = true;
                }
            }
            Ok(event) => {
                if writer.write_event(event).is_err() {
                    return input.to_string();
                }
            }
            Err(_) => return input.to_string(),
        }
    }
```

**If** Step 2 showed `non_redacted_entity_round_trips` FAILING (quick-xml's `write_event` does not faithfully re-emit `GeneralRef`), add an explicit non-redacted passthrough arm BEFORE the catch-all that reconstructs the reference — insert after the redaction arm:

```rust
            Ok(Event::GeneralRef(r)) => {
                // Re-emit `&name;` explicitly; write_event does not round-trip
                // a bare GeneralRef on this quick-xml version.
                let name = String::from_utf8_lossy(r.as_ref()).into_owned();
                if writer
                    .write_event(Event::Text(BytesText::from_escaped(format!("&{name};"))))
                    .is_err()
                {
                    return input.to_string();
                }
            }
```
(Use `BytesText::from_escaped` so the `&`/`;` are not double-escaped. Only add this arm if the round-trip test needs it; if `write_event(GeneralRef)` already round-trips, leave the catch-all to handle it and skip this arm.)

- [ ] **Step 4: Run — verify pass**

Run: `cargo test -p rust-srxmcp-core redacts_entity_split_secret_to_single_marker non_redacted_entity_round_trips 2>&1 | tail -20`
Expected: both PASS.

- [ ] **Step 5: Full redact + core suite (no regression)**

Run: `cargo test -p rust-srxmcp-core redact 2>&1 | tail -15 && cargo test -p rust-srxmcp-core 2>&1 | tail -6`
Expected: all existing redaction tests (#85/#89/#91/#92 lineage) still pass; core suite 0 failures.

- [ ] **Step 6: fmt + clippy + commit**

Run: `cargo fmt && cargo fmt -- --check && cargo clippy -p rust-srxmcp-core 2>&1 | tail -3`
```bash
git add rust-srxmcp-core/src/workflows/support_bundle/redact.rs
git commit -m "fix(srxmcp): redact quick-xml 0.41 GeneralRef entities; round-trip on passthrough (#103)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_019mPwHV2n6YmBTd5j8HcAAJ"
```

---

### Task 3: Docs + deploy to ct601 (pve2) + live smoke

**Files:**
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: Tasks 1-2.

- [ ] **Step 1: CHANGELOG**

Add under an Unreleased `### Security` entry:
```markdown
### Security
- Upgrade `quick-xml` 0.36→0.41 (+ `rustez` 0.12.1 / `rustnetconf` 0.12.3),
  closing RUSTSEC-2026-0194 / RUSTSEC-2026-0195 (quick-xml DoS). Redaction now
  suppresses quick-xml 0.41 `GeneralRef` entity events inside redacted elements
  (a bare version bump would have leaked entity fragments from secrets).
```
Commit:
```bash
git add CHANGELOG.md
git commit -m "docs: changelog for quick-xml 0.41 upgrade (#103)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_019mPwHV2n6YmBTd5j8HcAAJ"
```

- [ ] **Step 2: Full workspace gate + build release**

Run: `cargo fmt -- --check && cargo test --workspace 2>&1 | grep -E "FAILED|error\[" || echo "clean"` then `cargo build --release -p rust-srxmcp`
Expected: no failures; release binary built.

- [ ] **Step 3: Deploy the srx binary to ct601 (pve2)**

`scp` `target/release/rust-srxmcp` to `pve2.mechub.org:/tmp/`, then over SSH to `pve2.mechub.org`: backup the in-container binary (`.bak-$(date +%Y%m%d-%H%M%S)`, keep 2 most recent), `pct exec 601 -- systemctl stop rust-srxmcp.service`, `pct push 601 /tmp/rust-srxmcp /usr/local/bin/rust-srxmcp --perms 0755`, `chown root:root`, `systemctl start`, confirm `active`, verify in-container sha matches the local release sha, prune old backups. (junos binary is untouched — do NOT stop/replace it.)

- [ ] **Step 4: Live smoke `:30032`**

Drive `http://192.168.1.194:30032/mcp` with the bearer from `~/.claude.json` (streamable-http handshake: initialize → notifications/initialized → call):
- `tools/list` → 9 tools (srx surface unchanged).
- `srxmcp_status` (or another read-only tool) → success.
- Host allowlist still active: a `curl` with `Host: evil.example.com` + valid bearer → 403; normal `Host: 192.168.1.194` → 200.

- [ ] **Step 5: Record results** in the SDD ledger (versions, audit result, tool count, 403 check).

---

## Self-Review

**Spec coverage:**
- rustez 0.12.1 + quick-xml 0.41 bumps + cargo update + no-old-quick-xml check → Task 1. ✔
- cargo audit clean of -0194/-0195 (acceptance gate) → Task 1 Step 6. ✔
- redact.rs GeneralRef suppression under redaction + single-marker collapse → Task 2 Step 3. ✔
- Non-redacted GeneralRef round-trip (+ fallback if write_event doesn't) → Task 2 Step 3. ✔
- xml.rs zero-change (compiles) → covered by Task 1 Step 5 build. ✔
- Tests: redacted+entity, non-redacted round-trip, existing tests pass → Task 2 Steps 1/5. ✔
- Deploy + live smoke + Host-allowlist re-check → Task 3. ✔
- CHANGELOG → Task 3 Step 1. ✔

**Placeholder scan:** No TBD/TODO. The one genuine build-time unknown — whether `write_event(Event::GeneralRef)` round-trips — is resolved by the `non_redacted_entity_round_trips` test (Task 2 Step 2) with concrete fallback code (Step 3). All code steps show full code.

**Type consistency:** `redact_xml(&str) -> String` unchanged. `REDACTED_MARKER`/`REDACT_ELEMENT_NAMES` used verbatim. New state var `redacted_run: bool`. `Event::GeneralRef` (the 0.41 variant) used in Task 2 after Task 1 makes it available. Tests reference `REDACTED_MARKER` (in-scope in the test module via `use super::*`).

**Risk note for implementer:** the pure-passthrough `GeneralRef` round-trip is the subtle part — the `non_redacted_entity_round_trips` test is the gate; if it fails on the plain bump, add the explicit re-emit arm (Task 2 Step 3 fallback) and confirm it doesn't double-escape (`&amp;` must appear once, not `&amp;amp;`).
