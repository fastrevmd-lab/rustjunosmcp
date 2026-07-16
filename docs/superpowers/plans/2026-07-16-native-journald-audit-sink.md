# Native Journald Audit Sink Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in native journald fan-out sink for structured `target="audit"` events on both RustJunosMCP binaries, with fail-fast startup and documented field mappings.

**Architecture:** Extend `rust-junosmcp-audit` with the official `tracing-journald` layer, configured with an `AUDIT_` field namespace and the same exact target filter as the JSON file layer. Both binaries expose a disabled-by-default boolean flag/env pair and propagate journal socket setup errors before accepting work, while retaining stderr and optional file output.

**Tech Stack:** Rust 2021, `tracing` 0.1, `tracing-subscriber` 0.3, `tracing-journald` 0.3, Clap 4, anyhow, Cargo, journald/systemd native protocol.

## Global Constraints

- Work only in `/home/mharman/Projects/RustJunosMCP/.worktrees/issue-153-journald-audit-sink` on branch `issue-153-journald-audit-sink`.
- Preserve stderr and optional append-only JSON-file output; journald is an additional fan-out sink.
- Default behavior remains unchanged: native journald is disabled unless explicitly configured.
- Match only `tracing` metadata with exact, case-sensitive `target() == "audit"`.
- Prefix user event fields with `AUDIT_`; keep upstream `TARGET`, `PRIORITY`, `SYSLOG_IDENTIFIER`, `MESSAGE`, `CODE_FILE`, and `CODE_LINE` fields.
- Keep the existing tracing level and priority mapping: audit `INFO` maps to journal `PRIORITY=5` (`NOTICE`).
- Fail startup when journald is explicitly enabled and the journal socket probe fails.
- Preserve the audit schema, redaction behavior, `RUST_LOG` behavior, auth scopes, MCP schemas/annotations, timeouts, device I/O, and packaged systemd defaults.
- Add only `tracing-journald = "0.3"`; regenerate and commit `Cargo.lock` through Cargo, never by hand.
- Do not add RFC 3164/RFC 5424, remote syslog, buffering, retries, facility overrides, or real-device tests.
- Never run ignored real-device tests without `CONFIRM_LAB_INTEGRATION=yes`; this issue requires no device access.
- Because `just` is not installed in the current shell, run the exact checked-in Justfile recipes directly and report the missing wrapper explicitly.

---

### Task 1: Add the filtered journald layer and fail-fast audit initialization

**Files:**
- Modify: `rust-junosmcp-audit/Cargo.toml:13-20`
- Modify: `Cargo.lock` (Cargo-generated only)
- Modify: `rust-junosmcp-audit/src/init.rs:1-135`
- Modify: `rust-junosmcp/src/main.rs:33-38`
- Modify: `rust-srxmcp/src/main.rs:37-43`
- Test: `rust-junosmcp-audit/src/init.rs:108-135`

**Interfaces:**
- Consumes: existing `AuditConfig`, `audit_file_layer`, global subscriber composition, and `target="audit"` tracing events.
- Produces: `AuditConfig { journald: bool, .. }`; `init_tracing(&AuditConfig) -> std::io::Result<()>`; private `is_audit`, `audit_journald_layer`, and `make_journald_layer_with` helpers.

- [ ] **Step 1: Add the single runtime dependency and regenerate the lockfile**

In `rust-junosmcp-audit/Cargo.toml`, add the exact dependency beside the tracing dependencies:

```toml
tracing            = { workspace = true }
tracing-journald   = "0.3"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json", "fmt", "registry"] }
```

Run Cargo without `--locked` exactly once so it resolves the new package and updates `Cargo.lock`:

```bash
cargo check -p rust-junosmcp-audit
```

Expected: PASS; Cargo resolves `tracing-journald v0.3.2` (or the current semver-compatible 0.3 release) and changes `Cargo.lock` only by adding the package and the audit crate dependency edge. Do not edit the lockfile manually.

- [ ] **Step 2: Write failing tests for disabled construction and enabled failure propagation**

Append these tests inside `rust-junosmcp-audit/src/init.rs`'s existing `mod tests`:

```rust
    #[test]
    fn disabled_journald_does_not_call_factory() {
        let layer = make_journald_layer_with(
            false,
            || -> std::io::Result<tracing_journald::Layer> {
                panic!("disabled journald must not construct a socket")
            },
        )
        .expect("disabled journald is infallible");

        assert!(layer.is_none());
    }

    #[test]
    fn enabled_journald_propagates_factory_error() {
        let result = make_journald_layer_with(true, || {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "journal unavailable",
            ))
        });

        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("enabled journald must propagate construction failure"),
        };
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(error.to_string(), "journal unavailable");
    }
```

- [ ] **Step 3: Run the tests and verify the expected red state**

```bash
cargo test -p rust-junosmcp-audit init::tests::disabled_journald_does_not_call_factory
```

Expected: compile failure `E0425` because `make_journald_layer_with` does not exist yet. The failure must be about the missing production helper, not the test syntax or dependency.

- [ ] **Step 4: Implement the shared filter, factory seam, native layer, and result-returning initializer**

Update the module description and imports at the top of `rust-junosmcp-audit/src/init.rs`:

```rust
//! Configurable tracing/audit sinks: stderr (text or JSON), an optional
//! dedicated JSON audit file, and an optional native journald target.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};
```

Add the boolean field after `redaction` in `AuditConfig`, matching the approved
design's field order:

```rust
    /// When true, `target="audit"` events are also sent to journald natively.
    pub journald: bool,
```

Replace the current `audit_file_layer` and `init_tracing` section with this complete implementation:

```rust
fn is_audit(meta: &tracing::Metadata<'_>) -> bool {
    meta.target() == "audit"
}

/// A JSON fmt layer filtered to `target == "audit"`, writing to `handle`.
pub fn audit_file_layer<S>(handle: FileHandle) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        .json()
        .with_writer(handle)
        .with_filter(filter_fn(is_audit))
}

fn audit_journald_layer<S>(layer: tracing_journald::Layer) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    layer
        .with_field_prefix(Some("AUDIT".to_owned()))
        .with_filter(filter_fn(is_audit))
}

fn make_journald_layer_with<F>(
    enabled: bool,
    factory: F,
) -> io::Result<Option<tracing_journald::Layer>>
where
    F: FnOnce() -> io::Result<tracing_journald::Layer>,
{
    if enabled {
        factory().map(Some)
    } else {
        Ok(None)
    }
}

/// Initialize the global subscriber. Idempotent (`try_init`).
///
/// Returns an error only when the explicitly enabled journald layer cannot be
/// constructed. An already-installed global subscriber remains a no-op.
pub fn init_tracing(cfg: &AuditConfig) -> io::Result<()> {
    let env = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let stderr = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let stderr = match cfg.format {
        AuditFormat::Text => stderr.boxed(),
        AuditFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .with_writer(std::io::stderr)
            .boxed(),
    };
    let file_layer = cfg
        .audit_log_file
        .as_ref()
        .and_then(|p| FileHandle::open(p).ok())
        .map(audit_file_layer);
    let journald_layer =
        make_journald_layer_with(cfg.journald, tracing_journald::layer)?
            .map(audit_journald_layer);

    let _ = tracing_subscriber::registry()
        .with(env)
        .with(stderr)
        .with(file_layer)
        .with(journald_layer)
        .try_init();

    if let Some(redaction) = cfg.redaction.clone() {
        crate::redact::install(redaction);
    }

    Ok(())
}
```

Keep the workspace buildable before the CLI flag exists by updating both main call sites with `journald: false` and propagating the new result. In `rust-junosmcp/src/main.rs`:

```rust
    let audit_cfg = rust_junosmcp_audit::AuditConfig {
        format: rust_junosmcp_audit::AuditFormat::parse(&args.audit_format),
        audit_log_file: args.audit_log_file.clone(),
        redaction,
        journald: false,
    };
    rust_junosmcp_audit::init_tracing(&audit_cfg).context("initializing audit tracing")?;
```

In `rust-srxmcp/src/main.rs`, use the identical initializer and result propagation:

```rust
    let audit_cfg = rust_junosmcp_audit::AuditConfig {
        format: rust_junosmcp_audit::AuditFormat::parse(&args.audit_format),
        audit_log_file: args.audit_log_file.clone(),
        redaction,
        journald: false,
    };
    rust_junosmcp_audit::init_tracing(&audit_cfg).context("initializing audit tracing")?;
```

Both files already import `anyhow::Context`; add no new main-crate dependency.

- [ ] **Step 5: Run the audit tests and verify green behavior**

```bash
cargo test -p rust-junosmcp-audit init::tests -- --nocapture
```

Expected: PASS with 3 init tests: the existing audit-file isolation test plus the disabled-factory and propagated-error tests.

- [ ] **Step 6: Prove the intermediate commit builds across the workspace**

```bash
cargo check --workspace --locked
cargo clippy -p rust-junosmcp-audit --all-targets -- -D warnings
```

Expected: both PASS with no warnings. This proves the return-type and `AuditConfig` changes have complete workspace call-site coverage even though the binary switch is still hardcoded off.

- [ ] **Step 7: Review and commit the core sink**

```bash
git diff --check
git diff -- rust-junosmcp-audit/Cargo.toml rust-junosmcp-audit/src/init.rs rust-junosmcp/src/main.rs rust-srxmcp/src/main.rs Cargo.lock
git add Cargo.lock rust-junosmcp-audit/Cargo.toml rust-junosmcp-audit/src/init.rs rust-junosmcp/src/main.rs rust-srxmcp/src/main.rs
git commit -m "feat: add filtered journald audit layer"
```

Expected: commit succeeds; hooks report no whitespace, conflict, TOML, or secret findings.

---

### Task 2: Expose and wire the journald option on both binaries

**Files:**
- Modify: `rust-junosmcp/src/cli.rs:141-158,213-284`
- Modify: `rust-junosmcp/src/main.rs:33-39`
- Modify: `rust-srxmcp/src/cli.rs:124-141,144-186`
- Modify: `rust-srxmcp/src/main.rs:37-43`
- Test: `rust-junosmcp/src/cli.rs` unit tests
- Test: `rust-srxmcp/src/cli.rs` unit tests

**Interfaces:**
- Consumes: Task 1's `AuditConfig.journald: bool` and `init_tracing(&AuditConfig) -> std::io::Result<()>`.
- Produces: `Cli.audit_journald: bool`; Junos `--audit-journald` / `JMCP_AUDIT_JOURNALD`; SRX `--audit-journald` / `JMCP_SRX_AUDIT_JOURNALD`; runtime wiring into `AuditConfig`.

- [ ] **Step 1: Write failing flag/default tests in both CLI modules**

Append this test to `rust-junosmcp/src/cli.rs`'s `mod tests`:

```rust
    #[test]
    fn audit_journald_defaults_off_and_parses() {
        let default_cli = Cli::parse_from(["rust-junosmcp"]);
        assert!(!default_cli.audit_journald);

        let enabled = Cli::parse_from(["rust-junosmcp", "--audit-journald"]);
        assert!(enabled.audit_journald);
    }
```

Append this test to `rust-srxmcp/src/cli.rs`'s `mod tests`:

```rust
    #[test]
    fn audit_journald_defaults_off_and_parses() {
        let default_cli = Cli::parse_from(["rust-srxmcp"]);
        assert!(!default_cli.audit_journald);

        let enabled = Cli::parse_from(["rust-srxmcp", "--audit-journald"]);
        assert!(enabled.audit_journald);
    }
```

- [ ] **Step 2: Run both tests and verify the expected red state**

```bash
cargo test -p rust-junosmcp cli::tests::audit_journald_defaults_off_and_parses
cargo test -p rust-srxmcp --bin rust-srxmcp cli::tests::audit_journald_defaults_off_and_parses
```

Expected: each package fails to compile with `E0609` because `Cli` has no `audit_journald` field yet.

- [ ] **Step 3: Add the exact Clap fields and replace the temporary hardcoded values**

In `rust-junosmcp/src/cli.rs`, insert this field after `audit_log_file`:

```rust
    /// Also send structured audit events directly to journald.
    #[arg(long, env = "JMCP_AUDIT_JOURNALD")]
    pub audit_journald: bool,
```

In `rust-srxmcp/src/cli.rs`, insert this field after `audit_log_file`:

```rust
    /// Also send structured audit events directly to journald.
    #[arg(long, env = "JMCP_SRX_AUDIT_JOURNALD")]
    pub audit_journald: bool,
```

In both main files, replace the Task 1 temporary initializer line:

```rust
        journald: false,
```

with:

```rust
        journald: args.audit_journald,
```

Do not add a CLI-validation coupling: the flag is valid for stdio and streamable HTTP and composes independently with text/JSON stderr and the file sink.

- [ ] **Step 4: Run focused CLI tests and verify green behavior**

```bash
cargo test -p rust-junosmcp cli::tests::audit_journald_defaults_off_and_parses
cargo test -p rust-srxmcp --bin rust-srxmcp cli::tests::audit_journald_defaults_off_and_parses
```

Expected: both tests PASS; the default parses as `false` and the explicit flag as `true` without attempting a journal connection.

- [ ] **Step 5: Verify both help surfaces expose the flag without initializing journald**

```bash
cargo run -q -p rust-junosmcp -- --help | rg -- '--audit-journald'
cargo run -q -p rust-srxmcp -- --help | rg -- '--audit-journald'
```

Expected from the first command:

```text
--audit-journald
```

Expected from the second command:

```text
--audit-journald
```

Clap's help exit occurs before `main` constructs the journal layer, so these checks are offline and portable.

- [ ] **Step 6: Run both complete binary unit-test targets**

```bash
cargo test -p rust-junosmcp --bin rust-junosmcp
cargo test -p rust-srxmcp --bin rust-srxmcp
```

Expected: PASS with 40 Junos binary unit tests and 4 SRX binary unit tests after the two new cases are added; no existing default changes.

- [ ] **Step 7: Review and commit the public configuration wiring**

```bash
git diff --check
git diff -- rust-junosmcp/src/cli.rs rust-junosmcp/src/main.rs rust-srxmcp/src/cli.rs rust-srxmcp/src/main.rs
git add rust-junosmcp/src/cli.rs rust-junosmcp/src/main.rs rust-srxmcp/src/cli.rs rust-srxmcp/src/main.rs
git commit -m "feat: expose journald audit flags"
```

Expected: commit succeeds and hooks pass.

---

### Task 3: Document configuration, field mapping, delivery semantics, and release notes

**Files:**
- Modify: `docs/AUDIT.md:131-159`
- Modify: `README.md:281-289`
- Modify: `CHANGELOG.md:7-27`
- Modify: `rust-srxmcp/CHANGELOG.md:9-29`

**Interfaces:**
- Consumes: Task 2's exact flag/env names and Task 1's `AUDIT_` mapping, `PRIORITY=5`, fail-fast construction, and additive fan-out semantics.
- Produces: operator-facing setup, query, routing, duplicate-delivery, post-start failure, and RFC 5424 scope documentation.

- [ ] **Step 1: Add the flag to both detailed configuration tables**

In `docs/AUDIT.md`, add the following row to the `rust-junosmcp` table after `--audit-log-file`:

```markdown
| `--audit-journald` | `JMCP_AUDIT_JOURNALD` | `false` | Also send `target="audit"` events directly to journald as native structured fields. Startup fails if journald is unavailable. |
```

Add the following row to the `rust-srxmcp` table after `--audit-log-file`:

```markdown
| `--audit-journald` | `JMCP_SRX_AUDIT_JOURNALD` | `false` | Also send `target="audit"` events directly to journald as native structured fields. Startup fails if journald is unavailable. |
```

- [ ] **Step 2: Replace the existing journald forwarding paragraph with the complete native-target documentation**

Replace `docs/AUDIT.md`'s current `### journald` section (through its existing query example, before `### File sink`) with this exact content:

````markdown
### journald

By default, services running under systemd write their normal text/JSON stderr
stream into the journal. Set `--audit-journald` (or the binary-specific
environment variable above) to add a second, native journal record for every
`target="audit"` event. The native target is disabled by default and does not
replace stderr or `--audit-log-file`.

Enabling the target probes `/run/systemd/journal/socket` during startup. A
missing or inaccessible socket aborts startup with `initializing audit tracing`
and the operating-system error; the service never silently claims that an
explicitly requested sink is active. The upstream tracing layer cannot return
per-event send failures after initialization, so stderr and the optional file
sink remain the fallback if journald later becomes unavailable.

When systemd also captures stderr, an audit operation can appear twice: once as
the formatted stderr `MESSAGE`, and once as the native entry with indexed
`AUDIT_*` fields. Select `TARGET=audit` to consume only native entries.

#### Native field mapping

| Journal field | Audit value |
|---------------|-------------|
| `TARGET` | `audit` |
| `PRIORITY` | `5` (`NOTICE`; audit events use tracing `INFO`) |
| `SYSLOG_IDENTIFIER` | `rust-junosmcp` or `rust-srxmcp` |
| `MESSAGE` | `audit` |
| `AUDIT_CORRELATION_ID` | `correlation_id` |
| `AUDIT_CALLER` | `caller` |
| `AUDIT_TOOL` | `tool` |
| `AUDIT_ROUTERS` | `routers` |
| `AUDIT_ROUTER_COUNT` | `router_count` |
| `AUDIT_ACTION` | `action` |
| `AUDIT_AUTHORIZATION` | `authorization` |
| `AUDIT_RESULT` | `result` |
| `AUDIT_DURATION_MS` | `duration_ms` |
| `AUDIT_ERROR_KIND` | `error_kind` |
| `AUDIT_ERROR` | `error` |
| `AUDIT_REASON` | `reason` |
| `AUDIT_METADATA` | `metadata` |

The journal stores values as byte strings, but every field remains separately
indexed; consumers do not parse the JSON formatter's nested `fields` object.
Redaction is applied before fan-out, so native values match the redacted stderr
and file values.

Query native Junos and SRX audit entries with:

```bash
journalctl -t rust-junosmcp TARGET=audit
journalctl -t rust-srxmcp TARGET=audit
journalctl -t rust-junosmcp -o json | jq 'select(.TARGET == "audit")'
```

Direct RFC 5424 formatting and remote syslog transport are not implemented by
this option. Forward native journal fields with the host's journald/rsyslog or
SIEM integration when remote delivery is required.
````

- [ ] **Step 3: Add the concise README configuration row**

In the root README audit table, add:

```markdown
| `--audit-journald` | `JMCP_AUDIT_JOURNALD` (junos) / `JMCP_SRX_AUDIT_JOURNALD` (srx) | `false` | Optional native journald fan-out for structured audit fields; fails startup when explicitly enabled but unavailable. |
```

- [ ] **Step 4: Add matching Junos and SRX release notes**

Under `CHANGELOG.md`'s Unreleased `### Added`, insert:

```markdown
- **#153 - native journald audit sink.** Both binaries can opt into direct,
  structured journald fan-out with `--audit-journald`; only `target="audit"`
  events are routed, fields use a stable `AUDIT_` namespace, and an unavailable
  journal fails startup instead of silently dropping the configured sink.
```

Insert the same bullet under `rust-srxmcp/CHANGELOG.md`'s Unreleased
`### Added` so both release streams record the shared behavior.

- [ ] **Step 5: Verify every documented name and mapping against source**

```bash
rg -n "audit-journald|AUDIT_CORRELATION_ID|PRIORITY.*NOTICE|TARGET=audit|RFC 5424" README.md docs/AUDIT.md CHANGELOG.md rust-srxmcp/CHANGELOG.md
rg -n "JMCP(_SRX)?_AUDIT_JOURNALD|with_field_prefix|target\(\) == \"audit\"" rust-junosmcp rust-srxmcp rust-junosmcp-audit
git diff --check
```

Expected: both env names appear in their matching source and docs; the complete mapping and query appear in `docs/AUDIT.md`; source contains `Some("AUDIT".to_owned())` and one shared exact target predicate; `git diff --check` is silent.

- [ ] **Step 6: Commit the operator documentation**

```bash
git add README.md docs/AUDIT.md CHANGELOG.md rust-srxmcp/CHANGELOG.md
git commit -m "docs: document native journald audit sink"
```

Expected: commit succeeds and documentation hooks pass.

---

### Task 4: Run required verification and audit acceptance coverage

**Files:**
- Verify only; no planned source changes.

**Interfaces:**
- Consumes: all implementation and documentation from Tasks 1-3.
- Produces: completion evidence for issue #153 and branch-review handoff; no device mutations and no project-file output.

- [ ] **Step 1: Confirm scope, dependency delta, and worktree cleanliness before checks**

```bash
git status --short --branch
git log --oneline --decorate -4
git diff 41ac19fe94c2f213f3c50b7006d2dd1e1f048ae7...HEAD --stat
git diff 41ac19fe94c2f213f3c50b7006d2dd1e1f048ae7...HEAD -- Cargo.lock rust-junosmcp-audit/Cargo.toml
cargo tree -p rust-junosmcp-audit | rg 'tracing-journald|libc'
```

Expected: the branch contains the design, core sink, CLI wiring, and docs commits; no uncommitted files; the dependency delta is limited to `tracing-journald` and its already-present `libc` dependency; Cargo reports a semver-compatible `tracing-journald 0.3.x`.

- [ ] **Step 2: Run the exact `just fmt` recipe**

```bash
cargo fmt --all --check
```

Expected: exit 0 and no output.

- [ ] **Step 3: Run the exact `just lint` recipe**

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: exit 0 with no warnings.

- [ ] **Step 4: Run the exact `just test` recipe**

```bash
cargo test --workspace --locked
```

Expected: 912 passed, 0 failed, and 29 ignored across workspace/unit/integration/doc targets. The four added tests are two audit-construction tests and one CLI test per binary. Ignored tests remain the established real-device/environment cases.

- [ ] **Step 5: Record `just guard` equivalence**

The checked-in `guard` recipe is exactly `lint test`. Steps 3 and 4 are its two commands with their required arguments and both must be green. Record this mapping in the handoff because the `just` executable is unavailable; do not claim the wrapper itself ran.

- [ ] **Step 6: Run the exact `just e2e` recipe**

```bash
cargo run -p rust-junosmcp -- --help >/dev/null
cargo run -p rust-srxmcp -- --help >/dev/null
```

Expected: both exit 0 without connecting to journald or a device.

- [ ] **Step 7: Exercise deterministic fail-fast behavior through the unit seam**

```bash
cargo test -p rust-junosmcp-audit init::tests::enabled_journald_propagates_factory_error -- --exact
cargo test -p rust-junosmcp-audit init::tests::disabled_journald_does_not_call_factory -- --exact
```

Expected: both PASS. The first proves an enabled constructor error reaches the caller unchanged; the second proves disabled default execution never invokes the journal constructor.

- [ ] **Step 8: Run the exact `just security` recipe and compare the known baseline**

```bash
trivy fs --scanners vuln,misconfig,secret --exit-code 1 .
```

Expected in the current repository baseline: exit 1 only for the pre-existing `cmov 0.5.3` advisory and four pre-existing Dockerfile misconfigurations; no new vulnerability, misconfiguration, or secret is attributable to `tracing-journald` or this change. Capture the counts and identifiers. If any new finding appears, stop and remediate it before handoff.

- [ ] **Step 9: Record `just release-check` equivalence**

The checked-in `release-check` recipe is exactly `fmt lint test security`. Steps 2, 3, 4, and 8 execute those recipes directly. Record that formatting, lint, and tests pass while the aggregate security/release result remains nonzero only for the unchanged documented baseline; do not report a green release check.

- [ ] **Step 10: Confirm real-device tests were not run**

```bash
test "${CONFIRM_LAB_INTEGRATION:-}" != "yes"
```

Expected: exit 0. Report `just integration` as intentionally skipped because no lab confirmation was supplied and issue #153 requires no device interaction.

- [ ] **Step 11: Perform the requirement-by-requirement completion audit**

```bash
rg -n "audit_journald|JMCP_AUDIT_JOURNALD|JMCP_SRX_AUDIT_JOURNALD" rust-junosmcp rust-srxmcp rust-junosmcp-audit
rg -n "with_field_prefix|filter_fn\(is_audit\)|target\(\) == \"audit\"|init_tracing\(&audit_cfg\).*context" rust-junosmcp-audit rust-junosmcp rust-srxmcp
rg -n "AUDIT_CORRELATION_ID|AUDIT_METADATA|PRIORITY.*NOTICE|TARGET=audit|RFC 5424" docs/AUDIT.md
git diff --check
git status --short --branch
```

Expected evidence:

- both binaries expose their exact flag/env pair and default false;
- both pass the parsed boolean into `AuditConfig` and propagate initialization errors;
- the native layer uses `AUDIT_` prefixing and the shared audit-only filter;
- docs cover every audit field, priority, queries, duplication, fail-fast startup, post-start limitation, and RFC 5424 non-goal;
- the worktree is clean and all committed changes are scoped to #153.

- [ ] **Step 12: Prepare branch review handoff**

```bash
git log --oneline 41ac19fe94c2f213f3c50b7006d2dd1e1f048ae7..HEAD
git diff 41ac19fe94c2f213f3c50b7006d2dd1e1f048ae7...HEAD --stat
git status --short --branch
```

Expected: four commits total after the base—design, core sink, CLI wiring, and docs—with a clean worktree. Report files changed, schema/behavior compatibility, all command results, skipped real-device checks, the post-start journald delivery limitation, duplicate systemd storage risk, and the unchanged security baseline before requesting code review.

---

## Plan self-review checklist

- **Spec coverage:** Task 1 covers native construction, filtering, prefixing, failure behavior, dependency review, and compatibility; Task 2 covers both CLI/env surfaces; Task 3 covers the complete operator mapping and release notes; Task 4 proves every acceptance criterion and required repository check.
- **Placeholder scan:** Every edit step contains exact code or prose, every command has an expected result, and no unresolved implementation placeholders remain.
- **Type consistency:** `AuditConfig.journald: bool`, `Cli.audit_journald: bool`, `make_journald_layer_with(...) -> io::Result<Option<tracing_journald::Layer>>`, and `init_tracing(&AuditConfig) -> io::Result<()>` are identical across all tasks and call sites.
- **Scope:** The plan adds native journald only and explicitly excludes RFC 5424, facility overrides, delivery retries, packaging defaults, device access, and changes to existing sinks or schemas.
