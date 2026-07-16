# Design: Native journald audit sink (#153)

- **Issue:** #153 — Native syslog/journald audit sink
- **Date:** 2026-07-16
- **Status:** Approved (design), pending implementation plan
- **Follow-up from:** #132 (caller-attributed audit coverage, shipped in #152)

## Problem

`rust-junosmcp-audit::init_tracing` currently sends all tracing events to
stderr (text or JSON) and can fan `target="audit"` events out to an append-only
JSON file. A service manager can capture stderr, but that path stores the
formatted line as a journal `MESSAGE`; the audit fields are not native journal
fields that operators can index or route directly.

Issue #153 asks for an optional native syslog and/or journald target, restricted
to audit events, with structured fields and documented configuration and field
mapping. The accepted scope is a **native journald sink only**. This fits the
repository's Linux/systemd packaging and uses the Tokio tracing project's
maintained `tracing-journald` layer instead of adding a separate RFC 5424
transport stack.

## Accepted decisions

- Deliver a native journald target; RFC 5424 syslog is not part of this issue.
- The target is opt-in and disabled by default.
- An explicitly enabled target must connect during initialization or startup
  fails. There is no silent fallback that claims journald is active.
- Journald is an additional fan-out sink. Existing stderr and optional file
  output remain active.
- Native audit fields use an `AUDIT_` prefix to avoid collisions with trusted
  journal fields and provide a stable SIEM namespace.
- Use the official `tracing-journald` layer rather than implementing the journal
  native protocol or managing a `systemd-cat` child process.

## Non-goals

- RFC 3164 or RFC 5424 syslog formatting or remote syslog transport.
- Enabling native journald in packaged systemd units by default.
- Replacing, suppressing, or changing stderr and JSON-file output.
- Changing the audit event schema, redaction policy, event level, or `RUST_LOG`
  filtering semantics.
- Buffering, retries, acknowledgements, or durable delivery when journald stops
  after successful startup.
- Changing the existing audit-file open-error behavior or rotation strategy.
- Adding real-device or production-journal tests.

## Architecture and data flow

`AuditScope` continues to redact and emit one structured tracing event with
`target="audit"`. Subscriber initialization composes four layers:

```text
AuditScope::drop
    -> tracing event (target="audit", level=INFO, redacted fields)
       -> EnvFilter (existing RUST_LOG behavior)
       -> stderr fmt layer (existing text/JSON output)
       -> optional JSON file layer (target == "audit")
       -> optional journald layer (target == "audit")
```

The journald layer is built only when configured. It shares the same exact
target predicate as the file layer, so non-audit application and dependency
events never reach the native audit target. Redaction occurs before the tracing
event is emitted, so every sink receives the same already-redacted values.

The existing stderr fan-out is deliberately retained. When systemd captures
stderr and native journald is enabled, an audit operation can therefore appear
twice in the journal:

1. the existing formatted stderr record in `MESSAGE`; and
2. the new native record with indexed `AUDIT_*` fields.

This preserves backward compatibility and an independent delivery fallback.
The duplication is documented so operators can select native entries with
`TARGET=audit` or an `AUDIT_*` field.

## Configuration interface

Both binaries gain one boolean Clap flag with their established environment
prefixes:

| Binary | CLI flag | Environment variable | Default |
|--------|----------|----------------------|---------|
| `rust-junosmcp` | `--audit-journald` | `JMCP_AUDIT_JOURNALD` | `false` |
| `rust-srxmcp` | `--audit-journald` | `JMCP_SRX_AUDIT_JOURNALD` | `false` |

The flag is independent of `--audit-format` and `--audit-log-file`; all enabled
sinks receive the event. No systemd unit or container default sets the new
environment variable.

`AuditConfig` gains the corresponding process-level switch:

```rust
pub struct AuditConfig {
    pub format: AuditFormat,
    pub audit_log_file: Option<PathBuf>,
    pub redaction: Option<AuditRedaction>,
    pub journald: bool,
}
```

Each binary copies its parsed boolean into this field before calling
`init_tracing`.

## Native journal mapping

The journald layer is configured with
`with_field_prefix(Some("AUDIT".to_owned()))`. `tracing-journald` uppercases and
sanitizes tracing field names and inserts an underscore after the configured
prefix. The tracing `message` field is special and maps to the standard
`MESSAGE` field without a prefix.

### Standard fields

| Journal field | Value for audit events | Source |
|---------------|------------------------|--------|
| `TARGET` | `audit` | tracing event metadata |
| `PRIORITY` | `5` (`NOTICE`) | upstream default mapping for tracing `INFO` |
| `SYSLOG_IDENTIFIER` | executable filename (`rust-junosmcp` or `rust-srxmcp`) | upstream layer default |
| `MESSAGE` | `audit` | tracing event message |
| `CODE_FILE` / `CODE_LINE` | audit emission source | tracing event metadata |

The design keeps the upstream priority mapping. Audit events are currently
emitted at `INFO`, which `tracing-journald` maps to `NOTICE` so all five tracing
levels remain distinct across the eight journal priorities. No
`SYSLOG_FACILITY` is forced; operators route on the stable target and audit
field namespace instead.

### Audit fields

| Tracing field | Native journal field |
|---------------|----------------------|
| `correlation_id` | `AUDIT_CORRELATION_ID` |
| `caller` | `AUDIT_CALLER` |
| `tool` | `AUDIT_TOOL` |
| `routers` | `AUDIT_ROUTERS` |
| `router_count` | `AUDIT_ROUTER_COUNT` |
| `action` | `AUDIT_ACTION` |
| `authorization` | `AUDIT_AUTHORIZATION` |
| `result` | `AUDIT_RESULT` |
| `duration_ms` | `AUDIT_DURATION_MS` |
| `error_kind` | `AUDIT_ERROR_KIND` |
| `error` | `AUDIT_ERROR` |
| `reason` | `AUDIT_REASON` |
| `metadata` | `AUDIT_METADATA` |

Journal values are byte strings, so numeric tracing fields are represented by
their textual values. The field boundaries are preserved natively; consumers
do not need to parse a nested JSON `fields` object.

## Audit crate changes

### Dependency

`rust-junosmcp-audit` adds `tracing-journald = "0.3"`. The current 0.3.2 release
is maintained in `tokio-rs/tracing`, is MIT licensed, depends only on the
existing tracing stack plus `libc`, supports rustc 1.65+, and implements large
Linux payload delivery through the journal native protocol. `Cargo.lock` is
regenerated by Cargo and committed; it is never hand-edited.

The dependency compiles on non-Unix targets but constructing its layer returns
`io::ErrorKind::NotFound`. Since the new sink is disabled by default, existing
non-systemd executions remain unaffected; opting in outside a working journald
environment fails clearly.

### Shared target filter

The current inline file filter becomes a shared private predicate/layer helper
used by both sinks:

```rust
fn is_audit(meta: &tracing::Metadata<'_>) -> bool {
    meta.target() == "audit"
}
```

Both optional layers apply `filter_fn(is_audit)`. Matching remains exact and
case-sensitive.

### Testable journald construction

A private factory seam separates the configuration decision from the real
socket constructor:

```rust
fn make_journald_layer_with<F>(
    enabled: bool,
    factory: F,
) -> std::io::Result<Option<tracing_journald::Layer>>
where
    F: FnOnce() -> std::io::Result<tracing_journald::Layer>;
```

When disabled, it returns `Ok(None)` without invoking the factory. When enabled,
it calls the factory and propagates any error. Production passes
`tracing_journald::layer`; unit tests pass closures that panic if unexpectedly
called or return a deterministic error. Prefixing and target filtering are
applied to the returned production layer before subscriber composition.

### Initialization and errors

`init_tracing` changes from returning `()` to returning
`std::io::Result<()>`:

```rust
pub fn init_tracing(cfg: &AuditConfig) -> std::io::Result<()>;
```

When journald is enabled, `tracing_journald::layer()` creates an unbound Unix
datagram and probes `/run/systemd/journal/socket` with an empty payload. Failure
returns before the global subscriber or redaction policy is installed. Both
binaries propagate the error with context such as `initializing audit tracing`,
which aborts startup and exposes the OS cause.

The existing idempotent `try_init` behavior remains: an already-installed
global subscriber is not treated as an initialization error. The returned
`io::Result` represents optional sink construction, not global-subscriber
ownership.

After initialization, `tracing-journald` intentionally cannot propagate send
errors from its synchronous `Layer::on_event` callback and discards them. This
means fail-fast proves connectivity only at startup. The still-enabled stderr
and optional file layers are the fallback if journald later becomes
unavailable. This limitation is explicit in operator documentation.

The JSON-file sink and its current open-error behavior are unchanged to keep
this issue focused.

## Binary wiring

For both `rust-junosmcp` and `rust-srxmcp`:

1. Add the boolean field to `Cli` with the flag/env names above.
2. Copy it into `AuditConfig`.
3. Change the initialization call to
   `rust_junosmcp_audit::init_tracing(&audit_cfg).context(...) ?`.
4. Keep audit initialization before inventory loading, network listeners, or
   device access, so an explicitly requested but unavailable sink fails before
   the service begins accepting work.

No CLI validation rule couples journald to transport, authentication, TLS,
metrics, or the file sink.

## Documentation changes

`docs/AUDIT.md` will include:

- both flag/environment-variable pairs and the disabled default;
- additive fan-out and possible duplicate stderr/native records under systemd;
- the standard and `AUDIT_*` field mapping tables;
- startup failure and post-start delivery semantics;
- examples that select native records, including:

  ```bash
  journalctl -t rust-junosmcp TARGET=audit
  journalctl -t rust-srxmcp TARGET=audit
  journalctl -t rust-junosmcp -o json | jq 'select(.TARGET == "audit")'
  ```

- an explicit statement that remote RFC 5424 transport remains out of scope.

The root README configuration table gains the new flag. The root Junos
changelog and `rust-srxmcp/CHANGELOG.md` each record the opt-in native sink and
its fail-fast behavior.

## Testing strategy

All automated tests remain offline and do not require a running journal:

### `rust-junosmcp-audit`

- Existing file-layer test continues to prove that the shared predicate accepts
  `target="audit"` and excludes a non-audit target.
- Disabled construction returns `None` without calling the injected factory.
- Enabled construction propagates the injected `io::Error` unchanged.
- Existing JSON-file and redaction tests remain green, proving compatibility of
  the other sinks.

### Both binaries

- Default CLI parsing asserts `audit_journald == false`.
- Explicit `--audit-journald` parsing asserts `true`.
- Existing CLI help/e2e checks prove the new flag renders without contacting
  journald because Clap exits before application initialization.

The upstream crate's own tests cover journal native serialization, sanitation,
standard fields, priorities, and large-message transport. Our tests cover the
repository-owned configuration, filtering, and failure policy. A live-journal
smoke check can be performed during implementation when the development host
provides journald, but it is not a required or portable CI test.

## Compatibility and safety

- **Default behavior:** byte-for-byte unchanged because `journald=false`.
- **Audit schema:** unchanged; the new sink maps existing fields rather than
  adding or removing event fields.
- **Redaction:** unchanged and applied before fan-out; no secret-bearing source
  data is introduced.
- **MCP schemas/annotations:** unchanged.
- **Auth scopes and authorization:** unchanged.
- **Timeouts and device I/O:** unchanged; journald setup occurs before device
  handling and never contacts a Junos/SRX device.
- **Packaging:** systemd units remain valid and do not enable a new dependency
  at runtime. The sink talks directly to the standard journal socket and does
  not require `libsystemd` linking.
- **API:** adding an `AuditConfig` field and changing `init_tracing`'s return type
  updates all workspace call sites in the same change. The audit crate is at
  `0.1.0`; the behavioral default remains compatible.

## Alternatives considered

### Implement the journal native protocol locally

This avoids one dependency but would duplicate field encoding, Unix datagram
transport, field-name sanitation, and Linux memfd handling for oversized
payloads. That adds security and maintenance surface without improving the
accepted behavior.

### Run a persistent `systemd-cat` child

This avoids protocol code but introduces subprocess startup, lifetime,
backpressure, and broken-pipe handling, while structured field preservation is
weaker than the native tracing layer.

### Add RFC 5424 syslog in the same issue

RFC 5424 needs endpoint/facility/framing/TLS configuration and a separate
structured-data mapping and test matrix. The issue explicitly permits journald
**and/or** syslog, and native journald fully serves the repository's packaged
deployment model. Remote syslog can be a later independently designed feature.

## Acceptance-criteria traceability

| Issue criterion | Design evidence |
|-----------------|-----------------|
| Optional syslog and/or journald target on both binaries | Native journald boolean flag/env on Junos and SRX, disabled by default |
| Only `target="audit"` events routed | Shared exact target predicate applied to the journald layer |
| Structured fields and priority preserved | Native journal layer, `AUDIT_*` mapping, `TARGET`, `PRIORITY=5`, and `SYSLOG_IDENTIFIER` |
| Document configuration and field mapping | `docs/AUDIT.md` configuration, mapping, query, duplication, and failure sections |

## Remaining risks

- The journal can become unavailable after startup, and the upstream layer
  cannot report per-event send failures. Existing fan-out reduces but does not
  eliminate delivery risk.
- Enabling native journald under systemd can double-store each audit operation
  because stderr remains captured. This is intentional and documented.
- `RUST_LOG` can still suppress `INFO` audit events, exactly as it can today.
  This issue does not introduce a filter bypass.
- The implementation relies on the upstream crate's native serialization tests
  because a portable CI environment cannot intercept its fixed journal socket.
