# Blocklist Guardrails — Design

**Date:** 2026-05-04
**Status:** Approved (brainstorming complete; pre-implementation plan)
**Sub-project of:** v0.2

## Context

`v0.1` shipped six MCP tools for Junos automation, two of which take free-form
LLM-authored input that flows directly to the device:

- `execute_junos_command` — single-line operational CLI (`command: String`).
- `load_and_commit_config` — multi-line configuration payload
  (`config_text: String`, `config_format ∈ {set, text, xml}`).

The `README` already calls out that an LLM running these against production
devices is risky and tells operators to "review configurations before allowing
commit tools to run." The v0.2 roadmap names **blocklist guardrails** as the
mechanism that turns that human-vigilance ask into an enforced check.

This design covers the first sub-project of v0.2 (decomposed into four:
guardrails → remote transport+auth → PFE+batch → templates+inventory mutation).
It is intentionally narrow: it ships rule-based deny/allow filtering for the
two free-form-input tools, with rules authored in `devices.json`, and stops
there.

## Goals

- Per-device, layered allow/deny rules over `execute_junos_command` and
  `load_and_commit_config` inputs.
- Rules authored in `devices.json` (top-level defaults plus optional
  per-device overrides).
- Backward-compatible: a `devices.json` from v0.1 (or an unmodified
  Juniper/junos-mcp-server inventory) loads and runs identically.
- Fail-fast on bad rules at startup; clear, actionable error reported to the
  MCP client on denial.
- Pure, exhaustively unit-tested evaluation logic with no I/O dependencies.

## Non-goals (deferred)

Each is a candidate for a future sub-project:

- Allowlist-only / deny-by-default mode.
- Per-rule descriptions or labels.
- Runtime reload of the blocklist (folded into the future `reload_devices`
  sub-project).
- Audit log of *allowed* calls.
- Cross-format matching: rules that match equivalently against `set`, `text`,
  and `xml` payloads. (Non-`set` formats are rejected pre-flight when rules
  are present; see "Per-domain mechanics" below.)
- Time-of-day or rate-limiting policy.
- Filtering of `get_junos_config`, `junos_config_diff`, `gather_device_facts`,
  `get_router_list` — no free-form input worth filtering.

## Schema (`devices.json` extension)

Two **optional** top-level entries plus one **optional** per-device field.
Existing files without any of these parse unchanged.

```json
{
  "_blocklist_defaults": {
    "commands": [
      { "action": "deny", "pattern": "request system *" },
      { "action": "deny", "pattern": "clear system commit" }
    ],
    "config": [
      { "action": "deny", "pattern": "delete *" }
    ]
  },
  "r1": {
    "ip": "10.0.0.1",
    "username": "admin",
    "auth": { "type": "ssh_key", "private_key_path": "/etc/jmcp/keys/r1" },
    "blocklist": {
      "commands": [
        { "action": "allow", "pattern": "request system reboot" }
      ]
    }
  },
  "r2": {
    "ip": "10.0.0.2",
    "username": "admin",
    "auth": { "type": "password", "password": "x" }
  }
}
```

### Field reference

- **`_blocklist_defaults`** *(optional, top-level)*: rules merged into every
  device's effective rule set.
  - `commands: Vec<RuleSpec>` *(optional, default `[]`)*
  - `config: Vec<RuleSpec>` *(optional, default `[]`)*
- **`<device>.blocklist`** *(optional, per device)*: rules layered over the
  defaults for that device only.
  - `commands: Vec<RuleSpec>` *(optional, default `[]`)*
  - `config: Vec<RuleSpec>` *(optional, default `[]`)*
- **`RuleSpec`**:
  - `action: "deny" | "allow"` *(required)*
  - `pattern: String` *(required)* — glob with `*` (any chars) and `?` (one
    char). Compiled with `globset` at startup. Invalid globs reject the
    inventory at startup with `BlocklistRuleInvalid`.

### Empty / absent semantics

| Configuration | Effective behavior |
|---|---|
| No `_blocklist_defaults`, no per-device `blocklist` | All calls allowed (current v0.1 behavior). |
| `blocklist: {}` | Same as absent. |
| `blocklist: { "commands": [] }` | Empty rule lists; nothing matches → allow. |

### Naming choice: `_blocklist_defaults`

`devices.json` is a flat map keyed by router name. The leading underscore
avoids collision with any plausibly-named router. (Junos `host-name` only
allows `[A-Za-z0-9-]`, but devices.json keys are arbitrary; the underscore is
defensive.)

### Drop-in compatibility footnote

The README claims compatibility with the Juniper/junos-mcp-server inventory
format. That remains true for files without blocklist entries. Files that
*use* blocklist entries are no longer cross-compatible. README will gain a
brief note to that effect.

## Rule evaluation

For a tool call on device `D` in domain `dom ∈ {commands, config}`:

```
effective_rules(D, dom) = _blocklist_defaults.<dom> ⊕ devices[D].blocklist.<dom>
```

For a candidate input string `s`:

1. Find every rule whose pattern matches `s`.
2. If the matching set is empty → **allow**.
3. Otherwise, sort matching rules by specificity (descending):
   - **Primary key:** count of literal (non-wildcard) characters in the
     pattern. More literals = more specific.
   - **Secondary key:** total pattern length.
   - **Tertiary key (tiebreak):** device-level wins over `_blocklist_defaults`.
4. Top rule's `action` is the decision.

### Specificity examples

| Top-level rules | Device rules | Input | Matches (most-specific first) | Decision |
|---|---|---|---|---|
| `deny "request system *"` | `allow "request system *"` | `request system reboot` | both equal → device wins | **allow** |
| `deny "request system *"` | `allow "request system reboot"` | `request system reboot` | device's allow has more literals (21 vs 15) | **allow** |
| `deny "request system *"` | `allow "request system reboot"` | `request system halt` | only top deny matches | **deny** |
| (none) | (none) | `show version` | no matches | **allow** |
| `deny "*"` | `allow "show *"` | `show version` | device allow is more specific | **allow** |
| `deny "*"` | `allow "show *"` | `request system reboot` | only top `*` matches | **deny** |

### Per-domain mechanics

- **`commands` domain (`execute_junos_command`):**
  - Candidate `s` = command string after `trim()` and collapsing runs of
    whitespace to a single space.
  - One match decision, one outcome.
- **`config` domain (`load_and_commit_config`):**
  - Payload split by newlines.
  - Each line is `trim()`med and whitespace-collapsed.
  - Comment-only lines (`#...`) are skipped.
  - The decision algorithm runs **per line**.
  - Payload is rejected if **any line resolves to deny**. Error names the
    first denying line and the rule that matched it.
- **`config_format ≠ "set"` when device has any effective `config` rules:**
  rejected pre-flight with
  `JmcpError::ConfigFormatNotAllowedWithRules { format }`. Rationale: per-line
  glob matching is unreliable against curly-brace `text` or `xml`, so allowing
  those formats with rules present would create a silent bypass. `set` is
  already the default and the format used in every README example.

## Module layout

### New: `rust-junosmcp-core/src/policy.rs`

Pure, stateless evaluation. No I/O, no async, no rustez deps. Easy to
exhaustively unit-test.

```rust
pub struct Policy { /* compiled per-device matchers */ }

pub enum Decision<'a> {
    Allow,
    Deny {
        rule: &'a CompiledRule,
        source: RuleSource,
        line_number: Option<usize>,
    },
}

pub enum RuleSource {
    Defaults,
    Device,
}

impl Policy {
    pub fn build(inv: &Inventory) -> Result<Self, JmcpError>;
    pub fn check_command(&self, router: &str, command: &str) -> Decision<'_>;
    pub fn check_config(
        &self,
        router: &str,
        config_format: &str,
        config_text: &str,
    ) -> Result<Decision<'_>, JmcpError>;
}
```

`Policy::build` compiles every glob pattern once. Specificity scores
(`literal_char_count`, `total_len`) are computed once and cached on
`CompiledRule`. No per-call recomputation.

### Modified: `rust-junosmcp-core/src/inventory.rs`

Add `BlocklistRules { commands: Vec<RuleSpec>, config: Vec<RuleSpec> }` and
`RuleSpec { action: Action, pattern: String }`. Add optional `blocklist` to
`DeviceEntry` (`#[serde(default)]`).

The current inventory root is `HashMap<String, DeviceEntry>` (deserialized
directly). To carry both `_blocklist_defaults` and the device map, introduce
a small file-shape struct that serde flattens:

```rust
#[derive(Deserialize)]
struct InventoryFile {
    #[serde(default, rename = "_blocklist_defaults")]
    blocklist_defaults: Option<BlocklistRules>,
    #[serde(flatten)]
    devices: HashMap<String, DeviceEntry>,
}
```

`Inventory::load` deserializes into `InventoryFile`, splits the two halves,
and stores them. `Inventory::get(name)` continues to return `&DeviceEntry`.
A new accessor `Inventory::blocklist_defaults() -> Option<&BlocklistRules>`
exposes the defaults to `Policy::build`.

Existing v0.1 files (no `_blocklist_defaults` key) round-trip identically:
the optional field stays `None`, all other keys land in `devices` via the
flatten.

### Modified: tool handlers

- `tools/execute_command.rs::handle` — call `policy.check_command(...)`
  **before** `dm.open(...)`. On `Decision::Deny` return `JmcpError::Denied`.
  No connection is opened on denial.
- `tools/load_commit.rs::handle` — call `policy.check_config(...)` before
  `build_config_payload(...)`. Same deny path.
- Other tools unchanged.

### Modified: handler plumbing

`Policy` is built once at startup after inventory loads and held in
`Arc<Policy>` alongside `Arc<DeviceManager>`. `JmcpHandler` in
`rust-junosmcp/src/server.rs` gains a `policy: Arc<Policy>` field; tool
methods pass it down. Mirrors how `DeviceManager` is currently threaded.

### Glob engine

`globset = "0.4"`. Linear-time matching, supports `*` / `?` / `[...]`. Avoids
co-opting the `regex` crate (already a transitive dep) for a job globs do
better, and avoids the ReDoS authoring footgun for security-relevant rules.

## Errors

Three new variants on `JmcpError` (`rust-junosmcp-core/src/error.rs`):

```rust
#[error("denied by blocklist: {tool} on '{router}' matched rule '{pattern}' \
         (action=deny, source={source}); input: {input_excerpt}")]
Denied {
    tool: &'static str,         // "execute_junos_command" | "load_and_commit_config"
    router: String,
    pattern: String,
    source: &'static str,       // "defaults" | "device"
    input_excerpt: String,      // truncated to 120 chars
    line_number: Option<usize>, // present for config-domain denies
},

#[error("config blocklist rules require config_format=set; got '{format}'")]
ConfigFormatNotAllowedWithRules { format: String },

#[error("invalid blocklist rule for {scope}: pattern '{pattern}': {source}")]
BlocklistRuleInvalid {
    scope: String,              // "_blocklist_defaults.commands" | "device 'r1'.config"
    pattern: String,
    #[source]
    source: globset::Error,
},
```

`Denied` and `ConfigFormatNotAllowedWithRules` surface to MCP clients as tool
errors. `BlocklistRuleInvalid` is a startup error — server refuses to start
with an unparseable rule. Same fail-fast posture as v0.1's `KeyFileMissing`.

## Logging

One `tracing::warn!` per denial, structured fields:

```rust
tracing::warn!(
    tool = "execute_junos_command",
    router = %router,
    matched_rule = %pattern,
    rule_source = %source,        // "defaults" | "device"
    input_excerpt = %excerpt,     // first 120 chars
    "blocklist denied request",
);
```

Config-domain denies include an extra `line_number` field.

No logging on allow (consistent with v0.1's posture of not logging every
accepted call).

One `tracing::info!` line at startup summarizing rule counts:
`"blocklist policy loaded: 5 default command rules, 2 default config rules; 3/12 devices have device-level rules"`.
Helps operators verify their config was picked up.

No new metrics, no new log file, no new dependencies beyond `globset`.

## Testing

### Unit tests in `policy.rs`

| Group | Cases |
|---|---|
| Specificity ordering | More-literals beats fewer-literals; equal score → device beats defaults; longest-pattern tiebreak |
| Allow-overrides-deny | Top-deny + device-allow same pattern → allow; top-deny + device-allow narrower → allow on narrow input, deny on broader |
| Empty rules | No defaults + no device → allow; empty `blocklist: {}` → allow; empty arrays → allow |
| Glob mechanics | `*`, `?`, character classes; whitespace normalization (tabs, runs of spaces, leading/trailing); case sensitivity (Junos CLI is case-sensitive — match is too) |
| Config domain | Per-line eval; comment lines skipped; first-denying-line reported with correct `line_number`; multi-line allow-carve-out works |
| Format gate | `config_format=text/xml` with rules present → `ConfigFormatNotAllowedWithRules`; non-set with **zero** effective rules → allowed (no false positive when the device has no config rules at all) |
| Compile errors | Invalid glob in defaults → `BlocklistRuleInvalid` scoped to `_blocklist_defaults.commands`; invalid glob in device → scope names the device |

### Inventory-parse tests in `inventory.rs`

- v0.1 / Juniper-format file (no blocklist fields) parses identically.
- File with `_blocklist_defaults` and per-device `blocklist` parses into the
  expected struct.
- `blocklist: {}` and missing `commands` / `config` arrays default to empty.

### Tool-handler tests

- `execute_command.rs`: denied call returns `JmcpError::Denied` **and never
  opens a connection** (verified by pointing the fixture at an unreachable
  address — no connect timeout proves we short-circuited).
- `load_commit.rs`: same; plus `config_format=xml` with rules present returns
  `ConfigFormatNotAllowedWithRules` before any rustez interaction.
- Allowed call still propagates `UnknownRouter` / connection errors as before
  (regression coverage).

### Smoke test in `rust-junosmcp/tests/`

Extends the existing stdio smoke test: load a fixture `devices.json` with a
blocklist, drive an `execute_junos_command` for a denied input through the
MCP transport, assert the JSON-RPC error payload contains the matched-rule
text.

### No new real-device integration tests

The policy layer has no device interaction. Existing integration tests cover
the device-side regression surface.

## Documentation updates

- README — short paragraph describing the feature, pointer to a
  `blocklist-template.json` example fragment, footnote on Juniper-inventory
  cross-compat.
- `devices-template.json` — add a commented `_blocklist_defaults` example
  (commented because `devices.json` is JSON without comment support;
  practically: ship `devices-template.json` with a populated example and rely
  on the README to explain that fields are optional).

## Open questions resolved during brainstorming

- Scope: both tools, separate command/config rule lists. *(Q1.D)*
- Match mechanism: glob (`globset`). *(Q2.B)*
- Configuration source: per-device in `devices.json`, with top-level defaults
  merged in. *(Q3.C → Q4.B)*
- Allow + deny rules with most-specific-match-wins, device-tiebreaks-defaults.
  *(Q5.A)*
- Default action when no rules match: allow. *(Q5.A)*
- Non-`set` config format with rules present: reject. *(Q6.A)*
- Denial response: MCP tool error naming the matched rule. *(Q7.A)*
- Logging: `tracing::warn!` only, no audit log. *(Q8.A)*
