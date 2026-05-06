# Templates Implementation Plan (PR #6)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `render_and_apply_j2_template` (with YAML/JSON vars sniff, strict-undefined Jinja2 rendering, and full apply-path parity to `load_and_commit_config`) plus the trivial `pfe_smoke` CI fix from sub-project #3 follow-up.

**Architecture:** Add a new `tools/template.rs` handler in `rust-junosmcp-core`. Vars are parsed by sniffing the first non-whitespace character (`{` → JSON, else YAML). `minijinja` renders with `UndefinedBehavior::Strict`. Apply path reuses the existing `Policy` + `build_config_payload` infrastructure with the rendered string fanning out per-router parallel to the batch tool. Format auto-detection inspects the rendered output. The pfe_smoke CI fix is a one-line target swap bundled into Task 0.

**Tech Stack:** Rust 2021, `minijinja = "2"`, `serde_yml = "0.0.12"`, `serde_json` with `preserve_order` already enabled, `tokio` JoinSet/Semaphore (existing pattern from `tools/batch.rs`), `rmcp` 0.8.5 `#[tool]` macro, existing `rust-junosmcp-auth` `KNOWN_TOOLS` registry.

**Spec:** `docs/superpowers/specs/2026-05-05-templates-inventory-design.md` §4.1, §6, §7, §8, §9.

---

## File map

| Path | Action | Purpose |
|---|---|---|
| `Cargo.toml` (workspace) | Modify | Add `minijinja` and `serde_yml` workspace deps |
| `rust-junosmcp-core/Cargo.toml` | Modify | Pull in the two new deps |
| `rust-junosmcp-core/src/error.rs` | Modify | Add `TemplateSyntax`, `TemplateVars`, `TemplateRender`, `TemplateFormatMismatch` variants |
| `rust-junosmcp-core/src/tools/mod.rs` | Modify | Register `pub mod template;`; add `TemplateArgs` struct |
| `rust-junosmcp-core/src/tools/template.rs` | Create | Vars sniff, render, format auto-detect, render-only path, apply path |
| `rust-junosmcp-auth/src/file.rs` | Modify | Extend `KNOWN_TOOLS` with `"render_and_apply_j2_template"` |
| `rust-junosmcp/src/server.rs` | Modify | Add `#[tool]` adapter wired to `template::handle` |
| `rust-junosmcp/tests/stdio_smoke.rs` | Modify | Rename `lists_eight_tools` → `lists_nine_tools`; extend `EXPECTED_TOOLS` |
| `rust-junosmcp/tests/template_smoke.rs` | Create | End-to-end stdio smoke (render-only, JSON+YAML vars, strict-undefined surfaces) |
| `rust-junosmcp/tests/pfe_smoke.rs` | Modify | Replace `203.0.113.1:1` → `127.0.0.1:1` |
| `rust-junosmcp-core/tests/integration_real_device.rs` | Modify | Append `#[ignore]` `live_render_show_version_template_dry_run` |
| `README.md` | Modify | New "Templates (released)" subsection; CLI section unchanged |

---

## Task 0: Bundle the pfe_smoke CI fix

The `pfe_connect_failure_surfaces_through_tool_call` test in `pfe_smoke.rs` uses `203.0.113.1:1` (TEST-NET-3, kernel TCP-connect timeout ~70 s × 2 attempts). Switch to `127.0.0.1:1` for instant `ECONNREFUSED`. Bundling as Task 0 keeps it out of the way of the templates work.

**Files:**
- Modify: `rust-junosmcp/tests/pfe_smoke.rs`

- [ ] **Step 1: Identify the line(s) using the slow target**

Run: `grep -n "203.0.113.1" rust-junosmcp/tests/pfe_smoke.rs`
Expected: at least one match.

- [ ] **Step 2: Replace with the fast target**

Edit each occurrence in the connect-failure test:

```diff
-                "ip":"203.0.113.1",
-                "port":1,
+                "ip":"127.0.0.1",
+                "port":1,
```

- [ ] **Step 3: Run the suite to confirm it still asserts the same error class**

Run: `cargo test -p rust-junosmcp --test pfe_smoke -- --nocapture`
Expected: PASS, suite completes in <5 s instead of ~140 s.

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp/tests/pfe_smoke.rs
git commit -m "test(pfe_smoke): use 127.0.0.1:1 for instant ECONNREFUSED

Drops the connect-failure test from ~140s (TEST-NET-3 TCP timeout) to
<1s. No semantic change — both surface as a transport error from
rustez."
```

---

## Task 1: Add minijinja + serde_yml workspace deps

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `rust-junosmcp-core/Cargo.toml`

- [ ] **Step 1: Add to workspace dependency table**

In `Cargo.toml` `[workspace.dependencies]`, append:

```toml
minijinja        = { version = "2", default-features = false, features = ["builtins", "loader"] }
serde_yml        = "0.0.12"
```

`builtins` enables `default`, `upper`, `length`, etc. (matches Jinja2 standard filters). `loader` is unused for inline templates but cheap to leave on; can be dropped later if size is a concern.

- [ ] **Step 2: Pull into the core crate**

In `rust-junosmcp-core/Cargo.toml` `[dependencies]`:

```toml
minijinja  = { workspace = true }
serde_yml  = { workspace = true }
```

- [ ] **Step 3: Build to confirm resolution**

Run: `cargo build -p rust-junosmcp-core`
Expected: clean build, two new deps resolved.

- [ ] **Step 4: Audit the new deps**

Run: `cargo audit`
Expected: no advisories on the new crates. If `serde_yml 0.0.12` flags an advisory, pin to the most recent green release and document in commit message.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock rust-junosmcp-core/Cargo.toml
git commit -m "deps: add minijinja and serde_yml for template tool"
```

---

## Task 2: Add JmcpError template variants

**Files:**
- Modify: `rust-junosmcp-core/src/error.rs`

- [ ] **Step 1: Read the existing enum to find the right insertion point**

Run: `grep -n "JmcpError\|#\\[error" rust-junosmcp-core/src/error.rs | head -40`
Expected: see existing variants like `BadFormat(String)`, `BadPfeCommand(String)`, `Denied { ... }`. New variants go at the end of the enum, before any catch-all.

- [ ] **Step 2: Add the four new variants**

Append to the `JmcpError` enum:

```rust
    /// Jinja2 template failed to parse (`minijinja::Error` syntax kind).
    /// Inner string carries the line/col-formatted message.
    #[error("template syntax error: {0}")]
    TemplateSyntax(String),

    /// `vars_content` could not be parsed as JSON or YAML.
    /// Inner string mentions which parser was attempted last.
    #[error("template vars parse error: {0}")]
    TemplateVars(String),

    /// Render-time error (most commonly strict-undefined hits).
    #[error("template render error: {0}")]
    TemplateRender(String),

    /// Rendered template uses `text` or `xml` format against a device with
    /// active config blocklist rules. Same restriction as load_and_commit_config.
    #[error("template format `{format}` not allowed: device has config rules; use `set`")]
    TemplateFormatMismatch { format: String },
```

- [ ] **Step 3: Run unit tests for error.rs**

Run: `cargo test -p rust-junosmcp-core --lib error`
Expected: PASS (no behavior change to existing variants).

- [ ] **Step 4: Verify Display output**

Add a test (still in `error.rs`'s test module):

```rust
    #[test]
    fn template_syntax_display() {
        let e = JmcpError::TemplateSyntax("line 3: unexpected end-of-input".into());
        let s = format!("{e}");
        assert!(s.contains("template syntax"));
        assert!(s.contains("line 3"));
    }
```

Run: `cargo test -p rust-junosmcp-core --lib template_syntax_display`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/error.rs
git commit -m "feat(error): add template-related JmcpError variants"
```

---

## Task 3: Add TemplateArgs struct

**Files:**
- Modify: `rust-junosmcp-core/src/tools/mod.rs`

- [ ] **Step 1: Add the args struct alongside the others**

Append after `ExecuteBatchArgs`:

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TemplateArgs {
    /// Jinja2 template content as a string (inline; no file path).
    pub template_content: String,
    /// Vars as a JSON or YAML string. Sniffed by first non-whitespace char.
    /// Must deserialize to a top-level object/map.
    pub vars_content: String,
    /// Single router to apply to. Mutually exclusive with `router_names`.
    #[serde(default)]
    pub router_name: Option<String>,
    /// Multiple routers to apply to. Mutually exclusive with `router_name`.
    #[serde(default)]
    pub router_names: Option<Vec<String>>,
    /// If false (default), only renders and returns the rendered string.
    #[serde(default)]
    pub apply_config: bool,
    /// Commit comment recorded in the device commit log when applied.
    #[serde(default = "default_commit_comment")]
    pub commit_comment: String,
    /// If true, runs lock + load + diff + rollback (no commit). Implies apply_config=true.
    #[serde(default)]
    pub dry_run: bool,
    /// Override format detection ('set', 'text', 'xml'). Auto-detected if omitted.
    #[serde(default)]
    pub config_format: Option<String>,
}
```

- [ ] **Step 2: Register the new module**

Near the top, with the other `pub mod` declarations:

```rust
pub mod template;
```

- [ ] **Step 3: Add basic deserialization tests**

In the existing `#[cfg(test)] mod tests` block, append:

```rust
    #[test]
    fn template_args_defaults_apply_and_dry_run_to_false() {
        let v = serde_json::json!({
            "template_content":"set system host-name {{ name }}",
            "vars_content":"{\"name\":\"r1\"}",
            "router_name":"r1"
        });
        let a: TemplateArgs = serde_json::from_value(v).unwrap();
        assert!(!a.apply_config);
        assert!(!a.dry_run);
        assert_eq!(a.commit_comment, "Configuration loaded via MCP");
        assert_eq!(a.router_name.as_deref(), Some("r1"));
        assert!(a.router_names.is_none());
    }

    #[test]
    fn template_args_accepts_router_names_list() {
        let v = serde_json::json!({
            "template_content":"set foo",
            "vars_content":"{}",
            "router_names":["r1","r2"]
        });
        let a: TemplateArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.router_names.as_deref(), Some(&["r1".into(), "r2".into()][..]));
    }
```

- [ ] **Step 4: Run the deserialization tests**

Run: `cargo test -p rust-junosmcp-core --lib tools::tests::template_args`
Expected: 2 passing.

Note: `cargo build` will fail at this point because `tools/template.rs` doesn't exist yet — that's expected; Task 4 creates the file. Run *only* the unit tests above, which should still link the existing tools module.

If Step 4 fails because the missing module breaks compilation (`pub mod template;` references a missing file), insert a stub now:

```rust
// rust-junosmcp-core/src/tools/template.rs
//! Stub — full implementation lands in Task 4.
```

Then re-run the tests.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/mod.rs rust-junosmcp-core/src/tools/template.rs
git commit -m "feat(tools): add TemplateArgs struct and template module stub"
```

---

## Task 4: Implement vars sniff (JSON vs YAML)

**Files:**
- Modify: `rust-junosmcp-core/src/tools/template.rs`

- [ ] **Step 1: Write the failing tests first**

Replace the stub with:

```rust
//! `render_and_apply_j2_template` — Jinja2 render with optional commit.
//!
//! Vars input is parsed as JSON if it starts with `{` (after whitespace) or
//! YAML otherwise. Both must produce a top-level object.

use crate::error::JmcpError;
use serde_json::Value;

/// Parse `vars_content` as JSON if first non-whitespace char is `{`,
/// otherwise as YAML. Both branches must produce a `Value::Object`.
pub(crate) fn parse_vars(input: &str) -> Result<Value, JmcpError> {
    let trimmed = input.trim_start();
    let parsed = if trimmed.starts_with('{') {
        serde_json::from_str::<Value>(input).map_err(|e| {
            JmcpError::TemplateVars(format!("JSON parse failed: {e}"))
        })?
    } else {
        serde_yml::from_str::<Value>(input).map_err(|e| {
            JmcpError::TemplateVars(format!("YAML parse failed: {e}"))
        })?
    };
    if !parsed.is_object() {
        return Err(JmcpError::TemplateVars(
            "vars_content must deserialize to a top-level object/map".into(),
        ));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vars_sniff_routes_json() {
        let v = parse_vars(r#"{"name":"r1","port":22}"#).unwrap();
        assert_eq!(v["name"], "r1");
        assert_eq!(v["port"], 22);
    }

    #[test]
    fn vars_sniff_routes_yaml() {
        let v = parse_vars("name: r1\nport: 22\n").unwrap();
        assert_eq!(v["name"], "r1");
        assert_eq!(v["port"], 22);
    }

    #[test]
    fn vars_sniff_handles_leading_whitespace_for_json() {
        let v = parse_vars("   \n   {\"x\":1}").unwrap();
        assert_eq!(v["x"], 1);
    }

    #[test]
    fn vars_sniff_rejects_non_object_json_array() {
        let r = parse_vars("[1,2,3]");
        assert!(matches!(r, Err(JmcpError::TemplateVars(_))));
    }

    #[test]
    fn vars_sniff_rejects_non_object_yaml_scalar() {
        let r = parse_vars("just a string");
        assert!(matches!(r, Err(JmcpError::TemplateVars(_))));
    }

    #[test]
    fn vars_sniff_surfaces_yaml_parse_error() {
        // Stray colons + flow indentation will fail YAML parse.
        let r = parse_vars("key: : :\n  - bad: : :\n");
        assert!(matches!(r, Err(JmcpError::TemplateVars(s)) if s.contains("YAML")));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail or pass**

Run: `cargo test -p rust-junosmcp-core --lib tools::template::tests::vars`
Expected: 6 PASS. (The implementation is included with the tests in Step 1, so this is "test + impl in one commit" — acceptable for this small piece. Subsequent tasks will follow stricter red-green-refactor.)

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/src/tools/template.rs
git commit -m "feat(template): vars sniff parses JSON or YAML to top-level object"
```

---

## Task 5: Implement minijinja render with strict undefined

**Files:**
- Modify: `rust-junosmcp-core/src/tools/template.rs`

- [ ] **Step 1: Write the failing tests**

Append to the test module:

```rust
    #[test]
    fn render_substitutes_simple_var() {
        let out = render(
            "set system host-name {{ name }}",
            &parse_vars(r#"{"name":"r1"}"#).unwrap(),
        )
        .unwrap();
        assert_eq!(out, "set system host-name r1");
    }

    #[test]
    fn render_strict_undefined_fails_with_var_name() {
        let r = render(
            "set system host-name {{ missing }}",
            &parse_vars("{}").unwrap(),
        );
        match r {
            Err(JmcpError::TemplateRender(s)) => assert!(s.contains("missing")),
            other => panic!("expected TemplateRender, got {other:?}"),
        }
    }

    #[test]
    fn render_minijinja_filters_work() {
        let out = render(
            "{{ name | upper }}-{{ ports | length }}",
            &parse_vars(r#"{"name":"r1","ports":[1,2,3,4]}"#).unwrap(),
        )
        .unwrap();
        assert_eq!(out, "R1-4");
    }

    #[test]
    fn render_template_syntax_error_surfaces() {
        let r = render("{{ unterminated", &parse_vars("{}").unwrap());
        assert!(matches!(r, Err(JmcpError::TemplateSyntax(_))));
    }
```

- [ ] **Step 2: Run them to confirm `render` is undefined**

Run: `cargo test -p rust-junosmcp-core --lib tools::template::tests::render`
Expected: compilation error — `render` not found. Good.

- [ ] **Step 3: Implement `render`**

Add to `template.rs` (near the top, after `parse_vars`):

```rust
use minijinja::{Environment, UndefinedBehavior};

/// Render `template_content` with `vars` (a JSON object). Strict-undefined:
/// missing variables surface as `JmcpError::TemplateRender`, not silently as "".
pub(crate) fn render(template_content: &str, vars: &Value) -> Result<String, JmcpError> {
    let mut env = Environment::new();
    env.set_undefined_behavior(UndefinedBehavior::Strict);
    let tmpl = env.template_from_str(template_content).map_err(|e| {
        JmcpError::TemplateSyntax(format!("{e}"))
    })?;
    tmpl.render(vars).map_err(|e| {
        JmcpError::TemplateRender(format!("{e}"))
    })
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p rust-junosmcp-core --lib tools::template::tests::render`
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/template.rs
git commit -m "feat(template): minijinja render with strict undefined"
```

---

## Task 6: Implement format auto-detect

**Files:**
- Modify: `rust-junosmcp-core/src/tools/template.rs`

- [ ] **Step 1: Write the tests**

Append to the test module:

```rust
    #[test]
    fn format_autodetect_xml_for_leading_lt() {
        assert_eq!(detect_format("<configuration>...</configuration>"), "xml");
        assert_eq!(detect_format("\n  <foo/>"), "xml");
    }

    #[test]
    fn format_autodetect_set_for_set_lines() {
        assert_eq!(detect_format("set system host-name r1"), "set");
        assert_eq!(detect_format("delete protocols bgp"), "set");
        // Mixed input, but `set ` line wins:
        assert_eq!(detect_format("set foo\n# comment\nbar"), "set");
    }

    #[test]
    fn format_autodetect_text_otherwise() {
        assert_eq!(detect_format("system {\n  host-name r1;\n}"), "text");
        assert_eq!(detect_format(""), "text");
    }
```

- [ ] **Step 2: Run them to confirm `detect_format` is undefined**

Run: `cargo test -p rust-junosmcp-core --lib tools::template::tests::format`
Expected: compilation error.

- [ ] **Step 3: Implement `detect_format`**

Add to `template.rs`:

```rust
/// Auto-detect Junos config format from the rendered string.
/// Returns "xml" if the first non-whitespace char is `<`, "set" if any line
/// starts with `set ` or `delete `, otherwise "text".
pub(crate) fn detect_format(rendered: &str) -> &'static str {
    let trimmed = rendered.trim_start();
    if trimmed.starts_with('<') {
        return "xml";
    }
    for line in rendered.lines() {
        let line = line.trim_start();
        if line.starts_with("set ") || line.starts_with("delete ") {
            return "set";
        }
    }
    "text"
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p rust-junosmcp-core --lib tools::template::tests::format`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/template.rs
git commit -m "feat(template): auto-detect xml/set/text format from rendered string"
```

---

## Task 7: Implement render-only path

When `apply_config=false`, the tool short-circuits after rendering. This task wires up the public `handle()` for that case and returns a result shape parallel to `execute_junos_command_batch`.

**Files:**
- Modify: `rust-junosmcp-core/src/tools/template.rs`

- [ ] **Step 1: Write the failing test**

Append:

```rust
    use crate::device_manager::DeviceManager;
    use crate::inventory::Inventory;
    use crate::policy::Policy;
    use crate::tools::TemplateArgs;
    use std::io::Write;
    use std::sync::Arc;

    fn inv_with(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    fn args_render_only(routers: Vec<&str>) -> TemplateArgs {
        TemplateArgs {
            template_content: "set system host-name {{ name }}".into(),
            vars_content: r#"{"name":"r1"}"#.into(),
            router_name: None,
            router_names: Some(routers.iter().map(|s| s.to_string()).collect()),
            apply_config: false,
            commit_comment: "test".into(),
            dry_run: false,
            config_format: None,
        }
    }

    #[tokio::test]
    async fn render_only_returns_rendered_string_per_router() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(args_render_only(vec!["r1"]), dm, pol).await.unwrap();
        let rows = r["results"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["router"], "r1");
        assert_eq!(rows[0]["rendered_template"], "set system host-name r1");
        assert!(rows[0].get("commit_id").is_none());
        assert!(rows[0].get("error").is_none());
    }

    #[tokio::test]
    async fn render_only_unknown_router_returns_error_row() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(args_render_only(vec!["nope"]), dm, pol).await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn render_only_rejects_both_router_name_and_names() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let mut a = args_render_only(vec!["r1"]);
        a.router_name = Some("r1".into());
        let r = handle(a, dm, pol).await;
        assert!(matches!(r, Err(JmcpError::Validation(_))));
    }
```

(`JmcpError::Validation(String)` already exists in `error.rs`. If not, add it now in this same task.)

- [ ] **Step 2: Run to confirm compilation failure**

Run: `cargo test -p rust-junosmcp-core --lib tools::template::tests::render_only`
Expected: `handle` not found.

- [ ] **Step 3: Implement `handle()` for the render-only path**

Add to `template.rs` below `detect_format`:

```rust
use crate::device_manager::DeviceManager;
use crate::policy::Policy;
use crate::tools::TemplateArgs;
use serde_json::json;
use std::sync::Arc;

/// Resolve the router-selector args to a single canonical Vec<String>.
/// Rejects both-supplied; rejects empty `router_names`; allows neither
/// (returns an empty list — apply path will be a no-op).
fn resolve_routers(args: &TemplateArgs) -> Result<Vec<String>, JmcpError> {
    match (&args.router_name, &args.router_names) {
        (Some(_), Some(_)) => Err(JmcpError::Validation(
            "specify exactly one of `router_name` or `router_names`".into(),
        )),
        (Some(one), None) => Ok(vec![one.clone()]),
        (None, Some(many)) if many.is_empty() => Err(JmcpError::Validation(
            "`router_names` cannot be empty".into(),
        )),
        (None, Some(many)) => Ok(many.clone()),
        (None, None) => Ok(Vec::new()),
    }
}

pub async fn handle(
    args: TemplateArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
) -> Result<serde_json::Value, JmcpError> {
    let routers = resolve_routers(&args)?;

    // Pre-flight: verify every named router exists. Mirrors the batch tool.
    for r in &routers {
        let _ = dm.inventory().get(r)?;
    }

    let vars = parse_vars(&args.vars_content)?;
    let rendered = render(&args.template_content, &vars)?;
    let format = match args.config_format.as_deref() {
        Some(f) if f == "set" || f == "text" || f == "xml" => f.to_string(),
        Some(other) => return Err(JmcpError::BadFormat(other.to_string())),
        None => detect_format(&rendered).to_string(),
    };

    if !args.apply_config {
        let mut rows = Vec::with_capacity(routers.len().max(1));
        if routers.is_empty() {
            rows.push(json!({
                "router": null,
                "rendered_template": rendered,
                "config_format": format,
            }));
        } else {
            for r in routers {
                rows.push(json!({
                    "router": r,
                    "rendered_template": rendered,
                    "config_format": format,
                }));
            }
        }
        return Ok(json!({ "results": rows, "applied": false }));
    }

    // Apply path lands in Task 8; until then, refuse.
    Err(JmcpError::Validation(
        "apply_config=true is not yet wired (see Task 8)".into(),
    ))
}
```

If `JmcpError::Validation(String)` doesn't already exist, add to `error.rs`:

```rust
    #[error("validation error: {0}")]
    Validation(String),
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p rust-junosmcp-core --lib tools::template`
Expected: all template tests PASS, including the 3 new render_only tests.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/template.rs rust-junosmcp-core/src/error.rs
git commit -m "feat(template): render-only handle() with multi-router result rows"
```

---

## Task 8: Implement apply path (router-scope, blocklist, format gate, fan-out)

This task replaces the placeholder `apply_config=true` branch with a real implementation. Mirrors the structure of `tools/batch.rs` for the per-router fan-out and `tools/load_commit.rs` for the per-router commit logic.

**Files:**
- Modify: `rust-junosmcp-core/src/tools/template.rs`

- [ ] **Step 1: Write the failing tests**

Append to the test module:

```rust
    fn args_apply(routers: Vec<&str>, dry_run: bool) -> TemplateArgs {
        let mut a = args_render_only(routers);
        a.apply_config = true;
        a.dry_run = dry_run;
        a
    }

    #[tokio::test]
    async fn apply_blocklist_rejects_rendered_payload_pre_connect() {
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"127.0.0.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let mut a = args_apply(vec!["r1"], false);
        a.template_content = "set foo\ndelete protocols bgp".into();
        a.vars_content = "{}".into();
        let r = handle(a, dm, pol).await.unwrap();
        let rows = r["results"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0]["error"].as_str().unwrap().contains("delete *"));
    }

    #[tokio::test]
    async fn apply_text_format_with_rules_returns_format_mismatch() {
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"127.0.0.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let mut a = args_apply(vec!["r1"], false);
        a.template_content = "system { host-name r1; }".into();
        a.vars_content = "{}".into();
        a.config_format = Some("text".into());
        let r = handle(a, dm, pol).await;
        assert!(matches!(r, Err(JmcpError::TemplateFormatMismatch { ref format }) if format == "text"));
    }
```

- [ ] **Step 2: Run them**

Run: `cargo test -p rust-junosmcp-core --lib tools::template::tests::apply`
Expected: FAIL — current `apply_config=true` returns `Validation`.

- [ ] **Step 3: Replace the placeholder branch**

Replace the `if !args.apply_config { ... } Err(...)` block in `handle()` with:

```rust
    // Format gate: if any selected router has effective config rules,
    // the rendered format must be `set`. Same restriction as
    // load_and_commit_config.
    if format != "set" {
        for r in &routers {
            if policy.has_config_rules_for(r) {
                return Err(JmcpError::TemplateFormatMismatch { format });
            }
        }
    }

    if !args.apply_config {
        let mut rows = Vec::with_capacity(routers.len().max(1));
        if routers.is_empty() {
            rows.push(json!({
                "router": null,
                "rendered_template": rendered,
                "config_format": format,
            }));
        } else {
            for r in routers {
                rows.push(json!({
                    "router": r,
                    "rendered_template": rendered,
                    "config_format": format,
                }));
            }
        }
        return Ok(json!({ "results": rows, "applied": false }));
    }

    // Apply path: per-router blocklist on the rendered output, then commit.
    let mut rows: Vec<serde_json::Value> = Vec::with_capacity(routers.len());
    for r in &routers {
        match policy.check_config(r, &format, &rendered)? {
            crate::policy::Decision::Allow => {}
            crate::policy::Decision::Deny { rule, source, line_number } => {
                let pattern = rule.pattern.clone();
                let source_str = source.as_str();
                tracing::warn!(
                    tool = "render_and_apply_j2_template",
                    router = %r,
                    matched_rule = %pattern,
                    rule_source = %source_str,
                    line_number = ?line_number,
                    "blocklist denied request",
                );
                rows.push(json!({
                    "router": r,
                    "rendered_template": rendered,
                    "config_format": format,
                    "error": format!("blocklist denied: pattern `{pattern}` from {source_str}"),
                }));
                continue;
            }
        }

        // Per-router commit. Fan-out is sequential to keep the implementation
        // small and avoid load on a single host; we don't have a multi-router
        // template use case where parallelism is on the hot path. If that
        // changes, mirror tools/batch.rs's Semaphore + JoinSet pattern.
        let row = match commit_one(r, &rendered, &format, &args.commit_comment, args.dry_run, &dm).await {
            Ok(diff_or_id) => {
                if args.dry_run {
                    json!({
                        "router": r,
                        "rendered_template": rendered,
                        "config_format": format,
                        "diff": diff_or_id,
                    })
                } else {
                    json!({
                        "router": r,
                        "rendered_template": rendered,
                        "config_format": format,
                        "commit_id": diff_or_id,
                    })
                }
            }
            Err(e) => json!({
                "router": r,
                "rendered_template": rendered,
                "config_format": format,
                "error": e.to_string(),
            }),
        };
        rows.push(row);
    }
    Ok(json!({ "results": rows, "applied": !args.dry_run }))
```

Add the `commit_one` helper alongside `handle`:

```rust
use crate::helpers::build_config_payload;

/// Commit (or dry-run) a rendered config payload to one router.
/// Returns the diff string in dry-run mode, or the commit comment in apply mode.
async fn commit_one(
    router: &str,
    rendered: &str,
    format: &str,
    commit_comment: &str,
    dry_run: bool,
    dm: &Arc<DeviceManager>,
) -> Result<String, JmcpError> {
    let payload = build_config_payload(rendered.to_string(), Some(format))?;
    let mut dev = dm.open(router).await?;
    let mut cfg = dev.config()?;

    cfg.lock().await?;
    if let Err(e) = cfg.load(payload).await {
        let _ = cfg.unlock().await;
        let _ = dev.close().await;
        return Err(JmcpError::from(e));
    }
    let diff = cfg.diff().await?.unwrap_or_default();

    let result = if dry_run {
        // Roll back the candidate; no commit.
        let _ = cfg.rollback(0).await;
        Ok(diff)
    } else {
        match cfg.commit_with_comment(commit_comment).await {
            Ok(_) => Ok(commit_comment.to_string()),
            Err(e) => {
                let _ = cfg.rollback(0).await;
                Err(JmcpError::from(e))
            }
        }
    };

    let _ = cfg.unlock().await;
    let _ = dev.close().await;
    result
}
```

`Policy::has_config_rules_for(router: &str) -> bool` may not yet exist. If `cargo build` reports it missing, add to `rust-junosmcp-core/src/policy.rs`:

```rust
impl Policy {
    /// True if the per-router effective config rule list is non-empty.
    pub fn has_config_rules_for(&self, router: &str) -> bool {
        self.config_rules_for(router).map_or(false, |rs| !rs.is_empty())
    }
}
```

(`config_rules_for` is the existing accessor; check the source for its real name and adapt.)

- [ ] **Step 4: Run the tests**

Run: `cargo test -p rust-junosmcp-core --lib tools::template`
Expected: all template tests PASS.

Run the full lib suite to make sure nothing else regressed:

Run: `cargo test -p rust-junosmcp-core --lib`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/template.rs rust-junosmcp-core/src/policy.rs
git commit -m "feat(template): apply path with per-router blocklist + dry-run + commit"
```

---

## Task 9: Extend KNOWN_TOOLS

**Files:**
- Modify: `rust-junosmcp-auth/src/file.rs`

- [ ] **Step 1: Add the new tool name**

Find the `KNOWN_TOOLS` slice and append:

```rust
const KNOWN_TOOLS: &[&str] = &[
    "get_router_list",
    "gather_device_facts",
    "execute_junos_command",
    "get_junos_config",
    "junos_config_diff",
    "load_and_commit_config",
    "execute_junos_pfe_command",
    "execute_junos_command_batch",
    "render_and_apply_j2_template",   // NEW
];
```

Also bump any associated count tests. Search for `KNOWN_TOOLS.len()` and `8` literals in the file:

Run: `grep -n "KNOWN_TOOLS\\|len()" rust-junosmcp-auth/src/file.rs`
Update count assertions from 8 to 9.

- [ ] **Step 2: Run the auth crate tests**

Run: `cargo test -p rust-junosmcp-auth`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-auth/src/file.rs
git commit -m "feat(auth): KNOWN_TOOLS now includes render_and_apply_j2_template"
```

---

## Task 10: Add the #[tool] adapter in server.rs

**Files:**
- Modify: `rust-junosmcp/src/server.rs`

- [ ] **Step 1: Add the import**

In the existing `use rust_junosmcp_core::tools::...;` block, add:

```rust
use rust_junosmcp_core::tools::{template, TemplateArgs};
```

(Adapt to the file's actual import grouping style.)

- [ ] **Step 2: Add the adapter alongside the others**

Insert after the `execute_junos_command_batch` adapter (around the bottom of the `#[tool_router]` impl block):

```rust
    #[tool(
        name = "render_and_apply_j2_template",
        description = "Render a Jinja2 template (inline) with JSON or YAML vars. Optionally commit the rendered config to one or more routers; supports dry-run."
    )]
    async fn render_and_apply_j2_template(
        &self,
        Parameters(args): Parameters<TemplateArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        if let Err(e) = self.check_tool_scope(ctx, "render_and_apply_j2_template") {
            return Self::scope_to_call_result(e);
        }
        // Per-router scope is enforced inside the handler against the
        // resolved router list (router_name OR router_names). Same as
        // execute_junos_command_batch.
        let resolved = match (&args.router_name, &args.router_names) {
            (Some(one), None) => vec![one.clone()],
            (None, Some(many)) => many.clone(),
            _ => Vec::new(),
        };
        for r in &resolved {
            if let Err(e) =
                self.check_router_scope(ctx, "render_and_apply_j2_template", r)
            {
                return Self::scope_to_call_result(e);
            }
        }
        Self::to_call_result(
            template::handle(args, self.dm.clone(), self.policy.clone()).await,
        )
    }
```

- [ ] **Step 3: Build the binary crate**

Run: `cargo build -p rust-junosmcp`
Expected: clean build.

- [ ] **Step 4: Run the binary's existing test suite**

Run: `cargo test -p rust-junosmcp --lib`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp/src/server.rs
git commit -m "feat(server): wire render_and_apply_j2_template tool adapter"
```

---

## Task 11: Update stdio_smoke tool count

**Files:**
- Modify: `rust-junosmcp/tests/stdio_smoke.rs`

- [ ] **Step 1: Find the count test**

Run: `grep -n "lists_eight_tools\\|EXPECTED_TOOLS" rust-junosmcp/tests/stdio_smoke.rs`
Expected: a test named `lists_eight_tools` and an `EXPECTED_TOOLS` array of length 8.

- [ ] **Step 2: Rename and extend**

Rename the function:

```diff
-fn lists_eight_tools() {
+fn lists_nine_tools() {
```

Extend the `EXPECTED_TOOLS` array:

```rust
const EXPECTED_TOOLS: &[&str] = &[
    "get_router_list",
    "gather_device_facts",
    "execute_junos_command",
    "get_junos_config",
    "junos_config_diff",
    "load_and_commit_config",
    "execute_junos_pfe_command",
    "execute_junos_command_batch",
    "render_and_apply_j2_template",   // NEW
];
```

Update any internal `assert_eq!(tools.len(), 8)` to `9`.

- [ ] **Step 3: Run the test**

Run: `cargo test -p rust-junosmcp --test stdio_smoke -- --nocapture`
Expected: PASS, 9 tools advertised.

- [ ] **Step 4: Commit**

```bash
git add rust-junosmcp/tests/stdio_smoke.rs
git commit -m "test(stdio_smoke): expect 9 tools after templates land"
```

---

## Task 12: Add tests/template_smoke.rs

**Files:**
- Create: `rust-junosmcp/tests/template_smoke.rs`

- [ ] **Step 1: Create the smoke file**

Write to `rust-junosmcp/tests/template_smoke.rs`:

```rust
//! Stdio-transport smoke tests for `render_and_apply_j2_template`.
//!
//! Render-only paths run end-to-end (no real device I/O). Apply-path is
//! covered by integration_real_device.rs (`#[ignore]`).

mod common;
use common::{call_tool, spawn_stdio_server, write_inventory};
use serde_json::json;

#[test]
fn render_only_path_returns_rendered_string_with_json_vars() {
    let inv = write_inventory(
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server(inv.path());
    let resp = call_tool(
        &mut child,
        "render_and_apply_j2_template",
        json!({
            "template_content": "set system host-name {{ name }}",
            "vars_content": r#"{"name":"r1"}"#,
            "router_name": "r1"
        }),
    );
    let rows = resp["results"].as_array().unwrap();
    assert_eq!(rows[0]["rendered_template"], "set system host-name r1");
    assert_eq!(rows[0]["config_format"], "set");
    assert_eq!(resp["applied"], false);
}

#[test]
fn render_only_path_with_yaml_vars() {
    let inv = write_inventory(
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server(inv.path());
    let resp = call_tool(
        &mut child,
        "render_and_apply_j2_template",
        json!({
            "template_content": "set system host-name {{ name }}\ndelete protocols bgp",
            "vars_content": "name: r1\n",
            "router_name": "r1"
        }),
    );
    let rows = resp["results"].as_array().unwrap();
    assert!(rows[0]["rendered_template"]
        .as_str()
        .unwrap()
        .contains("set system host-name r1"));
}

#[test]
fn strict_undefined_surfaces_through_tool_call() {
    let inv = write_inventory(
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server(inv.path());
    let err = call_tool(
        &mut child,
        "render_and_apply_j2_template",
        json!({
            "template_content": "set foo {{ missing }}",
            "vars_content": "{}",
            "router_name": "r1"
        }),
    );
    // `call_tool` returns an error envelope when the handler errors —
    // `template render error` is the human-readable string from the variant.
    let s = err.to_string();
    assert!(s.contains("template render"), "expected render error, got: {s}");
}
```

If `common::call_tool`/`spawn_stdio_server`/`write_inventory` don't exist, copy the helper module from one of the other smoke tests (`tests/batch_smoke.rs` defines `mod common;` — read it to find the file path; common helpers usually live at `rust-junosmcp/tests/common.rs` or similar).

- [ ] **Step 2: Run the smoke test**

Run: `cargo test -p rust-junosmcp --test template_smoke -- --nocapture`
Expected: 3 PASS.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp/tests/template_smoke.rs
git commit -m "test(template_smoke): stdio end-to-end render-only paths"
```

---

## Task 13: Append a real-device test

**Files:**
- Modify: `rust-junosmcp-core/tests/integration_real_device.rs`

- [ ] **Step 1: Append the new test**

After the existing `live_pfe_show_jnh_stats_packet` test (which `#[ignore]`-gates real-device runs), add:

```rust
#[tokio::test]
#[ignore]
async fn live_render_show_version_template_dry_run() {
    let host = std::env::var("JMCP_TEST_HOST").expect("JMCP_TEST_HOST set");
    let user = std::env::var("JMCP_TEST_USER").expect("JMCP_TEST_USER set");
    let pass = std::env::var("JMCP_TEST_PASS").expect("JMCP_TEST_PASS set");

    let inv_json = format!(
        r#"{{"r1":{{"ip":{host:?},"username":{user:?},"auth":{{"type":"password","password":{pass:?}}}}}}}"#
    );
    let inv = std::sync::Arc::new(
        rust_junosmcp_core::inventory::Inventory::load_from_str(&inv_json).unwrap(),
    );
    let dm = std::sync::Arc::new(rust_junosmcp_core::device_manager::DeviceManager::new(inv.clone()));
    let pol = std::sync::Arc::new(rust_junosmcp_core::policy::Policy::build(&inv).unwrap());

    let args = rust_junosmcp_core::tools::TemplateArgs {
        template_content: "set system host-name {{ name }}".into(),
        vars_content: r#"{"name":"jmcp-test"}"#.into(),
        router_name: Some("r1".into()),
        router_names: None,
        apply_config: true,
        commit_comment: "rust-junosmcp template smoke".into(),
        dry_run: true,
        config_format: None,
    };

    let r = rust_junosmcp_core::tools::template::handle(args, dm, pol)
        .await
        .expect("handle ok");
    let row = &r["results"][0];
    assert_eq!(row["router"], "r1");
    assert!(row.get("diff").is_some(), "expected dry-run diff field");
    assert!(row.get("commit_id").is_none(), "expected no commit_id in dry-run");
}
```

If `Inventory::load_from_str` doesn't exist, write the JSON to a `tempfile::NamedTempFile` and call `Inventory::load(path)` instead.

- [ ] **Step 2: Verify it compiles (still ignored, won't run)**

Run: `cargo test -p rust-junosmcp-core --test integration_real_device --no-run`
Expected: clean build.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/tests/integration_real_device.rs
git commit -m "test(integration): #[ignore] live template dry-run smoke"
```

---

## Task 14: README updates

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add the v0.2 follow-up subsection for templates**

In the "Feature scope" section, after the `### v0.2 follow-up: PFE + batch (released)` subsection, add:

```markdown
### v0.2 follow-up: Templates (released)

- `render_and_apply_j2_template` — render a Jinja2 template (inline `template_content`) with JSON or YAML `vars_content`. Supports single (`router_name`) or multiple routers (`router_names`), dry-run, and full commit. Reuses the same blocklist + format gating as `load_and_commit_config`.
- Vars sniff: first non-whitespace `{` → JSON, otherwise YAML. Both must produce a top-level object.
- Strict-undefined: missing variables fail with the variable name rather than rendering empty.
- Auto-format detection: leading `<` → `xml`, any `set ` / `delete ` line → `set`, otherwise `text`. Override via `config_format`.

**Coming after v0.2.2:** `add_device` / `reload_devices` interactive tools (sub-project #4 PR #7).
```

Update the existing "Coming after v0.2" line at the end of the feature scope block to point at sub-project #4 PR #7 only:

```markdown
**Coming after v0.2:** `add_device` / `reload_devices` interactive tools.
```

- [ ] **Step 2: Confirm rendering**

Run: `head -90 README.md`
Expected: see the new section in the right place; no broken anchors.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: announce render_and_apply_j2_template in feature scope"
```

---

## Task 15: Final verification (Task-17 equivalent)

**Files:** none modified.

- [ ] **Step 1: Build the workspace**

Run: `cargo build --workspace`
Expected: clean build.

- [ ] **Step 2: Test the workspace**

Run: `cargo test --workspace`
Expected: all PASS.

- [ ] **Step 3: Clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 4: Format check** (CI-blocker — see `ci_format_check` memory)

Run: `cargo fmt --all -- --check`
Expected: no diff.

If diff: run `cargo fmt --all` and add to a follow-up commit:

```bash
git add -u
git commit -m "style: rustfmt sub-project #4 PR #6 files"
```

- [ ] **Step 5: Audit**

Run: `cargo audit`
Expected: no new advisories.

- [ ] **Step 6: Push the branch**

```bash
git push -u origin feature/templates-inventory
```

(Branch name reused from the brainstorming worktree. If a different branch name is desired for PR #6 vs PR #7, rename before push.)

- [ ] **Step 7: Open PR #6**

```bash
gh pr create --title "feat: render_and_apply_j2_template (sub-project #4 PR #6)" --body "$(cat <<'EOF'
## Summary

Sub-project #4 PR #6 / 2 — ships `render_and_apply_j2_template`, the first of three remaining tools needed for full Juniper/junos-mcp-server parity.

- New tool: render a Jinja2 template (inline `template_content`) with JSON or YAML `vars_content`. Supports single or multi-router, dry-run, and full commit.
- Vars-format sniff: `{...}` → JSON, anything else → YAML. Both must produce a top-level object.
- Strict-undefined: missing vars fail with the variable name (no silent empty-string substitution).
- Auto-format detection: `<` → xml, `set `/`delete ` lines → set, otherwise text.
- Apply-path reuses the existing blocklist + format-gate from `load_and_commit_config`. Per-router fan-out is sequential (no concurrent template use case observed; can be parallelized later if needed).
- Bundled: trivial pfe_smoke CI fix (`203.0.113.1:1` → `127.0.0.1:1`). Drops connect-failure test from ~140 s to <1 s.

Spec: `docs/superpowers/specs/2026-05-05-templates-inventory-design.md`
Plan: `docs/superpowers/plans/2026-05-05-templates.md`

## Test plan

- [x] `cargo build --workspace`
- [x] `cargo test --workspace`
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [x] `cargo fmt --all -- --check`
- [x] `cargo audit`
- [x] Stdio smoke (`template_smoke.rs`) — render-only paths with JSON and YAML vars; strict-undefined surfaces through the tool call.
- [x] Tool count assertion: `lists_nine_tools` (was eight).
- [ ] Real device dry-run (`#[ignore]` test, run manually with JMCP_TEST_HOST etc).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Cross-task notes

**TDD discipline:** Tasks 4–8 follow strict red-green-refactor; Tasks 0, 9, 10, 11, 13, 14, 15 are mechanical updates without a meaningful "fail" state, so they collapse the pattern.

**Why sequential per-router commit:** the apply path uses a simple `for` loop rather than `tools/batch.rs`'s Semaphore + JoinSet because (a) the template tool's typical use is "one template, one or two routers" — operators rarely template-blast a whole fleet — and (b) it keeps blast radius and rollback semantics easier to reason about. If a parallel use case emerges, copy the `tools/batch.rs` pattern.

**Why YAML *and* JSON:** parity with the upstream Python tool (which takes YAML) plus ergonomics for LLM callers (which lean JSON). Sniff is single-character; cost is one extra dep.

**`Policy::has_config_rules_for` may already exist** under a different name. Check `rust-junosmcp-core/src/policy.rs` before adding it. Use whatever the existing accessor is named.

**Branch / PR ordering:** This plan ships PR #6 (templates) on `feature/templates-inventory`. The companion plan `2026-05-05-inventory-mutation.md` (PR #7) starts from a fresh branch off main *after* this PR merges, OR rebases onto a stacked PR if the team prefers stacks.

**Self-review (writing-plans Step "Self-Review"):**

1. **Spec coverage:** Tasks cover spec §4.1 (tool surface), §6 (deps), §7 (CLI flags — none for templates), §8 (KNOWN_TOOLS), §9.1/§9.2/§9.3/§9.4/§9.5 (tests + verification). §3 release plan is inherent to PR #6 / #7 split.
2. **Placeholder scan:** No "TBD" or vague handoff. Every code step has concrete code. Step 8 makes one assumption about a Policy accessor name and explicitly tells the implementer how to handle the mismatch.
3. **Type consistency:** `TemplateArgs` is defined once (Task 3) and used unchanged through Tasks 7, 8, 10, 13. `JmcpError` variant names match between Task 2 and the use sites.
