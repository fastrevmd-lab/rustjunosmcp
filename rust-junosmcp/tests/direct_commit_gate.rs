//! `--allow-direct-commit` gates tools that commit to a device without an
//! independently approved change set.
//!
//! `load_and_commit_config` never creates a change set at all — it stages,
//! validates, and commits in one call, so there is no second-principal
//! approval by construction. Without the flag, the server must refuse the
//! call before it ever reaches the device, over stdio (no caller context at
//! all) exactly as over HTTP. With the flag, the call proceeds and the audit
//! trail shows it ran under the flag.

#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

/// Spawn `rust-junosmcp` over stdio with `extra_args`, send `initialize` then
/// `request`, and return every stderr line it produced. Modeled on
/// `rejected_call_audit.rs`'s harness, which needs the same thing: these
/// assertions read audit records, which only reach stderr, and the shared
/// `common::spawn_stdio_server_with_args` harness discards it.
fn stderr_for_request(extra_args: &[&str], request: &str) -> Vec<String> {
    common::ensure_built();

    let lease_dir = tempfile::tempdir().expect("device lease dir");
    let inventory = common::write_inventory_temp(&[("r1", "127.0.0.1", 22, "u", "/dev/null")]);

    let mut cmd = Command::new(common::binary_path());
    cmd.args(["-t", "stdio"])
        .arg("--device-lease-dir")
        .arg(lease_dir.path())
        .arg("-f")
        .arg(inventory.path());
    for a in extra_args {
        cmd.arg(a);
    }

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rust-junosmcp");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for line in [
            r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            request,
        ] {
            writeln!(stdin, "{line}").expect("write request");
        }
        stdin.flush().expect("flush");
    }
    drop(child.stdin.take());

    let stderr = child.stderr.take().expect("stderr");
    let lines: Vec<String> = BufReader::new(stderr)
        .lines()
        .map_while(Result::ok)
        .collect();
    let _ = child.wait();
    lines
}

fn audit_lines(lines: &[String]) -> Vec<&String> {
    lines.iter().filter(|line| line.contains("audit")).collect()
}

const LOAD_AND_COMMIT_REQUEST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"load_and_commit_config","arguments":{"device":"r1","config_text":"set system host-name test","config_format":"set"}}}"#;

/// Without `--allow-direct-commit`, a stdio session — which carries no caller
/// context at all — is refused before the device is ever touched.
#[test]
fn stdio_refuses_load_and_commit_config_without_the_flag() {
    let lines = stderr_for_request(&[], LOAD_AND_COMMIT_REQUEST);

    let audits = audit_lines(&lines);
    let record = audits
        .iter()
        .find(|line| line.contains("load_and_commit_config"))
        .unwrap_or_else(|| panic!("no load_and_commit_config audit record among: {audits:#?}"));
    assert!(
        record.contains("authorization=denied") && record.contains("direct_commit_disabled"),
        "refusal must be audited as a denial naming the reason: {record}"
    );
}

/// With `--allow-direct-commit`, the same stdio call passes the gate — it
/// then fails for an unrelated reason (there is no real device at
/// 127.0.0.1:22 in this test), but that failure must not be the direct-commit
/// refusal, and the audit trail must show the flag was exercised.
#[test]
fn stdio_allows_load_and_commit_config_with_the_flag() {
    let lines = stderr_for_request(&["--allow-direct-commit"], LOAD_AND_COMMIT_REQUEST);

    let audits = audit_lines(&lines);
    let record = audits
        .iter()
        .find(|line| line.contains("load_and_commit_config"))
        .unwrap_or_else(|| panic!("no load_and_commit_config audit record among: {audits:#?}"));
    assert!(
        !record.contains("direct_commit_disabled"),
        "the flag must let the call proceed past the gate: {record}"
    );
    assert!(
        record.contains("direct_commit_allowed=true"),
        "an allowed direct-commit call must be tagged in the audit trail: {record}"
    );
}

/// The refusal reaches the JSON-RPC caller as a tool error, not just the log.
#[test]
fn stdio_refusal_is_visible_to_the_caller() {
    let mut child = common::spawn_stdio_server_with_args(&[
        "-f",
        common::write_inventory_temp(&[("r1", "127.0.0.1", 22, "u", "/dev/null")])
            .path()
            .to_str()
            .unwrap(),
    ]);
    let result = common::call_tool(
        &mut child,
        "load_and_commit_config",
        serde_json::json!({
            "device": "r1",
            "config_text": "set system host-name test",
            "config_format": "set",
        }),
    );
    let text = result.to_string();
    assert!(
        text.contains("allow-direct-commit") || text.contains("direct-commit"),
        "the caller must be told why the call was refused: {text}"
    );
}

/// The gate applies identically over HTTP: an authenticated caller with full
/// scope is refused on exactly the same terms as the stdio session above, and
/// the flag lifts the refusal for HTTP too.
#[test]
fn http_gate_matches_stdio_with_and_without_the_flag() {
    use rust_junosmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};

    common::ensure_built();
    let inv = common::write_inv(
        r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "direct-commit-gate-test",
        ScopeSet::Wildcard,
        // A wildcard tool scope deliberately does not confer write authority
        // (rust_junosmcp_auth::WRITE_TOOLS); this test is about the
        // direct-commit gate, not scope grants, so name the write tool it
        // needs explicitly.
        ScopeSet::Allowlist(vec!["load_and_commit_config".into()]),
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "load_and_commit_config",
            "arguments": {
                "device": "r1",
                "config_text": "set system host-name test",
                "config_format": "set",
            }
        }
    });

    // Without the flag: refused.
    {
        let server = common::spawn(inv.path(), &tokens);
        let session = common::initialize(server.port, secret.expose_secret());
        let response = common::http_post(
            server.port,
            Some(secret.expose_secret()),
            Some(&session),
            request.clone(),
        );
        let body = response.body.to_string();
        assert!(
            body.contains("allow-direct-commit") || body.contains("direct-commit"),
            "HTTP call must be refused with the same reason as stdio: {body}"
        );
    }

    // With the flag: passes the gate (fails later for lack of a real device,
    // which is not what this test is about).
    {
        let server = common::spawn_with_auth_args(inv.path(), &tokens, &["--allow-direct-commit"]);
        let session = common::initialize(server.port, secret.expose_secret());
        let response = common::http_post(
            server.port,
            Some(secret.expose_secret()),
            Some(&session),
            request,
        );
        let body = response.body.to_string();
        assert!(
            !body.contains("allow-direct-commit"),
            "the flag must lift the refusal over HTTP too: {body}"
        );
    }
}
