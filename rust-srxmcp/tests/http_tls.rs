//! Real rustls handshake coverage for the SRX streamable-HTTP endpoint.

#![cfg(feature = "tls")]

mod common;
use common::{binary_path, ensure_built, init_body, parse_first_sse_data, pick_port, Server};
use rust_junosmcp_auth::{ScopeSet, TokenStoreFile};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn write_self_signed(dir: &Path) -> (PathBuf, PathBuf) {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, issued.cert.pem()).unwrap();
    std::fs::write(&key, issued.signing_key.serialize_pem()).unwrap();
    (cert, key)
}

fn spawn_tls(inventory: &Path, tokens: &Path, cert: &Path, key: &Path) -> Server {
    let port = pick_port();
    let mut child = Command::new(binary_path())
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--device-mapping",
            inventory.to_str().unwrap(),
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--tls-cert",
            cert.to_str().unwrap(),
            "--tls-key",
            key.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn TLS server");

    let stderr = child.stderr.take().unwrap();
    let mut reader = BufReader::new(stderr);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(Instant::now() < deadline, "TLS server did not become ready");
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => panic!("TLS server exited before readiness"),
            Ok(_) if line.contains("streamable-http listening (TLS)") => break,
            Ok(_) => {}
            Err(error) => panic!("reading TLS server stderr: {error}"),
        }
    }
    let drain = std::thread::spawn(move || {
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            line.clear();
        }
    });

    Server {
        child,
        port,
        _stderr_drain: drain,
    }
}

fn tls_agent(cert: &Path) -> ureq::Agent {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::CertificateDer;

    let pem = std::fs::read(cert).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(&pem) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ureq::AgentBuilder::new()
        .tls_config(Arc::new(config))
        .build()
}

fn fixture() -> (
    tempfile::TempDir,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    String,
) {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let inventory = dir.path().join("devices.json");
    std::fs::write(
        &inventory,
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    )
    .unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(&tokens, "tls-test", ScopeSet::Wildcard, ScopeSet::Wildcard)
        .unwrap()
        .expose()
        .to_string();
    let (cert, key) = write_self_signed(dir.path());
    (dir, inventory, tokens, cert, key, secret)
}

fn response_status(result: Result<ureq::Response, ureq::Error>) -> u16 {
    match result {
        Ok(response) => response.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(error) => panic!("TLS transport error: {error}"),
    }
}

#[test]
fn tls_handshake_completes_with_bearer_auth() {
    let (_dir, inventory, tokens, cert, key, secret) = fixture();
    let server = spawn_tls(&inventory, &tokens, &cert, &key);
    let response = tls_agent(&cert)
        .post(&format!("https://localhost:{}/mcp", server.port))
        .set("Authorization", &format!("Bearer {secret}"))
        .set("Accept", "application/json, text/event-stream")
        .send_json(init_body())
        .expect("authenticated TLS initialize");

    assert_eq!(response.status(), 200);
    let content_type = response.header("Content-Type").unwrap_or("").to_string();
    let text = response.into_string().unwrap_or_default();
    let body: Value = if content_type.contains("text/event-stream") {
        parse_first_sse_data(&text).unwrap_or(json!({}))
    } else {
        serde_json::from_str(&text).unwrap_or(json!({}))
    };
    assert!(body.pointer("/result").is_some(), "body: {body}");
}

#[test]
fn tls_does_not_replace_bearer_authentication() {
    let (_dir, inventory, tokens, cert, key, _secret) = fixture();
    let server = spawn_tls(&inventory, &tokens, &cert, &key);
    let result = tls_agent(&cert)
        .post(&format!("https://localhost:{}/mcp", server.port))
        .set("Accept", "application/json, text/event-stream")
        .send_json(init_body());
    assert_eq!(response_status(result), 401);
}

#[test]
fn tls_does_not_replace_host_validation() {
    let (_dir, inventory, tokens, cert, key, secret) = fixture();
    let server = spawn_tls(&inventory, &tokens, &cert, &key);
    let result = tls_agent(&cert)
        .post(&format!("https://localhost:{}/mcp", server.port))
        .set("Host", "evil.example")
        .set("Authorization", &format!("Bearer {secret}"))
        .set("Accept", "application/json, text/event-stream")
        .send_json(init_body());
    assert_eq!(response_status(result), 403);
}
