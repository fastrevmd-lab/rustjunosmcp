//! Fixture-server test for MEC-44.
//!
//! `--ssh-accept-new-host-keys` now maps to `HostKeyVerification::AcceptNew`
//! for NETCONF SSH (previously `AcceptAll`, which verified nothing). This
//! drives `rust_junosmcp_core::bootstrap::build_host_key_policy` end-to-end
//! against a real in-process SSH server: connect once to pin the host's key,
//! restart the server on the same host:port with a *different* key, and
//! assert the second connection is refused rather than silently re-pinned.
//!
//! The fixture server only implements enough of the SSH protocol to satisfy
//! `SshTransport::connect` up through host-key verification, auth, and the
//! `netconf` subsystem request — it never speaks NETCONF itself, since the
//! host-key check happens during the SSH handshake, before any NETCONF
//! bytes would be exchanged.

use std::sync::Arc;
use std::time::Duration;

use rust_junosmcp_core::bootstrap::{SshHostKeyMode, build_host_key_policy};
use rustnetconf::transport::ssh::{SshAuth, SshConfig, SshTransport};

use russh::keys::PrivateKey;
use russh::server::{Auth, Handler as ServerHandler, Msg, Session};
use russh::{Channel, ChannelId};
use tokio::net::TcpListener;

#[derive(Clone)]
struct FixtureHandler;

impl ServerHandler for FixtureHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }
}

/// Reserve a free loopback port by binding to `:0`, then dropping the
/// listener. There is an unavoidable, small TOCTOU window before the real
/// listener re-binds it below; `bind_same_port_with_retry` absorbs that.
async fn reserve_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("reserve port");
    listener.local_addr().expect("local_addr").port()
}

/// Bind `port`, retrying briefly if the OS hasn't released it yet (observed
/// under CI when the previous fixture server's socket is still closing).
async fn bind_same_port_with_retry(port: u16) -> TcpListener {
    for attempt in 0..20 {
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => return listener,
            Err(_) if attempt < 19 => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(e) => panic!("bind 127.0.0.1:{port} after retries: {e}"),
        }
    }
    unreachable!()
}

/// Accept exactly one SSH connection on `listener`, presenting `host_key`,
/// then return. Panics (in the spawned task) if the handshake/session setup
/// fails for a reason other than the client refusing the host key — the
/// caller inspects the client-side `SshTransport::connect` result instead.
fn spawn_single_connection_server(
    listener: TcpListener,
    host_key: PrivateKey,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (stream, _peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => return,
        };
        let config = Arc::new(russh::server::Config {
            keys: vec![host_key],
            ..Default::default()
        });
        if let Ok(session) = russh::server::run_stream(config, stream, FixtureHandler).await {
            let _ = session.await;
        }
    })
}

fn generate_host_key() -> PrivateKey {
    let mut rng = russh::keys::key::safe_rng();
    PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).expect("ed25519 keygen")
}

fn client_config(mode: SshHostKeyMode, known_hosts: std::path::PathBuf, port: u16) -> SshConfig {
    SshConfig {
        host: "127.0.0.1".to_string(),
        port,
        username: "test".to_string(),
        auth: SshAuth::Password(zeroize::Zeroizing::new("test".to_string())),
        host_key_verification: build_host_key_policy(mode, known_hosts),
        jump_hosts: Vec::new(),
        proxy_command: None,
    }
}

#[tokio::test]
async fn accept_new_pins_unknown_host_then_refuses_a_changed_key() {
    let known_hosts_dir = tempfile::tempdir().expect("tempdir");
    let known_hosts_path = known_hosts_dir.path().join("known_hosts");
    let port = reserve_port().await;

    // First contact: unknown host, AcceptNew must accept and pin the key.
    let key_a = generate_host_key();
    let server_a = spawn_single_connection_server(bind_same_port_with_retry(port).await, key_a);
    let first = SshTransport::connect(client_config(
        SshHostKeyMode::AcceptNew,
        known_hosts_path.clone(),
        port,
    ))
    .await;
    // `.err()` consumes `first`, dropping any `Ok(SshTransport)` right here.
    // That matters: the fixture server's session future only resolves once
    // the client side closes the connection, so it must happen before we
    // wait on the server task below, or the two futures deadlock.
    let first_err = first.err();
    tokio::time::timeout(Duration::from_secs(5), server_a)
        .await
        .expect("server_a task timed out — client connection was never closed")
        .expect("server_a task panicked");
    assert!(
        first_err.is_none(),
        "first connection to an unknown host under AcceptNew must succeed: {first_err:?}"
    );
    assert!(
        known_hosts_path.exists(),
        "AcceptNew must have pinned the first host key to {known_hosts_path:?}"
    );

    // Second contact, same host:port, a DIFFERENT key: AcceptNew must refuse.
    let key_b = generate_host_key();
    let server_b = spawn_single_connection_server(bind_same_port_with_retry(port).await, key_b);
    let second = SshTransport::connect(client_config(
        SshHostKeyMode::AcceptNew,
        known_hosts_path.clone(),
        port,
    ))
    .await;
    server_b.abort();
    assert!(
        second.is_err(),
        "a changed host key under AcceptNew must be refused, but the connection succeeded"
    );
}
