//! Cooperative cancellation primitives for the long-running MCP tools
//! (`upgrade_junos`, `transfer_file`).
//!
//! rmcp 0.8.5 exposes a [`CancellationToken`] on every `RequestContext`
//! that fires when the client sends a `notifications/cancelled` JSON-RPC
//! message or when the server-side request timeout elapses. This module
//! provides two small helpers that wrap an inner future in a `tokio::select!`
//! against the token, so every await site in the long-running tools can
//! short-circuit on cancel without hand-rolling the select form.
//!
//! Half B (tracked separately in issue #44): rmcp 0.8.5's streamable-HTTP
//! transport does NOT propagate raw TCP-disconnect to the request token. A
//! client that simply closes the socket leaves the in-flight tool future
//! detached, running to natural completion. The helpers in this module
//! therefore catch the two cancellation paths rmcp does honor today —
//! explicit `notifications/cancelled` and per-request timeout — but cannot
//! detect raw HTTP disconnect.
//!
//! ## `biased;` ordering
//!
//! Both helpers use `biased;` in the select, so on every poll the
//! `ct.cancelled()` branch is checked before the inner future. A token
//! that was cancelled before the helper was even reached therefore returns
//! `JmcpError::Cancelled` on the first poll instead of letting the inner
//! future run.

use crate::error::JmcpError;
use std::future::Future;
use tokio_util::sync::CancellationToken;

/// Race `fut` against `ct.cancelled()`. If the token fires first, drop
/// `fut` and return `JmcpError::Cancelled`. Otherwise return whatever
/// `fut` produced.
///
/// Use this when the inner future's `Output` is already
/// `Result<_, JmcpError>` — the common case for inter-tool calls.
pub async fn select_cancel<F, T>(ct: &CancellationToken, fut: F) -> Result<T, JmcpError>
where
    F: Future<Output = Result<T, JmcpError>>,
{
    tokio::select! {
        biased;
        _ = ct.cancelled() => Err(JmcpError::Cancelled),
        r = fut => r,
    }
}

/// Race `fut` against `ct.cancelled()`. If the token fires first, drop
/// `fut` and return `JmcpError::Cancelled`. Otherwise return `Ok(value)`.
///
/// Use this for futures whose `Output` is NOT already
/// `Result<_, JmcpError>` — e.g. `tokio::time::sleep`,
/// `tokio::time::timeout`, or a `dev.cli()` that returns
/// `Result<String, rustez::Error>` and needs caller-side mapping.
pub async fn select_cancel_raw<F, T>(ct: &CancellationToken, fut: F) -> Result<T, JmcpError>
where
    F: Future<Output = T>,
{
    tokio::select! {
        biased;
        _ = ct.cancelled() => Err(JmcpError::Cancelled),
        v = fut => Ok(v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn select_cancel_returns_inner_when_not_cancelled() {
        let ct = CancellationToken::new();
        let r: Result<u32, JmcpError> = select_cancel(&ct, async { Ok(42u32) }).await;
        assert!(matches!(r, Ok(42)));
    }

    #[tokio::test]
    async fn select_cancel_returns_cancelled_when_pre_cancelled() {
        let ct = CancellationToken::new();
        ct.cancel();
        // Inner future would sleep 10s if it ran; assert the helper
        // returns within 50ms.
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            select_cancel::<_, u32>(&ct, async {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                Ok(0)
            }),
        )
        .await;
        match r {
            Ok(Err(JmcpError::Cancelled)) => (),
            other => panic!("expected Ok(Err(Cancelled)), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn select_cancel_raw_returns_value_when_not_cancelled() {
        let ct = CancellationToken::new();
        let r: Result<&'static str, JmcpError> = select_cancel_raw(&ct, async { "ok" }).await;
        assert!(matches!(r, Ok("ok")));
    }

    #[tokio::test]
    async fn select_cancel_raw_returns_cancelled_when_cancelled_mid_flight() {
        let ct = CancellationToken::new();
        let ct2 = ct.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            ct2.cancel();
        });
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            select_cancel_raw::<_, ()>(&ct, async {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }),
        )
        .await;
        match r {
            Ok(Err(JmcpError::Cancelled)) => (),
            other => panic!("expected Ok(Err(Cancelled)), got {other:?}"),
        }
    }
}
