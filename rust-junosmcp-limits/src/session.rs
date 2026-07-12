//! Session count cap + idle/lifetime reaper layered over any rmcp
//! `SessionManager` (default `LocalSessionManager`).

use crate::config::LimitsConfig;
use dashmap::DashMap;
use futures::Stream;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::common::server_side_http::{ServerSseMessage, SessionId};
use rmcp::transport::streamable_http_server::session::{RestoreOutcome, SessionManager};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::task::AbortOnDropHandle;

/// Per-session activity metadata.
struct SessionMeta {
    created_at: Instant,
    last_active: Instant,
}

/// Tracks live sessions, enforces the count cap, and identifies stale sessions.
pub struct SessionTracker {
    active: AtomicUsize,
    max_sessions: usize,
    idle_timeout: Option<Duration>,
    max_lifetime: Option<Duration>,
    activity: DashMap<SessionId, SessionMeta>,
}

impl SessionTracker {
    /// Build from config.
    pub fn new(cfg: &LimitsConfig) -> Self {
        Self {
            active: AtomicUsize::new(0),
            max_sessions: cfg.max_sessions,
            idle_timeout: cfg.idle_timeout(),
            max_lifetime: cfg.max_lifetime(),
            activity: DashMap::new(),
        }
    }

    /// Current live session count.
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    /// True when at or above the configured cap (`0` = never).
    pub fn at_capacity(&self) -> bool {
        self.max_sessions > 0 && self.active() >= self.max_sessions
    }

    /// Reserve a slot and record the session. Returns false if over cap
    /// (race-free via fetch_add/rollback).
    pub fn try_register(&self, id: SessionId, now: Instant) -> bool {
        let prev = self.active.fetch_add(1, Ordering::AcqRel);
        if self.max_sessions > 0 && prev >= self.max_sessions {
            self.active.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        self.activity.insert(
            id,
            SessionMeta {
                created_at: now,
                last_active: now,
            },
        );
        true
    }

    /// Update last-active time for a session.
    pub fn touch(&self, id: &SessionId, now: Instant) {
        if let Some(mut m) = self.activity.get_mut(id) {
            m.last_active = now;
        }
    }

    /// Drop a session from tracking and decrement the gauge.
    pub fn unregister(&self, id: &SessionId) {
        if self.activity.remove(id).is_some() {
            self.active.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Session IDs that exceed the idle timeout or max lifetime as of `now`.
    pub fn reap(&self, now: Instant) -> Vec<SessionId> {
        let mut expired = Vec::new();
        for e in self.activity.iter() {
            let m = e.value();
            let idle = self
                .idle_timeout
                .is_some_and(|t| now.duration_since(m.last_active) >= t);
            let old = self
                .max_lifetime
                .is_some_and(|t| now.duration_since(m.created_at) >= t);
            if idle || old {
                expired.push(e.key().clone());
            }
        }
        expired
    }
}

/// Interval between reaper sweeps.
const REAP_PERIOD: Duration = Duration::from_secs(30);

/// Wraps an rmcp `SessionManager`, adding a session cap and idle/lifetime reaper.
pub struct LimitedSessionManager<S> {
    inner: Arc<S>,
    tracker: Arc<SessionTracker>,
    _reaper: AbortOnDropHandle<()>,
}

impl<S: SessionManager> LimitedSessionManager<S> {
    /// Build the wrapper and spawn the background reaper. Returns `Arc<Self>`
    /// so it can be handed directly to `StreamableHttpService::new`.
    pub fn new(inner: S, cfg: &LimitsConfig) -> Arc<Self> {
        let inner = Arc::new(inner);
        let tracker = Arc::new(SessionTracker::new(cfg));
        let reaper = {
            let inner = inner.clone();
            let tracker = tracker.clone();
            AbortOnDropHandle::new(tokio::spawn(async move {
                let mut tick = tokio::time::interval(REAP_PERIOD);
                loop {
                    tick.tick().await;
                    for id in tracker.reap(Instant::now()) {
                        let _ = inner.close_session(&id).await;
                        tracker.unregister(&id);
                        tracing::info!(session_id = %id, "session reaped");
                    }
                }
            }))
        };
        Arc::new(Self {
            inner,
            tracker,
            _reaper: reaper,
        })
    }

    /// Shared tracker handle for the concurrency middleware's session-cap shed.
    pub fn tracker(&self) -> Arc<SessionTracker> {
        self.tracker.clone()
    }
}

impl<S: SessionManager> SessionManager for LimitedSessionManager<S> {
    type Error = S::Error;
    type Transport = S::Transport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        let (id, transport) = self.inner.create_session().await?;
        // Best-effort registration; the middleware early-shed is the primary cap gate.
        self.tracker.try_register(id.clone(), Instant::now());
        Ok((id, transport))
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner.initialize_session(id, message).await
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner.has_session(id).await
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        let r = self.inner.close_session(id).await;
        self.tracker.unregister(id);
        r
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner.create_stream(id, message).await
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner.accept_message(id, message).await
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner.create_standalone_stream(id).await
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner.resume(id, last_event_id).await
    }

    async fn restore_session(
        &self,
        id: SessionId,
    ) -> Result<RestoreOutcome<Self::Transport>, Self::Error> {
        let outcome = self.inner.restore_session(id.clone()).await?;
        if matches!(outcome, RestoreOutcome::Restored(_)) {
            self.tracker.try_register(id, Instant::now());
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn id(s: &str) -> SessionId {
        Arc::from(s)
    }

    #[test]
    fn cap_enforced_and_gauge_accurate() {
        let t = SessionTracker::new(&LimitsConfig {
            max_sessions: 2,
            ..Default::default()
        });
        let now = Instant::now();
        assert!(t.try_register(id("a"), now));
        assert!(t.try_register(id("b"), now));
        assert_eq!(t.active(), 2);
        assert!(t.at_capacity());
        assert!(!t.try_register(id("c"), now)); // over cap
        assert_eq!(t.active(), 2);
        t.unregister(&id("a"));
        assert_eq!(t.active(), 1);
        assert!(!t.at_capacity());
    }

    #[test]
    fn reap_returns_idle_and_expired() {
        let t = SessionTracker::new(&LimitsConfig {
            max_sessions: 10,
            session_idle_timeout_secs: 60,
            session_max_lifetime_secs: 3600,
            ..Default::default()
        });
        let base = Instant::now();
        t.try_register(id("idle"), base);
        t.try_register(id("fresh"), base);
        // "fresh" gets touched recently; "idle" does not.
        let later = base + Duration::from_secs(120);
        t.touch(&id("fresh"), later);
        let expired = t.reap(later);
        assert!(expired.contains(&id("idle")));
        assert!(!expired.contains(&id("fresh")));
    }

    #[test]
    fn zero_disables_cap() {
        let t = SessionTracker::new(&LimitsConfig {
            max_sessions: 0,
            ..Default::default()
        });
        let now = Instant::now();
        for i in 0..1000 {
            assert!(t.try_register(id(&i.to_string()), now));
        }
        assert!(!t.at_capacity());
    }
}
