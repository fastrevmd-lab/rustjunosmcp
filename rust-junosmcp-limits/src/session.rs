//! Session count cap + idle/lifetime reaper layered over any rmcp
//! `SessionManager` (default `LocalSessionManager`).

use crate::config::LimitsConfig;
use dashmap::DashMap;
use futures::Stream;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::common::server_side_http::{ServerSseMessage, SessionId};
use rmcp::transport::streamable_http_server::session::{RestoreOutcome, SessionManager};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::task::AbortOnDropHandle;

/// Per-session activity metadata.
struct SessionMeta {
    created_at: Instant,
    last_active: Instant,
}

#[derive(Default)]
struct TokenSessionState {
    counts: HashMap<String, usize>,
    sessions: HashMap<SessionId, String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TokenSessionCapacity {
    pub(crate) current: usize,
    pub(crate) max: usize,
}

/// Tracks live sessions, enforces the count cap, and identifies stale sessions.
pub struct SessionTracker {
    active: AtomicUsize,
    max_sessions: usize,
    max_sessions_per_token: usize,
    idle_timeout: Option<Duration>,
    max_lifetime: Option<Duration>,
    activity: DashMap<SessionId, SessionMeta>,
    token_sessions: Mutex<TokenSessionState>,
}

pub(crate) struct TokenSessionReservation {
    tracker: Arc<SessionTracker>,
    token: Option<String>,
}

impl std::fmt::Debug for TokenSessionReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSessionReservation")
            .finish_non_exhaustive()
    }
}

impl TokenSessionReservation {
    pub(crate) fn commit(mut self, id: SessionId) -> bool {
        let token = self
            .token
            .as_ref()
            .expect("uncommitted reservation")
            .clone();
        let mut state = self.tracker.token_state();
        if state.sessions.contains_key(&id) {
            tracing::warn!(session_id = %id, token = %token, "duplicate token session binding");
            drop(state);
            return false;
        }
        // `unregister` releases its activity-map operation before taking this
        // mutex. Keeping the mutex through this check and the binding insert
        // therefore guarantees either-order cleanup without a lock inversion:
        // an earlier unregister makes commit roll back, while a later one sees
        // and removes the binding inserted below.
        if !self.tracker.activity.contains_key(&id) {
            tracing::warn!(session_id = %id, token = %token, "token session closed before binding");
            drop(state);
            return false;
        }
        state.sessions.insert(id, token);
        self.token = None;
        true
    }
}

impl Drop for TokenSessionReservation {
    fn drop(&mut self) {
        let Some(token) = self.token.take() else {
            return;
        };
        let mut state = self.tracker.token_state();
        SessionTracker::decrement_token(&mut state, &token);
    }
}

impl SessionTracker {
    /// Build from config.
    pub fn new(cfg: &LimitsConfig) -> Self {
        Self {
            active: AtomicUsize::new(0),
            max_sessions: cfg.max_sessions,
            max_sessions_per_token: cfg.max_sessions_per_token,
            idle_timeout: cfg.idle_timeout(),
            max_lifetime: cfg.max_lifetime(),
            activity: DashMap::new(),
            token_sessions: Mutex::new(TokenSessionState::default()),
        }
    }

    fn token_state(&self) -> std::sync::MutexGuard<'_, TokenSessionState> {
        self.token_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn decrement_token(state: &mut TokenSessionState, token: &str) {
        let remove = match state.counts.get_mut(token) {
            Some(count) if *count > 1 => {
                *count -= 1;
                false
            }
            Some(_) => true,
            None => false,
        };
        if remove {
            state.counts.remove(token);
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

    pub(crate) fn try_reserve_token(
        self: &Arc<Self>,
        token: String,
    ) -> Result<Option<TokenSessionReservation>, TokenSessionCapacity> {
        if self.max_sessions_per_token == 0 {
            return Ok(None);
        }
        let mut state = self.token_state();
        let current = state.counts.get(&token).copied().unwrap_or(0);
        if current >= self.max_sessions_per_token {
            return Err(TokenSessionCapacity {
                current,
                max: self.max_sessions_per_token,
            });
        }
        state.counts.insert(token.clone(), current + 1);
        drop(state);
        Ok(Some(TokenSessionReservation {
            tracker: self.clone(),
            token: Some(token),
        }))
    }

    #[cfg(test)]
    pub(crate) fn active_for_token(&self, token: &str) -> usize {
        self.token_state().counts.get(token).copied().unwrap_or(0)
    }

    #[cfg(test)]
    fn token_population_len(&self) -> usize {
        self.token_state().counts.len()
    }

    #[cfg(test)]
    fn token_binding_len(&self) -> usize {
        self.token_state().sessions.len()
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
        let mut state = self.token_state();
        if let Some(token) = state.sessions.remove(id) {
            Self::decrement_token(&mut state, &token);
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
    use std::sync::Barrier;
    use std::thread;
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

    #[test]
    fn token_reservations_enforce_isolation_and_drop_rollback() {
        let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
            max_sessions_per_token: 1,
            ..Default::default()
        }));
        let alice = tracker
            .try_reserve_token("alice".to_owned())
            .unwrap()
            .unwrap();
        let full = tracker.try_reserve_token("alice".to_owned()).unwrap_err();
        assert_eq!(full, TokenSessionCapacity { current: 1, max: 1 });
        let bob = tracker
            .try_reserve_token("bob".to_owned())
            .unwrap()
            .unwrap();
        assert_eq!(tracker.active_for_token("alice"), 1);
        assert_eq!(tracker.active_for_token("bob"), 1);
        drop(alice);
        drop(bob);
        assert_eq!(tracker.active_for_token("alice"), 0);
        assert_eq!(tracker.active_for_token("bob"), 0);
        assert_eq!(tracker.token_population_len(), 0);
    }

    #[test]
    fn committed_token_reservation_releases_on_unregister_once() {
        let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
            max_sessions_per_token: 1,
            ..Default::default()
        }));
        let session = id("session-a");
        assert!(tracker.try_register(session.clone(), Instant::now()));
        let reservation = tracker
            .try_reserve_token("alice".to_owned())
            .unwrap()
            .unwrap();
        assert!(reservation.commit(session.clone()));
        assert_eq!(tracker.active_for_token("alice"), 1);
        tracker.unregister(&session);
        tracker.unregister(&session);
        assert_eq!(tracker.active_for_token("alice"), 0);
        assert_eq!(tracker.token_population_len(), 0);
    }

    #[test]
    fn duplicate_session_binding_keeps_first_owner_and_rolls_back_second() {
        let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
            max_sessions_per_token: 2,
            ..Default::default()
        }));
        let session = id("duplicate");
        assert!(tracker.try_register(session.clone(), Instant::now()));
        assert!(tracker
            .try_reserve_token("alice".to_owned())
            .unwrap()
            .unwrap()
            .commit(session.clone()));
        assert!(!tracker
            .try_reserve_token("bob".to_owned())
            .unwrap()
            .unwrap()
            .commit(session.clone()));
        assert_eq!(tracker.active_for_token("alice"), 1);
        assert_eq!(tracker.active_for_token("bob"), 0);
        tracker.unregister(&session);
        assert_eq!(tracker.active_for_token("alice"), 0);
    }

    #[test]
    fn close_before_token_binding_rolls_back_reservation() {
        let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
            max_sessions_per_token: 1,
            ..Default::default()
        }));
        let session = id("closed-before-bind");
        assert!(tracker.try_register(session.clone(), Instant::now()));
        let reservation = tracker
            .try_reserve_token("alice".to_owned())
            .unwrap()
            .unwrap();

        tracker.unregister(&session);

        assert!(!reservation.commit(session));
        assert_eq!(tracker.active(), 0);
        assert_eq!(tracker.active_for_token("alice"), 0);
        assert_eq!(tracker.token_population_len(), 0);
        assert_eq!(tracker.token_binding_len(), 0);
    }

    #[test]
    fn reap_before_token_binding_rolls_back_reservation() {
        let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
            max_sessions: 10,
            max_sessions_per_token: 1,
            session_idle_timeout_secs: 1,
            ..Default::default()
        }));
        let base = Instant::now();
        let session = id("reaped-before-bind");
        assert!(tracker.try_register(session.clone(), base));
        let reservation = tracker
            .try_reserve_token("alice".to_owned())
            .unwrap()
            .unwrap();

        let expired = tracker.reap(base + Duration::from_secs(2));
        assert_eq!(expired, vec![session.clone()]);
        for expired_session in expired {
            tracker.unregister(&expired_session);
        }

        assert!(!reservation.commit(session));
        assert_eq!(tracker.active(), 0);
        assert_eq!(tracker.active_for_token("alice"), 0);
        assert_eq!(tracker.token_population_len(), 0);
        assert_eq!(tracker.token_binding_len(), 0);
    }

    #[test]
    fn concurrent_same_token_reservations_never_exceed_cap() {
        const CAP: usize = 4;
        const WORKERS: usize = 16;

        let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
            max_sessions_per_token: CAP,
            ..Default::default()
        }));
        let attempted = Arc::new(Barrier::new(WORKERS + 1));
        let release = Arc::new(Barrier::new(WORKERS + 1));
        let successes = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::with_capacity(WORKERS);

        for _ in 0..WORKERS {
            let tracker = tracker.clone();
            let attempted = attempted.clone();
            let release = release.clone();
            let successes = successes.clone();
            workers.push(thread::spawn(move || {
                let reservation = tracker.try_reserve_token("alice".to_owned()).ok().flatten();
                if reservation.is_some() {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
                attempted.wait();
                release.wait();
                drop(reservation);
            }));
        }

        attempted.wait();
        assert_eq!(successes.load(Ordering::SeqCst), CAP);
        assert_eq!(tracker.active_for_token("alice"), CAP);
        release.wait();

        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(tracker.active_for_token("alice"), 0);
        assert_eq!(tracker.token_population_len(), 0);
        assert_eq!(tracker.token_binding_len(), 0);
    }

    #[test]
    fn zero_disables_token_session_tracking() {
        let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
            max_sessions_per_token: 0,
            ..Default::default()
        }));
        assert!(tracker
            .try_reserve_token("alice".to_owned())
            .unwrap()
            .is_none());
        assert_eq!(tracker.token_population_len(), 0);
    }

    #[test]
    fn reaped_session_unregister_releases_token_slot() {
        let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
            max_sessions: 10,
            max_sessions_per_token: 1,
            session_idle_timeout_secs: 1,
            ..Default::default()
        }));
        let base = Instant::now();
        let session = id("idle-token-session");
        assert!(tracker.try_register(session.clone(), base));
        assert!(tracker
            .try_reserve_token("alice".to_owned())
            .unwrap()
            .unwrap()
            .commit(session.clone()));
        for expired in tracker.reap(base + Duration::from_secs(2)) {
            tracker.unregister(&expired);
        }
        assert_eq!(tracker.active_for_token("alice"), 0);
        assert_eq!(tracker.active(), 0);
    }
}
