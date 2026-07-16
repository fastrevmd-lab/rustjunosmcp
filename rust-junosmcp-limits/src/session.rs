//! Session count cap + idle/lifetime reaper layered over any rmcp
//! `SessionManager` (default `LocalSessionManager`).

use crate::config::LimitsConfig;
use dashmap::DashMap;
use futures::Stream;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::common::server_side_http::{ServerSseMessage, SessionId};
use rmcp::transport::streamable_http_server::session::{RestoreOutcome, SessionManager};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::task::AbortOnDropHandle;

/// Per-session activity metadata.
struct SessionMeta {
    created_at: Instant,
    last_active: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReapReason {
    Idle,
    Lifetime,
}

impl ReapReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Lifetime => "lifetime",
        }
    }
}

struct ExpiredSession {
    id: SessionId,
    reason: ReapReason,
}

#[derive(Default)]
struct TokenSessionState {
    counts: HashMap<String, usize>,
    sessions: HashMap<SessionId, String>,
    pending_reservations: usize,
    created_unbound: HashSet<SessionId>,
    closed_before_bind: HashSet<SessionId>,
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
        if state.closed_before_bind.remove(&id) {
            tracing::warn!(session_id = %id, token = %token, "token session closed before binding");
            drop(state);
            return false;
        }
        if !state.created_unbound.remove(&id) {
            tracing::warn!(session_id = %id, token = %token, "token session was not recorded at creation");
            drop(state);
            return false;
        }
        state.sessions.insert(id, token);
        SessionTracker::complete_pending_reservation(&mut state);
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
        SessionTracker::complete_pending_reservation(&mut state);
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

    fn complete_pending_reservation(state: &mut TokenSessionState) {
        debug_assert!(state.pending_reservations > 0);
        state.pending_reservations -= 1;
        if state.pending_reservations == 0 {
            state.created_unbound.clear();
            state.closed_before_bind.clear();
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
        state.pending_reservations += 1;
        drop(state);
        Ok(Some(TokenSessionReservation {
            tracker: self.clone(),
            token: Some(token),
        }))
    }

    pub(crate) fn note_session_created(&self, id: &SessionId) {
        let mut state = self.token_state();
        if state.pending_reservations > 0 {
            state.created_unbound.insert(id.clone());
        }
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

    #[cfg(test)]
    pub(crate) fn pending_reservation_count(&self) -> usize {
        self.token_state().pending_reservations
    }

    #[cfg(test)]
    fn closed_before_bind_len(&self) -> usize {
        self.token_state().closed_before_bind.len()
    }

    #[cfg(test)]
    fn created_unbound_len(&self) -> usize {
        self.token_state().created_unbound.len()
    }

    /// Reserve a slot and record the session. Returns false if over cap
    /// (race-free via fetch_add/rollback).
    pub fn try_register(&self, id: SessionId, now: Instant) -> bool {
        let prev = self.active.fetch_add(1, Ordering::AcqRel);
        if self.max_sessions > 0 && prev >= self.max_sessions {
            self.active.fetch_sub(1, Ordering::AcqRel);
            crate::prometheus::record_limit_hit("session_cap", "session_registration_rejected");
            return false;
        }
        self.activity.insert(
            id,
            SessionMeta {
                created_at: now,
                last_active: now,
            },
        );
        crate::prometheus::increment_active_sessions();
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
        let _ = self.unregister_inner(id);
    }

    fn unregister_inner(&self, id: &SessionId) -> bool {
        let removed = self.activity.remove(id).is_some();
        if removed {
            self.active.fetch_sub(1, Ordering::AcqRel);
            crate::prometheus::decrement_active_sessions();
        }
        let mut state = self.token_state();
        if let Some(token) = state.sessions.remove(id) {
            Self::decrement_token(&mut state, &token);
        } else if state.created_unbound.remove(id) {
            state.closed_before_bind.insert(id.clone());
        }
        removed
    }

    /// Session IDs that exceed the idle timeout or max lifetime as of `now`.
    pub fn reap(&self, now: Instant) -> Vec<SessionId> {
        self.reap_with_reasons(now)
            .into_iter()
            .map(|expired| expired.id)
            .collect()
    }

    fn reap_with_reasons(&self, now: Instant) -> Vec<ExpiredSession> {
        let mut expired = Vec::new();
        for entry in self.activity.iter() {
            let meta = entry.value();
            let idle = self
                .idle_timeout
                .is_some_and(|timeout| now.duration_since(meta.last_active) >= timeout);
            let lifetime = self
                .max_lifetime
                .is_some_and(|timeout| now.duration_since(meta.created_at) >= timeout);
            let reason = if lifetime {
                Some(ReapReason::Lifetime)
            } else if idle {
                Some(ReapReason::Idle)
            } else {
                None
            };
            if let Some(reason) = reason {
                expired.push(ExpiredSession {
                    id: entry.key().clone(),
                    reason,
                });
            }
        }
        expired
    }
}

/// Interval between reaper sweeps.
const REAP_PERIOD: Duration = Duration::from_secs(30);

fn finish_reap(tracker: &SessionTracker, expired: ExpiredSession) {
    if tracker.unregister_inner(&expired.id) {
        crate::prometheus::record_session_reaped(expired.reason.as_str());
        tracing::info!(session_id = %expired.id, "session reaped");
    }
}

/// Error returned by [`LimitedSessionManager`].
#[derive(Debug)]
pub enum LimitedSessionManagerError<E> {
    /// An error returned by the wrapped session manager.
    Inner(E),
    /// A newly created session lost the atomic global-cap race.
    SessionCapExceeded,
}

impl<E: Display> Display for LimitedSessionManagerError<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inner(error) => Display::fmt(error, f),
            Self::SessionCapExceeded => f.write_str("global session capacity exceeded"),
        }
    }
}

impl<E> std::error::Error for LimitedSessionManagerError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inner(error) => Some(error),
            Self::SessionCapExceeded => None,
        }
    }
}

tokio::task_local! {
    static SESSION_CAP_REJECTED: Cell<bool>;
}

pub(crate) async fn scope_session_cap_rejection<F>(future: F) -> (F::Output, bool)
where
    F: Future,
{
    SESSION_CAP_REJECTED
        .scope(Cell::new(false), async move {
            let output = future.await;
            (output, SESSION_CAP_REJECTED.with(Cell::get))
        })
        .await
}

pub(crate) fn mark_session_cap_rejected() {
    let _ = SESSION_CAP_REJECTED.try_with(|rejected| rejected.set(true));
}

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
                    for expired in tracker.reap_with_reasons(Instant::now()) {
                        let _ = inner.close_session(&expired.id).await;
                        finish_reap(&tracker, expired);
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
    type Error = LimitedSessionManagerError<S::Error>;
    type Transport = S::Transport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        let (id, transport) = self
            .inner
            .create_session()
            .await
            .map_err(LimitedSessionManagerError::Inner)?;
        self.tracker.note_session_created(&id);
        if self.tracker.try_register(id.clone(), Instant::now()) {
            return Ok((id, transport));
        }

        drop(transport);
        self.tracker.unregister(&id);
        let inner = self.inner.clone();
        let cleanup_id = id.clone();
        let cleanup = tokio::spawn(async move { inner.close_session(&cleanup_id).await });
        match cleanup.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(
                    session_id = %id,
                    error = %error,
                    "rejected session cleanup failed"
                );
            }
            Err(error) => {
                tracing::warn!(
                    session_id = %id,
                    error = %error,
                    "rejected session cleanup task failed"
                );
            }
        }
        tracing::warn!(
            limit = "session_cap",
            session_id = %id,
            "session creation rejected after atomic registration"
        );
        mark_session_cap_rejected();
        Err(LimitedSessionManagerError::SessionCapExceeded)
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner
            .initialize_session(id, message)
            .await
            .map_err(LimitedSessionManagerError::Inner)
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner
            .has_session(id)
            .await
            .map_err(LimitedSessionManagerError::Inner)
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        let r = self.inner.close_session(id).await;
        self.tracker.unregister(id);
        r.map_err(LimitedSessionManagerError::Inner)
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner
            .create_stream(id, message)
            .await
            .map_err(LimitedSessionManagerError::Inner)
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner
            .accept_message(id, message)
            .await
            .map_err(LimitedSessionManagerError::Inner)
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner
            .create_standalone_stream(id)
            .await
            .map_err(LimitedSessionManagerError::Inner)
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.tracker.touch(id, Instant::now());
        self.inner
            .resume(id, last_event_id)
            .await
            .map_err(LimitedSessionManagerError::Inner)
    }

    async fn restore_session(
        &self,
        id: SessionId,
    ) -> Result<RestoreOutcome<Self::Transport>, Self::Error> {
        let outcome = self
            .inner
            .restore_session(id.clone())
            .await
            .map_err(LimitedSessionManagerError::Inner)?;
        if matches!(outcome, RestoreOutcome::Restored(_)) {
            self.tracker.try_register(id, Instant::now());
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::transport::Transport;
    use rmcp::RoleServer;
    use std::convert::Infallible;
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Barrier;
    use std::thread;
    use std::time::{Duration, Instant};
    use tokio::sync::{Barrier as AsyncBarrier, Notify};
    use tokio::time::timeout;

    const ASYNC_TEST_TIMEOUT: Duration = Duration::from_secs(1);

    fn id(s: &str) -> SessionId {
        Arc::from(s)
    }

    #[derive(Debug)]
    struct TestTransport;

    impl Transport<RoleServer> for TestTransport {
        type Error = Infallible;

        fn send(
            &mut self,
            _item: ServerJsonRpcMessage,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
            futures::future::ready(Ok(()))
        }

        fn receive(&mut self) -> impl Future<Output = Option<ClientJsonRpcMessage>> + Send {
            futures::future::ready(None)
        }

        fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
            futures::future::ready(Ok(()))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestManagerError(&'static str);

    impl std::fmt::Display for TestManagerError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for TestManagerError {}

    struct TestSessionState {
        next_id: AtomicUsize,
        live: Mutex<HashSet<SessionId>>,
        closed: Mutex<Vec<SessionId>>,
        create_barrier: Option<Arc<AsyncBarrier>>,
        close_started: Notify,
        close_release: Notify,
        block_close: AtomicBool,
        fail_close: AtomicBool,
        fail_create: AtomicBool,
        fail_has_session: AtomicBool,
    }

    #[derive(Clone)]
    struct TestSessionManager {
        state: Arc<TestSessionState>,
    }

    impl TestSessionManager {
        fn new(create_barrier: Option<Arc<AsyncBarrier>>) -> Self {
            Self {
                state: Arc::new(TestSessionState {
                    next_id: AtomicUsize::new(0),
                    live: Mutex::new(HashSet::new()),
                    closed: Mutex::new(Vec::new()),
                    create_barrier,
                    close_started: Notify::new(),
                    close_release: Notify::new(),
                    block_close: AtomicBool::new(false),
                    fail_close: AtomicBool::new(false),
                    fail_create: AtomicBool::new(false),
                    fail_has_session: AtomicBool::new(false),
                }),
            }
        }

        fn live_ids(&self) -> HashSet<SessionId> {
            self.state
                .live
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        fn closed_ids(&self) -> Vec<SessionId> {
            self.state
                .closed
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        fn set_block_close(&self, enabled: bool) {
            self.state.block_close.store(enabled, Ordering::SeqCst);
        }

        fn set_fail_close(&self, enabled: bool) {
            self.state.fail_close.store(enabled, Ordering::SeqCst);
        }

        fn set_fail_create(&self, enabled: bool) {
            self.state.fail_create.store(enabled, Ordering::SeqCst);
        }

        fn set_fail_has_session(&self, enabled: bool) {
            self.state.fail_has_session.store(enabled, Ordering::SeqCst);
        }

        async fn wait_for_close_start(&self) {
            self.state.close_started.notified().await;
        }

        fn release_close(&self) {
            self.state.close_release.notify_one();
        }
    }

    impl SessionManager for TestSessionManager {
        type Error = TestManagerError;
        type Transport = TestTransport;

        async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
            if self.state.fail_create.load(Ordering::SeqCst) {
                return Err(TestManagerError("create failed"));
            }
            let sequence = self.state.next_id.fetch_add(1, Ordering::SeqCst);
            let session_id: SessionId = Arc::from(format!("test-session-{sequence}"));
            self.state
                .live
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(session_id.clone());
            if let Some(barrier) = &self.state.create_barrier {
                barrier.wait().await;
            }
            Ok((session_id, TestTransport))
        }

        async fn initialize_session(
            &self,
            _id: &SessionId,
            _message: ClientJsonRpcMessage,
        ) -> Result<ServerJsonRpcMessage, Self::Error> {
            Err(TestManagerError("unused test operation"))
        }

        async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
            if self.state.fail_has_session.load(Ordering::SeqCst) {
                return Err(TestManagerError("has failed"));
            }
            Ok(self
                .state
                .live
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains(id))
        }

        async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
            self.state.close_started.notify_one();
            if self.state.block_close.load(Ordering::SeqCst) {
                self.state.close_release.notified().await;
            }
            let removed = self
                .state
                .live
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(id);
            if removed {
                self.state
                    .closed
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(id.clone());
            }
            if self.state.fail_close.load(Ordering::SeqCst) {
                Err(TestManagerError("close failed"))
            } else {
                Ok(())
            }
        }

        async fn create_stream(
            &self,
            _id: &SessionId,
            _message: ClientJsonRpcMessage,
        ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error>
        {
            Result::<futures::stream::Empty<ServerSseMessage>, _>::Err(TestManagerError(
                "unused test operation",
            ))
        }

        async fn accept_message(
            &self,
            _id: &SessionId,
            _message: ClientJsonRpcMessage,
        ) -> Result<(), Self::Error> {
            Err(TestManagerError("unused test operation"))
        }

        async fn create_standalone_stream(
            &self,
            _id: &SessionId,
        ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error>
        {
            Result::<futures::stream::Empty<ServerSseMessage>, _>::Err(TestManagerError(
                "unused test operation",
            ))
        }

        async fn resume(
            &self,
            _id: &SessionId,
            _last_event_id: String,
        ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error>
        {
            Result::<futures::stream::Empty<ServerSseMessage>, _>::Err(TestManagerError(
                "unused test operation",
            ))
        }

        async fn restore_session(
            &self,
            _id: SessionId,
        ) -> Result<RestoreOutcome<Self::Transport>, Self::Error> {
            Ok(RestoreOutcome::NotSupported)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn limited_manager_concurrent_create_admits_one_and_closes_every_loser() {
        const CREATE_COUNT: usize = 4;
        let fake = TestSessionManager::new(Some(Arc::new(AsyncBarrier::new(CREATE_COUNT))));
        let manager = LimitedSessionManager::new(
            fake.clone(),
            &LimitsConfig {
                max_sessions: 1,
                ..Default::default()
            },
        );
        let mut tasks = Vec::with_capacity(CREATE_COUNT);
        for _ in 0..CREATE_COUNT {
            let manager = manager.clone();
            tasks.push(tokio::spawn(async move { manager.create_session().await }));
        }

        let mut winner_ids = HashSet::new();
        let mut capacity_errors = 0;
        for task in tasks {
            match timeout(ASYNC_TEST_TIMEOUT, task)
                .await
                .expect("concurrent create timed out")
                .expect("concurrent create task panicked")
            {
                Ok((session_id, _transport)) => {
                    assert!(winner_ids.insert(session_id));
                }
                Err(LimitedSessionManagerError::SessionCapExceeded) => capacity_errors += 1,
                Err(error) => panic!("unexpected manager error: {error}"),
            }
        }

        assert_eq!(winner_ids.len(), 1);
        assert_eq!(capacity_errors, CREATE_COUNT - 1);
        assert_eq!(manager.tracker().active(), 1);
        assert_eq!(fake.live_ids(), winner_ids);
        let closed_ids = fake.closed_ids();
        assert_eq!(closed_ids.len(), CREATE_COUNT - 1);
        assert_eq!(closed_ids.iter().cloned().collect::<HashSet<_>>().len(), 3);
        assert!(closed_ids
            .iter()
            .all(|session_id| !fake.live_ids().contains(session_id)));

        let winner_id = winner_ids.into_iter().next().unwrap();
        manager.close_session(&winner_id).await.unwrap();
        assert_eq!(manager.tracker().active(), 0);
        assert!(fake.live_ids().is_empty());
    }

    #[tokio::test]
    async fn limited_manager_cleanup_error_still_returns_capacity_and_removes_loser() {
        let fake = TestSessionManager::new(None);
        let manager = LimitedSessionManager::new(
            fake.clone(),
            &LimitsConfig {
                max_sessions: 1,
                ..Default::default()
            },
        );
        let (winner_id, _transport) = manager.create_session().await.unwrap();
        fake.set_fail_close(true);

        let (result, rejected) = scope_session_cap_rejection(manager.create_session()).await;
        assert!(rejected);
        assert!(matches!(
            result,
            Err(LimitedSessionManagerError::SessionCapExceeded)
        ));
        assert_eq!(manager.tracker().active(), 1);
        assert_eq!(fake.live_ids(), HashSet::from([winner_id.clone()]));
        assert_eq!(fake.closed_ids().len(), 1);

        fake.set_fail_close(false);
        manager.close_session(&winner_id).await.unwrap();
        assert_eq!(manager.tracker().active(), 0);
        assert!(fake.live_ids().is_empty());
    }

    #[tokio::test]
    async fn limited_manager_rejected_cleanup_survives_outer_cancellation() {
        let fake = TestSessionManager::new(None);
        let manager = LimitedSessionManager::new(
            fake.clone(),
            &LimitsConfig {
                max_sessions: 1,
                ..Default::default()
            },
        );
        let (winner_id, _transport) = manager.create_session().await.unwrap();
        fake.set_block_close(true);

        let losing_manager = manager.clone();
        let losing_create = tokio::spawn(async move { losing_manager.create_session().await });
        timeout(ASYNC_TEST_TIMEOUT, fake.wait_for_close_start())
            .await
            .expect("rejected cleanup did not start");
        losing_create.abort();
        let cancelled = timeout(ASYNC_TEST_TIMEOUT, losing_create)
            .await
            .expect("aborted create task did not finish")
            .expect_err("aborted create unexpectedly completed");
        assert!(cancelled.is_cancelled());

        fake.release_close();
        timeout(ASYNC_TEST_TIMEOUT, async {
            loop {
                if fake.live_ids() == HashSet::from([winner_id.clone()])
                    && fake.closed_ids().len() == 1
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached rejected-session cleanup did not finish");

        fake.set_block_close(false);
        manager.close_session(&winner_id).await.unwrap();
        assert_eq!(manager.tracker().active(), 0);
        assert!(fake.live_ids().is_empty());
    }

    #[tokio::test]
    async fn limited_manager_wraps_inner_create_and_delegated_errors() {
        let fake = TestSessionManager::new(None);
        fake.set_fail_create(true);
        let manager = LimitedSessionManager::new(fake.clone(), &LimitsConfig::default());

        let create_error = manager.create_session().await.unwrap_err();
        assert!(matches!(
            &create_error,
            LimitedSessionManagerError::Inner(TestManagerError("create failed"))
        ));
        assert_eq!(
            std::error::Error::source(&create_error)
                .expect("inner create error source")
                .to_string(),
            "create failed"
        );

        fake.set_fail_create(false);
        fake.set_fail_has_session(true);
        let has_error = manager.has_session(&id("missing")).await.unwrap_err();
        assert!(matches!(
            &has_error,
            LimitedSessionManagerError::Inner(TestManagerError("has failed"))
        ));

        mark_session_cap_rejected();
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
    fn session_metrics_cover_active_cap_and_reap_reasons() {
        let (recorder, handle) = crate::prometheus::test_recorder("junos");
        metrics::with_local_recorder(&recorder, || {
            let base = Instant::now();

            let capped = SessionTracker::new(&LimitsConfig {
                max_sessions: 1,
                ..Default::default()
            });
            assert!(capped.try_register(id("tracked"), base));
            assert!(!capped.try_register(id("race-loser"), base));
            capped.unregister(&id("tracked"));
            capped.unregister(&id("tracked"));

            let idle = SessionTracker::new(&LimitsConfig {
                max_sessions: 10,
                session_idle_timeout_secs: 60,
                session_max_lifetime_secs: 3600,
                ..Default::default()
            });
            assert!(idle.try_register(id("idle"), base));
            let expired = idle.reap_with_reasons(base + Duration::from_secs(120));
            assert_eq!(expired[0].reason, ReapReason::Idle);
            finish_reap(&idle, expired.into_iter().next().unwrap());

            let lifetime = SessionTracker::new(&LimitsConfig {
                max_sessions: 10,
                session_idle_timeout_secs: 60,
                session_max_lifetime_secs: 60,
                ..Default::default()
            });
            assert!(lifetime.try_register(id("both"), base));
            let expired = lifetime.reap_with_reasons(base + Duration::from_secs(120));
            assert_eq!(expired[0].reason, ReapReason::Lifetime);
            finish_reap(&lifetime, expired.into_iter().next().unwrap());
        });

        handle.run_upkeep();
        let text = handle.render();
        let active = text
            .lines()
            .find(|line| line.starts_with("junosmcp_active_sessions{"))
            .expect("active-session gauge");
        assert!(active.ends_with(" 0"));
        assert!(text.lines().any(|line| {
            line.starts_with("junosmcp_limit_hits_total{")
                && line.contains("limit=\"session_cap\"")
                && line.contains("event=\"session_registration_rejected\"")
                && line.ends_with(" 1")
        }));
        assert!(text.lines().any(|line| {
            line.starts_with("junosmcp_sessions_reaped_total{")
                && line.contains("reason=\"idle\"")
                && line.ends_with(" 1")
        }));
        assert!(text.lines().any(|line| {
            line.starts_with("junosmcp_sessions_reaped_total{")
                && line.contains("reason=\"lifetime\"")
                && line.ends_with(" 1")
        }));
    }

    #[test]
    fn reaper_finalizer_does_not_count_session_removed_by_explicit_close() {
        let (recorder, handle) = crate::prometheus::test_recorder("junos");
        metrics::with_local_recorder(&recorder, || {
            let base = Instant::now();
            let tracker = SessionTracker::new(&LimitsConfig {
                max_sessions: 10,
                session_idle_timeout_secs: 60,
                ..Default::default()
            });
            let session = id("concurrently-closed");
            assert!(tracker.try_register(session.clone(), base));

            let mut expired = tracker.reap_with_reasons(base + Duration::from_secs(120));
            assert_eq!(expired.len(), 1);
            let expired = expired.pop().unwrap();

            tracker.unregister(&session);
            assert_eq!(tracker.active(), 0);
            finish_reap(&tracker, expired);
            assert_eq!(tracker.active(), 0);
        });

        handle.run_upkeep();
        let text = handle.render();
        let active = text
            .lines()
            .find(|line| line.starts_with("junosmcp_active_sessions{"))
            .expect("active-session gauge");
        assert!(active.ends_with(" 0"));
        assert!(
            !text
                .lines()
                .any(|line| line.starts_with("junosmcp_sessions_reaped_total{")),
            "unexpected reaper counter in:\n{text}"
        );
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
        assert_eq!(tracker.pending_reservation_count(), 2);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 0);
        let created_open = id("created-open");
        let created_closed = id("created-closed");
        tracker.note_session_created(&created_open);
        tracker.note_session_created(&created_closed);
        assert_eq!(tracker.created_unbound_len(), 2);
        tracker.unregister(&created_closed);
        tracker.unregister(&created_closed);
        assert_eq!(tracker.created_unbound_len(), 1);
        assert_eq!(tracker.closed_before_bind_len(), 1);
        drop(alice);
        assert_eq!(tracker.pending_reservation_count(), 1);
        assert_eq!(tracker.created_unbound_len(), 1);
        assert_eq!(tracker.closed_before_bind_len(), 1);
        drop(bob);
        assert_eq!(tracker.active_for_token("alice"), 0);
        assert_eq!(tracker.active_for_token("bob"), 0);
        assert_eq!(tracker.token_population_len(), 0);
        assert_eq!(tracker.pending_reservation_count(), 0);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 0);
    }

    #[test]
    fn arbitrary_unregister_ids_do_not_grow_pending_coordination() {
        let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
            max_sessions_per_token: 1,
            ..Default::default()
        }));
        let reservation = tracker
            .try_reserve_token("alice".to_owned())
            .unwrap()
            .unwrap();

        for index in 0..10_000 {
            tracker.unregister(&id(&format!("arbitrary-{index}")));
        }

        assert_eq!(tracker.pending_reservation_count(), 1);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 0);
        drop(reservation);
        assert_eq!(tracker.active_for_token("alice"), 0);
        assert_eq!(tracker.pending_reservation_count(), 0);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 0);
    }

    #[test]
    fn created_session_hook_moves_to_closed_before_bind_once() {
        let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
            max_sessions_per_token: 1,
            ..Default::default()
        }));
        let session = id("created-then-closed");
        let reservation = tracker
            .try_reserve_token("alice".to_owned())
            .unwrap()
            .unwrap();

        tracker.note_session_created(&session);
        assert_eq!(tracker.created_unbound_len(), 1);
        assert_eq!(tracker.closed_before_bind_len(), 0);

        tracker.unregister(&session);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 1);
        tracker.unregister(&session);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 1);

        assert!(!reservation.commit(session));
        assert_eq!(tracker.active_for_token("alice"), 0);
        assert_eq!(tracker.pending_reservation_count(), 0);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 0);
    }

    #[test]
    fn unrecorded_response_session_does_not_bind() {
        let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
            max_sessions_per_token: 1,
            ..Default::default()
        }));
        let reservation = tracker
            .try_reserve_token("alice".to_owned())
            .unwrap()
            .unwrap();

        assert!(!reservation.commit(id("unrecorded-response")));
        assert_eq!(tracker.active_for_token("alice"), 0);
        assert_eq!(tracker.token_population_len(), 0);
        assert_eq!(tracker.token_binding_len(), 0);
        assert_eq!(tracker.pending_reservation_count(), 0);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 0);
    }

    #[test]
    fn committed_token_reservation_releases_on_unregister_once() {
        let tracker = Arc::new(SessionTracker::new(&LimitsConfig {
            max_sessions_per_token: 1,
            ..Default::default()
        }));
        let session = id("session-a");
        let reservation = tracker
            .try_reserve_token("alice".to_owned())
            .unwrap()
            .unwrap();
        tracker.note_session_created(&session);
        assert!(tracker.try_register(session.clone(), Instant::now()));
        assert_eq!(tracker.pending_reservation_count(), 1);
        assert_eq!(tracker.created_unbound_len(), 1);
        assert!(reservation.commit(session.clone()));
        assert_eq!(tracker.active_for_token("alice"), 1);
        assert_eq!(tracker.pending_reservation_count(), 0);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 0);
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
        let first = tracker
            .try_reserve_token("alice".to_owned())
            .unwrap()
            .unwrap();
        tracker.note_session_created(&session);
        assert!(tracker.try_register(session.clone(), Instant::now()));
        assert!(first.commit(session.clone()));
        assert!(!tracker
            .try_reserve_token("bob".to_owned())
            .unwrap()
            .unwrap()
            .commit(session.clone()));
        assert_eq!(tracker.active_for_token("alice"), 1);
        assert_eq!(tracker.active_for_token("bob"), 0);
        assert_eq!(tracker.pending_reservation_count(), 0);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 0);
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
        let reservation = tracker
            .try_reserve_token("alice".to_owned())
            .unwrap()
            .unwrap();
        tracker.note_session_created(&session);
        assert!(tracker.try_register(session.clone(), Instant::now()));

        tracker.unregister(&session);
        assert_eq!(tracker.pending_reservation_count(), 1);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 1);

        assert!(!reservation.commit(session));
        assert_eq!(tracker.active(), 0);
        assert_eq!(tracker.active_for_token("alice"), 0);
        assert_eq!(tracker.token_population_len(), 0);
        assert_eq!(tracker.token_binding_len(), 0);
        assert_eq!(tracker.pending_reservation_count(), 0);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 0);
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
        let reservation = tracker
            .try_reserve_token("alice".to_owned())
            .unwrap()
            .unwrap();
        tracker.note_session_created(&session);
        assert!(tracker.try_register(session.clone(), base));

        let expired = tracker.reap(base + Duration::from_secs(2));
        assert_eq!(expired, vec![session.clone()]);
        for expired_session in expired {
            tracker.unregister(&expired_session);
        }
        assert_eq!(tracker.pending_reservation_count(), 1);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 1);

        assert!(!reservation.commit(session));
        assert_eq!(tracker.active(), 0);
        assert_eq!(tracker.active_for_token("alice"), 0);
        assert_eq!(tracker.token_population_len(), 0);
        assert_eq!(tracker.token_binding_len(), 0);
        assert_eq!(tracker.pending_reservation_count(), 0);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 0);
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
        assert_eq!(tracker.pending_reservation_count(), CAP);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 0);
        release.wait();

        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(tracker.active_for_token("alice"), 0);
        assert_eq!(tracker.token_population_len(), 0);
        assert_eq!(tracker.token_binding_len(), 0);
        assert_eq!(tracker.pending_reservation_count(), 0);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 0);
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
        let disabled = id("disabled-created");
        tracker.note_session_created(&disabled);
        tracker.unregister(&disabled);
        assert_eq!(tracker.token_population_len(), 0);
        assert_eq!(tracker.token_binding_len(), 0);
        assert_eq!(tracker.pending_reservation_count(), 0);
        assert_eq!(tracker.created_unbound_len(), 0);
        assert_eq!(tracker.closed_before_bind_len(), 0);

        let enabled = Arc::new(SessionTracker::new(&LimitsConfig {
            max_sessions_per_token: 1,
            ..Default::default()
        }));
        let no_pending = id("no-pending-created");
        enabled.note_session_created(&no_pending);
        enabled.unregister(&no_pending);
        assert_eq!(enabled.pending_reservation_count(), 0);
        assert_eq!(enabled.created_unbound_len(), 0);
        assert_eq!(enabled.closed_before_bind_len(), 0);
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
        let reservation = tracker
            .try_reserve_token("alice".to_owned())
            .unwrap()
            .unwrap();
        tracker.note_session_created(&session);
        assert!(tracker.try_register(session.clone(), base));
        assert!(reservation.commit(session.clone()));
        for expired in tracker.reap(base + Duration::from_secs(2)) {
            tracker.unregister(&expired);
        }
        assert_eq!(tracker.active_for_token("alice"), 0);
        assert_eq!(tracker.active(), 0);
    }
}
