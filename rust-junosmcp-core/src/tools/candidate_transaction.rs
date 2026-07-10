//! Shared candidate configuration transaction lifecycle.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use async_trait::async_trait;
use rustez::{ConfigManager, ConfigPayload};
use std::future::Future;
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub(crate) enum CandidateMode {
    DryRun,
    CommitCheck,
    CommitWithComment(String),
    CommitConfirmed(u32),
    Discard,
}

#[derive(Debug)]
pub(crate) struct CandidateRequest {
    pub(crate) payload: Option<ConfigPayload>,
    pub(crate) mode: CandidateMode,
}

#[derive(Debug)]
pub(crate) enum CandidateResult {
    DryRun { diff: String },
    CommitCheck { diff: String, error: Option<String> },
    Committed { diff: String },
    CommitFailed { diff: String, error: String },
    Discarded,
}

#[async_trait]
trait CandidateBackend {
    async fn lock(&mut self) -> Result<(), JmcpError>;
    async fn load(&mut self, payload: ConfigPayload) -> Result<(), JmcpError>;
    async fn diff(&mut self) -> Result<String, JmcpError>;
    async fn commit_check(&mut self) -> Result<(), JmcpError>;
    async fn commit_with_comment(&mut self, comment: &str) -> Result<(), JmcpError>;
    async fn commit_confirmed(&mut self, seconds: u32) -> Result<(), JmcpError>;
    async fn rollback(&mut self) -> Result<(), JmcpError>;
    async fn unlock(&mut self) -> Result<(), JmcpError>;
}

#[async_trait]
impl CandidateBackend for ConfigManager<'_> {
    async fn lock(&mut self) -> Result<(), JmcpError> {
        ConfigManager::lock(self).await.map_err(Into::into)
    }

    async fn load(&mut self, payload: ConfigPayload) -> Result<(), JmcpError> {
        ConfigManager::load(self, payload)
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    async fn diff(&mut self) -> Result<String, JmcpError> {
        ConfigManager::diff(self)
            .await
            .map(|diff| diff.unwrap_or_default())
            .map_err(Into::into)
    }

    async fn commit_check(&mut self) -> Result<(), JmcpError> {
        ConfigManager::commit_check(self).await.map_err(Into::into)
    }

    async fn commit_with_comment(&mut self, comment: &str) -> Result<(), JmcpError> {
        ConfigManager::commit_with_comment(self, comment)
            .await
            .map_err(Into::into)
    }

    async fn commit_confirmed(&mut self, seconds: u32) -> Result<(), JmcpError> {
        ConfigManager::commit_confirmed(self, seconds)
            .await
            .map_err(Into::into)
    }

    async fn rollback(&mut self) -> Result<(), JmcpError> {
        ConfigManager::rollback(self, 0).await.map_err(Into::into)
    }

    async fn unlock(&mut self) -> Result<(), JmcpError> {
        ConfigManager::unlock(self).await.map_err(Into::into)
    }
}

struct Execution {
    result: Result<CandidateResult, JmcpError>,
    reusable: bool,
}

#[derive(Default)]
struct CleanupFailures {
    rollback: Option<String>,
    unlock: Option<String>,
}

impl CleanupFailures {
    fn is_empty(&self) -> bool {
        self.rollback.is_none() && self.unlock.is_none()
    }
}

/// Open a device and run one complete candidate transaction. The session starts
/// tainted and is made reusable only after all required cleanup succeeds.
pub(crate) async fn run(
    dm: &DeviceManager,
    router: &str,
    request: CandidateRequest,
    timeout: Duration,
    ct: &CancellationToken,
) -> Result<CandidateResult, JmcpError> {
    let deadline = Instant::now() + timeout;
    let mut dev = run_step(deadline, timeout, ct, dm.open(router)).await?;
    dev.prevent_reuse();

    let execution = {
        let mut cfg = dev.config()?;
        execute(&mut cfg, request, deadline, timeout, CLEANUP_TIMEOUT, ct).await
    };

    if execution.reusable {
        dev.allow_reuse();
    } else {
        // close() takes ownership of the underlying client on its first poll,
        // so even a close-session timeout drops the transport and releases any
        // remote candidate lock before a later request opens a new session.
        match tokio::time::timeout(CLEANUP_TIMEOUT, dev.close()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(router, error = %error, "failed to close tainted NETCONF session")
            }
            Err(_) => tracing::warn!(router, "timed out closing tainted NETCONF session"),
        }
    }
    execution.result
}

async fn execute<B: CandidateBackend>(
    backend: &mut B,
    request: CandidateRequest,
    deadline: Instant,
    operation_timeout: Duration,
    cleanup_timeout: Duration,
    ct: &CancellationToken,
) -> Execution {
    let lock = run_step(deadline, operation_timeout, ct, backend.lock()).await;
    if let Err(primary) = lock {
        if matches!(primary, JmcpError::Cancelled | JmcpError::Timeout(_)) {
            // The lock RPC was dropped with an unknown remote outcome. Try the
            // full invariant, then close the uncertain protocol session.
            let cleanup = cleanup(backend, true, cleanup_timeout).await;
            return Execution {
                result: combine(Err(primary), cleanup, None),
                reusable: false,
            };
        }
        return Execution {
            result: Err(primary),
            // Lock errors can include a lost response after the device took
            // the lock. Close this session instead of making that assumption.
            reusable: false,
        };
    }

    let mut committed = false;
    let outcome = primary_operation(
        backend,
        request,
        deadline,
        operation_timeout,
        ct,
        &mut committed,
    )
    .await;
    let reported_primary = match &outcome {
        Ok(CandidateResult::Committed { .. }) => Some("commit succeeded".into()),
        Ok(CandidateResult::CommitCheck {
            error: Some(error), ..
        })
        | Ok(CandidateResult::CommitFailed { error, .. }) => Some(error.clone()),
        _ => None,
    };
    let primary_rpc_was_dropped =
        matches!(&outcome, Err(JmcpError::Cancelled | JmcpError::Timeout(_)));
    let cleanup = cleanup(backend, !committed, cleanup_timeout).await;
    let reusable = cleanup.is_empty() && !primary_rpc_was_dropped;

    Execution {
        result: combine(outcome, cleanup, reported_primary),
        reusable,
    }
}

async fn primary_operation<B: CandidateBackend>(
    backend: &mut B,
    request: CandidateRequest,
    deadline: Instant,
    operation_timeout: Duration,
    ct: &CancellationToken,
    committed: &mut bool,
) -> Result<CandidateResult, JmcpError> {
    if matches!(request.mode, CandidateMode::Discard) {
        return Ok(CandidateResult::Discarded);
    }

    let payload = request.payload.ok_or_else(|| {
        JmcpError::Validation("candidate transaction requires a configuration payload".into())
    })?;
    run_step(deadline, operation_timeout, ct, backend.load(payload)).await?;
    let diff = run_step(deadline, operation_timeout, ct, backend.diff()).await?;

    match request.mode {
        CandidateMode::DryRun => Ok(CandidateResult::DryRun { diff }),
        CandidateMode::CommitCheck => {
            let error =
                match run_step(deadline, operation_timeout, ct, backend.commit_check()).await {
                    Ok(()) => None,
                    Err(error @ (JmcpError::Cancelled | JmcpError::Timeout(_))) => {
                        return Err(error);
                    }
                    Err(error) => Some(error.to_string()),
                };
            Ok(CandidateResult::CommitCheck { diff, error })
        }
        CandidateMode::CommitWithComment(comment) => {
            ensure_active(deadline, operation_timeout, ct)?;
            // A sent commit must reach a known result. Cancellation and the
            // outer deadline are deliberately not allowed to drop this RPC.
            match backend.commit_with_comment(&comment).await {
                Ok(()) => {
                    *committed = true;
                    Ok(CandidateResult::Committed { diff })
                }
                Err(error) => Ok(CandidateResult::CommitFailed {
                    diff,
                    error: error.to_string(),
                }),
            }
        }
        CandidateMode::CommitConfirmed(seconds) => {
            ensure_active(deadline, operation_timeout, ct)?;
            match backend.commit_confirmed(seconds).await {
                Ok(()) => {
                    *committed = true;
                    Ok(CandidateResult::Committed { diff })
                }
                Err(error) => Ok(CandidateResult::CommitFailed {
                    diff,
                    error: error.to_string(),
                }),
            }
        }
        CandidateMode::Discard => unreachable!("discard returned before payload handling"),
    }
}

async fn cleanup<B: CandidateBackend>(
    backend: &mut B,
    rollback_required: bool,
    timeout: Duration,
) -> CleanupFailures {
    let rollback = if rollback_required {
        cleanup_step(timeout, backend.rollback()).await.err()
    } else {
        None
    };
    // Unlock is attempted even when rollback fails or times out.
    let unlock = cleanup_step(timeout, backend.unlock()).await.err();
    CleanupFailures { rollback, unlock }
}

async fn cleanup_step<F>(timeout: Duration, future: F) -> Result<(), String>
where
    F: Future<Output = Result<(), JmcpError>>,
{
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result.map_err(|error| error.to_string()),
        Err(_) => Err(format!("cleanup timed out after {timeout:?}")),
    }
}

fn combine(
    outcome: Result<CandidateResult, JmcpError>,
    cleanup: CleanupFailures,
    reported_primary: Option<String>,
) -> Result<CandidateResult, JmcpError> {
    if cleanup.is_empty() {
        return outcome;
    }

    let primary = match &outcome {
        Err(error) => error.to_string(),
        Ok(_) => reported_primary.unwrap_or_else(|| "none".into()),
    };
    Err(JmcpError::CandidateCleanupFailed {
        primary,
        rollback: cleanup.rollback.unwrap_or_else(|| "ok".into()),
        unlock: cleanup.unlock.unwrap_or_else(|| "ok".into()),
    })
}

fn ensure_active(
    deadline: Instant,
    operation_timeout: Duration,
    ct: &CancellationToken,
) -> Result<(), JmcpError> {
    if ct.is_cancelled() {
        return Err(JmcpError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(JmcpError::Timeout(operation_timeout));
    }
    Ok(())
}

async fn run_step<T, F>(
    deadline: Instant,
    operation_timeout: Duration,
    ct: &CancellationToken,
    future: F,
) -> Result<T, JmcpError>
where
    F: Future<Output = Result<T, JmcpError>>,
{
    ensure_active(deadline, operation_timeout, ct)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    tokio::select! {
        biased;
        _ = ct.cancelled() => Err(JmcpError::Cancelled),
        result = tokio::time::timeout(remaining, future) => {
            result.map_err(|_| JmcpError::Timeout(operation_timeout))?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    enum Op {
        Lock,
        Load,
        Diff,
        Check,
        Commit,
        Rollback,
        Unlock,
    }

    #[derive(Default)]
    struct DeviceState {
        locked: bool,
        dirty: bool,
        events: Vec<Op>,
    }

    struct FakeBackend {
        state: Arc<Mutex<DeviceState>>,
        failures: HashSet<Op>,
        hang: Option<Op>,
    }

    impl FakeBackend {
        fn new(state: Arc<Mutex<DeviceState>>) -> Self {
            Self {
                state,
                failures: HashSet::new(),
                hang: None,
            }
        }

        fn failing(mut self, operations: &[Op]) -> Self {
            self.failures.extend(operations.iter().copied());
            self
        }

        fn hanging(mut self, operation: Op) -> Self {
            self.hang = Some(operation);
            self
        }

        async fn operation(&mut self, operation: Op) -> Result<(), JmcpError> {
            self.state.lock().unwrap().events.push(operation);
            if self.hang == Some(operation) {
                std::future::pending::<()>().await;
            }
            if self.failures.contains(&operation) {
                return Err(JmcpError::Validation(format!(
                    "injected {operation:?} failure"
                )));
            }
            Ok(())
        }

        fn close_tainted_session(&mut self) {
            let mut state = self.state.lock().unwrap();
            state.locked = false;
            state.dirty = false;
        }
    }

    #[async_trait]
    impl CandidateBackend for FakeBackend {
        async fn lock(&mut self) -> Result<(), JmcpError> {
            self.operation(Op::Lock).await?;
            let mut state = self.state.lock().unwrap();
            if state.locked {
                return Err(JmcpError::Validation("candidate already locked".into()));
            }
            state.locked = true;
            Ok(())
        }

        async fn load(&mut self, _payload: ConfigPayload) -> Result<(), JmcpError> {
            // Model a partial load: even a failed load can dirty candidate state.
            self.state.lock().unwrap().dirty = true;
            self.operation(Op::Load).await
        }

        async fn diff(&mut self) -> Result<String, JmcpError> {
            self.operation(Op::Diff).await?;
            Ok("fake diff".into())
        }

        async fn commit_check(&mut self) -> Result<(), JmcpError> {
            self.operation(Op::Check).await
        }

        async fn commit_with_comment(&mut self, _comment: &str) -> Result<(), JmcpError> {
            self.operation(Op::Commit).await?;
            self.state.lock().unwrap().dirty = false;
            Ok(())
        }

        async fn commit_confirmed(&mut self, _seconds: u32) -> Result<(), JmcpError> {
            self.commit_with_comment("").await
        }

        async fn rollback(&mut self) -> Result<(), JmcpError> {
            self.operation(Op::Rollback).await?;
            self.state.lock().unwrap().dirty = false;
            Ok(())
        }

        async fn unlock(&mut self) -> Result<(), JmcpError> {
            self.operation(Op::Unlock).await?;
            self.state.lock().unwrap().locked = false;
            Ok(())
        }
    }

    fn commit_request() -> CandidateRequest {
        CandidateRequest {
            payload: Some(ConfigPayload::Set("set system host-name test".into())),
            mode: CandidateMode::CommitWithComment("test".into()),
        }
    }

    fn check_request() -> CandidateRequest {
        CandidateRequest {
            payload: Some(ConfigPayload::Set("set system host-name test".into())),
            mode: CandidateMode::CommitCheck,
        }
    }

    fn dry_run_request() -> CandidateRequest {
        CandidateRequest {
            payload: Some(ConfigPayload::Set("set system host-name test".into())),
            mode: CandidateMode::DryRun,
        }
    }

    fn discard_request() -> CandidateRequest {
        CandidateRequest {
            payload: None,
            mode: CandidateMode::Discard,
        }
    }

    async fn run_fake(
        backend: &mut FakeBackend,
        request: CandidateRequest,
        timeout: Duration,
        cleanup_timeout: Duration,
        ct: &CancellationToken,
    ) -> Execution {
        execute(
            backend,
            request,
            Instant::now() + timeout,
            timeout,
            cleanup_timeout,
            ct,
        )
        .await
    }

    async fn assert_next_operation_can_lock(
        backend: &mut FakeBackend,
        execution: &Execution,
        state: Arc<Mutex<DeviceState>>,
    ) {
        if !execution.reusable {
            // Production does this by closing, rather than pooling, the tainted
            // PooledDevice. Closing a NETCONF session releases its lock.
            backend.close_tainted_session();
        }
        let mut next = FakeBackend::new(state);
        let result = run_fake(
            &mut next,
            discard_request(),
            Duration::from_secs(1),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;
        assert!(result.result.is_ok(), "next operation failed to lock");
    }

    #[tokio::test]
    async fn load_and_diff_failures_rollback_unlock_and_allow_next_lock() {
        for failed in [Op::Load, Op::Diff] {
            let state = Arc::new(Mutex::new(DeviceState::default()));
            let mut backend = FakeBackend::new(state.clone()).failing(&[failed]);
            let execution = run_fake(
                &mut backend,
                commit_request(),
                Duration::from_secs(1),
                Duration::from_millis(50),
                &CancellationToken::new(),
            )
            .await;

            assert!(execution.result.is_err());
            assert!(execution.reusable);
            let events = state.lock().unwrap().events.clone();
            assert!(events.ends_with(&[Op::Rollback, Op::Unlock]));
            assert_next_operation_can_lock(&mut backend, &execution, state.clone()).await;
        }
    }

    #[tokio::test]
    async fn check_failure_is_reported_after_cleanup_and_allows_next_lock() {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone()).failing(&[Op::Check]);
        let execution = run_fake(
            &mut backend,
            check_request(),
            Duration::from_secs(1),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;

        match &execution.result {
            Ok(CandidateResult::CommitCheck {
                error: Some(error), ..
            }) => assert!(error.contains("injected Check failure")),
            other => panic!("unexpected result: {other:?}"),
        }
        assert!(state
            .lock()
            .unwrap()
            .events
            .ends_with(&[Op::Rollback, Op::Unlock]));
        assert_next_operation_can_lock(&mut backend, &execution, state.clone()).await;
    }

    #[tokio::test]
    async fn commit_failure_preserves_primary_and_cleanup_failure() {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone()).failing(&[Op::Commit, Op::Rollback]);
        let execution = run_fake(
            &mut backend,
            commit_request(),
            Duration::from_secs(1),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;

        let error = execution.result.as_ref().unwrap_err().to_string();
        assert!(error.contains("primary=validation error: injected Commit failure"));
        assert!(error.contains("rollback=validation error: injected Rollback failure"));
        assert!(error.contains("unlock=ok"));
        assert!(!execution.reusable);
        assert_next_operation_can_lock(&mut backend, &execution, state.clone()).await;
    }

    #[tokio::test]
    async fn successful_commit_is_never_rolled_back_and_unlock_failure_is_an_error() {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone()).failing(&[Op::Unlock]);
        let execution = run_fake(
            &mut backend,
            commit_request(),
            Duration::from_secs(1),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;

        let error = execution.result.as_ref().unwrap_err().to_string();
        assert!(error.contains("primary=commit succeeded"));
        assert!(error.contains("unlock=validation error: injected Unlock failure"));
        assert!(!state.lock().unwrap().events.contains(&Op::Rollback));
        assert!(!execution.reusable);
        assert_next_operation_can_lock(&mut backend, &execution, state.clone()).await;
    }

    #[tokio::test]
    async fn rollback_timeout_still_attempts_unlock_and_taints_session() {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone()).hanging(Op::Rollback);
        let execution = run_fake(
            &mut backend,
            dry_run_request(),
            Duration::from_secs(1),
            Duration::from_millis(10),
            &CancellationToken::new(),
        )
        .await;

        let error = execution.result.as_ref().unwrap_err().to_string();
        assert!(error.contains("rollback=cleanup timed out"));
        assert!(state.lock().unwrap().events.contains(&Op::Unlock));
        assert!(!execution.reusable);
        assert_next_operation_can_lock(&mut backend, &execution, state.clone()).await;
    }

    #[tokio::test]
    async fn primary_timeout_rolls_back_unlocks_and_allows_next_lock() {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone()).hanging(Op::Diff);
        let execution = run_fake(
            &mut backend,
            commit_request(),
            Duration::from_millis(10),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;

        assert!(matches!(execution.result, Err(JmcpError::Timeout(_))));
        assert!(!execution.reusable);
        assert!(state
            .lock()
            .unwrap()
            .events
            .ends_with(&[Op::Rollback, Op::Unlock]));
        assert_next_operation_can_lock(&mut backend, &execution, state.clone()).await;
    }

    #[tokio::test]
    async fn cancellation_rolls_back_unlocks_and_allows_next_lock() {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone()).hanging(Op::Diff);
        let ct = CancellationToken::new();
        let cancel = ct.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel.cancel();
        });
        let execution = run_fake(
            &mut backend,
            commit_request(),
            Duration::from_secs(1),
            Duration::from_millis(50),
            &ct,
        )
        .await;

        assert!(matches!(execution.result, Err(JmcpError::Cancelled)));
        assert!(!execution.reusable);
        assert!(state
            .lock()
            .unwrap()
            .events
            .ends_with(&[Op::Rollback, Op::Unlock]));
        assert_next_operation_can_lock(&mut backend, &execution, state.clone()).await;
    }
}
