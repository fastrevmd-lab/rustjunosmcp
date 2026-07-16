# Strict Global Session Cap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `LimitedSessionManager::create_session` fail closed when concurrent initialization loses the atomic global-cap race, clean up the rejected inner session without cancellation leaks, and return the existing stable session-cap HTTP 503 from both binaries.

**Architecture:** The shared limits crate will wrap every inner manager error in a public generic error type and use a Tokio task-local rejection bit to bridge the one typed capacity error across rmcp's fixed HTTP-500 mapping. The manager remains the race-free authority: it atomically registers a just-created ID, spawns cleanup for a rejected ID, and returns `SessionCapExceeded`; the existing concurrency middleware scopes initialize requests and replaces only a marked rmcp response with `overload_response("session_cap")`.

**Tech Stack:** Rust 2021, Tokio task-local storage and tasks, rmcp 2.0 `SessionManager`, Axum 0.8 middleware, Cargo workspace tests, ureq binary HTTP tests, metrics 0.24, Trivy 0.70.

## Global Constraints

- Work only in `/home/mharman/Projects/RustJunosMCP/.worktrees/issue-151-session-cap-race` on branch `issue-151-session-cap-race`.
- Treat `SessionTracker::try_register` as the authoritative atomic global-cap gate; retain the middleware `at_capacity()` check as an unchanged fast path.
- A rejected inner session must be dropped, unregistered from pending token coordination, and passed to `inner.close_session` exactly once.
- Spawn the rejected-session cleanup before awaiting it so dropping the outer request future cannot abort cleanup.
- Return `SessionCapExceeded` even when cleanup returns an error or its task panics; log that diagnostic without exposing it to the client.
- Translate only a request whose task-local marker was set. Never inspect or parse rmcp's response body, and never rewrite an ordinary downstream 500.
- Preserve `max_sessions = 0`, per-token session behavior, early shedding, reaping, close semantics, non-cap errors, and all existing response contracts.
- Leave `restore_session`'s best-effort cap behavior unchanged because neither binary configures external session storage; wrap only its inner error type.
- Add no dependency and make no `Cargo.lock`, CLI, environment, configuration-default, MCP-schema, annotation, auth-scope, timeout, audit, device-I/O, or packaged-service change.
- Do not edit historical design or implementation-plan documents after implementation begins.
- Do not run ignored or real-device integration tests without `CONFIRM_LAB_INTEGRATION=yes`; issue #151 requires no device access.
- `just` is unavailable in this shell. Run the exact checked-in recipe commands directly and report that substitution at handoff.

## File and Responsibility Map

| File | Responsibility in this change |
| --- | --- |
| `rust-junosmcp-limits/src/session.rs` | Public wrapper error, request-local rejection helpers, strict race-loser cleanup, delegated error mapping, deterministic manager tests |
| `rust-junosmcp-limits/src/concurrency.rs` | Scope initialize requests, translate a marked rmcp response, preserve token accounting, concurrent response-isolation and metric test |
| `rust-junosmcp-limits/src/lib.rs` | Re-export `LimitedSessionManagerError` for direct Rust consumers |
| `rust-junosmcp/tests/common/mod.rs` | Capture `Retry-After` in Junos HTTP test results |
| `rust-srxmcp/tests/common/mod.rs` | Capture `Retry-After` in SRX HTTP test results |
| `rust-junosmcp/tests/http_limits.rs` | Junos public global-session-cap contract |
| `rust-srxmcp/tests/http_limits.rs` | SRX public global-session-cap contract |
| `README.md` | Strict global-cap behavior and stable response semantics |
| `docs/METRICS.md` | Explain manager-race and client-rejection event pairing |
| `CHANGELOG.md` | Junos release note under `Unreleased / Fixed` |
| `rust-srxmcp/CHANGELOG.md` | SRX release note under `Unreleased / Fixed` |

---

### Task 1: Make the session-manager wrapper a strict, cancellation-safe cap authority

**Files:**
- Modify: `rust-junosmcp-limits/src/session.rs:1-447`
- Modify: `rust-junosmcp-limits/src/session.rs:448-948`
- Modify: `rust-junosmcp-limits/src/lib.rs:14`

**Interfaces:**
- Produces: `LimitedSessionManagerError<E>`, `scope_session_cap_rejection`, `mark_session_cap_rejected`, and a strict `LimitedSessionManager<S>` implementation.
- Consumes: `SessionTracker::note_session_created`, `SessionTracker::try_register`, `SessionTracker::unregister`, and every existing `S: SessionManager` method.
- Invariant: after a manager call completes, only successful session IDs remain in the inner manager and tracker; a rejected ID is never returned to rmcp.

- [ ] **Step 1: Add deterministic fake-manager scaffolding in the existing session test module**

Extend the test imports with the exact test-only building blocks:

```rust
    use rmcp::transport::Transport;
    use rmcp::RoleServer;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::{Barrier as AsyncBarrier, Notify};
    use tokio::time::timeout;

    const ASYNC_TEST_TIMEOUT: Duration = Duration::from_secs(1);
```

Add a dependency-free fake transport and error. The transport is deliberately inert because these tests exercise manager ownership, not MCP message exchange:

```rust
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

        fn receive(
            &mut self,
        ) -> impl Future<Output = Option<ClientJsonRpcMessage>> + Send {
            futures::future::ready(None)
        }

        fn close(
            &mut self,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
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
```

Add `TestSessionManager`, backed by an `Arc<TestSessionState>`, with these exact fields and controls:

```rust
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
```

Implement test constructors and accessors for a manager with an optional create barrier, live-ID snapshot, closed-ID snapshot, and the four boolean controls. Implement all `SessionManager` methods rather than using a production seam:

- `create_session`: return `TestManagerError("create failed")` when configured; otherwise mint `test-session-{n}`, insert it into `live`, await the optional async barrier, and return `(id, TestTransport)`.
- `has_session`: return `TestManagerError("has failed")` when configured; otherwise test membership in `live`.
- `close_session`: notify `close_started`, await `close_release` when `block_close` is true, remove the ID from `live`, append it to `closed`, then return `TestManagerError("close failed")` when configured or `Ok(())` otherwise. Removing before the configured error models the deployed `LocalSessionManager` contract.
- `initialize_session` and `accept_message`: return `TestManagerError("unused test operation")`.
- `create_stream`, `create_standalone_stream`, and `resume`: return a typed `Err` whose success stream is `futures::stream::Empty<ServerSseMessage>`.
- `restore_session`: return `Ok(RestoreOutcome::NotSupported)`.

Use `std::sync::Mutex` only for short non-awaiting state access, and never hold a mutex guard across the async barriers or notifications.

Use these exact constructor and state accessors so the tests do not reach into
the fake's internals:

```rust
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
            self.state.live.lock().unwrap().clone()
        }

        fn closed_ids(&self) -> Vec<SessionId> {
            self.state.closed.lock().unwrap().clone()
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
            self.state
                .fail_has_session
                .store(enabled, Ordering::SeqCst);
        }

        async fn wait_for_close_start(&self) {
            self.state.close_started.notified().await;
        }

        fn release_close(&self) {
            self.state.close_release.notify_one();
        }
    }
```

`notify_one` is intentional: it retains a permit if the detached close task has
announced its start but has not yet begun awaiting the release notification.

- [ ] **Step 2: Replace the obsolete best-effort test and add failing strict-manager tests**

Delete `globally_untracked_live_session_still_binds_token_reservation`; that test asserts the defect being removed.

Add these four named Tokio tests:

```rust
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn limited_manager_concurrent_create_admits_one_and_closes_every_loser()

    #[tokio::test]
    async fn limited_manager_cleanup_error_still_returns_capacity_and_removes_loser()

    #[tokio::test]
    async fn limited_manager_rejected_cleanup_survives_outer_cancellation()

    #[tokio::test]
    async fn limited_manager_wraps_inner_create_and_delegated_errors()
```

The concurrency test uses four fake-manager creates and `AsyncBarrier::new(4)` with `max_sessions: 1`. Spawn four calls to the same `Arc<LimitedSessionManager<_>>`, await each with `ASYNC_TEST_TIMEOUT`, and assert:

```rust
    assert_eq!(winner_ids.len(), 1);
    assert_eq!(capacity_errors, 3);
    assert_eq!(manager.tracker().active(), 1);
    assert_eq!(fake.live_ids(), winner_ids);
    assert_eq!(fake.closed_ids().len(), 3);
```

Also assert that every closed ID is distinct and absent from `live`. Close the winner through the wrapper and finish with:

```rust
    assert_eq!(manager.tracker().active(), 0);
    assert!(fake.live_ids().is_empty());
```

The cleanup-error test creates one winner, sets `fail_close`, scopes the losing second create with `scope_session_cap_rejection`, and asserts the marker is true, the returned variant is `SessionCapExceeded`, the loser was removed and recorded once, and only the winner remains. Clear `fail_close` before closing the winner.

The cancellation test creates one winner, enables `block_close`, spawns a guaranteed losing second create, waits for `wait_for_close_start()`, aborts and joins the outer task, and calls `release_close()`. Use this exact bounded poll before closing the winner:

```rust
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
```

This proves the detached cleanup task outlives the aborted request. Disable
blocking and close the winner.

The error-wrapping test configures `fail_create`, then `fail_has_session`, and verifies both exact variants and source text:

```rust
    assert!(matches!(
        &create_error,
        LimitedSessionManagerError::Inner(TestManagerError("create failed"))
    ));
    assert!(matches!(
        &has_error,
        LimitedSessionManagerError::Inner(TestManagerError("has failed"))
    ));
    assert_eq!(
        std::error::Error::source(&create_error)
            .expect("inner create error source")
            .to_string(),
        "create failed"
    );
```

Finally call `mark_session_cap_rejected()` outside a scope and assert the test continues, proving direct library use does not panic.

Change the existing cfg-test accessor to crate visibility because the sibling
`concurrency` test module will verify reservation rollback directly:

```rust
    #[cfg(test)]
    pub(crate) fn pending_reservation_count(&self) -> usize {
        self.token_state().pending_reservations
    }
```

- [ ] **Step 3: Run one manager test and verify the expected red state**

```bash
cargo test -p rust-junosmcp-limits session::tests::limited_manager_concurrent_create_admits_one_and_closes_every_loser -- --exact --nocapture
```

Expected: FAIL before execution because `LimitedSessionManagerError`, `scope_session_cap_rejection`, and `mark_session_cap_rejected` do not exist and the wrapper still returns every race loser. Fix test-only syntax if necessary, but do not weaken the assertions.

- [ ] **Step 4: Add the dependency-free public error and task-local bridge**

Add `std::cell::Cell`, `std::future::Future`, and `std::fmt::{Display, Formatter}` imports. Place the public error and task-local helpers before `LimitedSessionManager`:

```rust
#[derive(Debug)]
pub enum LimitedSessionManagerError<E> {
    Inner(E),
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
            (output, SESSION_CAP_REJECTED.get())
        })
        .await
}

pub(crate) fn mark_session_cap_rejected() {
    let _ = SESSION_CAP_REJECTED.try_with(|rejected| rejected.set(true));
}
```

Do not make the task-local helpers public API; only the generic error type is public.

- [ ] **Step 5: Implement strict `create_session` cleanup and map every inner error**

Change the associated error type and replace `create_session` with:

```rust
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
                tracing::warn!(session_id = %id, error = %error, "rejected session cleanup failed");
            }
            Err(error) => {
                tracing::warn!(session_id = %id, error = %error, "rejected session cleanup task failed");
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
```

For every other delegated method, retain the existing touch/unregister/order behavior and add `.map_err(LimitedSessionManagerError::Inner)` to the awaited inner result. In particular:

- `close_session` must still call `tracker.unregister(id)` whether inner close succeeds or fails, then map its saved result.
- All three stream-producing methods must map the error after `.await` without boxing or changing the opaque stream.
- `restore_session` must map the inner error, preserve `Restored` best-effort registration, and return the same outcome in `Ok`.

In `rust-junosmcp-limits/src/lib.rs`, change the export to:

```rust
pub use session::{LimitedSessionManager, LimitedSessionManagerError, SessionTracker};
```

- [ ] **Step 6: Run the focused manager suite and clippy**

```bash
cargo test -p rust-junosmcp-limits session::tests::limited_manager -- --nocapture
cargo clippy -p rust-junosmcp-limits --all-targets -- -D warnings
```

Expected: all four `limited_manager_*` tests PASS; clippy exits 0 with no warnings. The cancellation test must complete under its one-second timeout.

- [ ] **Step 7: Review and commit the strict manager layer**

```bash
git diff --check
git diff -- rust-junosmcp-limits/src/session.rs rust-junosmcp-limits/src/lib.rs
git add rust-junosmcp-limits/src/session.rs rust-junosmcp-limits/src/lib.rs
git commit -m "fix: enforce global session cap atomically"
```

Expected: one implementation commit containing only the manager/error/task-local layer and its tests. Confirm the deleted best-effort test name no longer appears:

```bash
rg -n "globally_untracked_live_session_still_binds_token_reservation|Best-effort registration" rust-junosmcp-limits/src/session.rs
```

Expected: no matches.

---

### Task 2: Translate only marked manager race failures to the stable 503

**Files:**
- Modify: `rust-junosmcp-limits/src/concurrency.rs:74-188`
- Modify: `rust-junosmcp-limits/src/concurrency.rs:291-980`

**Interfaces:**
- Consumes: `scope_session_cap_rejection(next.run(req))`, `overload_response("session_cap")`, and the existing token reservation.
- Produces: a request-local translation from rmcp's capacity-related 500 to the existing 503 contract.
- Invariant: an unmarked HTTP 500 remains byte/status-compatible, including when it runs concurrently with a marked request.

- [ ] **Step 1: Add a concurrent response-isolation test before middleware changes**

Add this exact test name to `concurrency.rs`:

```rust
    #[tokio::test(flavor = "current_thread")]
    async fn marked_session_cap_response_is_isolated_and_releases_token_reservation()
```

Install a local metrics recorder using the established pattern in `streamed_body_over_outer_limit_stays_413`:

```rust
    let (recorder, handle) = crate::prometheus::test_recorder("junos");
    let recorder_guard = metrics::set_default_local_recorder(&recorder);
```

Build a `token_session_state(1)` app and an Axum POST handler with a two-party
`tokio::sync::Barrier` and an `Arc<AtomicUsize>` call counter. The first two
handler calls increment the counter and await the barrier; later calls skip it,
so the sequential isolation assertion cannot deadlock. The handler reads
`CallerCtx`; for token name `marked`, call
`crate::session::mark_session_cap_rejected()` and return
`StatusCode::INTERNAL_SERVER_ERROR`; for token name `plain`, return the same 500
without marking. The barrier gate is:

```rust
    let call = calls.fetch_add(1, Ordering::SeqCst);
    if call < 2 {
        barrier.wait().await;
    }
```

Spawn `marked` and `plain` initialize requests concurrently. Assert the marked result is exactly:

```rust
    assert_eq!(marked.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(marked.headers().get("retry-after").unwrap(), "1");
    assert!(marked.headers().get("mcp-session-id").is_none());
```

Drain its body and compare it to:

```rust
    json!({"error": "overloaded", "limit": "session_cap"})
```

Assert the concurrent plain response remains `StatusCode::INTERNAL_SERVER_ERROR`. Send a second sequential `plain` request and assert it also remains 500, proving a fresh scope on later use. After every response, assert:

```rust
    assert_eq!(tracker.active_for_token("marked"), 0);
    assert_eq!(tracker.active_for_token("plain"), 0);
    assert_eq!(tracker.pending_reservation_count(), 0);
```

Drop `recorder_guard`, run upkeep, and assert exactly one metric line has `limit="session_cap"`, `event="request_rejected"`, and value `1`. Assert no `session_registration_rejected` line exists because this test marks the request at the handler seam rather than invoking the manager.

- [ ] **Step 2: Run the isolation test and verify the expected red result**

```bash
cargo test -p rust-junosmcp-limits concurrency::tests::marked_session_cap_response_is_isolated_and_releases_token_reservation -- --exact --nocapture
```

Expected: FAIL because the marked response is still HTTP 500 and no `session_cap/request_rejected` client metric is recorded. The plain response must already remain 500.

- [ ] **Step 3: Scope session-creating downstream calls and replace only marked responses**

Replace the single `let resp = next.run(req).await;` with:

```rust
    let (mut resp, session_cap_rejected) = if session_creating {
        crate::session::scope_session_cap_rejection(next.run(req)).await
    } else {
        (next.run(req).await, false)
    };
    if session_cap_rejected {
        tracing::warn!(limit = "session_cap", "request shed after manager registration race");
        resp = overload_response("session_cap");
    }
```

Keep the token-reservation block after this replacement. Because the replacement status is non-success and carries no `Mcp-Session-Id`, the reservation drops without committing. Keep `attach_permits(resp, permits)` as the final expression so admitted-request concurrency permits remain owned by the replacement response body.

Do not condition the replacement on status text or body content. The marker is the sole authority.

- [ ] **Step 4: Run middleware tests and the whole limits crate**

```bash
cargo test -p rust-junosmcp-limits concurrency::tests::marked_session_cap_response_is_isolated_and_releases_token_reservation -- --exact --nocapture
cargo test -p rust-junosmcp-limits --locked
cargo clippy -p rust-junosmcp-limits --all-targets -- -D warnings
```

Expected: the isolation test PASSes; all existing limits tests PASS; clippy reports no warnings. Verify the metric assertion reports one client rejection, not two.

- [ ] **Step 5: Review and commit the HTTP translation layer**

```bash
git diff --check
git diff -- rust-junosmcp-limits/src/concurrency.rs
git add rust-junosmcp-limits/src/concurrency.rs
git commit -m "fix: return stable 503 for session race losers"
```

Expected: one commit limited to middleware behavior and tests.

---

### Task 3: Prove the public contract through both binaries

**Files:**
- Modify: `rust-junosmcp/tests/common/mod.rs:447-501`
- Modify: `rust-srxmcp/tests/common/mod.rs:155-209`
- Modify: `rust-junosmcp/tests/http_limits.rs:1-76`
- Modify: `rust-srxmcp/tests/http_limits.rs:1-76`

**Interfaces:**
- Produces: `PostResult::retry_after: Option<String>` in both test harnesses.
- Verifies: identical Junos and SRX `--max-sessions 1` behavior using the real shared rmcp/Axum wiring.

- [ ] **Step 1: Capture `Retry-After` in both HTTP test harnesses**

Add this public field after `session_id` in each `PostResult`:

```rust
    pub retry_after: Option<String>,
```

In each `http_post`, expand the response tuple to carry `retry_after`. In both the success and `ureq::Error::Status` branches, capture it before consuming the response:

```rust
    let retry_after = resp.header("Retry-After").map(str::to_string);
```

Return that value as `retry_after` in `PostResult`. Preserve all existing `Mcp-Session-Id`, content-type, `WWW-Authenticate`, SSE parsing, and empty-body behavior.

- [ ] **Step 2: Add the same end-to-end cap contract to each binary test file**

Add this test to both `rust-junosmcp/tests/http_limits.rs` and `rust-srxmcp/tests/http_limits.rs`:

```rust
#[test]
fn global_session_cap_returns_stable_503_and_releases_on_close() {
    let server = spawn_with_args(&["--max-sessions", "1"]);
    let first = initialize(server.port, &server.token);

    let shed = http_post(server.port, Some(&server.token), None, init_body());
    assert_eq!(shed.code, 503);
    assert_eq!(shed.retry_after.as_deref(), Some("1"));
    assert!(shed.session_id.is_none());
    assert_eq!(
        shed.body,
        serde_json::json!({"error": "overloaded", "limit": "session_cap"})
    );

    assert!(matches!(
        close_session(server.port, &server.token, &first),
        200 | 202 | 204
    ));
    let replacement = initialize(server.port, &server.token);
    assert!(matches!(
        close_session(server.port, &server.token, &replacement),
        200 | 202 | 204
    ));
}
```

Use `serde_json::json!` fully qualified so the current import list does not need to change. The shared-crate barrier test forces the actual race; these binary tests verify the stable endpoint contract and slot release without introducing timing-sensitive process races.

- [ ] **Step 3: Run both new tests before relying on the full suite**

```bash
cargo test -p rust-junosmcp --test http_limits global_session_cap_returns_stable_503_and_releases_on_close -- --exact --nocapture
cargo test -p rust-srxmcp --test http_limits global_session_cap_returns_stable_503_and_releases_on_close -- --exact --nocapture
```

Expected: each command runs one test and PASSes. The second initialize is 503 with `Retry-After: 1` and no session ID; the replacement initialize succeeds after close.

- [ ] **Step 4: Run both complete HTTP-limits test binaries**

```bash
cargo test -p rust-junosmcp --test http_limits --locked -- --nocapture
cargo test -p rust-srxmcp --test http_limits --locked -- --nocapture
```

Expected: all Junos and SRX HTTP resource-limit tests PASS with no ignored tests and no device connections.

- [ ] **Step 5: Review and commit endpoint coverage**

```bash
git diff --check
git diff -- rust-junosmcp/tests/common/mod.rs rust-srxmcp/tests/common/mod.rs rust-junosmcp/tests/http_limits.rs rust-srxmcp/tests/http_limits.rs
git add rust-junosmcp/tests/common/mod.rs rust-srxmcp/tests/common/mod.rs rust-junosmcp/tests/http_limits.rs rust-srxmcp/tests/http_limits.rs
git commit -m "test: cover strict global session cap endpoints"
```

Expected: one test-only commit with symmetric Junos/SRX harness and contract changes.

---

### Task 4: Document strict admission, metrics, and compatibility

**Files:**
- Modify: `README.md:568-589`
- Modify: `docs/METRICS.md:53-74`
- Modify: `CHANGELOG.md:25-44`
- Modify: `rust-srxmcp/CHANGELOG.md:23-42`

**Interfaces:**
- Documents: unchanged configuration and wire contract, new strict race-loser cleanup, paired metrics, and the public Rust associated-error-type change.

- [ ] **Step 1: Clarify the README global-session-cap guarantee**

After the resource-limit table, add a paragraph that states all of the following without promising queueing or retries:

```markdown
The global session cap is enforced atomically during session creation. The
middleware rejects obvious saturation early, while the shared session manager
closes any concurrently created session that loses the final slot race before
returning the same `session_cap` 503 contract. Rejected initialization never
returns an `Mcp-Session-Id`, and closing or reaping an admitted session returns
its slot.
```

Keep the existing general `Retry-After: 1` paragraph and per-token explanation.

- [ ] **Step 2: Explain the two intentional session-cap metric events**

After the fixed metric-value list in `docs/METRICS.md`, add:

```markdown
A concurrent initialize that reaches the manager race backstop records both
`limit="session_cap", event="session_registration_rejected"` for the atomic
manager decision and `limit="session_cap", event="request_rejected"` for the
503 returned to the client. An initialize rejected by the middleware fast path
records only the client-facing `request_rejected` event.
```

Do not add a metric, label, or PromQL query.

- [ ] **Step 3: Add matching `Unreleased / Fixed` release notes**

Add a matching leading bullet under `### Fixed` in both changelogs:

```markdown
- **#151 - strict global MCP session caps.** Concurrent initialize requests can
  no longer create live sessions beyond the tracked global cap. A race loser is
  closed without cancellation leaks and receives the existing `session_cap`
  `503` with `Retry-After: 1`; ordinary session-manager failures remain `500`.
```

In the root changelog only, append a concise compatibility sentence to that bullet: direct Rust users that explicitly name `LimitedSessionManager`'s associated error now receive `LimitedSessionManagerError<E>`. Do not describe this as an HTTP or CLI breaking change.

- [ ] **Step 4: Review documentation accuracy and commit**

```bash
git diff --check
git diff -- README.md docs/METRICS.md CHANGELOG.md rust-srxmcp/CHANGELOG.md
rg -n "#151|session_registration_rejected|loses the final slot race|LimitedSessionManagerError" README.md docs/METRICS.md CHANGELOG.md rust-srxmcp/CHANGELOG.md
git add README.md docs/METRICS.md CHANGELOG.md rust-srxmcp/CHANGELOG.md
git commit -m "docs: explain strict global session caps"
```

Expected: one documentation commit; every statement matches implemented behavior, and no historical plan/spec file changed.

---

### Task 5: Run the repository completion gate and prepare review evidence

**Files:**
- Verify only: entire workspace and committed diff
- Generated output: none

**Interfaces:**
- Produces: reproducible offline evidence for code review, PR CI comparison, merge, and cleanup.

- [ ] **Step 1: Prove formatting and lint cleanliness**

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: both commands exit 0; clippy emits no warning. These are the exact `fmt` and `lint` recipes.

- [ ] **Step 2: Run the complete locked workspace test suite**

```bash
cargo test --workspace --locked
```

Expected: exit 0 with no failed tests. The baseline had 912 passed and 29 ignored;
the four new manager tests replace one obsolete test, and the middleware plus
two endpoint tests add three more, for a net increase of six passed tests (918
aggregate) while the ignored count remains 29. Do not run those ignored tests.

This command plus the preceding workspace clippy command is the exact `guard` recipe.

- [ ] **Step 3: Run the offline CLI e2e recipe**

```bash
cargo run -p rust-junosmcp -- --help >/dev/null
cargo run -p rust-srxmcp -- --help >/dev/null
```

Expected: both binaries exit 0 without contacting a device.

- [ ] **Step 4: Run the security scan and classify only the established baseline**

```bash
PATH="/home/mharman/.local/share/mise/installs/trivy/0.70.0:$PATH" trivy fs --scanners vuln,misconfig,secret --exit-code 1 .
```

Expected in the current environment: Trivy exits nonzero only for the previously accepted repository baseline—`CVE-2026-50185` in `cmov 0.5.3`, Dockerfile `DS-0026` twice, `DS-0002`, and `DS-0004`—with zero secret findings. Any new vulnerability, misconfiguration, or secret finding blocks completion and must be investigated.

The exact `release-check` recipe is covered by Steps 1, 2, and 4. Record that `just` itself was unavailable and the checked-in commands were executed directly.

- [ ] **Step 5: Audit the final diff, commit graph, and scope**

```bash
git diff --check main...HEAD
git diff --stat main...HEAD
git log --oneline --decorate main..HEAD
git status --short --branch
git diff --name-only main...HEAD
```

Expected:

- only the files in the responsibility map plus the approved design and this plan are changed;
- `Cargo.toml` and `Cargo.lock` are unchanged;
- no generated schema, archive, build output, secret-bearing inventory, token, key, configuration, support bundle, or certificate is present;
- the worktree is clean and the branch contains the design/plan commits plus the four implementation commits.

- [ ] **Step 6: Review against every acceptance criterion before publishing**

Record explicit evidence for each item:

1. `create_session` closes and errors on atomic cap rejection.
2. The rejected cleanup survives cancellation and cleanup errors retain the capacity result.
3. A marked rmcp 500 becomes the exact 503/`Retry-After: 1`/stable body with no session ID.
4. A concurrent and later unmarked 500 remains 500.
5. Tracker, inner-manager, per-token, and metric assertions show no overshoot or leak.
6. Both real binaries pass the same public contract and admit a replacement after close.
7. No config, schema, auth, device, dependency, or packaged-service behavior changed.
8. External `restore_session` cap hardening remains explicitly out of scope and unreachable in both binaries.

If review changes code or tests, rerun Steps 1-5 before claiming readiness. Then use `superpowers:requesting-code-review`, publish a PR, inspect all GitHub Actions checks, merge only after they pass, and remove the issue worktree and local/remote feature branch after confirming `main` contains the merge.
