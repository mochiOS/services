use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use update::coordinator::{
    ApplyError, Coordinator, SnapshotFetcher, SnapshotRepository, SnapshotTimes, SyncResult,
};
use update::http::{FetchError, Response};
use update::scheduler::{EXPIRY_REVALIDATION_MS, SnapshotKind, TRUST_PERIOD_MS};

type Events = Rc<RefCell<Vec<String>>>;

struct Fetcher {
    events: Events,
    responses: VecDeque<Result<Response, FetchError>>,
    request_ids: Vec<u64>,
}

impl SnapshotFetcher for Fetcher {
    fn fetch(
        &mut self,
        kind: SnapshotKind,
        request_id: u64,
        if_none_match: &str,
    ) -> Result<Response, FetchError> {
        self.events
            .borrow_mut()
            .push(format!("fetch:{kind:?}:{if_none_match}"));
        self.request_ids.push(request_id);
        self.responses.pop_front().unwrap()
    }
}

struct Repository {
    events: Events,
    trust_etag: String,
    revocation_etag: String,
    apply_results: VecDeque<Result<SnapshotTimes, ApplyError>>,
    checked_results: VecDeque<Result<SnapshotTimes, ApplyError>>,
}

impl SnapshotRepository for Repository {
    fn etag(&self, kind: SnapshotKind) -> &str {
        match kind {
            SnapshotKind::Trust => &self.trust_etag,
            SnapshotKind::Revocations => &self.revocation_etag,
        }
    }

    fn apply(
        &mut self,
        kind: SnapshotKind,
        _body: &[u8],
        etag: &str,
        _now_utc: u64,
    ) -> Result<SnapshotTimes, ApplyError> {
        self.events
            .borrow_mut()
            .push(format!("apply:{kind:?}:{etag}"));
        self.apply_results.pop_front().unwrap()
    }

    fn mark_checked(
        &mut self,
        kind: SnapshotKind,
        _now_utc: u64,
    ) -> Result<SnapshotTimes, ApplyError> {
        self.events.borrow_mut().push(format!("checked:{kind:?}"));
        self.checked_results.pop_front().unwrap()
    }
}

fn times() -> SnapshotTimes {
    SnapshotTimes {
        generated_at: 100,
        expires_at: 1_000_000,
    }
}

fn response(status_code: u16, etag: Option<&str>, retry_after_seconds: Option<u64>) -> Response {
    Response {
        status_code,
        etag: etag.map(str::to_string),
        retry_after_seconds,
        body: vec![1],
    }
}

fn setup(
    responses: Vec<Result<Response, FetchError>>,
    apply_results: Vec<Result<SnapshotTimes, ApplyError>>,
    checked_results: Vec<Result<SnapshotTimes, ApplyError>>,
) -> (Coordinator, Fetcher, Repository, Events) {
    let events = Rc::new(RefCell::new(Vec::new()));
    (
        Coordinator::network_ready(0),
        Fetcher {
            events: events.clone(),
            responses: responses.into(),
            request_ids: Vec::new(),
        },
        Repository {
            events: events.clone(),
            trust_etag: "\"trust-old\"".to_string(),
            revocation_etag: "\"rev-old\"".to_string(),
            apply_results: apply_results.into(),
            checked_results: checked_results.into(),
        },
        events,
    )
}

#[test]
fn initial_sync_applies_trust_before_revocations_with_unique_ids() {
    let (mut coordinator, mut fetcher, mut repository, events) = setup(
        vec![
            Ok(response(200, Some("\"trust-new\""), None)),
            Ok(response(200, Some("\"rev-new\""), None)),
        ],
        vec![Ok(times()), Ok(times())],
        vec![],
    );
    coordinator.synchronize_due(&mut fetcher, &mut repository, 0, 200);
    assert_eq!(
        events.borrow().as_slice(),
        [
            "fetch:Trust:\"trust-old\"",
            "apply:Trust:\"trust-new\"",
            "fetch:Revocations:\"rev-old\"",
            "apply:Revocations:\"rev-new\"",
        ]
    );
    assert_eq!(fetcher.request_ids, [1, 2]);
    assert_eq!(coordinator.statistics().trust_sync_updated, 1);
    assert_eq!(coordinator.statistics().revocation_sync_updated, 1);
}

#[test]
fn not_modified_updates_checked_state_and_statistics() {
    let (mut coordinator, mut fetcher, mut repository, events) = setup(
        vec![
            Ok(response(304, Some("\"trust-old\""), None)),
            Ok(response(304, Some("\"rev-old\""), None)),
        ],
        vec![],
        vec![Ok(times()), Ok(times())],
    );
    coordinator.synchronize_due(&mut fetcher, &mut repository, 0, 200);
    assert_eq!(
        events.borrow().as_slice(),
        [
            "fetch:Trust:\"trust-old\"",
            "checked:Trust",
            "fetch:Revocations:\"rev-old\"",
            "checked:Revocations",
        ]
    );
    assert_eq!(coordinator.statistics().trust_sync_not_modified, 1);
    assert_eq!(coordinator.statistics().revocation_sync_not_modified, 1);
}

#[test]
fn not_modified_does_not_accept_an_expired_local_snapshot() {
    let expired = SnapshotTimes {
        generated_at: 100,
        expires_at: 200,
    };
    let (mut coordinator, mut fetcher, mut repository, _) = setup(
        vec![
            Ok(response(304, Some("\"trust-old\""), None)),
            Ok(response(304, Some("\"rev-old\""), None)),
        ],
        vec![],
        vec![Ok(expired), Ok(times())],
    );

    coordinator.synchronize_due(&mut fetcher, &mut repository, 0, 200);

    assert_eq!(coordinator.statistics().trust_sync_not_modified, 0);
    assert_eq!(coordinator.statistics().snapshot_expiration_failures, 1);
    assert_eq!(
        coordinator.scheduler().next_attempt_ms(SnapshotKind::Trust),
        TRUST_PERIOD_MS
    );
}

#[test]
fn not_modified_near_expiry_schedules_bounded_revalidation() {
    let near_expiry = SnapshotTimes {
        generated_at: 100,
        expires_at: 500,
    };
    let (mut coordinator, mut fetcher, mut repository, _) = setup(
        vec![
            Ok(response(304, Some("\"trust-old\""), None)),
            Ok(response(304, Some("\"rev-old\""), None)),
        ],
        vec![],
        vec![Ok(near_expiry), Ok(times())],
    );

    coordinator.synchronize_due(&mut fetcher, &mut repository, 10, 450);

    assert_eq!(
        coordinator.scheduler().next_attempt_ms(SnapshotKind::Trust),
        10 + 50_000
    );
    assert!(
        coordinator.scheduler().next_attempt_ms(SnapshotKind::Trust) <= 10 + EXPIRY_REVALIDATION_MS
    );
}

#[test]
fn transient_status_uses_retry_after_and_does_not_apply() {
    let (mut coordinator, mut fetcher, mut repository, _) = setup(
        vec![
            Ok(response(503, None, Some(600))),
            Err(FetchError::Transport(5)),
        ],
        vec![],
        vec![],
    );
    coordinator.synchronize_due(&mut fetcher, &mut repository, 0, 200);
    assert_eq!(
        coordinator.scheduler().next_attempt_ms(SnapshotKind::Trust),
        600_000
    );
    assert_eq!(
        coordinator
            .scheduler()
            .next_attempt_ms(SnapshotKind::Revocations),
        60_000
    );
    assert_eq!(coordinator.statistics().trust_sync_failures, 1);
    assert_eq!(coordinator.statistics().revocation_sync_failures, 1);
}

#[test]
fn signature_and_rollback_failures_are_security_rejections() {
    let (mut coordinator, mut fetcher, mut repository, _) = setup(
        vec![
            Ok(response(200, Some("\"trust-new\""), None)),
            Ok(response(200, Some("\"rev-new\""), None)),
        ],
        vec![Err(ApplyError::InvalidSignature), Err(ApplyError::Rollback)],
        vec![],
    );
    coordinator.synchronize_due(&mut fetcher, &mut repository, 0, 200);
    assert_eq!(coordinator.statistics().snapshot_signature_failures, 1);
    assert_eq!(coordinator.statistics().snapshot_rollback_rejections, 1);
    assert_eq!(
        coordinator.scheduler().next_attempt_ms(SnapshotKind::Trust),
        TRUST_PERIOD_MS
    );
    assert_eq!(
        coordinator.last_result(),
        SyncResult::Rejected(SnapshotKind::Revocations, ApplyError::Rollback)
    );
}

#[test]
fn unknown_revocation_issuer_refreshes_trust_once_then_retries() {
    let (mut coordinator, mut fetcher, mut repository, events) = setup(
        vec![
            Ok(response(200, Some("\"trust-1\""), None)),
            Ok(response(200, Some("\"rev-1\""), None)),
            Ok(response(200, Some("\"trust-2\""), None)),
            Ok(response(200, Some("\"rev-1\""), None)),
        ],
        vec![
            Ok(times()),
            Err(ApplyError::UnknownIssuer),
            Ok(times()),
            Ok(times()),
        ],
        vec![],
    );
    coordinator.synchronize_due(&mut fetcher, &mut repository, 0, 200);
    assert_eq!(
        events.borrow().as_slice(),
        [
            "fetch:Trust:\"trust-old\"",
            "apply:Trust:\"trust-1\"",
            "fetch:Revocations:\"rev-old\"",
            "apply:Revocations:\"rev-1\"",
            "fetch:Trust:\"trust-old\"",
            "apply:Trust:\"trust-2\"",
            "fetch:Revocations:\"rev-old\"",
            "apply:Revocations:\"rev-1\"",
        ]
    );
    assert_eq!(coordinator.statistics().trust_sync_attempts, 2);
    assert_eq!(coordinator.statistics().revocation_sync_attempts, 2);
    assert_eq!(coordinator.statistics().revocation_sync_failures, 0);
}

#[test]
fn storage_failure_is_counted_and_retried() {
    let (mut coordinator, mut fetcher, mut repository, _) = setup(
        vec![
            Ok(response(200, Some("\"trust-new\""), None)),
            Err(FetchError::Transport(5)),
        ],
        vec![Err(ApplyError::Storage)],
        vec![],
    );
    coordinator.synchronize_due(&mut fetcher, &mut repository, 0, 200);
    assert_eq!(coordinator.statistics().snapshot_storage_failures, 1);
    assert_eq!(coordinator.statistics().trust_sync_failures, 1);
    assert_eq!(
        coordinator.scheduler().next_attempt_ms(SnapshotKind::Trust),
        60_000
    );
}
