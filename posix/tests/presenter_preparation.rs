extern crate self as mochi_user_platform;

use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;

pub mod syscall {
    pub use mochi_user_syscall::{NativeError, SysError};
}

struct Case {
    main: std::thread::ThreadId,
    released: Mutex<bool>,
    release: Condvar,
    started: mpsc::Sender<()>,
    retained: mpsc::Sender<()>,
    spawned: AtomicUsize,
    endpoints: AtomicUsize,
    terminated: AtomicUsize,
    closed: AtomicUsize,
    owners_dropped: AtomicUsize,
    fail_ready: AtomicBool,
    exited: AtomicBool,
}

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: Mutex<Option<Arc<Case>>> = Mutex::new(None);
static RETAINED: Mutex<Vec<native_process::NativeProcess>> = Mutex::new(Vec::new());

fn case() -> Arc<Case> {
    CURRENT.lock().unwrap().as_ref().unwrap().clone()
}

pub mod handle {
    pub fn inherited(key: u64) -> Result<u32, crate::syscall::SysError> {
        assert_eq!(key, mochios_posix_protocol::CONTROL_HANDLE_KEY);
        Ok(11)
    }
    pub fn close(endpoint: u32) -> Result<(), crate::syscall::SysError> {
        assert_eq!(endpoint, 41);
        crate::case().closed.fetch_add(1, crate::Ordering::SeqCst);
        Ok(())
    }
}

pub mod service_ready {
    pub struct Target {
        pub endpoint: u64,
        pub token: u64,
    }
    pub fn generate_token() -> Result<u64, crate::syscall::SysError> {
        Ok(123)
    }
}

pub mod ipc {
    pub fn create() -> Result<u64, crate::syscall::SysError> {
        let case = crate::case();
        assert_ne!(std::thread::current().id(), case.main);
        case.endpoints.fetch_add(1, crate::Ordering::SeqCst);
        Ok(99)
    }
}

pub mod time {
    pub fn monotonic_nanoseconds() -> Result<u64, crate::syscall::SysError> {
        Ok(10_000_000_000)
    }
}

pub mod native_process {
    pub struct NativeProcess(pub(crate) std::sync::Arc<crate::Case>);
    impl NativeProcess {
        pub fn watch_target(&self) -> u32 {
            7
        }
        pub fn terminate(&self) {
            self.0.terminated.fetch_add(1, crate::Ordering::SeqCst);
        }
    }
    impl Drop for NativeProcess {
        fn drop(&mut self) {
            self.0.owners_dropped.fetch_add(1, crate::Ordering::SeqCst);
        }
    }
}

pub mod process_watch {
    #[derive(Debug)]
    pub struct ProcessWatchError;
    pub struct ProcessWatch;
    impl ProcessWatch {
        pub fn open(handle: u32) -> Result<Self, ProcessWatchError> {
            assert_eq!(handle, 7);
            Ok(Self)
        }
        pub fn exit_status(&self) -> Result<Option<i32>, ProcessWatchError> {
            Ok(crate::case()
                .exited
                .load(crate::Ordering::SeqCst)
                .then_some(37))
        }
    }
}

pub mod readiness {
    #[derive(Debug)]
    pub enum ReadyError {
        TimedOut,
    }
    pub fn wait_for_private_endpoint(token: u64, process: u32) -> Result<u32, ReadyError> {
        assert_eq!((token, process), (123, 7));
        let case = crate::case();
        assert_ne!(std::thread::current().id(), case.main);
        let mut released = case.released.lock().unwrap();
        while !*released {
            released = case.release.wait(released).unwrap();
        }
        if case.fail_ready.load(crate::Ordering::SeqCst) {
            Err(ReadyError::TimedOut)
        } else {
            Ok(41)
        }
    }
}

pub mod launch_rollback {
    pub fn retain_failed_launch(process: crate::native_process::NativeProcess, posix: u32) {
        assert_eq!(posix, 11);
        let case = process.0.clone();
        crate::RETAINED.lock().unwrap().push(process);
        case.retained.send(()).unwrap();
    }
}

pub mod service_launcher {
    pub fn has_failed_launch_cleanup() -> bool {
        false
    }
    fn spawn(target: crate::service_ready::Target) -> crate::native_process::NativeProcess {
        assert_eq!((target.endpoint, target.token), (99, 123));
        let case = crate::case();
        assert_ne!(std::thread::current().id(), case.main);
        case.spawned.fetch_add(1, crate::Ordering::SeqCst);
        case.started.send(()).unwrap();
        crate::native_process::NativeProcess(case)
    }
    pub fn spawn_permission_prompt_server(
        logger: u64,
        token: u64,
        target: crate::service_ready::Target,
    ) -> Result<crate::native_process::NativeProcess, crate::syscall::SysError> {
        assert_eq!((logger, token), (17, 123));
        Ok(spawn(target))
    }
    pub fn spawn_execution_prompt_server(
        logger: u64,
        target: crate::service_ready::Target,
    ) -> Result<crate::native_process::NativeProcess, crate::syscall::SysError> {
        assert_eq!(logger, 17);
        Ok(spawn(target))
    }
}

#[path = "../../service-manager/src/presenter.rs"]
#[allow(dead_code)]
mod presenter;

struct Harness {
    case: Arc<Case>,
    started: mpsc::Receiver<()>,
    retained: mpsc::Receiver<()>,
}

impl Harness {
    fn new() -> Self {
        RETAINED.lock().unwrap().clear();
        let (started_tx, started) = mpsc::channel();
        let (retained_tx, retained) = mpsc::channel();
        let case = Arc::new(Case {
            main: std::thread::current().id(),
            released: Mutex::new(false),
            release: Condvar::new(),
            started: started_tx,
            retained: retained_tx,
            spawned: AtomicUsize::new(0),
            endpoints: AtomicUsize::new(0),
            terminated: AtomicUsize::new(0),
            closed: AtomicUsize::new(0),
            owners_dropped: AtomicUsize::new(0),
            fail_ready: AtomicBool::new(false),
            exited: AtomicBool::new(false),
        });
        *CURRENT.lock().unwrap() = Some(case.clone());
        Self {
            case,
            started,
            retained,
        }
    }
    fn release(&self) {
        *self.case.released.lock().unwrap() = true;
        self.case.release.notify_all();
    }
    fn spawned(&self) {
        self.started.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    fn retained(&self) {
        self.retained.recv_timeout(Duration::from_secs(5)).unwrap();
    }
}

#[test]
fn preparations_do_not_block_dispatch_or_spawn_duplicates() {
    let _serial = TEST_LOCK.lock().unwrap();
    for kind in [presenter::Kind::Permission, presenter::Kind::Execution] {
        let harness = Harness::new();
        let mut slot = presenter::Slot::default();
        slot.maintain(kind, 17);
        harness.spawned();
        // The real preparation is still blocked in its private Ready wait.
        // The resident thread can continue accepting unrelated work.
        let mut requests = 0;
        for _ in 0..100 {
            slot.maintain(kind, 17);
            requests += 1;
        }
        assert_eq!(requests, 100);
        assert_eq!(harness.case.spawned.load(Ordering::SeqCst), 1);
        assert_eq!(harness.case.endpoints.load(Ordering::SeqCst), 1);
        harness.release();
        let prepared = slot.take_ready(kind, 17).unwrap();
        assert_eq!((prepared.endpoint(), prepared.token()), (41, 123));
        drop(prepared);
        harness.retained();
        assert_eq!(harness.case.terminated.load(Ordering::SeqCst), 1);
        assert_eq!(harness.case.closed.load(Ordering::SeqCst), 1);
        assert_eq!(harness.case.owners_dropped.load(Ordering::SeqCst), 0);
        RETAINED.lock().unwrap().clear();
        assert_eq!(harness.case.owners_dropped.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn both_presenters_can_prepare_while_neither_has_published_ready() {
    let _serial = TEST_LOCK.lock().unwrap();
    let harness = Harness::new();
    let mut permission = presenter::Slot::default();
    let mut execution = presenter::Slot::default();
    permission.maintain(presenter::Kind::Permission, 17);
    execution.maintain(presenter::Kind::Execution, 17);
    harness.spawned();
    harness.spawned();
    assert_eq!(harness.case.spawned.load(Ordering::SeqCst), 2);
    assert_eq!(harness.case.endpoints.load(Ordering::SeqCst), 2);
    harness.release();
    let first = permission
        .take_ready(presenter::Kind::Permission, 17)
        .unwrap();
    let second = execution
        .take_ready(presenter::Kind::Execution, 17)
        .unwrap();
    drop(first);
    drop(second);
    harness.retained();
    harness.retained();
    assert_eq!(harness.case.terminated.load(Ordering::SeqCst), 2);
    assert_eq!(harness.case.closed.load(Ordering::SeqCst), 2);
    RETAINED.lock().unwrap().clear();
}

#[test]
fn readiness_failure_retains_the_exact_child_for_rollback() {
    let _serial = TEST_LOCK.lock().unwrap();
    let harness = Harness::new();
    harness.case.fail_ready.store(true, Ordering::SeqCst);
    let mut slot = presenter::Slot::default();
    slot.maintain(presenter::Kind::Permission, 17);
    harness.spawned();
    harness.release();
    assert!(matches!(
        slot.take_ready(presenter::Kind::Permission, 17),
        Err(presenter::PrepareError::Readiness(
            readiness::ReadyError::TimedOut
        ))
    ));
    harness.retained();
    assert_eq!(harness.case.terminated.load(Ordering::SeqCst), 1);
    assert_eq!(harness.case.closed.load(Ordering::SeqCst), 0);
    assert_eq!(harness.case.owners_dropped.load(Ordering::SeqCst), 0);
    // A failed background attempt is not retried in a tight loop.
    for _ in 0..100 {
        slot.maintain(presenter::Kind::Permission, 17);
    }
    assert_eq!(harness.case.spawned.load(Ordering::SeqCst), 1);
    RETAINED.lock().unwrap().clear();
}

#[test]
fn dropping_a_pending_slot_does_not_orphan_a_late_presenter() {
    let _serial = TEST_LOCK.lock().unwrap();
    let harness = Harness::new();
    let mut slot = presenter::Slot::default();
    slot.maintain(presenter::Kind::Execution, 17);
    harness.spawned();
    drop(slot);
    harness.release();
    harness.retained();
    // Retention is requested before endpoint close; wait for that last cleanup
    // step without allowing another test to replace the fake native platform.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while harness.case.closed.load(Ordering::SeqCst) == 0 {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert_eq!(harness.case.terminated.load(Ordering::SeqCst), 1);
    assert_eq!(harness.case.owners_dropped.load(Ordering::SeqCst), 0);
    RETAINED.lock().unwrap().clear();
}
