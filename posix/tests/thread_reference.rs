//! Actual runtime reference ownership with controlled native duplication/close.
//! Host synchronization exercises source-selector reuse, not native IPC.
use mochios_posix_client::thread::ThreadToken;
use std::{
    cell::Cell,
    collections::BTreeMap,
    ffi::c_int,
    ops::{Deref, DerefMut},
    sync::{
        Barrier, Mutex,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
};

type Pthread = u32;
const ESRCH: c_int = 3;
const EIO: c_int = 5;
const EOVERFLOW: c_int = 139;
const THREAD_FREE: u32 = 0;
const THREAD_STARTING: u32 = 1;
const THREAD_RUNNING: u32 = 2;
const THREAD_REAPING: u32 = 4;
const TOKEN: Pthread = 64;
static SERIAL: Mutex<()> = Mutex::new(());
const NEXT_TOKEN: Pthread = 128;
const RIGHTS: u64 =
    mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL | mnu_abi::HANDLE_RIGHT_TRANSFER;
struct ThreadControl {
    state: AtomicU32,
    generation: AtomicU32,
    native_handle: AtomicU32,
    native_id: AtomicU64,
    cancel_pending: AtomicU32,
}
static CONTROL: ThreadControl = ThreadControl {
    state: AtomicU32::new(THREAD_RUNNING),
    generation: AtomicU32::new(1),
    native_handle: AtomicU32::new(7),
    native_id: AtomicU64::new(17),
    cancel_pending: AtomicU32::new(0),
};
thread_local! {
    static CURRENT: Cell<Option<Pthread>> = const { Cell::new(None) };
    static DEFERRED: Cell<usize> = const { Cell::new(0) };
    static LOCKED: Cell<usize> = const { Cell::new(0) };
}
fn thread_control(raw: Pthread) -> Option<&'static ThreadControl> {
    let token = ThreadToken::from_raw(raw)?;
    (token.slot() == 0
        && token.generation() == CONTROL.generation.load(Ordering::Acquire)
        && !matches!(
            CONTROL.state.load(Ordering::Acquire),
            THREAD_FREE | THREAD_REAPING
        ))
    .then_some(&CONTROL)
}
fn current_thread_control() -> Option<(Pthread, &'static ThreadControl)> {
    CURRENT.get().map(|token| (token, &CONTROL))
}
static GATE: mochios_posix_client::thread_lifecycle::Gate =
    mochios_posix_client::thread_lifecycle::Gate::new();
mod thread_lifecycle {
    pub struct Mutation {
        _activity: mochios_posix_client::thread_lifecycle::Activity<'static>,
        _delivery: Delivery,
    }
    struct Delivery;
    impl Drop for Delivery {
        fn drop(&mut self) {
            crate::DEFERRED.set(crate::DEFERRED.get() - 1);
        }
    }
    pub fn mutate() -> Mutation {
        crate::DEFERRED.set(crate::DEFERRED.get() + 1);
        Mutation {
            _activity: crate::GATE
                .try_enter()
                .expect("fixture never waits under freeze"),
            _delivery: Delivery,
        }
    }
}
struct RuntimeMutex<T>(Mutex<T>);
impl<T> RuntimeMutex<T> {
    const fn new(value: T) -> Self {
        Self(Mutex::new(value))
    }
    fn lock(&self) -> Guard<'_, T> {
        let guard = self.0.lock().unwrap();
        LOCKED.set(LOCKED.get() + 1);
        Guard(guard)
    }
}
struct Guard<'a, T>(std::sync::MutexGuard<'a, T>);
impl<T> Deref for Guard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T> DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        LOCKED.set(LOCKED.get() - 1);
    }
}
struct Kernel {
    handles: BTreeMap<u32, u64>,
    next: u32,
    closed: Vec<u32>,
    failure: Option<c_int>,
    malformed: Option<u64>,
    recycle: bool,
}
static KERNEL: Mutex<Kernel> = Mutex::new(Kernel {
    handles: BTreeMap::new(),
    next: 64,
    closed: Vec::new(),
    failure: None,
    malformed: None,
    recycle: false,
});
struct Pause {
    entered: std::sync::Arc<Barrier>,
    resume: std::sync::Arc<Barrier>,
}
static PAUSE: Mutex<Option<Pause>> = Mutex::new(None);
fn close_object_handle(handle: u32) {
    assert!(DEFERRED.get() > 0);
    assert!(GATE.try_freeze().is_none());
    if handle < 64 {
        assert!(LOCKED.get() > 0);
    } else {
        assert_eq!(LOCKED.get(), 0);
    }
    let mut kernel = KERNEL.lock().unwrap();
    assert!(
        kernel.handles.remove(&handle).is_some(),
        "double close of {handle}"
    );
    kernel.closed.push(handle);
    if handle == 7 && kernel.recycle {
        kernel.recycle = false;
        kernel.handles.insert(7, 200);
    }
}
mod syscall {
    pub enum SyscallNumber {
        HandleDuplicate,
    }
    pub fn raw_syscall2(_: SyscallNumber, source: u64, rights: u64) -> Result<u64, i32> {
        assert!(crate::DEFERRED.get() > 0);
        assert!(crate::LOCKED.get() > 0);
        assert!(crate::GATE.try_freeze().is_none());
        let pause = crate::PAUSE.lock().unwrap().take();
        if let Some(pause) = pause {
            pause.entered.wait();
            pause.resume.wait();
        }
        let mut kernel = crate::KERNEL.lock().unwrap();
        if let Some(error) = kernel.failure {
            return Err(error);
        }
        if let Some(raw) = kernel.malformed {
            return Ok(raw);
        }
        if rights & !crate::RIGHTS != 0 {
            return Err(13);
        }
        let object = *kernel.handles.get(&(source as u32)).ok_or(9)?;
        let handle = kernel.next;
        kernel.next += 1;
        kernel.handles.insert(handle, object);
        Ok(u64::from(handle))
    }
}
fn syscall_errno(value: Result<u64, c_int>) -> Result<u64, c_int> {
    value
}
#[path = "../../../user/crates/newlib-runtime/src/thread_reference.rs"]
mod production;

fn reset() {
    assert_eq!(DEFERRED.get(), 0);
    assert_eq!(LOCKED.get(), 0);
    *KERNEL.lock().unwrap() = Kernel {
        handles: BTreeMap::from([(7, 100)]),
        next: 64,
        closed: Vec::new(),
        failure: None,
        malformed: None,
        recycle: false,
    };
    CONTROL.generation.store(1, Ordering::Release);
    CONTROL.state.store(THREAD_RUNNING, Ordering::Release);
    CONTROL.native_handle.store(7, Ordering::Release);
    CONTROL.native_id.store(17, Ordering::Release);
    CONTROL.cancel_pending.store(0, Ordering::Release);
    CURRENT.set(None);
}
fn target(handle: u32) -> u64 {
    KERNEL.lock().unwrap().handles[&handle]
}

#[test]
fn actual_reference_capture_keeps_old_target_and_excludes_fork_until_release() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    for token in [0, NEXT_TOKEN] {
        assert_eq!(production::snapshot(token, RIGHTS).err(), Some(ESRCH));
    }
    KERNEL.lock().unwrap().failure = Some(11);
    assert_eq!(production::snapshot(TOKEN, RIGHTS).err(), Some(11));
    KERNEL.lock().unwrap().failure = None;
    for (raw, error) in [(0, EIO), (u64::from(u32::MAX) + 1, EOVERFLOW)] {
        KERNEL.lock().unwrap().malformed = Some(raw);
        assert_eq!(production::snapshot(TOKEN, RIGHTS).err(), Some(error));
    }
    KERNEL.lock().unwrap().malformed = None;
    assert_eq!(production::snapshot(TOKEN, 1).err(), Some(13));
    CONTROL.state.store(THREAD_STARTING, Ordering::Release);
    assert_eq!(production::snapshot(TOKEN, RIGHTS).err(), Some(ESRCH));
    CURRENT.set(Some(TOKEN));
    drop(production::snapshot(TOKEN, RIGHTS).unwrap());
    CURRENT.set(None);
    CONTROL.state.store(THREAD_RUNNING, Ordering::Release);
    let reference = production::snapshot(TOKEN, RIGHTS).unwrap();
    assert_eq!(target(reference.handle()), 100);
    assert!(GATE.try_freeze().is_none());
    assert_eq!(LOCKED.get(), 0);
    KERNEL.lock().unwrap().recycle = true;
    production::replace(&CONTROL, 0);
    assert_eq!(production::snapshot(TOKEN, RIGHTS).err(), Some(ESRCH));
    CONTROL.generation.store(2, Ordering::Release);
    production::replace(&CONTROL, 7);
    assert_eq!(production::snapshot(TOKEN, RIGHTS).err(), Some(ESRCH));
    let newer = production::snapshot(NEXT_TOKEN, RIGHTS).unwrap();
    assert_eq!(target(newer.handle()), 200);
    assert_eq!(target(reference.handle()), 100);
    drop(newer);
    drop(reference);
    assert_eq!(DEFERRED.get(), 0);
    assert!(GATE.try_freeze().is_some());
    assert_eq!(
        production::with_control(&CONTROL, |handle| {
            assert!(LOCKED.get() > 0);
            assert!(DEFERRED.get() > 0);
            assert!(GATE.try_freeze().is_none());
            Ok(target(handle))
        }),
        Ok(200)
    );
    production::replace(&CONTROL, 0);
    assert_eq!(production::with_control(&CONTROL, |_| Ok(())), Err(ESRCH));

    reset();
    let entered = std::sync::Arc::new(Barrier::new(2));
    let resume = std::sync::Arc::new(Barrier::new(2));
    *PAUSE.lock().unwrap() = Some(Pause {
        entered: entered.clone(),
        resume: resume.clone(),
    });
    let (captured_tx, captured_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let capture = std::thread::spawn(move || {
        let reference = production::snapshot(TOKEN, RIGHTS).unwrap();
        captured_tx.send(reference.handle()).unwrap();
        release_rx.recv().unwrap();
        drop(reference);
        assert_eq!(DEFERRED.get(), 0);
    });
    entered.wait();
    let replacing = std::sync::Arc::new(Barrier::new(2));
    let publishing = replacing.clone();
    let replace = std::thread::spawn(move || {
        publishing.wait();
        KERNEL.lock().unwrap().recycle = true;
        production::replace(&CONTROL, 0);
        CONTROL.generation.store(2, Ordering::Release);
        production::replace(&CONTROL, 7);
    });
    replacing.wait();
    assert!(KERNEL.lock().unwrap().closed.is_empty());
    assert!(GATE.try_freeze().is_none());
    resume.wait();
    let captured = captured_rx.recv().unwrap();
    replace.join().unwrap();
    assert_eq!(target(captured), 100);
    assert_eq!(target(7), 200);
    release_tx.send(()).unwrap();
    capture.join().unwrap();
    assert_eq!(
        KERNEL
            .lock()
            .unwrap()
            .closed
            .iter()
            .filter(|&&handle| handle == captured)
            .count(),
        1
    );
    assert!(GATE.try_freeze().is_some());
}

#[test]
fn live_token_actions_reject_dead_stale_and_unpublished_startup_slots() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    for token in [0, NEXT_TOKEN] {
        assert_eq!(
            production::with_live_token(token, |_| panic!("invalid token")),
            Err(ESRCH)
        );
    }
    for state in [THREAD_FREE, 3, THREAD_REAPING] {
        CONTROL.state.store(state, Ordering::Release);
        assert_eq!(
            production::with_live_token(TOKEN, |_| panic!("retired target")),
            Err(ESRCH)
        );
    }
    CONTROL.state.store(THREAD_STARTING, Ordering::Release);
    CONTROL.native_id.store(0, Ordering::Release);
    assert_eq!(
        production::with_live_token(TOKEN, |_| panic!("unpublished startup")),
        Err(ESRCH)
    );
    CONTROL.native_id.store(17, Ordering::Release);
    for state in [THREAD_STARTING, THREAD_RUNNING] {
        CONTROL.state.store(state, Ordering::Release);
        assert_eq!(
            production::with_live_token(TOKEN, |control| {
                assert!(LOCKED.get() > 0 && DEFERRED.get() > 0);
                assert!(GATE.try_freeze().is_none());
                control.cancel_pending.store(1, Ordering::Release);
                42
            }),
            Ok(42)
        );
    }
    assert_eq!(LOCKED.get(), 0);
    assert_eq!(DEFERRED.get(), 0);
    assert!(GATE.try_freeze().is_some());
}

#[test]
fn cancellation_action_finishes_before_retirement_can_publish_a_reused_tcb() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    let entered = std::sync::Arc::new(Barrier::new(2));
    let resume = std::sync::Arc::new(Barrier::new(2));
    let action_entered = entered.clone();
    let action_resume = resume.clone();
    let action = std::thread::spawn(move || {
        production::with_live_token(TOKEN, |control| {
            action_entered.wait();
            action_resume.wait();
            assert_eq!(control.generation.load(Ordering::Acquire), 1);
            control.cancel_pending.store(1, Ordering::Release);
        })
        .unwrap();
    });
    entered.wait();
    let (attempted_tx, attempted_rx) = std::sync::mpsc::channel();
    let reaper = std::thread::spawn(move || {
        CONTROL.state.store(THREAD_REAPING, Ordering::Release);
        KERNEL.lock().unwrap().recycle = true;
        attempted_tx.send(()).unwrap();
        production::replace(&CONTROL, 0);
        // Match actual reclamation: close source, reset, publish FREE,
        // then claim STARTING and publish the next generation.
        CONTROL.native_id.store(0, Ordering::Release);
        CONTROL.cancel_pending.store(0, Ordering::Release);
        CONTROL.state.store(THREAD_FREE, Ordering::Release);
        CONTROL.state.store(THREAD_STARTING, Ordering::Release);
        CONTROL.generation.store(2, Ordering::Release);
        CONTROL.native_id.store(18, Ordering::Release);
        production::replace(&CONTROL, 7);
        CONTROL.state.store(THREAD_RUNNING, Ordering::Release);
    });
    attempted_rx.recv().unwrap();
    assert_eq!(CONTROL.generation.load(Ordering::Acquire), 1);
    assert!(KERNEL.lock().unwrap().closed.is_empty());
    resume.wait();
    action.join().unwrap();
    reaper.join().unwrap();
    assert_eq!(CONTROL.cancel_pending.load(Ordering::Acquire), 0);
    assert_eq!(
        production::with_live_token(TOKEN, |_| panic!("old generation")),
        Err(ESRCH)
    );
    production::with_live_token(NEXT_TOKEN, |control| {
        control.cancel_pending.store(1, Ordering::Release)
    })
    .unwrap();
    assert_eq!(CONTROL.cancel_pending.load(Ordering::Acquire), 1);
}
