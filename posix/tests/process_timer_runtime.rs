//! Actual runtime C entry points, checked user-copy and local registry, with
//! controlled RPC outcomes. This does not substitute for native IPC tests.
#![allow(dead_code)]
use mochios_posix_client::signal_context::SigInfo;
use mochios_posix_protocol as posix_protocol;
use posix_protocol::process_timer::{Clock, Notification, Value};
use std::ffi::{c_char, c_int, c_void};
use std::sync::{
    Mutex, MutexGuard,
    atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering},
};

#[path = "../../../user/crates/newlib-runtime/src/process_timer.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/signal_info.rs"]
mod signal_info;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
const EINVAL: c_int = 22;
const EFAULT: c_int = 14;
const EIO: c_int = 5;
const EAGAIN: c_int = 11;
const ENOSYS: c_int = 88;
const ENOTSUP: c_int = 134;
const EOVERFLOW: c_int = 139;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const PAGE_SIZE: usize = 4096;
mod thread_clock {
    pub fn is_id(id: u64) -> bool {
        id >= 1 << 32
    }
    pub fn timer_source(id: u64) -> Result<super::Clock, super::c_int> {
        if id == 1 << 32 {
            Ok(super::Clock::ThreadCpu)
        } else {
            Err(super::EINVAL)
        }
    }
    pub struct Reference;
    impl Reference {
        pub fn handle(&self) -> u32 {
            18
        }
    }
    impl Drop for Reference {
        fn drop(&mut self) {
            assert!(super::TARGET_PINNED.swap(false, super::Ordering::AcqRel));
        }
    }
    pub fn timer_target(id: u64) -> Result<(Reference, u64), super::c_int> {
        if id != 1 << 32 {
            return Err(super::EINVAL);
        }
        assert!(!super::TARGET_PINNED.swap(true, super::Ordering::AcqRel));
        Ok((Reference, 18))
    }
}
static TARGET_PINNED: AtomicBool = AtomicBool::new(false);
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}
struct ThreadControl {
    native_delivery_defer: AtomicU32,
    native_id: AtomicU64,
}
static CONTROL: ThreadControl = ThreadControl {
    native_delivery_defer: AtomicU32::new(0),
    native_id: AtomicU64::new(17),
};
static REGISTER: AtomicBool = AtomicBool::new(true);
static ERRNO: AtomicI32 = AtomicI32::new(0);
static SERIAL: Mutex<()> = Mutex::new(());
struct RuntimeState {
    thread_clocks: mochios_posix_client::thread_clock::Registry<64>,
    timer_values: mochios_posix_client::timer_value::Registry<usize, 128>,
    timer_cleanup: implementation::CleanupBook,
}
static STATE: Mutex<RuntimeState> = Mutex::new(RuntimeState {
    thread_clocks: mochios_posix_client::thread_clock::Registry::new(),
    timer_values: mochios_posix_client::timer_value::Registry::new(),
    timer_cleanup: implementation::CleanupBook::new(),
});
fn state() -> MutexGuard<'static, RuntimeState> {
    STATE.lock().unwrap()
}
fn current_thread_control() -> Option<(u32, &'static ThreadControl)> {
    Some((1, &CONTROL))
}
fn register_current_thread() -> Option<(u32, &'static ThreadControl)> {
    REGISTER.load(Ordering::Relaxed).then_some((1, &CONTROL))
}
fn result_with_errno(result: Result<c_int, c_int>, failure: c_int) -> c_int {
    result.unwrap_or_else(|error| {
        ERRNO.store(error, Ordering::Relaxed);
        failure
    })
}
fn map_posix_client_error(error: c_int) -> c_int {
    error
}

#[derive(Default)]
struct Rpc {
    next: u64,
    objects: Vec<u64>,
    creates: Vec<(Clock, Notification)>,
    deletes: Vec<u64>,
    sets: Vec<(u64, bool, Value)>,
    create_error: Option<c_int>,
    delete_error: Option<c_int>,
    failing_delete_id: Option<u64>,
    values: Value,
    overrun: u32,
}
static RPC: Mutex<Rpc> = Mutex::new(Rpc {
    next: 100,
    objects: Vec::new(),
    creates: Vec::new(),
    deletes: Vec::new(),
    sets: Vec::new(),
    create_error: None,
    delete_error: None,
    failing_delete_id: None,
    values: Value {
        remaining_ns: 0,
        interval_ns: 0,
    },
    overrun: 0,
});
struct FakeClient;
fn posix_client() -> Result<&'static FakeClient, c_int> {
    Ok(&FakeClient)
}
fn rpc() -> MutexGuard<'static, Rpc> {
    assert_ne!(CONTROL.native_delivery_defer.load(Ordering::Relaxed), 0);
    assert!(STATE.try_lock().is_ok(), "runtime lock held across RPC");
    RPC.lock().unwrap()
}
impl FakeClient {
    fn timer_create_for_thread(
        &self,
        handle: u32,
        notification: Notification,
    ) -> Result<u64, c_int> {
        assert_eq!(handle, 18);
        assert!(TARGET_PINNED.load(Ordering::Acquire));
        self.timer_create(Clock::ThreadCpu, notification)
    }
    fn timer_create(&self, clock: Clock, notification: Notification) -> Result<u64, c_int> {
        let mut rpc = rpc();
        rpc.creates.push((clock, notification));
        if let Some(error) = rpc.create_error {
            return Err(error);
        }
        rpc.next += 1;
        let id = rpc.next;
        rpc.objects.push(id);
        Ok(id)
    }
    fn timer_delete(&self, id: u64) -> Result<(), c_int> {
        let mut rpc = rpc();
        rpc.deletes.push(id);
        if let Some(error) = rpc.delete_error {
            return Err(error);
        }
        if rpc.failing_delete_id == Some(id) {
            return Err(EIO);
        }
        let index = rpc
            .objects
            .iter()
            .position(|object| *object == id)
            .ok_or(EINVAL)?;
        rpc.objects.remove(index);
        Ok(())
    }
    fn timer_value(&self, id: u64) -> Result<Value, c_int> {
        let rpc = rpc();
        if !rpc.objects.contains(&id) {
            return Err(EINVAL);
        }
        Ok(rpc.values)
    }
    fn timer_set(&self, id: u64, absolute: bool, value: Value) -> Result<Value, c_int> {
        let mut rpc = rpc();
        if !rpc.objects.contains(&id) {
            return Err(EINVAL);
        }
        rpc.sets.push((id, absolute, value));
        Ok(rpc.values)
    }
    fn timer_overrun(&self, id: u64) -> Result<u32, c_int> {
        let rpc = rpc();
        if !rpc.objects.contains(&id) {
            return Err(EINVAL);
        }
        Ok(rpc.overrun)
    }
}
fn reset() -> MutexGuard<'static, ()> {
    let serial = SERIAL.lock().unwrap();
    *RPC.lock().unwrap() = Rpc {
        next: 100,
        ..Rpc::default()
    };
    *state() = RuntimeState {
        thread_clocks: Default::default(),
        timer_values: Default::default(),
        timer_cleanup: implementation::CleanupBook::new(),
    };
    REGISTER.store(true, Ordering::Relaxed);
    CONTROL.native_delivery_defer.store(0, Ordering::Relaxed);
    CONTROL.native_id.store(17, Ordering::Relaxed);
    ERRNO.store(77, Ordering::Relaxed);
    serial
}
fn event(kind: i32, signal: i32, value: usize) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&kind.to_ne_bytes());
    bytes[4..8].copy_from_slice(&signal.to_ne_bytes());
    bytes[8..].copy_from_slice(&value.to_ne_bytes());
    bytes
}

#[test]
fn foreign_clock_notification_belongs_to_target_and_exit_publication_prevents_late_registration() {
    let _serial = reset();
    let target = mochios_posix_client::thread_clock::Target {
        thread: 64,
        native_thread: 18,
    };
    let clock = state().thread_clocks.get_or_insert(target).unwrap();
    assert_eq!(clock, 1 << 32);
    let event = event(2, 10, 0x1234);
    let mut timer = 0;
    assert_eq!(
        implementation::timer_create(clock, event.as_ptr().cast(), &mut timer),
        0
    );
    assert!(!TARGET_PINNED.load(Ordering::Acquire));
    let token = match RPC.lock().unwrap().creates[0].1 {
        Notification::Signal { value, .. } => value,
        _ => panic!("signal expected"),
    };
    implementation::thread_exit(17, || {
        assert!(
            STATE.try_lock().is_err(),
            "exit publication must hold registration lock"
        );
    });
    assert_eq!(
        state().timer_values.resolve(timer as u64, token),
        Ok(0x1234)
    );
    assert_eq!(state().thread_clocks.resolve(clock), Some(target));
    implementation::thread_exit(18, || {
        assert!(STATE.try_lock().is_err());
    });
    assert!(state().timer_values.resolve(timer as u64, token).is_err());
    assert_eq!(state().thread_clocks.resolve(clock), None);
    let creates = RPC.lock().unwrap().creates.len();
    assert_eq!(
        implementation::timer_create(clock, event.as_ptr().cast(), &mut timer),
        -1
    );
    assert_eq!(ERRNO.load(Ordering::Acquire), EINVAL);
    assert_eq!(RPC.lock().unwrap().creates.len(), creates);
    assert!(!TARGET_PINNED.load(Ordering::Acquire));

    let clock = state().thread_clocks.get_or_insert(target).unwrap();
    // The fixture selects just FIRST_ID; restore a fresh registry to exercise
    // remote failure without making its fake selector accept arbitrary IDs.
    assert!(clock > 1 << 32);
    state().thread_clocks = Default::default();
    let clock = state().thread_clocks.get_or_insert(target).unwrap();
    RPC.lock().unwrap().create_error = Some(EIO);
    assert_eq!(
        implementation::timer_create(clock, event.as_ptr().cast(), &mut timer),
        -1
    );
    assert_eq!(ERRNO.load(Ordering::Acquire), EIO);
    assert!(!TARGET_PINNED.load(Ordering::Acquire));
}
fn create_none() -> usize {
    let event = event(1, -1, usize::MAX);
    let mut id = 0;
    assert_eq!(
        implementation::timer_create(4, event.as_ptr().cast(), &mut id),
        0
    );
    id
}
fn record(interval: (i64, i64), value: (i64, i64)) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (index, number) in [interval.0, interval.1, value.0, value.1]
        .into_iter()
        .enumerate()
    {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&number.to_ne_bytes());
    }
    bytes
}

#[test]
fn silent_timer_uses_newlib_clock_flags_full_timespec_range_and_aliased_output() {
    let _serial = reset();
    let id = create_none();
    let old = Value {
        interval_ns: 123,
        remaining_ns: 4_000_000_005,
    };
    RPC.lock().unwrap().values = old;
    let expected = Value {
        interval_ns: 999_999_999,
        remaining_ns: i64::MAX as u128 * 1_000_000_000 + 999_999_999,
    };
    let mut storage = [0xA5; 34];
    storage[1..33].copy_from_slice(&record((0, 999_999_999), (i64::MAX, 999_999_999)));
    let pointer = storage[1..].as_mut_ptr();
    assert_eq!(
        implementation::timer_settime(id, 4, pointer.cast(), pointer.cast()),
        0
    );
    assert_eq!(RPC.lock().unwrap().sets, [(id as u64, true, expected)]);
    assert_eq!(&storage[1..33], &record((0, 123), (4, 5)));
    assert_eq!(storage[0], 0xA5);
    assert_eq!(storage[33], 0xA5);
    assert_eq!(implementation::timer_gettime(id, pointer.cast()), 0);
    RPC.lock().unwrap().overrun = i32::MAX as u32;
    assert_eq!(implementation::timer_getoverrun(id), i32::MAX);
    assert_eq!(implementation::timer_delete(id), 0);
    assert!(RPC.lock().unwrap().objects.is_empty());
    assert_eq!(ERRNO.load(Ordering::Relaxed), 77);
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Relaxed), 0);
}

#[test]
fn invalid_inputs_fail_before_creation_or_set_rpc() {
    let _serial = reset();
    let mut id = 0;
    let none = event(1, 0, 0);
    for (clock, error) in [(0, EINVAL), (5, EINVAL), (u64::MAX, EINVAL)] {
        assert_eq!(
            implementation::timer_create(clock, none.as_ptr().cast(), &mut id),
            -1
        );
        assert_eq!(ERRNO.load(Ordering::Relaxed), error);
    }
    assert_eq!(
        implementation::timer_create(1, 1usize as *const _, &mut id),
        -1
    );
    assert_eq!(ERRNO.load(Ordering::Relaxed), EFAULT);
    for input in [
        event(0, 0, 0),
        event(2, 0, 0),
        event(2, 65, 0),
        event(3, 1, 0),
    ] {
        assert_eq!(
            implementation::timer_create(1, input.as_ptr().cast(), &mut id),
            -1
        );
    }
    assert!(RPC.lock().unwrap().creates.is_empty());
    let id = create_none();
    for flags in [1, 2, 5, -1] {
        assert_eq!(
            implementation::timer_settime(id, flags, std::ptr::null(), std::ptr::null_mut()),
            -1
        );
        assert_eq!(ERRNO.load(Ordering::Relaxed), EINVAL);
    }
    for input in [
        record((-1, 0), (0, 0)),
        record((0, 0), (0, -1)),
        record((0, 0), (0, 1_000_000_000)),
    ] {
        assert_eq!(
            implementation::timer_settime(id, 0, input.as_ptr().cast(), std::ptr::null_mut()),
            -1
        );
        assert_eq!(ERRNO.load(Ordering::Relaxed), EINVAL);
    }
    assert!(RPC.lock().unwrap().sets.is_empty());
}

#[test]
fn newlib_thread_clock_id_maps_to_thread_bound_timer_without_serializing_identity() {
    let _serial = reset();
    let event = event(1, 0, 0);
    let mut id = 0;
    assert_eq!(
        implementation::timer_create(3, event.as_ptr().cast(), &mut id),
        0
    );
    assert_eq!(
        RPC.lock().unwrap().creates,
        [(Clock::ThreadCpu, Notification::None)]
    );
    assert_ne!(id, 0);
    assert_eq!(implementation::timer_delete(id), 0);
}

#[test]
fn exiting_thread_retires_only_its_clock_bound_values_without_rpc() {
    let _serial = reset();
    let event = event(2, 10, 0x1234);
    let mut first = 0;
    let mut shared = 0;
    let mut other = 0;
    assert_eq!(
        implementation::timer_create(3, event.as_ptr().cast(), &mut first),
        0
    );
    assert_eq!(
        implementation::timer_create(4, event.as_ptr().cast(), &mut shared),
        0
    );
    CONTROL.native_id.store(18, Ordering::Release);
    assert_eq!(
        implementation::timer_create(3, event.as_ptr().cast(), &mut other),
        0
    );
    let tokens: Vec<_> = RPC
        .lock()
        .unwrap()
        .creates
        .iter()
        .map(|&(_, notification)| match notification {
            Notification::Signal { value, .. } => value,
            _ => panic!(),
        })
        .collect();
    implementation::thread_exit(17, || {});
    assert_eq!(
        state().timer_values.resolve(first as u64, tokens[0]),
        Err(mochios_posix_client::timer_value::ResolveError::StaleToken)
    );
    assert_eq!(
        state().timer_values.resolve(shared as u64, tokens[1]),
        Ok(0x1234)
    );
    assert_eq!(
        state().timer_values.resolve(other as u64, tokens[2]),
        Ok(0x1234)
    );
    assert!(RPC.lock().unwrap().deletes.is_empty());
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let body = runtime
        .split("fn finish_thread(")
        .nth(1)
        .unwrap()
        .split("fn ")
        .next()
        .unwrap();
    assert!(
        body.find("run_thread_specific_destructors(control)")
            .unwrap()
            < body.find("process_timer::thread_exit(").unwrap()
    );
    assert!(
        body.find("process_timer::thread_exit(").unwrap()
            < body.find("control.state.store(THREAD_EXITED").unwrap()
    );
}

#[test]
fn notifying_creation_sends_only_local_cookie_and_retires_values_on_delete() {
    let _serial = reset();
    let raw = 0x1122334455667788;
    let event = event(2, 10, raw);
    let mut id = 0;
    assert_eq!(
        implementation::timer_create(2, event.as_ptr().cast(), &mut id),
        0
    );
    let token = match RPC.lock().unwrap().creates[0] {
        (Clock::ProcessCpu, Notification::Signal { signal: 10, value }) => value,
        other => panic!("{other:?}"),
    };
    assert_ne!(token, raw as u64);
    assert_eq!(state().timer_values.resolve(id as u64, token), Ok(raw));
    assert_eq!(implementation::timer_delete(id), 0);
    assert!(state().timer_values.resolve(id as u64, token).is_err());
    assert_eq!(
        implementation::timer_create(1, std::ptr::null(), &mut id),
        0
    );
    let (_, Notification::Signal { signal: 14, value }) = RPC.lock().unwrap().creates[1] else {
        panic!()
    };
    assert_eq!(state().timer_values.resolve(id as u64, value), Ok(id));
}

#[test]
fn unsupported_service_notifications_release_every_local_reservation() {
    let _serial = reset();
    RPC.lock().unwrap().create_error = Some(ENOSYS);
    let input = event(2, 10, usize::MAX);
    let mut id = 47;
    for _ in 0..300 {
        assert_eq!(
            implementation::timer_create(1, input.as_ptr().cast(), &mut id),
            -1
        );
        assert_eq!(ERRNO.load(Ordering::Relaxed), ENOSYS);
        assert_eq!(id, 47);
    }
    assert!(RPC.lock().unwrap().deletes.is_empty());
    RPC.lock().unwrap().create_error = None;
    create_none();
}

#[test]
fn failed_copyout_deletes_new_timer_and_retains_failed_deletions_for_retry() {
    let _serial = reset();
    let input = event(2, 10, 1234);
    RPC.lock().unwrap().delete_error = Some(EIO);
    assert_eq!(
        implementation::timer_create(1, input.as_ptr().cast(), 1usize as *mut _),
        -1
    );
    assert_eq!(ERRNO.load(Ordering::Relaxed), EFAULT);
    assert_eq!(RPC.lock().unwrap().objects, [101]);
    assert_eq!(
        state().timer_values.resolve(101, 1),
        Err(mochios_posix_client::timer_value::ResolveError::StaleToken)
    );
    RPC.lock().unwrap().delete_error = None;
    let id = create_none();
    assert_eq!(RPC.lock().unwrap().objects, [id as u64]);
    assert!(
        RPC.lock()
            .unwrap()
            .deletes
            .iter()
            .filter(|id| **id == 101)
            .count()
            >= 2
    );
}

#[test]
fn cleanup_capacity_is_reserved_before_rpc_and_recovery_releases_it() {
    let _serial = reset();
    let input = event(1, 0, 0);
    RPC.lock().unwrap().delete_error = Some(EIO);
    for _ in 0..128 {
        assert_eq!(
            implementation::timer_create(1, input.as_ptr().cast(), 1usize as *mut _),
            -1
        );
        assert_eq!(ERRNO.load(Ordering::Relaxed), EFAULT);
    }
    let before = RPC.lock().unwrap().creates.len();
    let mut id = 0;
    assert_eq!(
        implementation::timer_create(1, input.as_ptr().cast(), &mut id),
        -1
    );
    assert_eq!(ERRNO.load(Ordering::Relaxed), EAGAIN);
    assert_eq!(RPC.lock().unwrap().creates.len(), before);
    RPC.lock().unwrap().delete_error = None;
    // Every entry is eventually retried; a failed early ID cannot starve later entries.
    for _ in 0..128 {
        implementation::timer_getoverrun(0);
    }
    assert!(RPC.lock().unwrap().objects.is_empty());
    create_none();
}

#[test]
fn one_failed_cleanup_cannot_starve_later_ids_and_absence_finishes_retirement() {
    let _serial = reset();
    let input = event(1, 0, 0);
    RPC.lock().unwrap().delete_error = Some(EIO);
    for _ in 0..3 {
        assert_eq!(
            implementation::timer_create(1, input.as_ptr().cast(), 1usize as *mut _),
            -1
        );
    }
    {
        let mut rpc = RPC.lock().unwrap();
        rpc.delete_error = None;
        rpc.failing_delete_id = Some(101);
    }
    for _ in 0..5 {
        implementation::timer_getoverrun(0);
    }
    assert_eq!(RPC.lock().unwrap().objects, [101]);
    // Simulate authoritative owner cleanup having already removed that ID.
    {
        let mut rpc = RPC.lock().unwrap();
        rpc.failing_delete_id = None;
        rpc.objects.clear();
    }
    implementation::timer_getoverrun(0);
    let count = RPC.lock().unwrap().deletes.len();
    implementation::timer_getoverrun(0);
    assert_eq!(RPC.lock().unwrap().deletes.len(), count);
}

#[test]
fn failed_delete_keeps_value_until_success_or_authoritative_absence() {
    let _serial = reset();
    let mut id = 0;
    assert_eq!(
        implementation::timer_create(1, std::ptr::null(), &mut id),
        0
    );
    let (_, Notification::Signal { value: token, .. }) = RPC.lock().unwrap().creates[0] else {
        panic!()
    };
    RPC.lock().unwrap().delete_error = Some(EIO);
    assert_eq!(implementation::timer_delete(id), -1);
    assert_eq!(state().timer_values.resolve(id as u64, token), Ok(id));
    {
        let mut rpc = RPC.lock().unwrap();
        rpc.delete_error = None;
        rpc.objects.clear();
    }
    assert_eq!(implementation::timer_delete(id), -1);
    assert_eq!(ERRNO.load(Ordering::Relaxed), EINVAL);
    assert!(state().timer_values.resolve(id as u64, token).is_err());
}

#[test]
fn registration_overflow_and_bad_outputs_do_not_panic_or_publish_unchecked_data() {
    let _serial = reset();
    REGISTER.store(false, Ordering::Relaxed);
    let input = event(1, 0, 0);
    let mut id = 0;
    assert_eq!(
        implementation::timer_create(1, input.as_ptr().cast(), &mut id),
        -1
    );
    assert_eq!(ERRNO.load(Ordering::Relaxed), EAGAIN);
    REGISTER.store(true, Ordering::Relaxed);
    CONTROL
        .native_delivery_defer
        .store(u32::MAX, Ordering::Relaxed);
    assert_eq!(
        implementation::timer_create(1, input.as_ptr().cast(), &mut id),
        -1
    );
    assert_eq!(ERRNO.load(Ordering::Relaxed), EOVERFLOW);
    CONTROL.native_delivery_defer.store(0, Ordering::Relaxed);
    assert!(RPC.lock().unwrap().creates.is_empty());
    let id = create_none();
    assert_eq!(implementation::timer_gettime(id, 1usize as *mut _), -1);
    assert_eq!(ERRNO.load(Ordering::Relaxed), EFAULT);
    assert_eq!(implementation::timer_delete(0), -1);
    assert_eq!(ERRNO.load(Ordering::Relaxed), EINVAL);
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Relaxed), 0);
}

fn timer_origin(id: u64, token: u64) -> posix_protocol::signal_origin::Origin {
    use posix_protocol::signal_origin::{Origin, TIMER, TimerStatus};
    Origin {
        source: TIMER,
        timer: Some(TimerStatus {
            timer_id: id,
            value_token: token,
            overrun: 7,
        }),
        ..Origin::system()
    }
}

#[test]
fn actual_timer_creation_resolves_local_sigval_before_deletion_without_leaking_cookie_bits() {
    let _serial = reset();
    for raw in [0, 0x1122334455667788, usize::MAX] {
        let event = event(2, 10, raw);
        let mut id = 0;
        assert_eq!(
            implementation::timer_create(1, event.as_ptr().cast(), &mut id),
            0
        );
        let (_, Notification::Signal { value: token, .. }) =
            *RPC.lock().unwrap().creates.last().unwrap()
        else {
            panic!()
        };
        let origin = timer_origin(id as u64, token);
        let prepared = signal_info::prepare(10, origin).unwrap().unwrap();
        // A copied snapshot remains valid; it does not hold STATE or the slot.
        assert_eq!(implementation::timer_delete(id), 0);
        let info = prepared.into_info().unwrap();
        assert_eq!((info.si_signo, info.si_code), (10, 3));
        assert_eq!(unsafe { info.si_value.sival_ptr }, raw);
        assert_eq!(
            (
                info.si_errno,
                info.si_pid,
                info.si_uid,
                info.reserved_uid,
                info.si_status,
                info.si_addr
            ),
            (0, 0, 0, 0, 0, 0)
        );
        assert!(signal_info::prepare(10, origin).unwrap().is_none());
        // Stale metadata must never resolve through the next occupied slot.
        let new_id = create_none();
        assert_ne!(new_id, id);
        assert!(signal_info::prepare(10, origin).unwrap().is_none());
        assert_eq!(implementation::timer_delete(new_id), 0);
    }
}

#[test]
fn malformed_unknown_unbound_and_wrong_timer_values_are_not_retired_notifications() {
    let _serial = reset();
    let token = state().timer_values.reserve(0x1234).unwrap();
    assert!(matches!(
        signal_info::prepare(10, timer_origin(101, token.raw())),
        Err(EIO)
    ));
    state().timer_values.bind(token, 101).unwrap();
    for (id, cookie) in [(101, 0), (101, token.raw() + 1), (102, token.raw())] {
        assert!(matches!(
            signal_info::prepare(10, timer_origin(id, cookie)),
            Err(EIO)
        ));
    }
    state().timer_values.retire(101);
    let origin = timer_origin(101, token.raw());
    assert!(signal_info::prepare(10, origin).unwrap().is_none());
    let mut cases = vec![origin; 6];
    cases[0].timer = None;
    cases[1].timer.as_mut().unwrap().overrun = u32::MAX;
    cases[2].timer.as_mut().unwrap().timer_id = 0;
    cases[3].process_id = 9;
    cases[4].real_uid = 7;
    cases[5].child.status = 1;
    for bad in cases {
        assert!(matches!(signal_info::prepare(10, bad), Err(EIO)));
    }
    for signal in [0, 65, u32::MAX] {
        assert!(matches!(signal_info::prepare(signal, origin), Err(EIO)));
    }
}

#[test]
fn ordinary_plain_delivery_does_not_narrow_identity_but_siginfo_still_checks_c_overflow() {
    let _serial = reset();
    use posix_protocol::signal_origin::{Origin, USER};
    let origin = Origin {
        source: USER,
        process_id: i32::MAX as u64 + 1,
        real_uid: 0,
        ..Origin::system()
    };
    let prepared = signal_info::prepare(10, origin).unwrap().unwrap();
    assert!(matches!(prepared.into_info(), Err(EOVERFLOW)));
    let info = signal_info::prepare(10, Origin::system())
        .unwrap()
        .unwrap()
        .into_info()
        .unwrap();
    assert_eq!((info.si_signo, info.si_code), (10, 128));
}
