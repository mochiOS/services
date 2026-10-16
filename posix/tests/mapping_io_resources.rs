//! Execute mmap's production source owner, not a duplicate lease model.
use mochios_posix_client::upcall_guard::Guard;
use std::ffi::c_int;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/mapping_io.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;

const EAGAIN: c_int = 11;
const EBADF: c_int = 9;
static SERIAL: Mutex<()> = Mutex::new(());
static PINS: AtomicU32 = AtomicU32::new(0);
static RETIRED: AtomicU32 = AtomicU32::new(0);
static CLOSED: AtomicU32 = AtomicU32::new(0);
static LOOKUPS: AtomicU32 = AtomicU32::new(0);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FdEntry(u64);
struct ThreadControl {
    callback_resources: callback_resources::Chain,
    active_signal_scope_id: AtomicU64,
    native: AtomicU32,
}
static CONTROL: ThreadControl = ThreadControl {
    callback_resources: callback_resources::Chain::new(),
    active_signal_scope_id: AtomicU64::new(0),
    native: AtomicU32::new(0),
};
fn register_current_thread() -> Option<(u32, &'static ThreadControl)> {
    Some((1, &CONTROL))
}
fn defer_native_delivery() -> Option<Guard<'static>> {
    Guard::enter(&CONTROL.native)
}
struct Lease(FdEntry);
impl std::ops::Deref for Lease {
    type Target = FdEntry;
    fn deref(&self) -> &FdEntry {
        &self.0
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
        assert_eq!(PINS.fetch_sub(1, Ordering::Relaxed), 1);
        if RETIRED.load(Ordering::Relaxed) != 0 {
            CLOSED.fetch_add(1, Ordering::Relaxed);
        }
    }
}
fn with_fd_entry(fd: c_int) -> Result<Lease, c_int> {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    LOOKUPS.fetch_add(1, Ordering::Relaxed);
    if fd != 7 {
        return Err(EBADF);
    }
    assert_eq!(PINS.fetch_add(1, Ordering::Relaxed), 0);
    Ok(Lease(FdEntry(42)))
}
fn reset() {
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(PINS.load(Ordering::Relaxed), 0);
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    RETIRED.store(0, Ordering::Relaxed);
    CLOSED.store(0, Ordering::Relaxed);
    LOOKUPS.store(0, Ordering::Relaxed);
}

#[test]
fn source_survives_reentrant_close_until_mapping_success_or_error() {
    let _serial = SERIAL.lock().unwrap();
    for outcome in [Ok(0x10000u64), Err(12), Err(13), Err(4)] {
        reset();
        assert_eq!(
            implementation::with_source(false, 7, |source| {
                assert_eq!(source, Some(FdEntry(42)));
                assert_eq!(PINS.load(Ordering::Relaxed), 1);
                assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
                assert!(!CONTROL.callback_resources.is_deferred());
                assert!(!CONTROL.callback_resources.is_empty());
                // A callback closes/reuses fd 7. The captured object stays alive;
                // neither policy lookup nor map may look that FD up again.
                RETIRED.store(1, Ordering::Relaxed);
                assert_eq!(CLOSED.load(Ordering::Relaxed), 0);
                outcome
            }),
            outcome
        );
        assert_eq!(CLOSED.load(Ordering::Relaxed), 1);
        assert_eq!(LOOKUPS.load(Ordering::Relaxed), 1);
        reset();
    }
}

#[test]
fn abandoned_mapping_releases_the_source_once_before_thread_frame_disposal() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    implementation::with_source(false, 7, |source| {
        assert_eq!(source, Some(FdEntry(42)));
        RETIRED.store(1, Ordering::Relaxed);
        let _native = defer_native_delivery();
        unsafe { CONTROL.callback_resources.abandon_from(0) };
        assert_eq!(CLOSED.load(Ordering::Relaxed), 1);
        // The simulation returns without touching the abandoned resource.
        // The scope's normal retirement must not release it a second time.
        Ok(())
    })
    .unwrap();
    assert_eq!(CLOSED.load(Ordering::Relaxed), 1);
    reset();
}

#[test]
fn anonymous_mapping_ignores_fd_without_registering_a_borrow() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    for fd in [-1, 7, c_int::MAX] {
        implementation::with_source(true, fd, |source| {
            assert_eq!(source, None);
            assert!(CONTROL.callback_resources.is_empty());
            Ok(())
        })
        .unwrap();
    }
    assert_eq!(LOOKUPS.load(Ordering::Relaxed), 0);
    reset();
}

#[test]
fn invalid_file_descriptor_never_reaches_policy_or_native_map() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    assert_eq!(
        implementation::with_source(false, -1, |_| -> Result<(), c_int> {
            panic!("invalid source reached mapper")
        }),
        Err(EBADF)
    );
    reset();
}

#[test]
fn public_mmap_keeps_validation_and_the_entire_map_inside_the_source_owner() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let body = source
        .split("pub extern \"C\" fn mmap(")
        .nth(1)
        .unwrap()
        .split("pub extern \"C\" fn munmap(")
        .next()
        .unwrap();
    assert!(body.find("if len == 0").unwrap() < body.find("mapping_io::with_source").unwrap());
    assert!(
        body.find("mapping_io::with_source").unwrap()
            < body.find("address_space::current()?").unwrap()
    );
    assert!(!body.contains("with_fd_entry("));
    assert!(body.contains("entry.rights & required != required"));
}
