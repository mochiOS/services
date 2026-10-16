use std::sync::Mutex;
use std::ffi::c_int;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use mochios_posix_client::upcall_guard::Guard;
#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod implementation;

const EAGAIN: c_int = 11;
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
static LOCK: Mutex<()> = Mutex::new(());
static DROPS: AtomicU32 = AtomicU32::new(0);
static PREPARE_FAIL: AtomicU32 = AtomicU32::new(0);
fn register_current_thread() -> Option<(u32, &'static ThreadControl)> {
    Some((1, &CONTROL))
}
fn defer_native_delivery() -> Option<Guard<'static>> {
    Guard::enter(&CONTROL.native)
}
struct Resource(u32);
impl Drop for Resource {
    fn drop(&mut self) {
        assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
        DROPS.fetch_add(1, Ordering::Relaxed);
    }
}
fn prepare() -> Result<Resource, i32> {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    if PREPARE_FAIL.load(Ordering::Relaxed) != 0 {
        Err(9)
    } else {
        Ok(Resource(7))
    }
}
fn reset() {
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    CONTROL.active_signal_scope_id.store(0, Ordering::Relaxed);
    DROPS.store(0, Ordering::Relaxed);
    PREPARE_FAIL.store(0, Ordering::Relaxed);
}
#[test]
fn success_and_error_retire_before_return_without_delaying_callbacks() {
    let _lock = LOCK.lock().unwrap();
    for result in [Ok(7), Ok(0), Err(4)] {
        reset();
        assert_eq!(
            implementation::with(prepare, |resource| {
                assert_eq!(resource.0, 7);
                assert!(!CONTROL.callback_resources.is_empty());
                assert!(!CONTROL.callback_resources.is_deferred());
                assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
                assert!(!CONTROL.callback_resources.record_notification());
                result
            }),
            result
        );
        assert_eq!(DROPS.load(Ordering::Relaxed), 1);
        assert!(CONTROL.callback_resources.is_empty());
    }
    reset();
    PREPARE_FAIL.store(1, Ordering::Relaxed);
    assert_eq!(
        implementation::with(prepare, |_| panic!("failed preparation reached I/O")),
        Err::<isize, _>(9)
    );
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(DROPS.load(Ordering::Relaxed), 0);
}
#[test]
fn nested_returning_handler_preserves_parent_ownership() {
    let _lock = LOCK.lock().unwrap();
    reset();
    assert_eq!(
        implementation::with(prepare, |parent| {
            CONTROL.active_signal_scope_id.store(7, Ordering::Relaxed);
            assert_eq!(
                implementation::with(prepare, |child| {
                    assert_eq!((parent.0, child.0), (7, 7));
                    Ok(2)
                }),
                Ok(2)
            );
            CONTROL.active_signal_scope_id.store(0, Ordering::Relaxed);
            assert!(!CONTROL.callback_resources.is_empty());
            assert_eq!(DROPS.load(Ordering::Relaxed), 1);
            Ok(3)
        }),
        Ok(3)
    );
    assert_eq!(DROPS.load(Ordering::Relaxed), 2);
    assert!(CONTROL.callback_resources.is_empty());
}

#[test]
fn initialization_runs_after_tracking_but_before_any_delivery_reopens() {
    let _lock = LOCK.lock().unwrap();
    for fail in [false, true] {
        reset();
        let mut ran = false;
        let result = implementation::with_initialized(
            prepare,
            |resource| {
                assert!(!CONTROL.callback_resources.is_empty());
                assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
                resource.0 = 11;
                if fail { Err(14) } else { Ok(()) }
            },
            |resource| {
                assert_eq!(resource.0, 11);
                assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
                ran = true;
                Ok(7)
            },
        );
        assert_eq!(result, if fail { Err(14) } else { Ok(7) });
        assert_eq!(ran, !fail);
        assert_eq!(DROPS.load(Ordering::Relaxed), 1);
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn copied_record_outcome_owns_no_resource_after_the_scope_retires() {
    let _lock = LOCK.lock().unwrap();
    reset();
    let result = implementation::with(prepare, |resource| {
        assert!(!CONTROL.callback_resources.is_empty());
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
        Ok((resource.0, [17u8; 128], Some(9isize)))
    });
    assert_eq!(result, Ok((7, [17; 128], Some(9))));
    assert_eq!(DROPS.load(Ordering::Relaxed), 1);
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
}

#[test]
fn every_public_io_path_tracks_its_owned_lease_and_vector_storage() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for signature in [
        "pub extern \"C\" fn _read(",
        "pub extern \"C\" fn _write(",
        "pub unsafe extern \"C\" fn readv(",
        "pub unsafe extern \"C\" fn writev(",
        "fn positioned_file_io(",
    ] {
        let start = source.find(signature).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap();
        assert!(
            source[start..end].contains("io_resources::with"),
            "{signature}"
        );
    }
}

#[test]
fn terminal_entry_points_keep_leases_tracked_through_callbacks_and_user_copies() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for name in [
        "tcgetwinsize",
        "tcsetwinsize",
        "_isatty",
        "tcgetattr",
        "tcsetattr",
        "tcdrain",
        "tcflush",
        "tcflow",
        "tcgetpgrp",
        "tcsetpgrp",
        "login_tty",
    ] {
        let signature = format!("fn {name}(");
        let start = source.find(&signature).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap();
        let body = &source[start..end];
        assert!(body.contains("io_resources::with"), "{name}");
        if matches!(name, "tcsetattr" | "tcsetwinsize") {
            assert!(body.contains("io_resources::with_initialized"), "{name}");
            assert!(
                body.find("with_fd_entry(fd)").unwrap()
                    < body.find("terminal_memory::read_").unwrap()
            );
        }
        if name == "tcdrain" {
            assert!(body.contains("pthread_testcancel()"));
            assert!(body.contains("finish_io_cancellation(result_with_errno(result, -1))"));
        }
    }
}

#[test]
fn descriptor_metadata_and_sync_paths_keep_the_source_tracked_until_return() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for name in [
        "fchmod",
        "fchown",
        "_lseek",
        "sync_file_descriptor",
        "_fstat",
    ] {
        let signature = format!("fn {name}(");
        let start = source.find(&signature).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap();
        let body = &source[start..end];
        assert!(body.contains("io_resources::with"), "{name}");
        assert!(body.contains("|| with_fd_entry(fd)"), "{name}");
        if name == "_fstat" {
            for kind in [
                "ObjectSharedMemory",
                "is_socket()",
                "ObjectFile",
                "ObjectSpecial",
                "ObjectDirectory",
                "ObjectStreamRead",
                "ObjectStreamWrite",
                "ObjectPty",
            ] {
                assert!(body.contains(kind), "{kind}");
            }
            assert!(body.contains("stat_output::write(stat_buf,"));
            assert!(!body.contains("ptr::write(stat_buf.cast::<NewlibStat>()"));
        }
    }
}

#[test]
fn socket_control_paths_keep_the_source_tracked_through_user_memory_access() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/socket.rs");
    for name in [
        "setsockopt",
        "getsockopt",
        "bind",
        "listen",
        "socket_name",
        "shutdown",
    ] {
        let signature = format!("fn {name}(");
        let start = source.find(&signature).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap();
        let body = &source[start..end];
        assert!(body.contains("io_resources::with"), "{name}");
        assert!(body.contains("|| with_fd_entry(fd)"), "{name}");
    }
}

#[test]
fn multiplex_waits_own_partial_lease_arrays_and_snapshot_poll_inputs_before_callbacks() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for name in ["select_with_deadline", "poll_with_deadline"] {
        let start = source.find(&format!("fn {name}(")).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap();
        let body = &source[start..end];
        assert!(body.contains("io_resources::with"), "{name}");
        assert!(
            !body.contains("let mut leases ="),
            "untracked lease array: {name}"
        );
        assert!(
            body.contains("defer_native_delivery()"),
            "publication gap: {name}"
        );
        if name == "poll_with_deadline" {
            assert!(body.contains("io_resources::with_initialized"));
            assert!(
                body.find("multiplex_memory::read_pollfds(fds,").unwrap()
                    < body.find("socket::poll_events(").unwrap()
            );
        }
    }
}
