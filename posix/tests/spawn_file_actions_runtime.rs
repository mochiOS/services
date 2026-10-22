//! Execute production capture, callback ownership, list traversal and cleanup.
#![allow(dead_code)]
use mochios_posix_client::upcall_guard::Guard;
use mochios_posix_protocol as posix_protocol;
use std::sync::{
    Mutex,
    atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
};
use std::{
    ffi::{CStr, c_char, c_int, c_void},
    ptr,
};
#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
#[path = "../../../user/crates/newlib-runtime/src/spawn_file_actions.rs"]
mod implementation;
const EFAULT: c_int = 14;
const EIO: c_int = 5;
const EINVAL: c_int = 22;
const EAGAIN: c_int = 11;
const ENOMEM: c_int = 12;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const PAGE_SIZE: usize = 4096;
const FAE_OPEN: c_int = 0;
const FAE_DUP2: c_int = 1;
const FAE_CLOSE: c_int = 2;
const FAE_CHDIR: c_int = 3;
const FAE_FCHDIR: c_int = 4;
#[repr(C)]
#[derive(Clone, Copy)]
struct StailqHead<T> {
    stqh_first: *mut T,
    stqh_last: *mut *mut T,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct StailqEntry<T> {
    stqe_next: *mut T,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct PosixSpawnFileActions {
    fa_list: StailqHead<PosixSpawnFileActionsEntry>,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct PosixSpawnFileActionOpen {
    path: *mut c_char,
    oflag: c_int,
    mode: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct PosixSpawnFileActionDup2 {
    newfildes: c_int,
}
#[repr(C)]
#[derive(Clone, Copy)]
union PosixSpawnFileActionData {
    open: PosixSpawnFileActionOpen,
    dup2: PosixSpawnFileActionDup2,
    dir: *mut c_char,
    dirfd: c_int,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct PosixSpawnFileActionsEntry {
    fae_list: StailqEntry<PosixSpawnFileActionsEntry>,
    fae_action: c_int,
    fae_fildes: c_int,
    fae_data: PosixSpawnFileActionData,
}
static SERIAL: Mutex<()> = Mutex::new(());
static LIVE: Mutex<std::collections::BTreeSet<usize>> =
    Mutex::new(std::collections::BTreeSet::new());
static ALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
static FAIL_AT: AtomicUsize = AtomicUsize::new(0);
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
unsafe extern "C" {
    #[link_name = "malloc"]
    fn host_malloc(bytes: usize) -> *mut c_void;
    #[link_name = "free"]
    fn host_free(pointer: *mut c_void);
}
unsafe fn malloc(bytes: usize) -> *mut c_void {
    assert!(!CONTROL.callback_resources.is_empty());
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    let call = ALLOC_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    if call == FAIL_AT.load(Ordering::Relaxed) {
        return ptr::null_mut();
    }
    let pointer = unsafe { host_malloc(bytes) };
    if !pointer.is_null() {
        assert!(LIVE.lock().unwrap().insert(pointer as usize));
    }
    pointer
}
unsafe fn free(pointer: *mut c_void) {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    assert!(
        LIVE.lock().unwrap().remove(&(pointer as usize)),
        "must free only owned allocations exactly once"
    );
    unsafe { host_free(pointer) };
}
fn reset() {
    assert!(LIVE.lock().unwrap().is_empty());
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    ALLOC_CALLS.store(0, Ordering::Relaxed);
    FAIL_AT.store(0, Ordering::Relaxed);
    user_copy_native::DENIED.with_borrow_mut(|denied| *denied = None);
}
fn retired() {
    assert!(LIVE.lock().unwrap().is_empty());
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
}
fn entry(kind: c_int, fd: c_int, data: PosixSpawnFileActionData) -> PosixSpawnFileActionsEntry {
    PosixSpawnFileActionsEntry {
        fae_list: StailqEntry {
            stqe_next: ptr::null_mut(),
        },
        fae_action: kind,
        fae_fildes: fd,
        fae_data: data,
    }
}
fn object(entries: &mut [PosixSpawnFileActionsEntry]) -> PosixSpawnFileActions {
    let base = entries.as_mut_ptr();
    for index in 0..entries.len() {
        entries[index].fae_list.stqe_next = if index + 1 == entries.len() {
            ptr::null_mut()
        } else {
            unsafe { base.add(index + 1) }
        };
    }
    PosixSpawnFileActions {
        fa_list: StailqHead {
            stqh_first: if entries.is_empty() {
                ptr::null_mut()
            } else {
                base
            },
            stqh_last: usize::MAX as *mut _,
        },
    }
}
fn capture<T>(
    object: &mut PosixSpawnFileActions,
    mut apply: impl FnMut(&implementation::Actions) -> T,
) -> c_int {
    let handle = object as *mut _;
    let result = implementation::with(
        (&handle as *const *mut PosixSpawnFileActions).cast(),
        |actions| {
            assert!(!CONTROL.callback_resources.is_empty());
            assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
            apply(actions);
            0
        },
    );
    retired();
    result
}
fn describe(action: &implementation::Action) -> String {
    use implementation::Action::*;
    match action {
        Close(fd) => format!("close {fd}"),
        Dup2 { source, target } => format!("dup {source} {target}"),
        Open {
            fd,
            flags,
            mode,
            path,
        } => format!(
            "open {fd} {flags} {mode:o} {}",
            unsafe { CStr::from_ptr(path.as_ptr()) }.to_str().unwrap()
        ),
        Chdir(path) => format!(
            "chdir {}",
            unsafe { CStr::from_ptr(path.as_ptr()) }.to_str().unwrap()
        ),
        Fchdir(fd) => format!("fchdir {fd}"),
    }
}

#[test]
fn complete_list_and_paths_are_owned_before_first_action_and_keep_original_order() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    let mut path = b"relative\0".to_vec();
    let mut directory = b"/directory\0".to_vec();
    let mut entries = [
        entry(FAE_CLOSE, 3, PosixSpawnFileActionData { dirfd: 0 }),
        entry(
            FAE_DUP2,
            4,
            PosixSpawnFileActionData {
                dup2: PosixSpawnFileActionDup2 { newfildes: 5 },
            },
        ),
        entry(
            FAE_OPEN,
            6,
            PosixSpawnFileActionData {
                open: PosixSpawnFileActionOpen {
                    path: path.as_mut_ptr().cast(),
                    oflag: 513,
                    mode: 0o640,
                },
            },
        ),
        entry(
            FAE_CHDIR,
            0,
            PosixSpawnFileActionData {
                dir: directory.as_mut_ptr().cast(),
            },
        ),
        entry(FAE_FCHDIR, 0, PosixSpawnFileActionData { dirfd: 7 }),
    ];
    let mut list = object(&mut entries);
    let mut seen = vec![];
    assert_eq!(
        capture(&mut list, |actions| {
            actions
                .apply(|action| {
                    if seen.is_empty() {
                        entries.fill(entry(99, -1, PosixSpawnFileActionData { dirfd: 0 }));
                        path.fill(b'x');
                        directory.fill(b'x');
                    }
                    seen.push(describe(action));
                    Ok(())
                })
                .unwrap();
        }),
        0
    );
    assert_eq!(
        seen,
        [
            "close 3",
            "dup 4 5",
            "open 6 513 640 relative",
            "chdir /directory",
            "fchdir 7"
        ]
    );
}

#[test]
fn cycles_and_invalid_links_never_reach_application_or_provider_operations() {
    let _serial = SERIAL.lock().unwrap();
    for mode in 0..5 {
        reset();
        let mut entries = [entry(FAE_CLOSE, 3, PosixSpawnFileActionData { dirfd: 0 }); 2];
        let mut list = object(&mut entries);
        match mode {
            0 => entries[0].fae_list.stqe_next = entries.as_mut_ptr(),
            1 => entries[1].fae_list.stqe_next = entries.as_mut_ptr(),
            2 => entries[1].fae_list.stqe_next = 1usize as *mut _,
            3 => entries[1].fae_list.stqe_next = usize::MAX as *mut _,
            _ => entries[1].fae_action = 99,
        }
        let expected = if mode == 2 || mode == 3 {
            EFAULT
        } else {
            EINVAL
        };
        assert_eq!(
            capture(&mut list, |_| panic!(
                "must finish validation before execution"
            )),
            expected
        );
    }
    for address in [1usize, usize::MAX] {
        reset();
        assert_eq!(
            implementation::with(address as *const _, |_| panic!("invalid handle")),
            EFAULT
        );
        retired();
        let handle = address;
        assert_eq!(
            implementation::with((&handle as *const usize).cast(), |_| panic!(
                "invalid object"
            )),
            EFAULT
        );
        retired();
    }
}

#[test]
fn empty_lists_preserve_optional_behavior_without_allocations() {
    let _serial = SERIAL.lock().unwrap();
    for mode in 0..3 {
        reset();
        let mut entries = [];
        let mut list = object(&mut entries);
        let mut handle = &mut list as *mut _;
        let source = if mode == 0 {
            ptr::null()
        } else {
            if mode == 1 {
                handle = ptr::null_mut();
            }
            (&handle as *const *mut PosixSpawnFileActions).cast()
        };
        let mut count = 0;
        assert_eq!(
            implementation::with(source, |actions| {
                actions
                    .apply(|_| {
                        count += 1;
                        Ok(())
                    })
                    .unwrap();
                0
            }),
            0
        );
        assert_eq!(count, 0);
        assert_eq!(ALLOC_CALLS.load(Ordering::Relaxed), 0);
        retired();
    }
}

#[test]
fn path_faults_and_every_allocation_failure_release_all_partial_capture_owners() {
    let _serial = SERIAL.lock().unwrap();
    for failure in 0..=4 {
        reset();
        let path = c"file";
        let mut entries = [
            entry(
                FAE_CHDIR,
                0,
                PosixSpawnFileActionData {
                    dir: path.as_ptr().cast_mut(),
                },
            ),
            entry(
                FAE_OPEN,
                7,
                PosixSpawnFileActionData {
                    open: PosixSpawnFileActionOpen {
                        path: path.as_ptr().cast_mut(),
                        oflag: 0,
                        mode: 0,
                    },
                },
            ),
        ];
        let mut list = object(&mut entries);
        if failure == 0 {
            unsafe { entries[1].fae_data.open.path = 1usize as *mut _ };
        } else {
            FAIL_AT.store(failure, Ordering::Relaxed);
        }
        assert_eq!(
            capture(&mut list, |_| panic!(
                "failed capture must not apply a prefix"
            )),
            if failure == 0 { EFAULT } else { ENOMEM }
        );
    }
    reset();
    let mut path = vec![b'x'; posix_protocol::MAX_PATH_LEN + 2];
    path.push(0);
    let mut entries = [entry(
        FAE_CHDIR,
        0,
        PosixSpawnFileActionData {
            dir: path.as_mut_ptr().cast(),
        },
    )];
    let mut list = object(&mut entries);
    assert_eq!(
        capture(&mut list, |_| panic!("overlong path")),
        ENAMETOOLONG
    );
}

#[test]
fn action_count_is_not_limited_to_the_number_of_descriptors() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    let mut entries = vec![entry(FAE_CLOSE, 3, PosixSpawnFileActionData { dirfd: 0 }); 1025];
    let mut list = object(&mut entries);
    let mut count = 0;
    assert_eq!(
        capture(&mut list, |actions| {
            actions
                .apply(|_| {
                    count += 1;
                    Ok(())
                })
                .unwrap();
        }),
        0
    );
    assert_eq!(count, 1025);
}

#[test]
fn cycle_detection_remains_linear_with_acyclic_prefixes_and_varied_periods() {
    let _serial = SERIAL.lock().unwrap();
    for length in [1, 2, 3, 7, 8, 9, 17, 33] {
        for start in [0, length / 2, length - 1] {
            reset();
            let mut entries =
                vec![entry(FAE_CLOSE, 3, PosixSpawnFileActionData { dirfd: 0 }); length];
            let mut list = object(&mut entries);
            entries[length - 1].fae_list.stqe_next = unsafe { entries.as_mut_ptr().add(start) };
            assert_eq!(
                capture(&mut list, |_| panic!("cyclic list must not execute")),
                EINVAL
            );
            assert!(ALLOC_CALLS.load(Ordering::Relaxed) <= length * 4);
        }
    }
}

#[test]
fn apply_failure_stops_at_the_exact_action_and_retires_the_snapshot() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    let mut entries = [entry(FAE_CLOSE, 3, PosixSpawnFileActionData { dirfd: 0 }); 3];
    let mut list = object(&mut entries);
    let handle = &mut list as *mut _;
    let mut calls = 0;
    assert_eq!(
        implementation::with(
            (&handle as *const *mut PosixSpawnFileActions).cast(),
            |actions| {
                actions
                    .apply(|_| {
                        calls += 1;
                        if calls == 2 { Err(EIO) } else { Ok(()) }
                    })
                    .map(|_| 0)
                    .unwrap_or_else(|error| error)
            }
        ),
        EIO
    );
    assert_eq!(calls, 2);
    retired();
}
