//! Execute both production search entry points with checked caller-memory copy.
#![allow(dead_code, non_upper_case_globals)]
use mochios_posix_client::upcall_guard::Guard;
use mochios_posix_protocol as posix_protocol;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::ptr;
use std::sync::{
    Mutex,
    atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
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
#[path = "../../../user/crates/newlib-runtime/src/exec_inputs.rs"]
mod exec_inputs;
#[path = "../../../user/crates/newlib-runtime/src/exec_interpreter.rs"]
mod exec_interpreter;
#[path = "../../../user/crates/newlib-runtime/src/exec_search.rs"]
mod implementation;
const MAX_EXEC_VECTOR_ENTRIES: usize = 256;
const MAX_EXECUTABLE_PATH_LEN: usize = 256;
const ENOEXEC: c_int = 8;
const E2BIG: c_int = 7;
const EFAULT: c_int = 14;
const EIO: c_int = 5;
const EINVAL: c_int = 22;
const ENOENT: c_int = 2;
const ENOMEM: c_int = 12;
const EAGAIN: c_int = 11;
const ENAMETOOLONG: c_int = 91;
const PAGE_SIZE: usize = 4096;
static SERIAL: Mutex<()> = Mutex::new(());
static PATH: AtomicUsize = AtomicUsize::new(0);
static PATH_READS: AtomicUsize = AtomicUsize::new(0);
static MUTATE_FILE: AtomicUsize = AtomicUsize::new(0);
static MUTATE_PATH: AtomicUsize = AtomicUsize::new(0);
static ERRNO: AtomicU32 = AtomicU32::new(0);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static ALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
static FAIL_ALLOCATION: AtomicUsize = AtomicUsize::new(0);
unsafe extern "C" {
    #[link_name = "malloc"]
    fn host_malloc(bytes: usize) -> *mut c_void;
    #[link_name = "free"]
    fn host_free(pointer: *mut c_void);
}
unsafe fn malloc(bytes: usize) -> *mut c_void {
    let call = ALLOC_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    if FAIL_ALLOCATION.load(Ordering::Relaxed) == call {
        return ptr::null_mut();
    }
    let pointer = unsafe { host_malloc(bytes) };
    if !pointer.is_null() {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
    pointer
}
unsafe fn free(pointer: *mut c_void) {
    assert!(!pointer.is_null());
    assert!(ALLOCATIONS.fetch_sub(1, Ordering::Relaxed) > 0);
    unsafe { host_free(pointer) };
}
static CALLS: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
static REPLIES: Mutex<std::collections::VecDeque<c_int>> =
    Mutex::new(std::collections::VecDeque::new());
static EXPECT: Mutex<[usize; 6]> = Mutex::new([0; 6]);
static SHELL_ARGUMENTS: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
static SHELL_ENVIRONMENT: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
static SHELL_MUTATIONS: Mutex<Vec<usize>> = Mutex::new(Vec::new());
static mut environ: *mut *mut c_char = std::ptr::null_mut();
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
unsafe fn getenv(name: *const c_char) -> *mut c_char {
    assert_eq!(unsafe { CStr::from_ptr(name) }.to_bytes(), b"PATH");
    assert!(!CONTROL.callback_resources.is_empty());
    PATH_READS.fetch_add(1, Ordering::Relaxed);
    PATH.load(Ordering::Relaxed) as *mut _
}
fn result_with_errno(result: Result<c_int, c_int>, fallback: c_int) -> c_int {
    match result {
        Ok(value) => value,
        Err(error) => {
            ERRNO.store(error as u32, Ordering::Relaxed);
            fallback
        }
    }
}
fn execute(path: *const c_char) -> c_int {
    assert!(!CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    CALLS
        .lock()
        .unwrap()
        .push(unsafe { CStr::from_ptr(path) }.to_bytes().to_vec());
    for pointer in [&MUTATE_FILE, &MUTATE_PATH] {
        let address = pointer.swap(0, Ordering::Relaxed);
        if address != 0 {
            unsafe {
                (address as *mut u8).write(b'z');
            }
        }
    }
    REPLIES
        .lock()
        .unwrap()
        .pop_front()
        .expect("unexpected candidate")
}
fn execve_with_launch_context(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> Result<(), c_int> {
    if unsafe { CStr::from_ptr(path) }.to_bytes() == b"/bin/sh" {
        for address in SHELL_MUTATIONS.lock().unwrap().drain(..) {
            unsafe { (address as *mut u8).write(b'z') };
        }
        let read = |vector: *const *const c_char| {
            let mut result = Vec::new();
            for index in 0..MAX_EXEC_VECTOR_ENTRIES {
                let pointer = unsafe { vector.add(index).read() };
                if pointer.is_null() {
                    return result;
                }
                result.push(unsafe { CStr::from_ptr(pointer) }.to_bytes().to_vec());
            }
            panic!("interpreter vector is not terminated");
        };
        *SHELL_ARGUMENTS.lock().unwrap() = read(argv);
        *SHELL_ENVIRONMENT.lock().unwrap() = read(envp);
    } else {
        let expected = EXPECT.lock().unwrap();
        assert_eq!([argv as usize, envp as usize], [expected[4], expected[5]]);
    }
    let error = execute(path);
    if error == 0 { Ok(()) } else { Err(error) }
}
fn _posix_spawn(
    pid: *mut c_int,
    path: *const c_char,
    actions: *const c_void,
    attributes: *const c_void,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    let expected = EXPECT.lock().unwrap();
    assert_eq!(
        [
            pid as usize,
            0,
            actions as usize,
            attributes as usize,
            argv as usize,
            envp as usize
        ],
        *expected
    );
    drop(expected);
    execute(path)
}
fn reset(path: *const c_char, replies: &[c_int]) {
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 0);
    ALLOC_CALLS.store(0, Ordering::Relaxed);
    FAIL_ALLOCATION.store(0, Ordering::Relaxed);
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    PATH.store(path as usize, Ordering::Relaxed);
    PATH_READS.store(0, Ordering::Relaxed);
    MUTATE_FILE.store(0, Ordering::Relaxed);
    MUTATE_PATH.store(0, Ordering::Relaxed);
    ERRNO.store(0, Ordering::Relaxed);
    CALLS.lock().unwrap().clear();
    *REPLIES.lock().unwrap() = replies.iter().copied().collect();
    *EXPECT.lock().unwrap() = [0; 6];
    SHELL_ARGUMENTS.lock().unwrap().clear();
    SHELL_ENVIRONMENT.lock().unwrap().clear();
    SHELL_MUTATIONS.lock().unwrap().clear();
    user_copy_native::DENIED.with_borrow_mut(|denied| *denied = None);
}

fn call_exec(file: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    unsafe {
        environ = envp.cast_mut().cast();
    }
    *EXPECT.lock().unwrap() = [0, 0, 0, 0, argv as usize, envp as usize];
    let result = implementation::execvp(file, argv.cast());
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 0);
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    if result == -1 {
        ERRNO.load(Ordering::Relaxed) as c_int
    } else {
        result
    }
}

#[test]
fn execvp_uses_the_selected_candidate_and_interpreter_failure_ends_path_search() {
    let _serial = SERIAL.lock().unwrap();
    reset(c"/one:/two:/three".as_ptr(), &[2, ENOEXEC, 0]);
    assert_eq!(call(false, c"tool".as_ptr()), 0);
    assert_eq!(
        *CALLS.lock().unwrap(),
        [
            b"/one/tool".to_vec(),
            b"/two/tool".to_vec(),
            b"/bin/sh".to_vec()
        ]
    );
    assert_eq!(
        *SHELL_ARGUMENTS.lock().unwrap(),
        [b"sh".to_vec(), b"/two/tool".to_vec()]
    );
    assert_eq!(*SHELL_ENVIRONMENT.lock().unwrap(), [b"K=explicit".to_vec()]);
    for error in [2, 13, ENOEXEC, EINVAL, ENOMEM] {
        reset(c"/one:/two".as_ptr(), &[ENOEXEC, error]);
        assert_eq!(call(false, c"tool".as_ptr()), error);
        assert_eq!(
            *CALLS.lock().unwrap(),
            [b"/one/tool".to_vec(), b"/bin/sh".to_vec()]
        );
    }
    // spawnp returns the format error; it must not introduce a shell process.
    reset(c"/one:/two".as_ptr(), &[ENOEXEC]);
    assert_eq!(call(true, c"tool".as_ptr()), ENOEXEC);
    assert_eq!(*CALLS.lock().unwrap(), [b"/one/tool".to_vec()]);
}

#[test]
fn non_format_failures_never_invoke_an_interpreter_and_slash_paths_do_not_search_path() {
    let _serial = SERIAL.lock().unwrap();
    for error in [EFAULT, EINVAL, ENOMEM, E2BIG, 13] {
        reset(c"/one".as_ptr(), &[error]);
        assert_eq!(call(false, c"tool".as_ptr()), error);
        assert!(SHELL_ARGUMENTS.lock().unwrap().is_empty());
        assert_eq!(*CALLS.lock().unwrap(), [b"/one/tool".to_vec()]);
    }
    reset(1usize as *const _, &[ENOEXEC, 0]);
    assert_eq!(call(false, c"./tool".as_ptr()), 0);
    assert_eq!(PATH_READS.load(Ordering::Relaxed), 0);
    assert_eq!(
        *CALLS.lock().unwrap(),
        [b"./tool".to_vec(), b"/bin/sh".to_vec()]
    );
}

#[test]
fn interpreter_arguments_are_owned_byte_strings_and_dash_filenames_are_not_options() {
    let _serial = SERIAL.lock().unwrap();
    let mut argument = b"value\0".to_vec();
    let mut variable = b"K=value\0".to_vec();
    let argv = [
        c"ignored-argv0".as_ptr(),
        argument.as_ptr().cast(),
        c"".as_ptr(),
        b"raw\xff\0".as_ptr().cast(),
        ptr::null(),
    ];
    let environment = [
        variable.as_ptr().cast(),
        c"SHELL=/untrusted/interpreter".as_ptr(),
        ptr::null(),
    ];
    reset(c"".as_ptr(), &[ENOEXEC, 0]);
    *SHELL_MUTATIONS.lock().unwrap() = vec![
        argument.as_mut_ptr() as usize,
        variable.as_mut_ptr() as usize,
    ];
    assert_eq!(
        call_exec(c"-command".as_ptr(), argv.as_ptr(), environment.as_ptr()),
        0
    );
    assert_eq!(
        *CALLS.lock().unwrap(),
        [b"-command".to_vec(), b"/bin/sh".to_vec()]
    );
    assert_eq!(
        *SHELL_ARGUMENTS.lock().unwrap(),
        [
            b"sh".to_vec(),
            b"./-command".to_vec(),
            b"value".to_vec(),
            b"".to_vec(),
            b"raw\xff".to_vec()
        ]
    );
    assert_eq!(
        *SHELL_ENVIRONMENT.lock().unwrap(),
        [
            b"K=value".to_vec(),
            b"SHELL=/untrusted/interpreter".to_vec()
        ]
    );
    assert_eq!(argument[0], b'z');
    assert_eq!(variable[0], b'z');
}

#[test]
fn interpreter_snapshot_checks_faultable_vectors_and_space_for_extra_operand() {
    let _serial = SERIAL.lock().unwrap();
    for (argv, envp) in [
        (1usize as *const _, ptr::null()),
        (ptr::null(), 1usize as *const _),
    ] {
        reset(c"/bin".as_ptr(), &[ENOEXEC]);
        assert_eq!(call_exec(c"tool".as_ptr(), argv, envp), EFAULT);
        assert_eq!(*CALLS.lock().unwrap(), [b"/bin/tool".to_vec()]);
    }
    let invalid = [1usize as *const c_char, ptr::null()];
    reset(c"/bin".as_ptr(), &[ENOEXEC]);
    assert_eq!(
        call_exec(c"tool".as_ptr(), invalid.as_ptr(), ptr::null()),
        EFAULT
    );
    let mut argv = [c"a".as_ptr(); MAX_EXEC_VECTOR_ENTRIES];
    argv[MAX_EXEC_VECTOR_ENTRIES - 1] = ptr::null();
    reset(c"/bin".as_ptr(), &[ENOEXEC]);
    assert_eq!(
        call_exec(c"tool".as_ptr(), argv.as_ptr(), ptr::null()),
        E2BIG
    );
    assert_eq!(*CALLS.lock().unwrap(), [b"/bin/tool".to_vec()]);
    argv[MAX_EXEC_VECTOR_ENTRIES - 2] = ptr::null();
    reset(c"/bin".as_ptr(), &[ENOEXEC, 0]);
    assert_eq!(call_exec(c"tool".as_ptr(), argv.as_ptr(), ptr::null()), 0);
    assert_eq!(
        SHELL_ARGUMENTS.lock().unwrap().len(),
        MAX_EXEC_VECTOR_ENTRIES - 1
    );
    for argv in [ptr::null(), [ptr::null()].as_ptr()] {
        reset(c"/bin".as_ptr(), &[ENOEXEC, 0]);
        assert_eq!(call_exec(c"tool".as_ptr(), argv, ptr::null()), 0);
        assert_eq!(
            *SHELL_ARGUMENTS.lock().unwrap(),
            [b"sh".to_vec(), b"/bin/tool".to_vec()]
        );
    }
}
fn call(spawn: bool, file: *const c_char) -> c_int {
    let argv = [c"custom-argv0".as_ptr(), std::ptr::null()];
    let mut environment = [c"K=explicit".as_ptr().cast_mut(), std::ptr::null_mut()];
    let mut pid = -37;
    let actions = 16usize as *const c_void;
    let attributes = 24usize as *const c_void;
    unsafe {
        environ = environment.as_mut_ptr();
    }
    *EXPECT.lock().unwrap() = [
        (&mut pid as *mut c_int) as usize,
        0,
        actions as usize,
        attributes as usize,
        argv.as_ptr() as usize,
        environment.as_ptr() as usize,
    ];
    let result = if spawn {
        implementation::_posix_spawnp(
            &mut pid,
            file,
            actions,
            attributes,
            argv.as_ptr(),
            environment.as_ptr().cast(),
        )
    } else {
        implementation::execvp(file, argv.as_ptr().cast())
    };
    assert_eq!(pid, -37);
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 0);
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    if spawn {
        result
    } else if result == -1 {
        ERRNO.load(Ordering::Relaxed) as c_int
    } else {
        result
    }
}

#[test]
fn both_entry_points_search_owned_names_and_path_after_caller_mutation() {
    let _serial = SERIAL.lock().unwrap();
    for spawn in [false, true] {
        let mut file = b"tool\0".to_vec();
        let mut path = b"/one:/two\0".to_vec();
        reset(path.as_ptr().cast(), &[2, 0]);
        MUTATE_FILE.store(file.as_mut_ptr() as usize, Ordering::Relaxed);
        MUTATE_PATH.store(path.as_mut_ptr() as usize + 6, Ordering::Relaxed);
        assert_eq!(call(spawn, file.as_ptr().cast()), 0);
        assert_eq!(
            *CALLS.lock().unwrap(),
            [b"/one/tool".to_vec(), b"/two/tool".to_vec()]
        );
        assert_eq!(file[0], b'z');
        assert_eq!(path[6], b'z');
    }
}

#[test]
fn invalid_file_and_path_memory_fail_before_any_execution_attempt() {
    let _serial = SERIAL.lock().unwrap();
    for spawn in [false, true] {
        for pointer in [0usize, 1, usize::MAX] {
            reset(c"/bin".as_ptr(), &[]);
            assert_eq!(call(spawn, pointer as *const _), EFAULT);
            assert!(CALLS.lock().unwrap().is_empty());
            assert_eq!(PATH_READS.load(Ordering::Relaxed), 0);
        }
        for pointer in [1usize, usize::MAX] {
            reset(pointer as *const _, &[]);
            assert_eq!(call(spawn, c"tool".as_ptr()), EFAULT);
            assert!(CALLS.lock().unwrap().is_empty());
        }
        reset(c"/bin".as_ptr(), &[]);
        let path = b"/valid:/invalid\0";
        PATH.store(path.as_ptr() as usize, Ordering::Relaxed);
        user_copy_native::DENIED.with_borrow_mut(|denied| {
            *denied = Some(path.as_ptr() as usize + 7..path.as_ptr() as usize + path.len())
        });
        assert_eq!(call(spawn, c"tool".as_ptr()), EFAULT);
        assert!(CALLS.lock().unwrap().is_empty());
    }
}

#[test]
fn slash_paths_never_read_path_and_empty_names_never_attempt_execution() {
    let _serial = SERIAL.lock().unwrap();
    for spawn in [false, true] {
        reset(1usize as *const _, &[13]);
        assert_eq!(call(spawn, c"./tool".as_ptr()), 13);
        assert_eq!(PATH_READS.load(Ordering::Relaxed), 0);
        assert_eq!(*CALLS.lock().unwrap(), [b"./tool".to_vec()]);
        reset(1usize as *const _, &[]);
        assert_eq!(call(spawn, c"".as_ptr()), ENOENT);
        assert_eq!(PATH_READS.load(Ordering::Relaxed), 0);
        assert!(CALLS.lock().unwrap().is_empty());
    }
}

#[test]
fn default_empty_and_long_search_lists_preserve_search_and_errno_rules() {
    let _serial = SERIAL.lock().unwrap();
    for spawn in [false, true] {
        reset(std::ptr::null(), &[2, 13]);
        assert_eq!(call(spawn, c"tool".as_ptr()), 13);
        assert_eq!(
            *CALLS.lock().unwrap(),
            [b"/bin/tool".to_vec(), b"/usr/bin/tool".to_vec()]
        );
        reset(c"".as_ptr(), &[0]);
        assert_eq!(call(spawn, c"tool".as_ptr()), 0);
        assert_eq!(*CALLS.lock().unwrap(), [b"tool".to_vec()]);
        let mut path = b"/x:".repeat(2000);
        path.extend_from_slice(b"/last\0");
        let mut replies = vec![2; 2000];
        replies.push(0);
        reset(path.as_ptr().cast(), &replies);
        assert_eq!(call(spawn, c"tool".as_ptr()), 0);
        assert_eq!(CALLS.lock().unwrap().len(), 2001);
        assert_eq!(CALLS.lock().unwrap().last().unwrap(), b"/last/tool");
        reset(c"/one:/two".as_ptr(), &[5]);
        assert_eq!(call(spawn, c"tool".as_ptr()), 5);
        assert_eq!(CALLS.lock().unwrap().len(), 1);
    }
}

#[test]
fn failed_initial_or_growing_path_allocation_releases_prior_storage_without_execution() {
    let _serial = SERIAL.lock().unwrap();
    for spawn in [false, true] {
        for failure in 1..=5 {
            let mut path = b"/x:".repeat(2000);
            path.push(0);
            reset(path.as_ptr().cast(), &[]);
            FAIL_ALLOCATION.store(failure, Ordering::Relaxed);
            assert_eq!(call(spawn, c"tool".as_ptr()), ENOMEM);
            assert!(CALLS.lock().unwrap().is_empty());
            assert_eq!(ALLOC_CALLS.load(Ordering::Relaxed), failure);
        }
    }
}

#[test]
fn a_later_path_fault_releases_already_captured_chunks() {
    let _serial = SERIAL.lock().unwrap();
    for spawn in [false, true] {
        let mut path = vec![b':'; 800];
        path.push(0);
        reset(path.as_ptr().cast(), &[]);
        user_copy_native::DENIED.with_borrow_mut(|denied| {
            *denied = Some(path.as_ptr() as usize + 600..path.as_ptr() as usize + path.len());
        });
        assert_eq!(call(spawn, c"tool".as_ptr()), EFAULT);
        assert!(ALLOC_CALLS.load(Ordering::Relaxed) >= 2);
        assert!(CALLS.lock().unwrap().is_empty());
    }
}

#[test]
fn capture_chunk_boundaries_and_overlong_names_are_checked_without_raw_loads() {
    let _serial = SERIAL.lock().unwrap();
    for spawn in [false, true] {
        for length in [0, 255, 256, 257, 511, 512, 513] {
            let mut path = vec![b':'; length];
            path.push(0);
            reset(path.as_ptr().cast(), &[0]);
            // Simulate an inaccessible sub-page tail immediately after NUL.
            user_copy_native::DENIED.with_borrow_mut(|denied| {
                *denied = Some(
                    path.as_ptr() as usize + path.len()..path.as_ptr() as usize + path.len() + 256,
                );
            });
            assert_eq!(call(spawn, c"tool".as_ptr()), 0);
            assert_eq!(*CALLS.lock().unwrap(), [b"tool".to_vec()]);
        }
        reset(c"/bin".as_ptr(), &[]);
        let mut name = vec![b'x'; posix_protocol::MAX_PATH_LEN + 1];
        name.push(0);
        assert_eq!(call(spawn, name.as_ptr().cast()), ENAMETOOLONG);
        assert_eq!(PATH_READS.load(Ordering::Relaxed), 0);
        assert!(CALLS.lock().unwrap().is_empty());
    }
}
