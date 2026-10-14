use std::io::Write;
use std::process::{Command, Stdio};

fn item<'a>(source: &'a str, declaration: &str) -> &'a str {
    let start = source.find(declaration).unwrap();
    let body = start + source[start..].find('{').unwrap();
    let mut depth = 0;
    for (offset, byte) in source[body..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..body + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated {declaration}")
}

#[test]
fn private_recursive_lock_identity_survives_native_thread_replacement() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    // Compile the production lock operations, not a second implementation of
    // their ownership/recursion rules. Only native identity and wait transport
    // are controlled here; the C/KVM probe exercises real ThreadControl setup.
    let declarations = [
        "pub struct LockOpaque {",
        "impl LockOpaque {",
        "fn newlib_lock_identity()",
        "pub extern \"C\" fn __retarget_lock_acquire(",
        "pub extern \"C\" fn __retarget_lock_acquire_recursive(",
        "pub extern \"C\" fn __retarget_lock_try_acquire(",
        "pub extern \"C\" fn __retarget_lock_try_acquire_recursive(",
        "pub extern \"C\" fn __retarget_lock_release(",
        "pub extern \"C\" fn __retarget_lock_release_recursive(",
    ];
    let operations = declarations.map(|name| item(source, name)).join("\n");
    let fork_source = include_str!("../../../user/crates/newlib-runtime/src/atfork.rs");
    let guard = [
        "pub(super) struct AllocatorGuard {",
        "pub(super) fn freeze_allocator()",
        "impl Drop for AllocatorGuard {",
    ]
    .map(|name| item(fork_source, name))
    .join("\n");
    let program = format!(
        r#"
#![allow(non_camel_case_types, dead_code)]
use std::sync::atomic::{{AtomicU32, AtomicU64, Ordering}};
use std::ptr;
extern crate self as mochios_posix_client;
type c_int = i32;
static DEFERRED: AtomicU32 = AtomicU32::new(0);
pub mod upcall_guard {{
    pub struct Guard<'a>(pub std::marker::PhantomData<&'a ()>);
    impl Drop for Guard<'_> {{
        fn drop(&mut self) {{ assert!(super::DEFERRED.fetch_sub(1, super::Ordering::Relaxed) > 0); }}
    }}
}}
fn defer_native_delivery() -> Option<upcall_guard::Guard<'static>> {{
    DEFERRED.fetch_add(1, Ordering::Relaxed);
    Some(upcall_guard::Guard(std::marker::PhantomData))
}}
struct Control {{ newlib_lock_identity: AtomicU64 }}
static CONTROL: Control = Control {{ newlib_lock_identity: AtomicU64::new(17) }};
static NATIVE: AtomicU64 = AtomicU64::new(17);
static REGISTERED: AtomicU32 = AtomicU32::new(0);
fn current_thread_control() -> Option<(u32, &'static Control)> {{
    (REGISTERED.load(Ordering::Relaxed) != 0).then_some((64, &CONTROL))
}}
fn native_thread_id() -> Result<u64, ()> {{ Ok(NATIVE.load(Ordering::Relaxed)) }}
fn process_exit(_: i32) -> ! {{ panic!("unexpected lock failure") }}
fn native_mutex_acquire(state: &AtomicU32) {{ assert!(native_mutex_try_acquire(state)); }}
fn native_mutex_try_acquire(state: &AtomicU32) -> bool {{
    state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
}}
fn native_mutex_release(state: &AtomicU32) {{ assert_eq!(state.swap(0, Ordering::Release), 1); }}
{operations}
#[allow(non_upper_case_globals)]
static __lock___malloc_recursive_mutex: LockOpaque = LockOpaque::new(false);
mod atfork {{ use super::*; {guard} }}
fn main() {{
    let mut lock = LockOpaque::new(false);
    let pointer = &mut lock as *mut LockOpaque;
    // Bootstrap ownership stays valid after thread registration.
    __retarget_lock_acquire_recursive(pointer);
    REGISTERED.store(1, Ordering::Relaxed);
    __retarget_lock_acquire_recursive(pointer);
    assert_eq!(lock.depth.load(Ordering::Relaxed), 2);
    // The child has a new native thread, but the caller's private identity.
    NATIVE.store(51, Ordering::Relaxed);
    assert_eq!(__retarget_lock_try_acquire_recursive(pointer), 1);
    __retarget_lock_acquire_recursive(pointer);
    assert_eq!(lock.depth.load(Ordering::Relaxed), 4);
    // A different thread must not inherit the calling thread's authority.
    CONTROL.newlib_lock_identity.store(51, Ordering::Relaxed);
    assert_eq!(__retarget_lock_try_acquire_recursive(pointer), 0);
    assert_eq!(lock.depth.load(Ordering::Relaxed), 4);
    CONTROL.newlib_lock_identity.store(17, Ordering::Relaxed);
    for remaining in (0..4).rev() {{
        __retarget_lock_release_recursive(pointer);
        assert_eq!(lock.depth.load(Ordering::Relaxed), remaining);
    }}
    assert_eq!(lock.owner.load(Ordering::Relaxed), 0);
    assert_eq!(lock.state.load(Ordering::Relaxed), 0);
    CONTROL.newlib_lock_identity.store(51, Ordering::Relaxed);
    assert_eq!(__retarget_lock_try_acquire_recursive(pointer), 1);
    __retarget_lock_release_recursive(pointer);
    let allocator = ptr::from_ref(&__lock___malloc_recursive_mutex).cast_mut();
    __retarget_lock_acquire_recursive(allocator);
    __retarget_lock_acquire_recursive(allocator);
    {{
        let _guard = atfork::freeze_allocator();
        assert_eq!(__lock___malloc_recursive_mutex.depth.load(Ordering::Relaxed), 3);
        assert_eq!(DEFERRED.load(Ordering::Relaxed), 1);
        NATIVE.store(99, Ordering::Relaxed);
    }}
    assert_eq!(__lock___malloc_recursive_mutex.depth.load(Ordering::Relaxed), 2);
    assert_eq!(DEFERRED.load(Ordering::Relaxed), 0);
    __retarget_lock_release_recursive(allocator);
    __retarget_lock_release_recursive(allocator);
    // Error returns before capture must release the same guard as success.
    let failed = (|| -> Result<(), ()> {{ let _guard = atfork::freeze_allocator(); Err(()) }})();
    assert_eq!(failed, Err(()));
    assert_eq!(__lock___malloc_recursive_mutex.state.load(Ordering::Relaxed), 0);
    assert_eq!(DEFERRED.load(Ordering::Relaxed), 0);
}}
"#
    );
    let directory =
        std::env::temp_dir().join(format!("mochios-newlib-fork-locks-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compile = Command::new("rustc")
        .args([
            "--edition=2024",
            "--crate-name=newlib_fork_locks",
            "-",
            "-o",
        ])
        .arg(&executable)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compile
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let result = compile.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
    std::fs::remove_dir_all(directory).unwrap();
}
