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
fn fork_freezes_libc_bookkeeping_across_vm_capture_without_inverting_malloc() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let clone = item(source, "fn clone_registered_process_owned(");
    let positions = [
        "let lifecycle_guard = thread_lifecycle::capture()?",
        "other.callback_resources.capture_for_fork().ok_or(EAGAIN)?",
        "let libc_guard = libc_lock::capture()?",
        "let allocator_guard = atfork::freeze_allocator()",
        "let libc_registry = libc_guard.freeze_registry()",
        "mochios_posix_client::snapshot::capture_native(",
        "drop(libc_registry)",
        "drop(allocator_guard)",
        "drop(libc_guard)",
        "drop(resource_guards)",
        "drop(lifecycle_guard)",
    ].map(|text| clone.find(text).unwrap());
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(clone.contains("other.state.load(Ordering::Acquire) == THREAD_STARTING"));
    assert!(!clone.contains("THREAD_STARTING | THREAD_RUNNING"),
        "running siblings use the non-walking inherited-memory path");
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
    let lock_module = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../user/crates/newlib-runtime/src/libc_lock.rs")
        .canonicalize()
        .unwrap();
    let program = format!(
        r#"
#![allow(non_camel_case_types, dead_code)]
use std::sync::atomic::{{AtomicU32, AtomicU64, AtomicUsize, Ordering}};
use std::ptr;
extern crate self as mochios_posix_client;
type c_int = i32;
const EAGAIN:c_int=11;
struct RuntimeMutex<T>(std::sync::Mutex<T>);
impl<T> RuntimeMutex<T>{{
    const fn new(value:T)->Self{{Self(std::sync::Mutex::new(value))}}
    fn lock(&self)->RuntimeMutexGuard<'_,T>{{self.0.lock().unwrap()}}
}}
type RuntimeMutexGuard<'a,T> = std::sync::MutexGuard<'a,T>;
#[path={lock_module:?}]mod libc_lock;
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
thread_local!{{static OVERRIDE:std::cell::Cell<Option<u64>>=const{{std::cell::Cell::new(None)}};}}
fn current_thread_control() -> Option<(u32, &'static Control)> {{
    if OVERRIDE.get().is_some() {{return None;}}
    (REGISTERED.load(Ordering::Relaxed) != 0).then_some((64, &CONTROL))
}}
fn native_thread_id() -> Result<u64, ()> {{ Ok(OVERRIDE.get().unwrap_or_else(||NATIVE.load(Ordering::Relaxed))) }}
fn process_exit(_: i32) -> ! {{ panic!("unexpected lock failure") }}
fn native_mutex_acquire(state: &AtomicU32) {{ assert!(native_mutex_try_acquire(state)); }}
fn native_mutex_try_acquire(state: &AtomicU32) -> bool {{
    state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
}}
fn native_mutex_release(state: &AtomicU32) {{ assert!([1,2].contains(&state.swap(0, Ordering::Release))); }}
fn native_mutex_wait(state:&AtomicU32,expected:u32){{
    WAITING.fetch_add(1,Ordering::Release);
    let deadline=std::time::Instant::now()+std::time::Duration::from_secs(5);
    while state.load(Ordering::Acquire)==expected {{
        assert!(std::time::Instant::now()<deadline,"native wait stranded");
        std::thread::yield_now();
    }}
}}
fn native_mutex_wake_all(_:&AtomicU32){{}}
static WAITING:AtomicUsize=AtomicUsize::new(0);
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
    // The allocation-free list supports arbitrary release order, not a lock
    // stack. A foreign held lock blocks capture even if malloc is unlocked.
    let mut a=LockOpaque::new(false);let mut b=LockOpaque::new(false);
    let mut c=LockOpaque::new(false);
    __retarget_lock_acquire(&mut a);
    __retarget_lock_acquire(&mut b);
    __retarget_lock_acquire(&mut c);
    __retarget_lock_release(&mut b);
    CONTROL.newlib_lock_identity.store(17,Ordering::Relaxed);
    assert!(matches!(libc_lock::capture(),Err(EAGAIN)));
    CONTROL.newlib_lock_identity.store(51,Ordering::Relaxed);
    let capture=libc_lock::capture().unwrap();
    assert!(matches!(libc_lock::capture(),Err(EAGAIN)));
    CONTROL.newlib_lock_identity.store(17,Ordering::Relaxed);
    assert_eq!(__retarget_lock_try_acquire(&mut b),0);
    CONTROL.newlib_lock_identity.store(51,Ordering::Relaxed);
    assert_eq!(__retarget_lock_try_acquire(&mut b),1);
    __retarget_lock_release(&mut a); // remove tail
    __retarget_lock_release(&mut b); // remove head
    __retarget_lock_release(&mut c); // remove last
    {{let _registry=capture.freeze_registry();}}
    drop(capture);
    CONTROL.newlib_lock_identity.store(17,Ordering::Relaxed);
    assert_eq!(__retarget_lock_try_acquire(&mut a),1);
    __retarget_lock_release(&mut a);
    let capture=libc_lock::capture().unwrap();
    drop(capture);

    // A frozen registry blocks a foreign acquisition without losing its
    // notification, while the capturing thread may still use malloc.
    let shared=std::sync::Arc::new(LockOpaque::new(false));
    let capture=libc_lock::capture().unwrap();
    let waits=WAITING.load(Ordering::Acquire);
    let worker_lock=shared.clone();
    let worker=std::thread::spawn(move||{{
        OVERRIDE.set(Some(700));
        libc_lock::acquire(&worker_lock);
        libc_lock::release(&worker_lock);
    }});
    let deadline=std::time::Instant::now()+std::time::Duration::from_secs(5);
    while WAITING.load(Ordering::Acquire)==waits{{
        assert!(std::time::Instant::now()<deadline);
        std::thread::yield_now();
    }}
    {{let _allocator=atfork::freeze_allocator();}}
    drop(capture);
    worker.join().unwrap();

    // Contending plain and recursive locks remain mutually exclusive while
    // the caller repeatedly attempts fork capture. No allocation in tracking.
    let value=std::sync::Arc::new(AtomicUsize::new(0));
    let mut workers=Vec::new();
    for owner in 701..705{{
        let lock=shared.clone();let value=value.clone();
        workers.push(std::thread::spawn(move||{{
            OVERRIDE.set(Some(owner));
            for _ in 0..2000{{
                libc_lock::acquire(&lock);
                let old=value.load(Ordering::Relaxed);
                std::thread::yield_now();
                value.store(old+1,Ordering::Relaxed);
                libc_lock::release(&lock);
            }}
        }}));
    }}
    for _ in 0..2000{{if let Ok(capture)=libc_lock::capture(){{
        {{let _registry=capture.freeze_registry();}}
        drop(capture);
    }}}}
    for worker in workers{{worker.join().unwrap();}}
    assert_eq!(value.load(Ordering::Relaxed),8000);
    let capture=libc_lock::capture().unwrap();
    drop(capture);
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
