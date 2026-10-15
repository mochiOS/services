//! Exercise the production physical-root lifetime registry. Only physical
//! destruction and the interrupt lock are replaced; no PTE access is modeled.
extern crate alloc;
use std::cell::Cell;
use std::sync::{Arc, Mutex};

thread_local! {
    static DENY_ALLOC: Cell<bool> = const { Cell::new(false) };
    static ALLOC_ATTEMPTS: Cell<usize> = const { Cell::new(0) };
}
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if DENY_ALLOC.try_with(|slot| slot.get()).unwrap_or(false) {
            ALLOC_ATTEMPTS.with(|count| count.set(count.get() + 1));
            core::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.alloc(layout) }
        }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        if DENY_ALLOC.try_with(|slot| slot.get()).unwrap_or(false) {
            ALLOC_ATTEMPTS.with(|count| count.set(count.get() + 1));
            core::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.realloc(pointer, layout, size) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn without_allocations<T>(operation: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            DENY_ALLOC.with(|slot| slot.set(false));
        }
    }
    ALLOC_ATTEMPTS.with(|count| count.set(0));
    DENY_ALLOC.with(|slot| slot.set(true));
    let reset = Reset;
    let result = operation();
    drop(reset);
    assert_eq!(ALLOC_ATTEMPTS.with(Cell::get), 0);
    result
}
mod interrupt {
    pub mod spinlock {
        pub struct SpinLock<T>(std::sync::Mutex<T>);
        impl<T> SpinLock<T> {
            pub const fn new(value: T) -> Self {
                Self(std::sync::Mutex::new(value))
            }
            pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
                self.0.lock().unwrap()
            }
        }
    }
}
#[macro_export]
macro_rules! warn { ($($args:tt)*) => { let _ = format_args!($($args)*); }; }

static DESTROYED: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static TEST_LOCK: Mutex<()> = Mutex::new(());
mod paging {
    pub fn destroy_user_page_table_unpinned(table: u64) -> Result<(), ()> {
        // Cleanup can reenter registry lookup; no registry guard may survive
        // into the final native destructor, and retired roots cannot resurrect.
        assert!(!super::root_lifetime::retire(table));
        super::DESTROYED.lock().unwrap().push(table);
        Ok(())
    }
}
#[path = "../../../core/src/mem/root_lifetime.rs"]
mod root_lifetime;

fn pin(table: u64) -> root_lifetime::Pin {
    root_lifetime::pin_with(table, |state| Ok(Arc::new(state))).unwrap()
}

#[test]
fn retirement_is_allocation_free_and_final_pin_owns_exactly_one_cleanup() {
    let _test = TEST_LOCK.lock().unwrap();
    DESTROYED.lock().unwrap().reserve(4);
    let table = 0x1000;
    let first = pin(table);
    let alias = without_allocations(|| {
        root_lifetime::pin_with(table, |_| panic!("live pin must reuse ownership"))
    })
    .unwrap();
    without_allocations(|| assert!(root_lifetime::retire(table)));
    assert!(!DESTROYED.lock().unwrap().contains(&table));
    assert!(
        without_allocations(|| root_lifetime::pin_with(table, |_| panic!(
            "retired root must reject acquisition"
        )))
        .is_err()
    );
    without_allocations(|| drop(first));
    assert!(!DESTROYED.lock().unwrap().contains(&table));
    without_allocations(|| drop(alias));
    assert_eq!(
        DESTROYED
            .lock()
            .unwrap()
            .iter()
            .filter(|root| **root == table)
            .count(),
        1
    );
    assert!(!root_lifetime::retire(table));
    // Only after physical ownership has ended may the allocator reuse a key.
    let reused = pin(table);
    assert!(root_lifetime::retire(table));
    drop(reused);
    assert_eq!(
        DESTROYED
            .lock()
            .unwrap()
            .iter()
            .filter(|root| **root == table)
            .count(),
        2
    );
}

#[test]
fn failed_or_cancelled_pin_never_assumes_the_owners_destruction_obligation() {
    let _test = TEST_LOCK.lock().unwrap();
    let table = 0x2000;
    for invalid in [0, 1, 4095] {
        assert!(
            root_lifetime::pin_with(invalid, |_| panic!("invalid geometry must not allocate"))
                .is_err()
        );
    }
    assert!(root_lifetime::pin_with(table, |_| Err(())).is_err());
    assert!(!root_lifetime::retire(table));
    assert!(!DESTROYED.lock().unwrap().contains(&table));
    let first = pin(table);
    drop(first);
    assert!(!root_lifetime::retire(table));
    assert!(!DESTROYED.lock().unwrap().contains(&table));
    paging::destroy_user_page_table_unpinned(table).unwrap();
    assert_eq!(
        DESTROYED
            .lock()
            .unwrap()
            .iter()
            .filter(|root| **root == table)
            .count(),
        1
    );
}

#[test]
fn owner_retirement_racing_last_pin_drop_never_loses_or_duplicates_cleanup() {
    let _test = TEST_LOCK.lock().unwrap();
    for iteration in 0..32 {
        let table = 0x10000 + iteration * 4096;
        let pin = pin(table);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let peer = barrier.clone();
        let thread = std::thread::spawn(move || {
            peer.wait();
            drop(pin);
        });
        barrier.wait();
        if !root_lifetime::retire(table) {
            paging::destroy_user_page_table_unpinned(table).unwrap();
        }
        thread.join().unwrap();
        assert_eq!(
            DESTROYED
                .lock()
                .unwrap()
                .iter()
                .filter(|root| **root == table)
                .count(),
            1
        );
    }
}

#[test]
fn native_pin_allocator_failure_never_publishes_or_destroys_the_owners_root() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let implementation = root.join("core/src/mem/root_lifetime.rs");
    let native = root.join("core/src/mem/root_lifetime_native.rs");
    let program = format!(
        r#"
#![feature(allocator_api)]
extern crate alloc;
use std::sync::atomic::{{AtomicBool, AtomicUsize, Ordering}};
static DENY:AtomicBool=AtomicBool::new(false);
static ATTEMPTS:AtomicUsize=AtomicUsize::new(0);
static DESTROYED:AtomicUsize=AtomicUsize::new(0);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {{
    unsafe fn alloc(&self, layout:std::alloc::Layout)->*mut u8 {{
        if DENY.load(Ordering::Relaxed) {{ATTEMPTS.fetch_add(1,Ordering::Relaxed); core::ptr::null_mut()}}
        else {{unsafe {{ std::alloc::System.alloc(layout) }}}}
    }}
    unsafe fn dealloc(&self, pointer:*mut u8, layout:std::alloc::Layout) {{unsafe {{std::alloc::System.dealloc(pointer,layout)}}}}
}}
#[global_allocator] static ALLOCATOR:Allocator=Allocator;
mod interrupt {{pub mod spinlock {{
    pub struct SpinLock<T>(std::sync::Mutex<T>);
    impl<T> SpinLock<T> {{
        pub const fn new(value:T)->Self {{Self(std::sync::Mutex::new(value))}}
        pub fn lock(&self)->std::sync::MutexGuard<'_,T> {{self.0.lock().unwrap()}}
    }}
}}}}
#[macro_export] macro_rules! warn {{($($args:tt)*)=>{{let _=format_args!($($args)*);}};}}
mod paging {{pub fn destroy_user_page_table_unpinned(table:u64)->Result<(),()> {{
    assert_eq!(table,0x2000); super::DESTROYED.fetch_add(1,super::Ordering::Relaxed); Ok(())
}}}}
#[path={implementation:?}] mod root_lifetime;
#[path={native:?}] mod root_lifetime_native;
fn main() {{
    // Leave registry capacity available, isolating failure of actual Arc::try_new.
    drop(root_lifetime_native::pin(0x1000).unwrap());
    DENY.store(true,Ordering::Relaxed);
    let failed=root_lifetime_native::pin(0x2000);
    DENY.store(false,Ordering::Relaxed);
    assert!(failed.is_err()); assert_eq!(ATTEMPTS.load(Ordering::Relaxed),1);
    assert!(!root_lifetime::retire(0x2000)); assert_eq!(DESTROYED.load(Ordering::Relaxed),0);
    let retry=root_lifetime_native::pin(0x2000).unwrap();
    assert!(root_lifetime::retire(0x2000));
    assert_eq!(DESTROYED.load(Ordering::Relaxed),0);
    DENY.store(true,Ordering::Relaxed); drop(retry); DENY.store(false,Ordering::Relaxed);
    assert_eq!(DESTROYED.load(Ordering::Relaxed),1); assert_eq!(ATTEMPTS.load(Ordering::Relaxed),1);
}}
"#
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-root-pin-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustup")
        .args([
            "run",
            "nightly-2026-07-16",
            "rustc",
            "--edition=2024",
            "-Awarnings",
            "-",
        ])
        .arg("-o")
        .arg(&binary)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
