use mochios_posix_client::upcall_guard::Guard;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

#[test]
fn thread_guard_nests_without_wrapping_or_changing_the_counter_on_failure() {
    let word = AtomicU32::new(0);
    let outer = Guard::enter(&word).unwrap();
    assert_eq!(word.load(Ordering::Acquire), 1);
    let inner = Guard::enter(&word).unwrap();
    assert_eq!(word.load(Ordering::Acquire), 2);
    drop(inner);
    assert_eq!(word.load(Ordering::Acquire), 1);
    drop(outer);
    assert_eq!(word.load(Ordering::Acquire), 0);
    let word = AtomicU32::new(u32::MAX);
    assert!(Guard::enter(&word).is_none());
    assert_eq!(word.load(Ordering::Acquire), u32::MAX);
}

#[test]
fn a_deferral_guard_cannot_be_released_by_another_thread() {
    let module = include_str!("../../../user/crates/posix-client/src/upcall_guard.rs");
    let program = format!(
        "mod actual {{\n{module}\n}}\n\
         fn main() {{\n\
         let word=std::sync::atomic::AtomicU32::new(0);\n\
         std::thread::scope(|scope|{{\n\
         let guard=actual::Guard::enter(&word).unwrap();\n\
         scope.spawn(move || drop(guard));\n\
         }});\n}}\n"
    );
    let directory =
        std::env::temp_dir().join(format!("mochios-defer-thread-bound-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let compile = |program: &str| {
        let mut compiler = Command::new("rustc")
            .args(["--edition=2024", "-Awarnings", "-", "-o"])
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
        compiler.wait_with_output().unwrap()
    };
    let rejected = compile(&program);
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("cannot be sent between threads safely")
    );
    // Prove the rejection is the thread-bound marker, not a broken harness.
    let movable = program.replace("PhantomData<*mut ()>", "PhantomData<()>");
    assert_ne!(movable, program);
    let accepted = compile(&movable);
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
}

#[test]
fn actual_native_readiness_defers_unreadable_or_nonzero_words_without_holding_thread_locks() {
    let source = include_str!("../../../core/src/syscall/upcall.rs");
    let start = source.find("fn current_has_deliverable_upcall(").unwrap();
    let end = start + source[start..].find("\n}\n").unwrap() + 3;
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicU32,Ordering};
static WORD:AtomicU32=AtomicU32::new(0);
thread_local! {
    static MODE:std::cell::Cell<u8>=const{std::cell::Cell::new(0)};
    static LOCK:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};
    static COPIES:std::cell::Cell<usize>=const{std::cell::Cell::new(0)};
}
mod task {
    pub fn current_thread_id()->Option<u64>{if crate::MODE.with(|v|v.get())==1 {None}else{Some(7)}}
    pub struct Thread;
    impl Thread {
        pub fn pending_upcall_defer_word(&self)->Option<u64>{
            match crate::MODE.with(|v|v.get()) {2=>None,3=>Some(0),_=>Some(crate::WORD.as_ptr() as u64)}
        }
    }
    pub fn with_thread<T>(id:u64,callback:impl FnOnce(&Thread)->T)->Option<T>{
        assert_eq!(id,7);crate::LOCK.with(|v|v.set(true));
        let result=callback(&Thread);crate::LOCK.with(|v|v.set(false));Some(result)
    }
}
mod address_wait {use super::*;
pub fn read_upcall_defer_word(pointer:u64)->Result<u32,u64>{
    assert!(!LOCK.with(|v|v.get()),"faultable usercopy under thread lock");
    assert_eq!(pointer,WORD.as_ptr() as u64);
    COPIES.with(|v|v.set(v.get()+1));
    if MODE.with(|v|v.get())==4 {return Err(14)}
    Ok(WORD.load(Ordering::Acquire))
}
}
mod actual {use super::*;
"#,
    );
    program.push_str("pub ");
    program.push_str(&source[start..end]);
    program.push_str(
        r#"
}
fn main(){
    for (mode,expected) in [(1,false),(2,false),(3,true)] {
        MODE.with(|v|v.set(mode));assert_eq!(actual::current_has_deliverable_upcall(),expected);
        assert_eq!(COPIES.with(|v|v.get()),0);
    }
    MODE.with(|v|v.set(0));
    for word in [1,2,u32::MAX] {
        WORD.store(word,Ordering::Release);assert!(!actual::current_has_deliverable_upcall());
    }
    WORD.store(0,Ordering::Release);assert!(actual::current_has_deliverable_upcall());
    MODE.with(|v|v.set(4));assert!(!actual::current_has_deliverable_upcall());
    assert_eq!(COPIES.with(|v|v.get()),5);
}
"#,
    );
    let directory =
        std::env::temp_dir().join(format!("mochios-upcall-defer-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings", "-", "-o"])
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
    let output = compiler.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn runtime_locks_cover_acquisition_and_publication_but_release_before_delivery() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let lock = runtime
        .split("fn lock(&self) -> RuntimeMutexGuard")
        .nth(1)
        .unwrap()
        .split("// Safety:")
        .next()
        .unwrap();
    assert!(
        lock.find("defer_native_delivery()").unwrap() < lock.find("native_mutex_acquire").unwrap()
    );
    assert!(lock.contains("_delivery: delivery"));
    let guard = runtime
        .split("struct RuntimeMutexGuard")
        .nth(1)
        .unwrap()
        .split("struct RuntimeOnce")
        .next()
        .unwrap();
    assert!(guard.contains("_delivery: Option<mochios_posix_client::upcall_guard::Guard<'static>>"));
    assert!(guard.contains("native_mutex_release(&self.mutex.state)"));
    let once = runtime
        .split("fn get_or_try_init")
        .nth(1)
        .unwrap()
        .split("// Safety: initialization")
        .next()
        .unwrap();
    assert!(
        once.find("defer_native_delivery()").unwrap()
            < once.find(".compare_exchange(0, 1").unwrap()
    );
    assert!(runtime.contains("defer_word: control.native_delivery_defer.as_ptr() as u64"));
    let drain = include_str!("../../../user/crates/newlib-runtime/src/signal_delivery.rs");
    let drain = drain.split("pub(super) fn drain()").nth(1).unwrap();
    assert!(
        drain.find("native_delivery_defer.load").unwrap()
            < drain.find("signal_checkpoint::run_with").unwrap()
    );
    let exception = include_str!("../../../core/src/syscall/upcall.rs");
    let exception = exception
        .split("fn prepare_user_exception(")
        .nth(1)
        .unwrap()
        .split("fn valid_user_return")
        .next()
        .unwrap();
    assert!(!exception.contains("current_has_deliverable_upcall"));
}
