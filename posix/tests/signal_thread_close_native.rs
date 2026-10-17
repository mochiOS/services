//! Production reap/close control flow. Lifecycle observation and native close
//! are controlled independently; a failed reference discard retains ownership.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn thread_reference_is_reaped_only_after_confirmed_termination_and_successful_close() {
    let mut program = probe::program();
    program.push_str(
        r#"
extern crate self as mochi_user_platform;
use std::cell::{Cell,RefCell};
use std::collections::BTreeMap;
thread_local! {
    static TERMINATED:Cell<bool>=const{Cell::new(true)};
    static RESULT:Cell<SysResult<()>>=const{Cell::new(Ok(()))};
    static CLOSES:Cell<usize>=const{Cell::new(0)};
    static FAILURES:RefCell<Vec<String>>=const{RefCell::new(Vec::new())};
    static RECLAIMED:RefCell<Vec<String>>=const{RefCell::new(Vec::new())};
}
mod syscall {pub use crate::mochi_user_syscall::*;}
mod handle {
    pub fn close(handle:u32)->crate::SysResult<()> {
        assert_eq!(handle,37);crate::CLOSES.set(crate::CLOSES.get()+1);crate::RESULT.get()
    }
}
#[macro_export]
macro_rules! logln {($($arg:tt)*)=>{
    $crate::FAILURES.with_borrow_mut(|logs|logs.push(format!($($arg)*)))
};}
mod logger {
    pub fn write_status_fmt(args:core::fmt::Arguments<'_>)->Result<(),()> {
        crate::RECLAIMED.with_borrow_mut(|logs|logs.push(args.to_string()));Ok(())
    }
}
mod posix_service {pub struct PosixService<T>(pub core::marker::PhantomData<T>);}
#[derive(Clone,Copy)]
struct RegisteredSignalThread {process_id:u64,handle:u32}
fn signal_thread_terminated(
    _: &mut posix_service::PosixService<u32>,id:u64,thread:RegisteredSignalThread,
)->bool {
    assert_eq!((id,thread.process_id,thread.handle),(71,9,37));TERMINATED.get()
}
"#,
    );
    let source = include_str!("../src/main.rs");
    program.push_str(probe::between(
        source,
        "fn reap_signal_threads(",
        "\n#[cfg(target_os = \"mochios\")]\nfn close_retired_signal_thread(",
    ));
    program.push_str(probe::between(
        source,
        "fn close_retired_signal_thread(",
        "\n#[cfg(target_os = \"mochios\")]\nfn deliver_signal_notifications(",
    ));
    program.push_str(
        r#"
fn main() {
    use mnu_abi::status::Error;
    let mut service=posix_service::PosixService(core::marker::PhantomData);
    let mut threads=BTreeMap::from([(71,RegisteredSignalThread{process_id:9,handle:37})]);
    for raw in [Error::NotReady.into_raw() as i64,Error::InvalidArgument.into_raw() as i64,
                Error::AccessDenied.into_raw() as i64,Error::BackingFailure.into_raw() as i64,
                -9,9,0,i64::MIN] {
        CLOSES.set(0);FAILURES.with_borrow_mut(Vec::clear);RECLAIMED.with_borrow_mut(Vec::clear);
        RESULT.set(Err(SysError::from_raw(raw)));
        reap_signal_threads(&mut service,&mut threads);
        assert_eq!(CLOSES.get(),1);
        assert_eq!(threads.len(),1,"failure {raw} must retain the exact reference");
        assert_eq!(threads[&71].handle,37);
        RECLAIMED.with_borrow(|logs|assert!(logs.is_empty()));
        FAILURES.with_borrow(|logs|{
            assert_eq!(logs.len(),1);assert!(logs[0].contains(&format!("errno={raw}")));
        });
    }
    TERMINATED.set(false);CLOSES.set(0);RESULT.set(Ok(()));
    reap_signal_threads(&mut service,&mut threads);
    assert_eq!(CLOSES.get(),0);assert_eq!(threads.len(),1);
    TERMINATED.set(true);
    reap_signal_threads(&mut service,&mut threads);
    assert!(threads.is_empty());assert_eq!(CLOSES.get(),1);
    RECLAIMED.with_borrow(|logs|assert_eq!(logs.as_slice(),[
        "posix.service: reclaimed signal thread pid=9 tid=71\n"]));
    reap_signal_threads(&mut service,&mut threads);
    assert_eq!(CLOSES.get(),1,"successful reap must not discard the reference twice");
}
"#,
    );
    probe::run(&program);
}
