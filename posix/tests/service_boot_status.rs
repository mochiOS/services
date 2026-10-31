#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn boot_status_records_exact_lifecycle_messages_without_console_fallback() {
    let source = include_str!("../../service-manager/src/bootstrap.rs");
    let mut program = String::from(
        r#"
use std::cell::RefCell;
thread_local!{static MESSAGES:RefCell<Vec<String>>=const{RefCell::new(Vec::new())};}
mod platform { pub mod logger {
    pub fn write_status_fmt(message:core::fmt::Arguments<'_>)->Result<(),()> {
        crate::MESSAGES.with_borrow_mut(|lines|lines.push(message.to_string()));
        Err(())
    }
}}
"#,
    );
    program.push_str(probe::between(
        source,
        "fn boot_status(",
        "fn log_ready_error(",
    ));
    program.push_str(
        r#"
fn main(){
    boot_status(format_args!("service-manager.service: {} spawned pid={}","posix.service",42));
    boot_status(format_args!("service-manager.service: resident phase reason={:?}","PosixSpawnFailed"));
    MESSAGES.with_borrow(|lines|assert_eq!(lines.as_slice(),[
        "service-manager.service: posix.service spawned pid=42\n",
        "service-manager.service: resident phase reason=\"PosixSpawnFailed\"\n"
    ]));
}
"#,
    );
    probe::run(&program);
}

#[test]
fn endpoint_handoff_diagnostics_preserve_the_original_failure() {
    let source = include_str!("../../service-manager/src/spawn_support.rs");
    let mut program = String::from(
        r#"
use std::cell::{Cell,RefCell};
thread_local!{
    static LOOKUP:Cell<Result<u64,i64>>=const{Cell::new(Ok(7))};
    static INSTALL:Cell<Result<(),i64>>=const{Cell::new(Ok(()))};
    static CALLS:Cell<usize>=const{Cell::new(0)};
    static LOGS:RefCell<Vec<String>>=const{RefCell::new(Vec::new())};
}
mod mochi_user_syscall {
    #[derive(Clone,Copy,Debug,PartialEq,Eq)] pub struct SysError(pub i64);
    impl SysError{pub fn raw(self)->i64{self.0}}
}
mod platform {
    pub mod handle{pub type Handle=u32;}
    pub mod process{
        pub fn find_by_name(_: &str)->Result<u64,crate::mochi_user_syscall::SysError>{
            crate::LOOKUP.get().map_err(crate::mochi_user_syscall::SysError)
        }
    }
    pub mod logger{
        pub fn write_status_fmt(args:core::fmt::Arguments<'_>)->Result<(),()> {
            crate::LOGS.with_borrow_mut(|logs|logs.push(args.to_string())); Err(())
        }
    }
}
fn install_posix_endpoint_at(_:u64,_:u32,_:u32,_:u64)->Result<(),mochi_user_syscall::SysError>{
    CALLS.set(CALLS.get()+1);
    INSTALL.get().map_err(mochi_user_syscall::SysError)
}
mod implementation{
use crate::{platform,mochi_user_syscall,install_posix_endpoint_at};
"#,
    );
    program.push_str(probe::between(
        source,
        "fn install_posix_endpoint_for(",
        "fn install_posix_endpoint_at(",
    ));
    program.push_str(r#"
pub fn invoke()->Result<(),mochi_user_syscall::SysError>{install_posix_endpoint_for("package.service",1,8,4)}
}
fn main(){
    assert_eq!(implementation::invoke(),Ok(()));
    LOGS.with_borrow(|logs|assert!(logs.is_empty()));
    LOOKUP.set(Err(-4099));
    assert_eq!(implementation::invoke(),Err(mochi_user_syscall::SysError(-4099)));
    assert_eq!(CALLS.get(),1);
    LOOKUP.set(Ok(7)); INSTALL.set(Err(-13));
    assert_eq!(implementation::invoke(),Err(mochi_user_syscall::SysError(-13)));
    assert_eq!(CALLS.get(),2);
    LOGS.with_borrow(|logs|assert_eq!(logs.as_slice(),[
        "service-manager.service: POSIX endpoint handoff to package.service failed status=-4099\n",
        "service-manager.service: POSIX endpoint handoff to package.service failed status=-13\n"
    ]));
}
"#);
    probe::run(&program);
}
