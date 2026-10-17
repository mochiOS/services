#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn update_controls_use_native_mechanism_errors_and_filesystem_owns_retry_conversion() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = probe::program().replacen(
        "mod mnu_abi {",
        &format!(
            "mod mnu_abi {{#[path={:?}]pub mod memory_update;",
            root.join("core/crates/abi/src/memory_update.rs")
        ),
        1,
    );
    program.push_str(r#"
use std::cell::{Cell,RefCell,RefMut};
use mnu_abi::status::Error;
const SUCCESS:u64=0;
thread_local!{
    static CALLS:Cell<usize>=const{Cell::new(0)};
    static OP:Cell<u64>=const{Cell::new(0)};
    static RESULT:Cell<Result<(),u64>>=const{Cell::new(Ok(()))};
}
struct SpinLock<T>(RefCell<T>);
impl<T> SpinLock<T>{fn try_lock(&self)->Option<RefMut<'_,T>>{self.0.try_borrow_mut().ok()}}
struct ExtentTransaction;
fn invoked(operation:u64)->Result<(),u64>{CALLS.set(CALLS.get()+1);OP.set(operation);RESULT.get()}
impl ExtentTransaction{
    fn begin_external(&mut self)->Result<(),u64>{invoked(mnu_abi::memory_update::BEGIN)}
    fn confirm_unchanged(&mut self)->Result<(),u64>{invoked(mnu_abi::memory_update::UNCHANGED)}
    fn request_external_publication(&mut self)->Result<(),u64>{invoked(mnu_abi::memory_update::PUBLISH)}
}
mod mochi_user_platform{pub mod syscall{pub use crate::mochi_user_syscall::SysError;}}
mod mochios_filesystem_protocol{
"#);
    probe::constants(
        &mut program,
        include_str!("../../../user/crates/filesystem-protocol/src/lib.rs"),
        &["ERROR_MEMORY_ADMISSION_BUSY"],
    );
    program.push_str("}\n");
    let source = include_str!("../../../core/src/syscall/handle/memory_update.rs");
    program.push_str(
        &source[source.find("pub(super) fn control(").unwrap()..]
            .replace("pub(super) fn control(", "fn control("),
    );
    let filesystem = include_str!("../../filesystem/src/memory_updates.rs");
    program.push_str(&filesystem[filesystem.find("fn native_error(").unwrap()..]);
    program.push_str(probe::between(
        filesystem,
        "pub(crate) fn admission_error(",
        "pub trait Update:",
    ));
    program.push_str(r#"
fn main(){
    let update=SpinLock(RefCell::new(ExtentTransaction));
    for operation in [mnu_abi::memory_update::BEGIN,mnu_abi::memory_update::UNCHANGED,mnu_abi::memory_update::PUBLISH]{
        assert_eq!(control(&update,operation,0,0,0,0),0);assert_eq!(OP.get(),operation);
        let before=CALLS.get();let held=update.0.borrow_mut();
        let result=control(&update,operation,0,0,0,0);drop(held);
        assert_eq!(result,Error::NotReady.into_raw());assert_eq!(CALLS.get(),before);
        for (i,il,o,ol) in [(1,0,0,0),(0,1,0,0),(0,0,1,0),(0,0,0,1)]{
            assert_eq!(control(&update,operation,i,il,o,ol),Error::InvalidArgument.into_raw());assert_eq!(CALLS.get(),before);
        }
        for error in [Error::InvalidArgument.into_raw(),Error::BackingFailure.into_raw(),Error::NotReady.into_raw(),(-5i64)as u64]{
            RESULT.set(Err(error));assert_eq!(control(&update,operation,0,0,0,0),error);
        }
        RESULT.set(Ok(()));
    }
    let before=CALLS.get();for operation in [0,4,u64::MAX]{
        assert_eq!(control(&update,operation,0,0,0,0),Error::InvalidArgument.into_raw());
    }assert_eq!(CALLS.get(),before);
    for (error,expected) in [(Error::InvalidArgument,22),(Error::ResourceUnavailable,12),
        (Error::BackingFailure,5),(Error::NotReady,11),(Error::AccessDenied,13)]{
        let wire=native_error(mochi_user_platform::syscall::SysError::from_raw(error.into_raw()as i64));
        assert_eq!(wire,expected);
        assert_eq!(admission_error(wire),if expected==11{mochios_filesystem_protocol::ERROR_MEMORY_ADMISSION_BUSY}else{expected});
    }
}
"#);
    probe::run(&program);
}
