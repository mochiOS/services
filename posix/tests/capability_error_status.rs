use mochi_user_platform::syscall::{self, SysError};

#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn compatibility_errors_are_raw_negative_statuses_not_positive_errno() {
    for (status, errno) in [
        (syscall::ENOENT, 2),
        (mochios_posix_protocol::STATUS_EEXIST as i64 as u64, 17),
        (syscall::EACCES, 13),
    ] {
        let error = SysError::from_raw(status as i64);
        assert_eq!(error.raw(), -(errno as i64));
        assert_eq!(error.errno(), Some(errno));
        assert_ne!(error.errno(), Some(status));
    }
}

#[test]
fn capability_file_error_branches_compare_raw_statuses() {
    for source in [
        include_str!("../../capability/src/persistent_grant.rs"),
        include_str!("../../capability/src/resolver.rs"),
    ] {
        assert!(!source.contains("error.errno() == Some(mochi_user_syscall::"));
        assert!(!source.contains("error.errno() != Some(mochi_user_syscall::"));
        assert!(source.contains("error.raw() == mochi_user_syscall::ENOENT as i64"));
    }
    assert!(
        include_str!("../../capability/src/persistent_grant.rs")
            .contains("error.raw() != posix::STATUS_EEXIST as i64")
    );
}

#[test]
fn policy_directory_accepts_only_posix_exists_not_native_transport_exists() {
    let mut program = probe::program();
    program.push_str("mod posix {\n");
    probe::constants(
        &mut program,
        include_str!("../../../user/crates/posix-protocol/src/lib.rs"),
        &["STATUS_EEXIST"],
    );
    program.push_str(
        r#"
}
use std::cell::{Cell,RefCell};
const POLICY_DIR: &str = "/var/lib/security";
enum OpenAtBase {ProcessRoot}
struct Client;
thread_local! {
    static RESULT:Cell<Result<(),SysError>>=const {Cell::new(Ok(()))};
    static PATHS:RefCell<Vec<String>>=const {RefCell::new(Vec::new())};
}
fn with_client<T>(operation:impl FnOnce(&Client)->Result<T,SysError>)->Result<T,SysError>{operation(&Client)}
impl Client {
    fn mkdir_at(&self,_:OpenAtBase,mode:u32,path:&str)->Result<(),SysError>{
        assert_eq!(mode,0o755);PATHS.with_borrow_mut(|p|p.push(path.into()));RESULT.get()
    }
}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../capability/src/persistent_grant.rs"),
        "fn ensure_policy_dir(",
        "\nfn write_file(",
    ));
    program.push_str(
        r#"
fn main(){
    assert_eq!(posix::STATUS_EEXIST,-17);
    for result in [Ok(()),Err(SysError::from_raw(posix::STATUS_EEXIST as i64))] {
        RESULT.set(result);PATHS.with_borrow_mut(Vec::clear);
        assert_eq!(ensure_policy_dir(),Ok(()));
        PATHS.with_borrow(|p|assert_eq!(p.as_slice(),["/var","/var/lib",POLICY_DIR]));
    }
    for status in [
        NativeError::AlreadyExists.into_raw() as i64,
        NativeError::AccessDenied.into_raw() as i64,
        NativeError::PeerClosed.into_raw() as i64,
        -13,-5,-2,17,
    ]{
        let error=SysError::from_raw(status);
        RESULT.set(Err(error));PATHS.with_borrow_mut(Vec::clear);
        assert_eq!(ensure_policy_dir(),Err(error));
        PATHS.with_borrow(|p|assert_eq!(p.as_slice(),["/var"]));
    }
}
"#,
    );
    probe::run(&program);
}
