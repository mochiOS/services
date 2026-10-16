#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn logger_reports_native_failures_in_the_posix_wire_namespace() {
    let mut program = probe::program();
    program.push_str("mod wire_status {\n");
    program.push_str(
        &include_str!("../../../user/crates/posix-protocol/src/status.rs")
            .replace("mnu_abi::", "crate::mnu_abi::"),
    );
    program.push_str("}\n");
    probe::constants(
        &mut program,
        include_str!("../../../user/crates/posix-protocol/src/lib.rs"),
        &["STATUS_EIO", "STATUS_EAGAIN"],
    );
    program.push_str(
        r#"
    mod platform {
        pub mod syscall {pub use crate::mochi_user_syscall::SysError;}
        pub mod io {pub const STDERR:u64=2;}
        pub static MESSAGE:std::sync::Mutex<String>=std::sync::Mutex::new(String::new());
        pub fn write_fmt(fd:u64,args:std::fmt::Arguments<'_>)->Result<(),()> {
            assert_eq!(fd,2); *MESSAGE.lock().unwrap()=args.to_string(); Ok(())
        }
    }
    "#,
    );
    program.push_str(
        &probe::between(
            include_str!("../../logger/src/main.rs"),
            "fn error_errno(",
            "fn main(",
        )
        .replace("mochios_posix_protocol::status::", "wire_status::"),
    );
    program.push_str(
        r#"
    fn main() {
        use mnu_abi::status::Error;
        for (raw,expected) in [
            (-13,13),(13,13),
            (Error::LimitExceeded.into_raw() as i64,75),
            (Error::InvalidAddress.into_raw() as i64,14),
            (Error::ResourceUnavailable.into_raw() as i64,12),
            (Error::BackingFailure.into_raw() as i64,5),
            (Error::InvalidArgument.into_raw() as i64,22),
            (Error::AccessDenied.into_raw() as i64,13),
            (Error::NotReady.into_raw() as i64,11),
            (((Error::LimitExceeded.into_raw() & !0xffff)|0xffff) as i64,5),
            (0,5),(i64::MIN,5),(i64::MAX,5),
        ] {
            let error=SysError::from_raw(raw);
            assert_eq!(error_errno(error),expected);
            report_persistence_error(error);
            assert_eq!(*platform::MESSAGE.lock().unwrap(),format!(
                "logger.service: log persistence failed errno={expected}\n"));
        }
    }
    "#,
    );
    probe::run(&program);
}
