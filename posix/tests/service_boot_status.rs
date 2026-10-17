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
