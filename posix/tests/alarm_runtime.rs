#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn runtime_alarm_preserves_success_errno_and_reports_endpoint_errors() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let implementation = probe::between(
        runtime,
        "/// Process-wide elapsed-time alarm;",
        "/// Unlike nanosleep, POSIX clock_nanosleep",
    );
    let mut program = String::from(
        r#"
use std::cell::Cell;
thread_local! {
static REPLY:Cell<Result<u32,i32>>=const{Cell::new(Ok(0))};
static CONNECT:Cell<bool>=const{Cell::new(true)};
static INPUT:Cell<u32>=const{Cell::new(0)};
static ERRNO:Cell<i32>=const{Cell::new(77)};
}
struct Client;
fn posix_client()->Result<Client,i32>{if CONNECT.get(){Ok(Client)}else{Err(5)}}
fn map_posix_client_error(error:i32)->i32{error}
fn set_errno(error:i32){ERRNO.set(error);}
impl Client{fn alarm(&self,seconds:u32)->Result<u32,i32>{INPUT.set(seconds);REPLY.get()}}
"#,
    );
    program.push_str(implementation);
    program.push_str(r#"
fn main(){
for seconds in [0,1,u32::MAX] {for previous in [0,1,u32::MAX]{
ERRNO.set(77);REPLY.set(Ok(previous));assert_eq!(alarm(seconds),previous);
assert_eq!(INPUT.get(),seconds);assert_eq!(ERRNO.get(),77);
}}
for error in [5,22,75]{REPLY.set(Err(error));assert_eq!(alarm(1),0);assert_eq!(ERRNO.get(),error);}
CONNECT.set(false);INPUT.set(99);assert_eq!(alarm(2),0);assert_eq!(ERRNO.get(),5);assert_eq!(INPUT.get(),99);
}
"#);
    probe::run(&program);
}
