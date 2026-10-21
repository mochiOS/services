#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn exec_requires_read_not_cursor_authority_and_closes_denied_images() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let replace = probe::between(
        runtime,
        "fn replace_process_image(",
        "fn execve_with_launch_context(",
    );
    let gate = probe::between(
        replace,
        "    let required_rights =",
        "    if let Err(error) = authorize_exec_path(",
    );
    let mut program = String::from(
        r#"
use std::cell::RefCell;
const EACCES:i32=13;
mod syscall {
    pub const HANDLE_RIGHT_READ:u64=1;
    pub const HANDLE_RIGHT_SEEK:u64=4;
}
thread_local! {static CLOSED:RefCell<Vec<u32>>=const {RefCell::new(Vec::new())};}
struct Opened {handle:u32,rights:u64}
fn close_object_handle(handle:u32) {CLOSED.with_borrow_mut(|closed|closed.push(handle));}
fn gate(opened:Opened)->Result<(),i32> {
"#,
    );
    program.push_str(gate);
    program.push_str(
        r#"
    Ok(())
}
fn main() {
    for rights in [1, 1|4, u64::MAX] {
        assert_eq!(gate(Opened{handle:7,rights}),Ok(()));
        CLOSED.with_borrow(|closed|assert!(closed.is_empty()));
    }
    for rights in [0, 4, u64::MAX & !1] {
        CLOSED.with_borrow_mut(Vec::clear);
        assert_eq!(gate(Opened{handle:9,rights}),Err(EACCES));
        CLOSED.with_borrow(|closed|assert_eq!(closed.as_slice(),[9]));
    }
}
"#,
    );
    probe::run(&program);
}
