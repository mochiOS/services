pub use mnu_abi::{ExecutionIdentity, SyscallNumber};

#[derive(Debug, PartialEq, Eq)]
pub struct SysError(i64);
impl SysError {
    pub fn from_raw(raw: i64) -> Self {
        Self(raw)
    }
}
pub type SysResult<T> = Result<T, SysError>;

struct Reply {
    status: i64,
    process: u64,
    thread: u64,
    calls: usize,
}
static REPLY: std::sync::Mutex<Reply> = std::sync::Mutex::new(Reply {
    status: 0,
    process: 70,
    thread: 7,
    calls: 0,
});
pub fn call2(number: SyscallNumber, pointer: u64, length: u64) -> SysResult<u64> {
    assert_eq!(number, SyscallNumber::ExecutionIdentityRead);
    assert_eq!(length, std::mem::size_of::<ExecutionIdentity>() as u64);
    let mut reply = REPLY.lock().unwrap();
    reply.calls += 1;
    if reply.status < 0 {
        return Err(SysError(reply.status));
    }
    // The production helper passes a live, aligned stack allocation.
    unsafe {
        (pointer as *mut ExecutionIdentity).write(ExecutionIdentity {
            process_id: reply.process,
            thread_id: reply.thread,
        });
    }
    Ok(reply.status as u64)
}
pub fn call3(number: SyscallNumber, pointer: u64, length: u64, endpoint: u64) -> SysResult<u64> {
    assert_eq!(number, SyscallNumber::IpcEndpointIdentityRead);
    assert_eq!(endpoint, 0x4000_0005);
    call2(SyscallNumber::ExecutionIdentityRead, pointer, length)
}
#[path = "../../../user/crates/syscall/src/execution.rs"]
mod production;

#[test]
fn client_rejects_invalid_identity_and_propagates_errors_without_fallback() {
    for (status, process, thread, expected) in [
        (
            0,
            70,
            7,
            Ok(ExecutionIdentity {
                process_id: 70,
                thread_id: 7,
            }),
        ),
        (-13, 70, 7, Err(SysError(-13))),
        (-38, 70, 7, Err(SysError(-38))),
        (1, 70, 7, Err(SysError(mnu_abi::EIO as i64))),
        (0, 0, 7, Err(SysError(mnu_abi::EIO as i64))),
        (0, 70, 0, Err(SysError(mnu_abi::EIO as i64))),
    ] {
        *REPLY.lock().unwrap() = Reply {
            status,
            process,
            thread,
            calls: 0,
        };
        assert_eq!(production::identity(), expected);
        assert_eq!(REPLY.lock().unwrap().calls, 1);
        assert_eq!(production::endpoint_identity(0x4000_0005), expected);
        assert_eq!(REPLY.lock().unwrap().calls, 2);
        assert_eq!(
            production::endpoint_identity(0),
            Err(SysError(mnu_abi::EINVAL as i64))
        );
        assert_eq!(REPLY.lock().unwrap().calls, 2);
    }
}

#[test]
fn self_identification_callers_do_not_request_kernel_credentials() {
    let platform = include_str!("../../../user/crates/platform/src/lib.rs");
    assert!(!platform.contains("fn current_security_context("));
    let current = platform
        .split("pub fn current_thread_id()")
        .nth(1)
        .unwrap()
        .split("pub fn open_handle_for_endpoint")
        .next()
        .unwrap();
    assert!(!current.contains("thread_security_context"));
    assert!(current.contains("syscall::execution::identity()"));
    for source in [
        include_str!("../src/main.rs"),
        include_str!("../../capability/src/dynamic_grant.rs"),
        include_str!("../../../binaries/coreutils/src/bin/test_desktop.rs"),
    ] {
        assert!(!source.contains("current_security_context()"));
        assert!(source.contains("current_execution_identity()"));
    }
}
