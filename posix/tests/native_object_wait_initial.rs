use mnu_abi::{ClockId, HandleWaitGuard, HandleWaitItem, SyscallNumber, ThreadCreateContext};

#[test]
fn isolated_wait_probe_matches_native_abi_and_has_no_posix_runtime() {
    let source = include_str!("native_object_wait_initial.c");
    assert_eq!(core::mem::size_of::<HandleWaitItem>(), 24);
    assert_eq!(core::mem::size_of::<HandleWaitGuard>(), 16);
    assert_eq!(core::mem::size_of::<ThreadCreateContext>(), 176);
    assert_eq!(ClockId::Monotonic as u64, 0x4d4e55434c4b0002);
    for number in [
        SyscallNumber::ClockRead,
        SyscallNumber::ThreadCreate,
        SyscallNumber::ThreadExit,
        SyscallNumber::ThreadYield,
        SyscallNumber::HandleClose,
        SyscallNumber::HandleDuplicate,
        SyscallNumber::HandleWaitMany,
        SyscallNumber::StreamPairCreate,
        SyscallNumber::WakeAddress,
        SyscallNumber::DebugWrite,
        SyscallNumber::StreamWrite,
        SyscallNumber::StreamRead,
        SyscallNumber::HandleWaitManyGuarded,
    ] {
        assert!(source.contains(&format!("native({},", number as u64)));
    }
    for (name, error) in [
        ("NOT_READY", mnu_abi::status::Error::NotReady),
        ("INVALID_ARGUMENT", mnu_abi::status::Error::InvalidArgument),
        ("INVALID_ADDRESS", mnu_abi::status::Error::InvalidAddress),
        ("ACCESS_DENIED", mnu_abi::status::Error::AccessDenied),
    ] {
        assert!(source.contains(&format!(
            "#define {name} INT64_C({})",
            error.into_raw() as i64
        )));
    }
    assert!(source.contains("void _start(void)"));
    assert!(!source.contains("#include <stdio.h>"));
    assert!(!source.contains("pthread_"));
    assert!(!source.contains("posix.service"));
}
