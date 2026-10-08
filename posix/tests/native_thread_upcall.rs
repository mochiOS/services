use mochi_user_platform::syscall::{SyscallNumber, ThreadUpcallConfig};

#[test]
fn native_thread_upcall_configuration_is_fixed_and_policy_free() {
    let config = ThreadUpcallConfig {
        entry: 0x1000,
        stack_base: 0x8000,
        stack_size: 0x4000,
        flags: 0,
        reserved: [0; 4],
    };

    assert_eq!(core::mem::size_of::<ThreadUpcallConfig>(), 64);
    assert_eq!(core::mem::align_of::<ThreadUpcallConfig>(), 8);
    assert_eq!(config.entry, 0x1000);
    assert_eq!(config.stack_base, 0x8000);
    assert_eq!(config.stack_size, 0x4000);
    assert_eq!(config.flags, 0);
    assert_eq!(config.reserved, [0; 4]);
}

#[test]
fn native_thread_upcall_syscalls_are_not_posix_operations() {
    assert_eq!(SyscallNumber::ThreadUpcallInstall as u64, 654);
    assert_eq!(SyscallNumber::ThreadUpcallReturn as u64, 655);
    assert_eq!(SyscallNumber::ThreadHandleCreate as u64, 656);
    assert_eq!(SyscallNumber::ThreadInterrupt as u64, 657);
    assert_eq!(SyscallNumber::ThreadHandleStatus as u64, 658);
    assert_eq!(SyscallNumber::ProcessHandleOpenById as u64, 659);
}

#[test]
fn legacy_posix_kill_is_not_a_native_syscall() {
    let native_numbers = [
        SyscallNumber::ThreadInterrupt as u64,
        SyscallNumber::ProcessHandleTerminate as u64,
        SyscallNumber::ProcessHandleOpenById as u64,
    ];

    assert!(!native_numbers.contains(&62));
}
