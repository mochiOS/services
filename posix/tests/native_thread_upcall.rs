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

#[test]
fn image_replacement_discards_upcalls_only_after_committing_the_new_address_space() {
    let source = include_str!("../../../core/src/syscall/exec.rs");
    let replacement = source
        .split("fn replace_current_process_image(")
        .nth(1)
        .unwrap();
    let committed = replacement
        .find("process.set_page_table(new_pt_phys)")
        .unwrap();
    let reset = replacement
        .find("thread.clear_upcall_for_image_replace()")
        .unwrap();
    let release = replacement.find("destroy_user_page_table(old)").unwrap();
    let enter = replacement
        .find("jump_to_usermode(entry, initial_rsp, 0)")
        .unwrap();
    assert!(committed < reset && reset < release && release < enter);
    let thread = include_str!("../../../core/src/task/thread.rs");
    let clear = thread
        .split("pub fn clear_upcall_for_image_replace(")
        .nth(1)
        .unwrap()
        .split("pub fn enqueue_upcall(")
        .next()
        .unwrap();
    assert!(clear.contains("next_token: self.upcall.next_token"));
    assert!(clear.contains("..ThreadUpcallState::new()"));
}
