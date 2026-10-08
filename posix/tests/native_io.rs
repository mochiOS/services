use mochi_user_platform::syscall::SyscallNumber;

#[test]
fn native_io_uses_objects_instead_of_posix_file_descriptors() {
    assert_eq!(SyscallNumber::HandleRead as u64, 634);
    assert_eq!(SyscallNumber::HandleWrite as u64, 635);
    assert_eq!(SyscallNumber::DebugWrite as u64, 660);
    assert_eq!(SyscallNumber::HandleSameObject as u64, 666);
    assert_eq!(SyscallNumber::ProviderObjectSignal as u64, 667);

    let native_numbers = [
        SyscallNumber::HandleRead as u64,
        SyscallNumber::HandleWrite as u64,
        SyscallNumber::DebugWrite as u64,
        SyscallNumber::HandleSameObject as u64,
        SyscallNumber::ProviderObjectSignal as u64,
    ];
    assert!(!native_numbers.contains(&0));
    assert!(!native_numbers.contains(&1));
}
