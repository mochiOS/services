//! Kernel-local errors must not model userspace filesystem/service policy.
use std::cell::RefCell;

thread_local! {static LOG: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };}
macro_rules! record {
    ($($arg:tt)*) => {crate::LOG.with_borrow_mut(|log| log.push(format!($($arg)*)))};
}
pub(crate) use record as warn;
pub(crate) use record as debug;
pub(crate) use record as info;

#[path = "../../../core/src/result.rs"]
#[allow(dead_code)]
mod result;

#[test]
fn unused_fd_directory_service_and_zombie_policy_are_not_kernel_error_types() {
    let source = include_str!("../../../core/src/result.rs");
    for forbidden in [
        "pub enum Syscall",
        "Syscall(Syscall)",
        "pub type SyscallErr",
        "BadFd",
        "NotDirectory",
        "IsDirectory",
        "pub enum Service",
        "Service(Service)",
        "ZombieProcess",
    ] {
        assert!(
            !source.contains(forbidden),
            "userspace policy in kernel result: {forbidden}"
        );
    }
}

#[test]
fn generic_errors_keep_their_result_and_diagnostic_behavior() {
    use result::{Device, Elf, Kernel, Memory, Process};
    for (error, diagnostic, fatal, retryable) in [
        (
            Kernel::Memory(Memory::InvalidAddress),
            "Memory error: InvalidAddress",
            false,
            false,
        ),
        (
            Kernel::Memory(Memory::OutOfMemory),
            "Memory error: OutOfMemory",
            true,
            false,
        ),
        (
            Kernel::Process(Process::ProcessNotFound),
            "Process error: ProcessNotFound",
            false,
            false,
        ),
        (
            Kernel::Process(Process::MaxProcessesReached),
            "Process error: MaxProcessesReached",
            false,
            false,
        ),
        (
            Kernel::Device(Device::Busy),
            "Device error: Busy",
            false,
            true,
        ),
        (
            Kernel::Device(Device::HardwareFailure),
            "Device error: HardwareFailure",
            true,
            false,
        ),
        (
            Kernel::Elf(Elf::InvalidFormat),
            "ELF error: InvalidFormat",
            false,
            false,
        ),
        (Kernel::InvalidParam, "Invalid parameter", false, false),
        (Kernel::NotImplemented, "Not implemented", false, false),
    ] {
        let value: result::Result<()> = Err(error);
        assert_eq!(value, Err(error));
        assert_eq!(error.to_string(), diagnostic);
        assert_eq!(error.is_fatal(), fatal);
        assert_eq!(error.is_retryable(), retryable);
        LOG.with_borrow_mut(Vec::clear);
        result::handle_kernel_error(error);
        LOG.with_borrow(|log| assert_eq!(log[0], format!("KERNEL ERROR: {diagnostic}")));
    }
    assert_eq!(Memory::PermissionDenied.to_string(), "Permission denied");
    assert_eq!(
        Memory::Busy.to_string(),
        "Memory backing is temporarily reserved"
    );
}
