#[test]
fn production_runtime_maps_native_causes_only_inside_posix_userspace() {
    use mnu_abi::MemoryFaultCause::*;
    use mochios_posix_client::signal_context::*;
    use mochios_posix_protocol as protocol;
    for (cause, signal, code) in [
        (Unmapped, protocol::SIGNAL_SEGV, SEGV_MAPERR),
        (AccessDenied, protocol::SIGNAL_SEGV, SEGV_ACCERR),
        (Unresolved, protocol::SIGNAL_SEGV, SI_KERNEL),
        (OutsideBacking, protocol::SIGNAL_BUS, BUS_ADRERR),
        (BackingFailure, protocol::SIGNAL_BUS, BUS_OBJERR),
        (ResourceUnavailable, protocol::SIGNAL_BUS, BUS_OBJERR),
    ] {
        let info = SigInfo::memory_fault(cause as u64, 0x1234).unwrap();
        assert!(
            !(1..=5).contains(&info.si_code),
            "fault aliases a generic SI_* source"
        );
        assert_eq!(
            (info.si_signo, info.si_code, info.si_addr),
            (signal as i32, code, 0x1234)
        );
        assert_eq!(
            (info.si_pid, info.si_uid, info.si_errno, info.reserved_uid),
            (0, 0, 0, 0)
        );
    }
    for invalid in [0, 7, u64::MAX] {
        assert!(SigInfo::memory_fault(invalid, 0).is_err());
    }
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/fault_signal.rs");
    assert!(runtime.contains("signal_context::SigInfo::memory_fault(cause, address)"));
}

#[test]
fn native_probe_numbers_and_runtime_exception_opt_in_match_the_current_abi() {
    let probe = include_str!("posix_memory_fault.c");
    for (name, value) in [
        ("MEMORY_MAP", mnu_abi::SyscallNumber::MemoryMap),
        ("MEMORY_UNMAP", mnu_abi::SyscallNumber::MemoryUnmap),
        ("MEMORY_CREATE", mnu_abi::SyscallNumber::MemoryObjectCreate),
        ("MEMORY_RESIZE", mnu_abi::SyscallNumber::MemoryObjectResize),
        ("HANDLE_CLOSE", mnu_abi::SyscallNumber::HandleClose),
    ] {
        assert!(probe.contains(&format!("{name} = {}", value as u64)));
    }
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let setup = runtime.split("fn setup_signal_delivery(").nth(1).unwrap();
    assert!(
        setup
            .split("let install =")
            .next()
            .unwrap()
            .contains("flags: syscall::THREAD_UPCALL_EXCEPTIONS")
    );
    assert!(runtime.contains("fault_signal::deliver(cause, address as usize)"));
}
