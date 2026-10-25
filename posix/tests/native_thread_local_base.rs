//! CPU register and saved-context coherence across native calls and rescheduling.
#[cfg(target_os = "mochios")]
pub fn run() {
    use mochi_user_syscall::{NativeError, SyscallNumber, call2, execution, thread_local};
    #[repr(C, align(16))]
    struct Block([u64; 4]);
    let initial: u64;
    unsafe {
        core::arch::asm!("mov {}, fs:[0]", out(reg) initial, options(nostack, readonly, preserves_flags));
    }
    assert_ne!(initial, 0);
    let mut block = Block([0, 0x78a6_2903_feb4_c51d, 0, 0]);
    let base = &mut block as *mut Block as u64;
    unsafe {
        core::ptr::addr_of_mut!(block.0[0]).write_volatile(base);
    }
    thread_local::set_base(base).unwrap();
    let mut coherent = true;
    for _ in 0..16 {
        mochi_user_platform::thread::yield_now();
        let found: u64;
        let marker: u64;
        unsafe {
            core::arch::asm!("mov {}, fs:[0]", out(reg) found, options(nostack, readonly, preserves_flags));
            core::arch::asm!("mov {}, fs:[8]", out(reg) marker, options(nostack, readonly, preserves_flags));
        }
        coherent &=
            found == base && marker == 0x78a6_2903_feb4_c51d && execution::identity().is_ok();
    }
    let reserved = call2(SyscallNumber::ThreadLocalBaseSet, base, 1);
    let invalid = thread_local::set_base(0xffff_8000_0000_0000);
    let after_invalid: u64;
    unsafe {
        core::arch::asm!("mov {}, fs:[0]", out(reg) after_invalid, options(nostack, readonly, preserves_flags));
    }
    let cleared = thread_local::set_base(0);
    let native_without_base = execution::identity();
    // Restore the runtime's original private selector before assertions or I/O.
    thread_local::set_base(initial).unwrap();
    let restored: u64;
    unsafe {
        core::arch::asm!("mov {}, fs:[0]", out(reg) restored, options(nostack, readonly, preserves_flags));
    }
    assert!(coherent);
    assert_eq!(after_invalid, base);
    assert_eq!(
        reserved.unwrap_err().native_error(),
        Some(NativeError::InvalidArgument)
    );
    assert_eq!(
        invalid.unwrap_err().native_error(),
        Some(NativeError::InvalidAddress)
    );
    assert!(cleared.is_ok() && native_without_base.is_ok());
    assert_eq!(restored, initial);
    mochi_user_platform::io::stdout(b"thread-base: PASS current CPU base saved context syscall yield validation zero and restore\n").unwrap();
}
