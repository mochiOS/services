//! Run the C++ target executable only after normal userspace bootstrap.
#[cfg(all(target_os = "mochios", mochios_thread_local_probe_227))]
#[path = "native_thread_local_base.rs"]
mod thread_local_base;

#[cfg(all(target_os = "mochios", mochios_residency_probe_224))]
#[path = "native_memory_usage.rs"]
mod memory_usage;

#[cfg(target_os = "mochios")]
pub fn run() {
    #[cfg(mochios_thread_local_probe_227)]
    thread_local_base::run();
    #[cfg(mochios_residency_probe_224)]
    memory_usage::run();
    #[cfg(mochios_memory_advice_probe_218)]
    {
        use mochi_user_syscall::{SyscallNumber, call2};
        let local = 0u8;
        assert_eq!(
            call2(
                SyscallNumber::MemoryRangeCheck,
                (&local as *const u8) as u64,
                1
            )
            .unwrap(),
            0
        );
        assert_eq!(
            call2(SyscallNumber::MemoryRangeCheck, u64::MAX, 0).unwrap(),
            0
        );
        for (address, length) in [(0, 1), (u64::MAX, 1), (0xffff800000000000, 4096)] {
            assert_eq!(
                call2(SyscallNumber::MemoryRangeCheck, address, length)
                    .unwrap_err()
                    .native_error(),
                Some(mnu_abi::status::Error::InvalidAddress)
            );
        }
    }
    unsafe extern "C" {
        fn fork() -> i32;
        fn execve(path: *const u8, argv: *const *const u8, env: *const *const u8) -> i32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn _exit(status: i32) -> !;
        fn __errno() -> *mut i32;
        fn seteuid(uid: u32) -> i32;
    }
    unsafe {
        for reduced_identity in [false, true] {
            let child = fork();
            assert!(child >= 0, "C++ probe fork errno={}", *__errno());
            if child == 0 {
                if reduced_identity && seteuid(501) != 0 {
                    _exit(125);
                }
                let arguments = [
                    c"deliberately-unrelated-argv0".as_ptr().cast(),
                    core::ptr::null(),
                ];
                let environment = [core::ptr::null()];
                execve(
                    c"/system/bin/llvm-runtime-probe".as_ptr().cast(),
                    arguments.as_ptr(),
                    environment.as_ptr(),
                );
                _exit(126);
            }
            let mut status = 0;
            assert_eq!(waitpid(child, &mut status, 0), child);
            assert_eq!(status, 0, "C++ probe child wait status={status}");
        }
        mochi_user_platform::io::stdout(b"llvm-runtime: PASS child exec and wait\n").unwrap();
    }
}
