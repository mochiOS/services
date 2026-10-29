//! Real Rust libc ABI and caller capability enforcement, in disposable children.
#![cfg(target_os = "mochios")]
use mochi_user_platform as p;
pub fn run() {
    unsafe extern "C" {
        fn __errno() -> *mut i32;
    }
    for uid in [0, 501] {
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                assert_eq!(libc::seteuid(uid), 0);
                let capability = b"net.connect";
                p::syscall::call2(
                    mnu_abi::SyscallNumber::CapDrop,
                    capability.as_ptr() as u64,
                    capability.len() as u64,
                )
                .unwrap();
                let mut hints: libc::addrinfo = core::mem::zeroed();
                hints.ai_family = libc::AF_INET;
                hints.ai_socktype = libc::SOCK_STREAM;
                let mut result = core::ptr::null_mut();
                assert_eq!(
                    libc::getaddrinfo(
                        c"netdb-probe.invalid".as_ptr(),
                        c"73".as_ptr(),
                        &hints,
                        &mut result
                    ),
                    libc::EAI_SYSTEM
                );
                assert!(result.is_null());
                assert_eq!(*__errno(), libc::EACCES);
                hints.ai_flags = libc::AI_NUMERICHOST | libc::AI_NUMERICSERV;
                assert_eq!(
                    libc::getaddrinfo(c"192.0.2.73".as_ptr(), c"73".as_ptr(), &hints, &mut result),
                    0
                );
                assert_eq!((*result).ai_family, libc::AF_INET);
                assert_eq!((*result).ai_addrlen, 16);
                let mut host = [0; libc::NI_MAXHOST as usize];
                assert_eq!(
                    libc::getnameinfo(
                        (*result).ai_addr,
                        (*result).ai_addrlen,
                        host.as_mut_ptr(),
                        host.len() as u32,
                        core::ptr::null_mut(),
                        0,
                        libc::NI_NUMERICHOST
                    ),
                    0
                );
                assert_eq!(core::ffi::CStr::from_ptr(host.as_ptr()), c"192.0.2.73");
                libc::freeaddrinfo(result);
                p::io::stdout(if uid==0 {b"netdb-rust: PASS libc ABI and numeric-only resolution after CapDrop euid 0\n"} else {b"netdb-rust: PASS libc ABI and numeric-only resolution after CapDrop euid 501\n"}).unwrap();
                libc::_exit(0);
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert_eq!(status, 0);
        }
    }
}
