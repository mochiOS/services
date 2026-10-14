//! Compile against the actual target libc, not an extracted host shim.
#![no_std]
// This probe intentionally checks the libc instance used to build Rust std.
#![feature(rustc_private)]
extern crate libc;
use libc::*;

const _: [(); 2] = [(); core::mem::size_of::<sa_family_t>()];
const _: [(); 4] = [(); core::mem::size_of::<socklen_t>()];
const _: [(); 16] = [(); core::mem::size_of::<sockaddr>()];
const _: [(); 110] = [(); core::mem::size_of::<sockaddr_un>()];
const _: [(); 128] = [(); core::mem::size_of::<sockaddr_storage>()];
const _: [(); 8] = [(); core::mem::align_of::<sockaddr_storage>()];
const _: [(); 56] = [(); core::mem::size_of::<msghdr>()];
const _: [(); 16] = [(); core::mem::size_of::<cmsghdr>()];
const _: [(); 16] = [(); core::mem::offset_of!(msghdr, msg_iov)];
const _: [(); 32] = [(); core::mem::offset_of!(msghdr, msg_control)];
const _: [(); 48] = [(); core::mem::offset_of!(msghdr, msg_flags)];
const _: [(); 1] = [(); (SOL_SOCKET == 1 && SO_TYPE == 3 && SO_ERROR == 4
    && SO_SNDBUF == 7 && SO_RCVBUF == 8 && SO_RCVTIMEO == 20 && SO_SNDTIMEO == 21
    && SO_ACCEPTCONN == 30 && SOCK_CLOEXEC == 0x80000 && SOCK_NONBLOCK == 0x800
    && AF_INET6 == 10 && PF_INET6 == 10 && MSG_DONTWAIT == 0x40
    && MSG_WAITALL == 0x100 && MSG_NOSIGNAL == 0x4000 && SCM_RIGHTS == 1) as usize];
const _: [(); 24] = [(); unsafe { CMSG_SPACE(4) } as usize];
const _: [(); 20] = [(); unsafe { CMSG_LEN(4) } as usize];
const _: [(); 0x5421] = [(); FIONBIO as usize];
const _: unsafe extern "C" fn(i32, u64, ...) -> i32 = ioctl;
const _: unsafe extern "C" fn(i32, *const msghdr, i32) -> isize = sendmsg;
const _: unsafe extern "C" fn(i32, *mut msghdr, i32) -> isize = recvmsg;
const _: unsafe extern "C" fn(i32, *mut sockaddr, *mut socklen_t, i32) -> i32 = accept4;
const _: unsafe extern "C" fn(*const msghdr) -> *mut cmsghdr = CMSG_FIRSTHDR;
const _: unsafe extern "C" fn(*const cmsghdr) -> *mut u8 = CMSG_DATA;
const _: unsafe extern "C" fn(*const msghdr, *const cmsghdr) -> *mut cmsghdr = CMSG_NXTHDR;
