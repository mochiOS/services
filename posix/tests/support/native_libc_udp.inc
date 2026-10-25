// C ABI integration, linked against the standalone runtime, not a host libc.
use core::ffi::c_void;
#[repr(C, align(4))]
#[derive(Clone, Copy)]
struct InetAddress {
    family: u16,
    port: u16,
    address: [u8; 4],
    zero: [u8; 8],
}
impl InetAddress {
    fn local() -> Self {
        Self {
            family: 2,
            port: 0,
            address: [127, 0, 0, 1],
            zero: [0; 8],
        }
    }
}
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}
unsafe extern "C" {
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn bind(fd: i32, address: *const c_void, length: u32) -> i32;
    fn connect(fd: i32, address: *const c_void, length: u32) -> i32;
    fn getsockname(fd: i32, address: *mut c_void, length: *mut u32) -> i32;
    fn sendto(
        fd: i32,
        data: *const c_void,
        len: usize,
        flags: i32,
        address: *const c_void,
        address_len: u32,
    ) -> isize;
    fn recvfrom(
        fd: i32,
        data: *mut c_void,
        len: usize,
        flags: i32,
        address: *mut c_void,
        address_len: *mut u32,
    ) -> isize;
    fn send(fd: i32, data: *const c_void, len: usize, flags: i32) -> isize;
    fn poll(fds: *mut PollFd, count: u32, timeout: i32) -> i32;
    fn dup(fd: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn __errno() -> *mut i32;
}
unsafe fn ready(fd: i32) {
    let mut item = PollFd {
        fd,
        events: 1,
        revents: 0,
    };
    assert_eq!(unsafe { poll(&mut item, 1, 2000) }, 1);
    assert_ne!(item.revents & 1, 0);
}
pub fn run() {
    unsafe {
        let receiver = socket(2, 2 | 0x800, 0);
        assert!(receiver >= 0, "socket errno={}", *__errno());
        let sender = socket(2, 2 | 0x800, 17);
        assert!(sender >= 0, "socket errno={}", *__errno());
        let mut address = InetAddress::local();
        assert_eq!(
            bind(receiver, core::ptr::addr_of!(address).cast(), 16),
            0,
            "bind errno={}",
            *__errno()
        );
        let mut length = 16;
        assert_eq!(
            getsockname(
                receiver,
                core::ptr::addr_of_mut!(address).cast(),
                &mut length
            ),
            0
        );
        assert_eq!(length, 16);
        assert_ne!(u16::from_be(address.port), 0);
        assert_eq!(
            sendto(
                sender,
                b"hello".as_ptr().cast(),
                5,
                0,
                core::ptr::addr_of!(address).cast(),
                16
            ),
            5,
            "sendto errno={}",
            *__errno()
        );
        ready(receiver);
        let mut output = [0u8; 64];
        let mut source = InetAddress::local();
        let mut source_length = 16;
        assert_eq!(
            recvfrom(
                receiver,
                output.as_mut_ptr().cast(),
                2,
                2,
                core::ptr::addr_of_mut!(source).cast(),
                &mut source_length
            ),
            2,
            "peek errno={}",
            *__errno()
        );
        assert_eq!(&output[..2], b"he");
        assert_eq!(source_length, 16);
        assert_eq!(source.address, [127, 0, 0, 1]);
        assert_ne!(u16::from_be(source.port), 0);
        assert_eq!(
            recvfrom(
                receiver,
                output.as_mut_ptr().cast(),
                2,
                0x20,
                core::ptr::null_mut(),
                core::ptr::null_mut()
            ),
            5
        );
        assert_eq!(&output[..2], b"he");
        assert_eq!(
            recvfrom(
                receiver,
                output.as_mut_ptr().cast(),
                64,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut()
            ),
            -1
        );
        assert_eq!(*__errno(), mochios_posix_client::newlib_errno::EAGAIN);
        assert_eq!(
            sendto(
                sender,
                core::ptr::null(),
                0,
                0,
                core::ptr::addr_of!(address).cast(),
                16
            ),
            0
        );
        ready(receiver);
        assert_eq!(
            recvfrom(
                receiver,
                core::ptr::null_mut(),
                0,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut()
            ),
            0
        );
        assert_eq!(
            sendto(
                sender,
                b"discard".as_ptr().cast(),
                7,
                0,
                core::ptr::addr_of!(address).cast(),
                16
            ),
            7
        );
        ready(receiver);
        assert_eq!(
            recvfrom(
                receiver,
                core::ptr::null_mut(),
                0,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut()
            ),
            0
        );
        assert_eq!(
            recvfrom(
                receiver,
                output.as_mut_ptr().cast(),
                64,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut()
            ),
            -1
        );
        assert_eq!(*__errno(), mochios_posix_client::newlib_errno::EAGAIN);
        assert_eq!(
            connect(sender, core::ptr::addr_of!(address).cast(), 16),
            0,
            "connect errno={}",
            *__errno()
        );
        let alias = dup(receiver);
        assert!(alias >= 0);
        assert_eq!(close(receiver), 0);
        assert_eq!(send(sender, b"connected".as_ptr().cast(), 9, 0), 9);
        ready(alias);
        assert_eq!(
            recvfrom(
                alias,
                output.as_mut_ptr().cast(),
                64,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut()
            ),
            9
        );
        assert_eq!(&output[..9], b"connected");
        assert_eq!(close(alias), 0);
        assert_eq!(close(sender), 0);
        mochi_user_platform::io::stdout(b"libc-udp: PASS socket bind sendto recvfrom source peek MSG_TRUNC empty/zero receive connect poll dup close\n").unwrap();
    }
}
pub fn denied_after_capability_drop() {
    unsafe {
        assert_eq!(socket(2, 2 | 0x800, 0), -1);
        assert_eq!(*__errno(), mochios_posix_client::newlib_errno::EACCES);
    }
}
