fn main() {
    macro_rules! value { ($($name:ident),+) => {$(println!("{}={}", stringify!($name), $name);)+}; }
    macro_rules! size { ($type:ty, $name:literal) => {println!("sizeof({})={}", $name, core::mem::size_of::<$type>());}; }
    macro_rules! align { ($type:ty, $name:literal) => {println!("alignof({})={}", $name, core::mem::align_of::<$type>());}; }
    macro_rules! offset { ($type:ty, $name:literal, $($field:ident),+) => {$(println!("{}.{}={}", $name, stringify!($field), core::mem::offset_of!($type, $field));)+}; }
    value!(AF_UNSPEC, AF_UNIX, AF_LOCAL, AF_INET, AF_INET6, PF_UNSPEC, PF_UNIX, PF_LOCAL, PF_INET, PF_INET6);
    value!(SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET, SOCK_NONBLOCK, SOCK_CLOEXEC);
    value!(SOL_SOCKET, SO_DEBUG, SO_REUSEADDR, SO_TYPE, SO_ERROR, SO_DONTROUTE, SO_BROADCAST, SO_SNDBUF, SO_RCVBUF);
    value!(SO_KEEPALIVE, SO_OOBINLINE, SO_LINGER, SO_REUSEPORT, SO_RCVLOWAT, SO_SNDLOWAT, SO_RCVTIMEO, SO_SNDTIMEO);
    value!(SO_TIMESTAMP, SO_ACCEPTCONN, SOMAXCONN, SHUT_RD, SHUT_WR, SHUT_RDWR);
    value!(SCM_RIGHTS, MSG_OOB, MSG_PEEK, MSG_DONTROUTE, MSG_CTRUNC, MSG_TRUNC, MSG_DONTWAIT, MSG_WAITALL);
    value!(MSG_NOSIGNAL, MSG_MORE, MSG_CMSG_CLOEXEC);
    size!(sa_family_t, "sa_family_t"); size!(socklen_t, "socklen_t");
    size!(sockaddr, "struct sockaddr"); align!(sockaddr, "struct sockaddr"); offset!(sockaddr, "struct sockaddr", sa_data);
    size!(sockaddr_un, "struct sockaddr_un"); align!(sockaddr_un, "struct sockaddr_un"); offset!(sockaddr_un, "struct sockaddr_un", sun_path);
    size!(iovec, "struct iovec"); align!(iovec, "struct iovec"); offset!(iovec, "struct iovec", iov_base, iov_len);
    size!(msghdr, "struct msghdr"); align!(msghdr, "struct msghdr");
    offset!(msghdr, "struct msghdr", msg_name, msg_namelen, msg_iov, msg_iovlen, msg_control, msg_controllen, msg_flags);
    size!(cmsghdr, "struct cmsghdr"); align!(cmsghdr, "struct cmsghdr"); offset!(cmsghdr, "struct cmsghdr", cmsg_len, cmsg_level, cmsg_type);
    unsafe {
        for length in 0..=1012 { println!("space={},len={}", CMSG_SPACE(length), CMSG_LEN(length)); }
        let header: cmsghdr = core::mem::zeroed();
        println!("data={}", CMSG_DATA(&header) as usize - &header as *const cmsghdr as usize);
        for bound in [0, 1, 15, 16, 17, 23, 24, 31, 32, 39, 40, 44, 64, 128] {
            for size in [0, 1, 15, 16, 17, 20, 24, 40, 64, 128, usize::MAX, usize::MAX - 7] {
                for position in [0, 8, 16, 112, 120, 128] {
                    let mut data = [0usize; 16];
                    let base = data.as_mut_ptr().cast::<u8>();
                    let mut message: msghdr = core::mem::zeroed();
                    message.msg_control = base.cast(); message.msg_controllen = bound;
                    let header = base.add(position).cast::<cmsghdr>();
                    if position + core::mem::size_of::<cmsghdr>() <= core::mem::size_of_val(&data) {
                        (*header).cmsg_len = size;
                    }
                    let first = CMSG_FIRSTHDR(&message); let next = CMSG_NXTHDR(&message, header);
                    println!("first={},next={}", if first.is_null() { usize::MAX } else { first as usize - base as usize },
                        if next.is_null() { usize::MAX } else { next as usize - base as usize });
                }
            }
        }
        let mut message: msghdr = core::mem::zeroed();
        message.msg_controllen = 128;
        assert!(CMSG_FIRSTHDR(&message).is_null() && CMSG_NXTHDR(&message, core::ptr::null()).is_null());
    }
    const _: unsafe extern "C" fn(i32, *const msghdr, i32) -> isize = sendmsg;
    const _: unsafe extern "C" fn(i32, *mut msghdr, i32) -> isize = recvmsg;
    const _: unsafe extern "C" fn(i32, *mut sockaddr, *mut socklen_t, i32) -> i32 = accept4;
}
