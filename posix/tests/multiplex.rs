use mochios_posix_client::multiplex::select_ready_count;

#[test]
fn select_counts_each_ready_set_instead_of_distinct_descriptors() {
    assert_eq!(select_ready_count(0, 0, 0), 0);
    for fd in 0..64 {
        let bit = 1u64 << fd;
        assert_eq!(select_ready_count(bit, 0, 0), 1);
        assert_eq!(select_ready_count(bit, bit, 0), 2);
        assert_eq!(select_ready_count(bit, bit, bit), 3);
    }
    assert_eq!(select_ready_count(0b101, 0b110, 0b100), 5);
    assert_eq!(select_ready_count(u64::MAX, u64::MAX, u64::MAX), 192);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn select_count_matches_host_select_for_a_readable_and_writable_file() {
    use std::os::fd::AsRawFd;

    unsafe extern "C" {
        fn select(
            nfds: i32,
            read: *mut [u64; 16],
            write: *mut [u64; 16],
            exceptional: *mut [u64; 16],
            timeout: *mut [i64; 2],
        ) -> i32;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    let fd = file.as_raw_fd();
    assert!((0..64).contains(&fd));
    let mut read = [0u64; 16];
    let mut write = [0u64; 16];
    let mut exceptional = [0u64; 16];
    read[0] = 1u64 << fd;
    write[0] = 1u64 << fd;
    let mut timeout = [0i64; 2];
    // Linux x86_64 fd_set is 1024 bits and timeval has two signed longs.
    let count = unsafe {
        select(
            fd + 1,
            &mut read,
            &mut write,
            &mut exceptional,
            &mut timeout,
        )
    };
    assert_eq!(count, 2);
    assert_eq!(
        select_ready_count(read[0], write[0], exceptional[0]),
        count as u32
    );
}

#[test]
fn newlib_select_uses_the_shared_posix_result_count() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(runtime.contains("mochios_posix_client::multiplex::select_ready_count("));
    assert!(!runtime.contains("(ready_read | ready_write | ready_except).count_ones()"));
}
