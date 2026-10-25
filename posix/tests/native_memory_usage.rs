//! Native memory snapshots, not POSIX rusage or PID-based observation.
#[cfg(target_os = "mochios")]
pub fn run() {
    use core::ffi::c_void;
    use mochi_user_platform::{handle, process};
    use mochi_user_syscall::{
        HANDLE_RIGHT_DUPLICATE, HANDLE_RIGHT_TRANSFER, HANDLE_RIGHT_WAIT, SyscallNumber, call3,
        execution,
    };
    use mochios_posix_client::memory::{
        MAP_ANONYMOUS, MAP_PRIVATE, PROT_NONE, PROT_READ, PROT_WRITE,
    };
    unsafe extern "C" {
        fn mmap(
            address: *mut c_void,
            length: usize,
            protection: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut c_void;
        fn mprotect(address: *mut c_void, length: usize, protection: i32) -> i32;
        fn munmap(address: *mut c_void, length: usize) -> i32;
        fn fork() -> i32;
        fn __errno() -> *mut i32;
        fn pipe(output: *mut i32) -> i32;
        fn read(fd: i32, output: *mut u8, length: usize) -> isize;
        fn write(fd: i32, input: *const u8, length: usize) -> isize;
        fn close(fd: i32) -> i32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn _exit(status: i32) -> !;
        fn usleep(microseconds: u32) -> i32;
    }
    unsafe {
        // Warm any process-local allocation policy cache before exact deltas.
        let warm = mmap(
            core::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(warm as usize, usize::MAX);
        warm.cast::<u8>().write_volatile(1);
        assert_eq!(munmap(warm, 4096), 0);
        let before = execution::memory_usage(None).unwrap();
        let size = 4 * 4096;
        let mapping = mmap(
            core::ptr::null_mut(),
            size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(mapping as usize, usize::MAX);
        for page in 0..4 {
            mapping.cast::<u8>().add(page * 4096).write_volatile(17);
        }
        let mapped = execution::memory_usage(None).unwrap();
        assert_eq!(mapped.current_bytes, before.current_bytes + size as u64);
        assert!(mapped.peak_bytes >= mapped.current_bytes);
        assert_eq!(mprotect(mapping, size, PROT_NONE), 0);
        assert_eq!(
            execution::memory_usage(None).unwrap().current_bytes,
            mapped.current_bytes
        );
        assert_eq!(mprotect(mapping, size, PROT_READ | PROT_WRITE), 0);
        assert_eq!(munmap(mapping, size), 0);
        let after = execution::memory_usage(None).unwrap();
        assert_eq!(after.current_bytes, before.current_bytes);
        assert!(after.peak_bytes >= mapped.peak_bytes);
        assert!(execution::memory_usage(Some(0)).is_err());
        assert_eq!(
            call3(SyscallNumber::ProcessMemoryRead, 0, 1, 16)
                .unwrap_err()
                .native_error(),
            Some(mnu_abi::status::Error::InvalidAddress)
        );
        assert_eq!(
            call3(SyscallNumber::ProcessMemoryRead, 0, 1, 15)
                .unwrap_err()
                .native_error(),
            Some(mnu_abi::status::Error::InvalidArgument)
        );
        let identity = execution::identity().unwrap();
        let own = process::open_handle_for_process_id(
            identity.process_id,
            HANDLE_RIGHT_WAIT | HANDLE_RIGHT_DUPLICATE | HANDLE_RIGHT_TRANSFER,
        )
        .unwrap();
        let restricted = handle::duplicate(own, HANDLE_RIGHT_TRANSFER).unwrap();
        assert_eq!(
            execution::memory_usage(Some(restricted))
                .unwrap_err()
                .native_error(),
            Some(mnu_abi::status::Error::AccessDenied)
        );
        assert_eq!(
            execution::memory_usage(Some(own)).unwrap().current_bytes,
            execution::memory_usage(None).unwrap().current_bytes
        );
        handle::close(restricted).unwrap();
        handle::close(own).unwrap();

        let mut identities = [0; 2];
        let mut gate = [0; 2];
        assert_eq!(pipe(identities.as_mut_ptr()), 0);
        assert_eq!(pipe(gate.as_mut_ptr()), 0);
        let child = fork();
        assert!(child >= 0, "memory-read fork errno={}", *__errno());
        if child == 0 {
            close(identities[0]);
            close(gate[1]);
            let mapping = mmap(
                core::ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );
            if mapping as usize == usize::MAX {
                _exit(120)
            }
            for page in 0..4 {
                mapping.cast::<u8>().add(page * 4096).write_volatile(23);
            }
            let identity = execution::identity().unwrap().process_id.to_ne_bytes();
            if write(identities[1], identity.as_ptr(), identity.len()) != identity.len() as isize {
                _exit(121)
            }
            let mut byte = 0;
            if read(gate[0], &mut byte, 1) != 1 {
                _exit(122)
            }
            if munmap(mapping, size) != 0 {
                _exit(123)
            }
            _exit(0)
        }
        close(identities[1]);
        close(gate[0]);
        let mut native_id = [0; 8];
        assert_eq!(read(identities[0], native_id.as_mut_ptr(), 8), 8);
        // Existing admin-gated handle acquisition is used only by this probe.
        // The new reader itself accepts no process ID or endpoint lookup.
        let retained =
            process::open_handle_for_process_id(u64::from_ne_bytes(native_id), HANDLE_RIGHT_WAIT)
                .unwrap();
        let live = execution::memory_usage(Some(retained)).unwrap();
        assert!(live.current_bytes >= size as u64 && live.peak_bytes >= live.current_bytes);
        assert_eq!(write(gate[1], b"x".as_ptr(), 1), 1);
        close(identities[0]);
        close(gate[1]);
        let mut status = 0;
        assert_eq!(waitpid(child, &mut status, 0), child);
        assert_eq!(status, 0);
        let mut dead = execution::memory_usage(Some(retained)).unwrap();
        for _ in 0..100 {
            if dead.current_bytes == 0 {
                break;
            }
            usleep(2000);
            dead = execution::memory_usage(Some(retained)).unwrap();
        }
        if dead.current_bytes != 0 {
            let mut records = [0u8; 104 * 128];
            let count = mochi_user_syscall::call2(
                SyscallNumber::ListProcesses,
                records.as_mut_ptr() as u64,
                records.len() as u64,
            )
            .unwrap() as usize;
            let target = u64::from_ne_bytes(native_id);
            let entry = records
                .chunks_exact(104)
                .take(count)
                .find(|record| u64::from_ne_bytes(record[..8].try_into().unwrap()) == target);
            let detail = entry.map(|record| {
                (
                    u64::from_ne_bytes(record[16..24].try_into().unwrap()),
                    u64::from_ne_bytes(record[40..48].try_into().unwrap()),
                )
            });
            let message = format!(
                "memory-read: retained child native={target} metrics={dead:?} table_state_and_threads={detail:?} lifecycle={:?}\n",
                process::handle_status(retained).unwrap()
            );
            mochi_user_platform::io::stdout(message.as_bytes()).unwrap();
        }
        assert_eq!(dead.current_bytes, 0);
        assert!(dead.peak_bytes >= live.peak_bytes);
        handle::close(retained).unwrap();
        mochi_user_platform::io::stdout(b"memory-read: PASS exact RAM deltas inaccessible pages peak retention handle rights and reclaimed child\n").unwrap();
    }
}
