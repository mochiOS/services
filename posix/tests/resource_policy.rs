use mochios_posix_protocol::resource_policy::{
    BYTE_LEN, Error, HEADER_LEN, MAGIC, ResourcePolicy, VERSION,
};
use mochios_posix_protocol::{RLIM_INFINITY, RLIMIT_COUNT, ResourceLimit};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

fn page() -> ResourcePolicy {
    ResourcePolicy::new([ResourceLimit::INFINITY; RLIMIT_COUNT as usize]).unwrap()
}

// Mutate protocol words only in an exclusively owned, unpublished test page.
fn word(page: &mut ResourcePolicy, index: usize, value: u64) {
    assert!(index < BYTE_LEN / 8);
    unsafe {
        (&*std::ptr::from_mut(page).cast::<AtomicU64>().add(index))
            .store(value.to_le(), Ordering::SeqCst);
    }
}

#[test]
fn exact_versioned_atomic_layout_has_no_native_pointer_or_handle_fields() {
    let page = page();
    assert_eq!(std::mem::size_of::<ResourcePolicy>(), BYTE_LEN);
    assert_eq!(std::mem::align_of::<ResourcePolicy>(), 8);
    let bytes =
        unsafe { std::slice::from_raw_parts(std::ptr::from_ref(&page).cast::<u8>(), BYTE_LEN) };
    assert_eq!(&bytes[..8], b"POSXRLM\0");
    assert_eq!(&bytes[8..12], &RLIMIT_COUNT.to_le_bytes());
    assert_eq!(&bytes[12..16], &VERSION.to_le_bytes());
    assert_eq!(&bytes[16..HEADER_LEN], &[0; 8]);
    for resource in 0..RLIMIT_COUNT {
        assert_eq!(page.read(resource), Ok(ResourceLimit::INFINITY));
    }
}

#[test]
fn record_lock_extension_is_independent_and_rejects_unknown_state() {
    use mochios_posix_protocol::resource_policy::BASE_BYTE_LEN;
    let mut policy = page();
    assert_eq!(BASE_BYTE_LEN, HEADER_LEN + RLIMIT_COUNT as usize * 16);
    assert_eq!(policy.read_record_locks(), Ok(false));
    policy.publish_record_locks(true);
    assert_eq!(policy.read_record_locks(), Ok(true));
    policy
        .publish(0, ResourceLimit { soft: 7, hard: 9 })
        .unwrap();
    assert_eq!(policy.read_record_locks(), Ok(true));
    policy.publish_record_locks(false);
    assert_eq!(policy.read(0), Ok(ResourceLimit { soft: 7, hard: 9 }));
    assert_eq!(policy.read_record_locks(), Ok(false));
    word(&mut policy, BASE_BYTE_LEN / 8 + 1, 2);
    assert_eq!(policy.read_record_locks(), Err(Error::InvalidLayout));
    policy.publish_record_locks(true);
    word(&mut policy, BASE_BYTE_LEN / 8, 0);
    assert_eq!(policy.read_record_locks(), Err(Error::InvalidLayout));
    // Readers of the original limit prefix need no lock extension support.
    assert_eq!(policy.read(0), Ok(ResourceLimit { soft: 7, hard: 9 }));
}

#[test]
fn invalid_publication_never_changes_any_limit_and_updates_are_independent() {
    let policy = page();
    let value = ResourceLimit { soft: 9, hard: 19 };
    assert_eq!(policy.publish(1, value), Ok(()));
    assert_eq!(policy.read(1), Ok(value));
    for resource in [RLIMIT_COUNT, u32::MAX] {
        assert_eq!(policy.publish(resource, value), Err(Error::InvalidResource));
        assert_eq!(policy.read(resource), Err(Error::InvalidResource));
    }
    assert_eq!(
        policy.publish(1, ResourceLimit { soft: 20, hard: 19 }),
        Err(Error::InvalidLimit)
    );
    assert_eq!(policy.read(1), Ok(value));
    assert_eq!(policy.read(0), Ok(ResourceLimit::INFINITY));
    let mut initial = [ResourceLimit::INFINITY; RLIMIT_COUNT as usize];
    initial[0] = ResourceLimit { soft: 1, hard: 0 };
    assert!(matches!(
        ResourcePolicy::new(initial),
        Err(Error::InvalidLimit)
    ));
    assert_eq!(
        policy.publish(1, ResourceLimit { soft: 0, hard: 0 }),
        Ok(())
    );
    assert_eq!(policy.read(1), Ok(ResourceLimit { soft: 0, hard: 0 }));
}

#[test]
fn unknown_or_uninitialized_headers_are_rejected_not_treated_as_unlimited() {
    for (index, value) in [
        (0, 0),
        (0, MAGIC ^ 1),
        (1, 0),
        (1, (2u64 << 32) | RLIMIT_COUNT as u64),
        (1, (1u64 << 32) | (RLIMIT_COUNT as u64 + 1)),
    ] {
        let mut policy = page();
        word(&mut policy, index, value);
        assert_eq!(policy.validate(), Err(Error::InvalidLayout));
        assert_eq!(policy.read(0), Err(Error::InvalidLayout));
        assert_eq!(
            policy.publish(0, ResourceLimit::INFINITY),
            Err(Error::InvalidLayout)
        );
    }
}

#[test]
fn busy_exhausted_or_malformed_data_never_returns_a_torn_policy() {
    let mut policy = page();
    word(&mut policy, 2, 1);
    assert_eq!(policy.read(0), Err(Error::Busy));
    assert_eq!(
        policy.publish(0, ResourceLimit { soft: 1, hard: 2 }),
        Err(Error::Busy)
    );
    word(&mut policy, 2, u64::MAX - 1);
    assert_eq!(
        policy.publish(0, ResourceLimit { soft: 1, hard: 2 }),
        Err(Error::Exhausted)
    );
    assert_eq!(policy.read(0), Ok(ResourceLimit::INFINITY));
    word(&mut policy, 3, RLIM_INFINITY);
    word(&mut policy, 4, 0);
    assert_eq!(policy.read(0), Err(Error::InvalidLimit));
}

#[test]
fn concurrent_readers_and_publishers_never_mix_generations() {
    let policy = Arc::new(
        ResourcePolicy::new([ResourceLimit { soft: 0, hard: 1 }; RLIMIT_COUNT as usize]).unwrap(),
    );
    std::thread::scope(|scope| {
        for writer in 0..2u64 {
            let policy = &policy;
            scope.spawn(move || {
                for sequence in 1..=10_000u64 {
                    let soft = (sequence << 32) | writer;
                    loop {
                        match policy.publish(
                            0,
                            ResourceLimit {
                                soft,
                                hard: soft + 1,
                            },
                        ) {
                            Ok(()) => break,
                            Err(Error::Busy) => std::thread::yield_now(),
                            other => panic!("{other:?}"),
                        }
                    }
                }
            });
        }
        for _ in 0..2 {
            let policy = &policy;
            scope.spawn(move || {
                for _ in 0..20_000 {
                    match policy.read(0) {
                        Ok(limit) => assert_eq!(limit.hard, limit.soft + 1),
                        Err(Error::Busy) => {}
                        other => panic!("{other:?}"),
                    }
                }
            });
        }
    });
    let limit = policy.read(0).unwrap();
    assert_eq!(limit.hard, limit.soft + 1);
    assert_eq!(policy.read(1), Ok(ResourceLimit { soft: 0, hard: 1 }));
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn reader_works_on_an_os_enforced_read_only_mapping() {
    const PROBE: &str = "MOCHIOS_RESOURCE_POLICY_READ_ONLY_PROBE";
    if std::env::var_os(PROBE).is_some() {
        unsafe extern "C" {
            fn mmap(
                address: *mut core::ffi::c_void,
                length: usize,
                protection: i32,
                flags: i32,
                fd: i32,
                offset: i64,
            ) -> *mut core::ffi::c_void;
            fn mprotect(address: *mut core::ffi::c_void, length: usize, protection: i32) -> i32;
            fn munmap(address: *mut core::ffi::c_void, length: usize) -> i32;
        }
        // Linux host-only constants from bits/mman-linux.h. No mochiOS native
        // API is replaced here: this isolates faults from forbidden writes.
        let backing = unsafe { mmap(std::ptr::null_mut(), 4096, 3, 0x22, -1, 0) };
        assert_ne!(backing as usize, usize::MAX);
        let pointer = backing.cast::<ResourcePolicy>();
        unsafe {
            pointer.write(page());
        }
        let limit = ResourceLimit { soft: 11, hard: 29 };
        assert_eq!(unsafe { &*pointer }.publish(1, limit), Ok(()));
        assert_eq!(unsafe { mprotect(backing, 4096, 1) }, 0);
        {
            // Aligned, initialized backing remains mapped throughout this
            // borrow. Read-only access uses Relaxed loads plus acquire fences.
            let readonly = unsafe { &*pointer };
            for _ in 0..10_000 {
                assert_eq!(readonly.read(1), Ok(limit));
            }
        }
        assert_eq!(unsafe { munmap(backing, 4096) }, 0);
        return;
    }
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "reader_works_on_an_os_enforced_read_only_mapping",
            "--nocapture",
        ])
        .env(PROBE, "1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "status={} stderr={}",
        result.status,
        String::from_utf8_lossy(&result.stderr)
    );
}
