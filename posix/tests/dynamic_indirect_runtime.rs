//! Actual CRT resolver adapter and faultable MemoryCopy; aux lookup is mocked.
#![allow(dead_code)]
use core::{
    ffi::{c_char, c_int},
    sync::atomic::{AtomicUsize, Ordering},
};
use mochios_posix_client::{
    indirect_image::{Access, Fixup, Region, encode},
    newlib_errno::*,
};
use mochios_posix_protocol as posix_protocol;
use std::cell::{Cell, RefCell};
const PAGE_SIZE: usize = 4096;
const NATIVE_READ_WRITE: u64 = 3;
#[path = "support/startup_storage_vm.rs"]
mod address_space;
#[path = "../../../user/crates/newlib-runtime/src/dynamic_indirect.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/startup_storage.rs"]
mod startup_storage;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
thread_local! {
    static AUX: Cell<Option<usize>> = const { Cell::new(None) };
    static METADATA: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static CALLS: Cell<usize> = const { Cell::new(0) };
    static COPY_TARGET: Cell<Option<usize>> = const { Cell::new(None) };
}
mod auxiliary {
    pub struct Vector;
    pub fn vector() -> Option<Vector> {
        Some(Vector)
    }
    impl Vector {
        pub fn lookup(&self, key: usize) -> Result<usize, i32> {
            assert_eq!(
                key,
                mochios_posix_client::process_image::AT_INDIRECT_IMAGE as usize
            );
            super::AUX.get().ok_or(super::ENOENT)
        }
    }
}
extern "C" fn first() -> u64 {
    CALLS.set(CALLS.get() + 1);
    // The callback may modify its input metadata. Later fixups must continue
    // using the private snapshot, not these now-invalid original bytes.
    METADATA.with_borrow_mut(|bytes| bytes.fill(0xff));
    73
}
extern "C" fn second() -> u64 {
    CALLS.set(CALLS.get() + 1);
    if let Some(address) = COPY_TARGET.get() {
        // SAFETY: the test retains this private readable mapping until return.
        assert_eq!(
            unsafe { core::ptr::read_unaligned(address as *const u64) },
            78
        );
    }
    0
}
struct Mapping(*mut libc::c_void);
impl Mapping {
    fn new() -> Self {
        let p = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        Self(p)
    }
    fn protect(&self, flags: i32) {
        assert_eq!(unsafe { libc::mprotect(self.0, PAGE_SIZE, flags) }, 0);
    }
    fn word(&self, index: usize) -> u64 {
        // SAFETY: this mapping owns a readable page for the entire test.
        unsafe { (self.0 as *const u64).add(index).read() }
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        assert_eq!(unsafe { libc::munmap(self.0, PAGE_SIZE) }, 0);
    }
}

#[test]
fn crt_resolves_once_from_private_metadata_and_propagates_real_memory_faults() {
    const CASE: &str = "MOCHIOS_INDIRECT_ADAPTER_CASE";
    // Each initial image owns one static execution state. Use separate actual
    // processes for successful and terminally failed startup transactions.
    let Ok(case) = std::env::var(CASE) else {
        for case in [
            "success",
            "fault",
            "copy",
            "copy-read-fault",
            "copy-write-fault",
            "large",
            "large-denied",
            "large-fault",
        ] {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "crt_resolves_once_from_private_metadata_and_propagates_real_memory_faults",
                ])
                .env(CASE, case)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "case={case}: {}\n{}\n{}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        return;
    };
    assert_eq!(implementation::__mochios_indirect_v1(), 1);
    assert_eq!(implementation::__mochios_indirect_v2(), 2);
    assert_eq!(implementation::initialize(), Ok(false));
    AUX.set(Some(1));
    assert_eq!(implementation::initialize(), Err(ENOEXEC));
    let target = Mapping::new();
    let copy = Mapping::new();
    let with_copy = case.starts_with("copy");
    if with_copy {
        COPY_TARGET.set(Some(copy.0 as usize));
    }
    let a = first as *const () as u64;
    let b = second as *const () as u64;
    let mut regions = vec![
        Region {
            address: a.min(b),
            length: a.max(b) - a.min(b) + 1,
            access: Access::Executable,
        },
        Region {
            address: target.0 as u64,
            length: PAGE_SIZE as u64,
            access: Access::Writable,
        },
    ];
    if with_copy {
        regions[1].access = Access::ReadWrite;
        regions.push(Region {
            address: copy.0 as u64,
            length: PAGE_SIZE as u64,
            access: Access::ReadWrite,
        });
    }
    regions.sort_unstable_by_key(|r| r.address);
    let mut fixups = vec![
        Fixup::new(target.0 as u64, a, 5),
        Fixup::new(target.0 as u64 + 8, b, 0),
    ];
    if with_copy {
        fixups.insert(1, Fixup::copy(copy.0 as u64, target.0 as u64, 16));
    }
    if case.starts_with("large") {
        for i in 0..180 {
            fixups.push(Fixup::new(target.0 as u64 + 16 + i * 8, b, 0));
        }
    }
    let expected_calls = fixups.len() - usize::from(with_copy);
    let mut bytes = vec![0; 40 + regions.len() * 24 + fixups.len() * 32];
    assert_eq!(encode(&regions, &mut fixups, &mut bytes), Ok(bytes.len()));
    let original = bytes.clone();
    METADATA.with_borrow_mut(|m| *m = bytes);
    AUX.set(Some(METADATA.with_borrow(|m| m.as_ptr() as usize)));
    // Fail before calling even the first resolver when the last record is bad.
    METADATA.with_borrow_mut(|m| {
        let last = m.len() - 8;
        m[last] = 2;
    });
    assert_eq!(implementation::initialize(), Err(ENOEXEC));
    assert_eq!(CALLS.get(), 0);
    METADATA.with_borrow_mut(|m| m.copy_from_slice(&original));
    if case == "large-denied" {
        address_space::DENIED.set(true);
        assert_eq!(implementation::initialize(), Err(ENOMEM));
        assert_eq!(CALLS.get(), 0);
        address_space::DENIED.set(false);
    }
    if case == "fault" || case == "large-fault" {
        target.protect(libc::PROT_READ);
    } else if case == "copy-write-fault" {
        copy.protect(libc::PROT_READ);
    } else if case == "copy-read-fault" {
        user_copy_native::DENIED
            .with_borrow_mut(|r| *r = Some(target.0 as usize..target.0 as usize + 16));
    }
    let result = implementation::initialize();
    METADATA.with_borrow_mut(|m| m.copy_from_slice(&original));
    if case.ends_with("fault") {
        assert_eq!(result, Err(EFAULT));
        assert_eq!(CALLS.get(), 1);
        assert_eq!(target.word(0), if with_copy { 78 } else { 0 });
        assert_eq!(copy.word(0), 0);
        target.protect(libc::PROT_READ | libc::PROT_WRITE);
        copy.protect(libc::PROT_READ | libc::PROT_WRITE);
        user_copy_native::DENIED.with_borrow_mut(|r| *r = None);
        assert_eq!(implementation::initialize(), Err(ENOEXEC));
        assert_eq!(CALLS.get(), 1);
    } else {
        assert!(case == "success" || case == "copy" || case.starts_with("large"));
        assert_eq!(result, Ok(true));
        assert_eq!(target.word(0), 78);
        assert_eq!(target.word(1), 0);
        if with_copy {
            assert_eq!(copy.word(0), 78);
            assert_eq!(copy.word(1), 0);
        }
        assert_eq!(CALLS.get(), expected_calls);
        assert_eq!(implementation::initialize(), Ok(true));
        assert_eq!(CALLS.get(), expected_calls);
    }
}
