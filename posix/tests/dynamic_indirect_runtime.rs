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
    static REVOKE_WRITE: Cell<Option<usize>> = const { Cell::new(None) };
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
    if let Some(address) = REVOKE_WRITE.get() {
        assert_eq!(
            unsafe { libc::mprotect(address as *mut _, 4096, libc::PROT_READ) },
            0
        );
    }
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

#[test]
fn crt_seals_relro_after_relocations_and_retains_the_private_plan_through_callbacks() {
    const CASE: &str = "MOCHIOS_RELRO_ADAPTER_CASE";
    let Ok(case) = std::env::var(CASE) else {
        for case in [
            "success",
            "empty",
            "large",
            "protect-fault",
            "relocate-fault",
            "denied",
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "crt_seals_relro_after_relocations_and_retains_the_private_plan_through_callbacks"])
                .env(CASE, case).output().unwrap();
            assert!(
                output.status.success(),
                "case={case}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    };
    use mochios_posix_client::relocation_protection::{self as protection, Range};
    assert_eq!(implementation::__mochios_relro_v1(), 1);
    let target = Mapping::new();
    let other = Mapping::new();
    let a = first as *const () as u64;
    let b = second as *const () as u64;
    let mut regions = [
        Region {
            address: a.min(b),
            length: a.max(b) - a.min(b) + 1,
            access: Access::Executable,
        },
        Region {
            address: target.0 as u64,
            length: 4096,
            access: Access::Writable,
        },
    ];
    regions.sort_unstable_by_key(|r| r.address);
    let mut fixups = vec![
        Fixup::new(target.0 as u64, a, 5),
        Fixup::new(target.0 as u64 + 8, b, 0),
    ];
    if case == "large" {
        for i in 0..180 {
            fixups.push(Fixup::new(target.0 as u64 + 16 + i * 8, b, 0));
        }
    }
    let inner = if case == "empty" {
        0
    } else {
        mochios_posix_client::indirect_image::encoded_length(2, fixups.len()).unwrap()
    };
    let mut ranges = [
        Range {
            address: target.0 as u64,
            length: 4096,
        },
        Range {
            address: other.0 as u64,
            length: 4096,
        },
    ];
    ranges.sort_unstable_by_key(|r| r.address);
    let mut bytes = vec![0; protection::encoded_length(2, inner).unwrap()];
    if inner != 0 {
        assert_eq!(encode(&regions, &mut fixups, &mut bytes), Ok(inner));
    }
    assert_eq!(
        protection::wrap(inner, &ranges, &mut bytes),
        Ok(bytes.len())
    );
    let original = bytes.clone();
    METADATA.with_borrow_mut(|m| *m = bytes);
    AUX.set(Some(METADATA.with_borrow(|m| m.as_ptr() as usize)));
    METADATA.with_borrow_mut(|m| m[56..64].fill(0));
    assert_eq!(implementation::initialize(), Err(ENOEXEC));
    assert_eq!(CALLS.get(), 0);
    assert!(user_copy_native::PROTECTED.with_borrow(|c| c.is_empty()));
    METADATA.with_borrow_mut(|m| m.copy_from_slice(&original));
    if case == "denied" {
        address_space::DENIED.set(true);
        assert_eq!(implementation::initialize(), Err(ENOMEM));
        address_space::DENIED.set(false);
        assert_eq!(CALLS.get(), 0);
    }
    if case == "protect-fault" {
        user_copy_native::PROTECT_FAILURE.replace(Some(2));
    }
    if case == "relocate-fault" {
        target.protect(libc::PROT_READ);
    }
    let result = implementation::initialize();
    if case == "relocate-fault" {
        assert_eq!(result, Err(EFAULT));
        assert_eq!(CALLS.get(), 1);
        assert!(user_copy_native::PROTECTED.with_borrow(|c| c.is_empty()));
        assert_eq!(implementation::initialize(), Err(ENOEXEC));
        return;
    }
    assert_eq!(CALLS.get(), if case == "empty" { 0 } else { fixups.len() });
    assert_eq!(target.word(0), if case == "empty" { 0 } else { 78 });
    assert_eq!(user_copy_native::PROTECTED.with_borrow(|c| c.len()), 2);
    assert_eq!(
        user_copy::write(ranges[0].address as *mut u8, &[0]),
        Err(EFAULT)
    );
    if case == "protect-fault" {
        assert_eq!(result, Err(EACCES));
        assert_eq!(user_copy::write(ranges[1].address as *mut u8, &[0]), Ok(()));
        assert_eq!(implementation::initialize(), Err(ENOEXEC));
    } else {
        assert_eq!(result, Ok(true));
        assert_eq!(
            user_copy::write(ranges[1].address as *mut u8, &[0]),
            Err(EFAULT)
        );
        assert_eq!(implementation::initialize(), Ok(true));
    }
    assert_eq!(user_copy_native::PROTECTED.with_borrow(|c| c.len()), 2);
}

#[test]
fn crt_temporarily_writes_only_after_full_capture_and_rolls_back_failed_transactions() {
    const CASE: &str = "MOCHIOS_WRITABLE_ADAPTER_CASE";
    let Ok(case) = std::env::var(CASE) else {
        for case in [
            "success",
            "large",
            "invalid-inner",
            "first-prepare-fault",
            "second-prepare-fault",
            "first-restore-fault",
            "second-restore-fault",
            "resolver-fault",
        ] {
            let output=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","crt_temporarily_writes_only_after_full_capture_and_rolls_back_failed_transactions"]).env(CASE,case).output().unwrap();
            assert!(
                output.status.success(),
                "case={case}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    };
    use mochios_posix_client::relocation_protection::{self as protection, Range};
    assert_eq!(implementation::__mochios_relro_v2(), 2);
    let target = Mapping::new();
    let other = Mapping::new();
    let a = first as *const () as u64;
    let b = second as *const () as u64;
    let mut regions = [
        Region {
            address: a.min(b),
            length: a.max(b) - a.min(b) + 1,
            access: Access::Executable,
        },
        Region {
            address: target.0 as u64,
            length: 4096,
            access: Access::Writable,
        },
        Region {
            address: other.0 as u64,
            length: 4096,
            access: Access::Writable,
        },
    ];
    regions.sort_unstable_by_key(|r| r.address);
    let mut fixups = vec![
        Fixup::new(target.0 as u64, a, 5),
        Fixup::new(other.0 as u64, b, 0),
    ];
    if case == "large" {
        for i in 0..180 {
            fixups.push(Fixup::new(target.0 as u64 + 8 + i * 8, b, 0));
        }
    }
    let inner = mochios_posix_client::indirect_image::encoded_length(3, fixups.len()).unwrap();
    let mut ranges = [
        Range {
            address: target.0 as u64,
            length: 4096,
        },
        Range {
            address: other.0 as u64,
            length: 4096,
        },
    ];
    ranges.sort_unstable_by_key(|r| r.address);
    let mut bytes = vec![0; protection::encoded_length_with_writable(2, 2, inner).unwrap()];
    assert_eq!(encode(&regions, &mut fixups, &mut bytes), Ok(inner));
    if case == "invalid-inner" {
        bytes[inner - 8] = 2;
    }
    assert_eq!(
        protection::wrap_with_writable(inner, &ranges, &ranges, &mut bytes),
        Ok(bytes.len())
    );
    METADATA.with_borrow_mut(|m| *m = bytes);
    AUX.set(Some(METADATA.with_borrow(|m| m.as_ptr() as usize)));
    target.protect(libc::PROT_READ);
    other.protect(libc::PROT_READ);
    let failure = match case.as_str() {
        "first-prepare-fault" => Some(1),
        "second-prepare-fault" => Some(2),
        "first-restore-fault" => Some(3),
        "second-restore-fault" => Some(4),
        _ => None,
    };
    user_copy_native::PROTECT_FAILURE.replace(failure);
    if case == "resolver-fault" {
        REVOKE_WRITE.set(Some(target.0 as usize));
    }
    let result = implementation::initialize();
    if case == "invalid-inner" {
        assert_eq!(result, Err(ENOEXEC));
        assert_eq!(CALLS.get(), 0);
        assert!(user_copy_native::PROTECTED.with_borrow(|c| c.is_empty()));
    } else if case.contains("prepare-fault") {
        assert_eq!(result, Err(EACCES));
        assert_eq!(CALLS.get(), 0);
    } else if case == "resolver-fault" {
        assert_eq!(result, Err(EFAULT));
        assert_eq!(CALLS.get(), 1);
    } else {
        assert_eq!(CALLS.get(), fixups.len());
        assert_eq!(target.word(0), 78);
        assert_eq!(
            result,
            if failure.is_some() {
                Err(EACCES)
            } else {
                Ok(true)
            }
        );
    }
    for range in ranges {
        assert_eq!(
            user_copy::write(range.address as *mut u8, &[0]),
            Err(EFAULT)
        );
    }
    let calls = CALLS.get();
    let edits = user_copy_native::PROTECTED.with_borrow(|p| p.len());
    assert_eq!(
        implementation::initialize(),
        if result.is_ok() {
            Ok(true)
        } else {
            Err(ENOEXEC)
        }
    );
    assert_eq!(CALLS.get(), calls);
    assert_eq!(user_copy_native::PROTECTED.with_borrow(|p| p.len()), edits);
}
