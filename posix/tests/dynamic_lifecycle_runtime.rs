//! Real lifecycle and resolver CRT adapters; only the aux lookup is mocked.
#![allow(dead_code)]
use core::{
    ffi::c_int,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::cell::{Cell, RefCell};
const EFAULT: c_int = 14;
const EIO: c_int = 5;
const E2BIG: c_int = 7;
const ENOEXEC: c_int = 8;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const PAGE_SIZE: usize = 4096;
const NATIVE_READ_WRITE: u64 = 3;
#[path = "support/startup_storage_vm.rs"]
mod address_space;
#[path = "../../../user/crates/newlib-runtime/src/startup_storage.rs"]
mod startup_storage;
use core::ffi::c_char;
use mochios_posix_protocol as posix_protocol;
#[path = "support/lifecycle_fixture.rs"]
mod fixture;
#[path = "../../../user/crates/newlib-runtime/src/dynamic_lifecycle.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/dynamic_indirect.rs"]
mod indirect;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
thread_local! {
    static AUX:Cell<Option<usize>>=const{Cell::new(None)};
    static INDIRECT_AUX:Cell<Option<usize>>=const{Cell::new(None)};
    static EVENTS:RefCell<Vec<u8>>=const{RefCell::new(Vec::new())};
    static METADATA:RefCell<Vec<u8>>=const{RefCell::new(Vec::new())};
    static ARRAYS:RefCell<[u64;2]>=const{RefCell::new([0;2])};
}
mod auxiliary {
    pub struct Vector;
    pub fn vector() -> Option<Vector> {
        Some(Vector)
    }
    impl Vector {
        pub fn lookup(&self, key: usize) -> Result<usize, i32> {
            use mochios_posix_client::process_image::*;
            match key as u64 {
                AT_LIFECYCLE_IMAGE => super::AUX.get(),
                AT_INDIRECT_IMAGE => super::INDIRECT_AUX.get(),
                _ => panic!("unexpected auxiliary key"),
            }
            .ok_or(super::ENOENT)
        }
    }
}
extern "C" fn preinit() {
    EVENTS.with_borrow_mut(|events| events.push(1));
}
extern "C" fn init() {
    EVENTS.with_borrow_mut(|events| events.push(2));
    // Constructors must not be able to replace the previously captured fini.
    ARRAYS.with_borrow_mut(|a| a[1] = 0);
}
extern "C" fn fini() {
    EVENTS.with_borrow_mut(|events| events.push(3));
}
extern "C" fn resolve_init() -> u64 {
    EVENTS.with_borrow_mut(|events| events.push(4));
    METADATA.with_borrow_mut(|m| m.fill(0xff));
    // Lifecycle metadata was already captured; this cannot replace it.
    AUX.set(Some(1));
    init as *const () as u64
}
extern "C" fn resolve_fini() -> u64 {
    EVENTS.with_borrow_mut(|events| events.push(5));
    fini as *const () as u64
}
fn put(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn late_plan(count: usize) -> Vec<u8> {
    let functions = [
        preinit as *const () as u64,
        init as *const () as u64,
        fini as *const () as u64,
        resolve_init as *const () as u64,
        resolve_fini as *const () as u64,
    ];
    let low = *functions.iter().min().unwrap();
    let high = *functions.iter().max().unwrap();
    let arrays = ARRAYS.with_borrow(|a| a.as_ptr() as u64);
    let mut regions = [(low, high - low + 1, 5), (arrays, 16, 6)];
    regions.sort_unstable_by_key(|r| r.0);
    let fini_offset = 144 + count * 16;
    let mut bytes = vec![0; fini_offset + 16];
    bytes[..8].copy_from_slice(b"MLIFE001");
    for (at, v) in [
        (8, 2 | (1 << 32)),
        (16, (fini_offset + 16) as u64),
        (24, 1),
        (32, 2),
        (48, 144),
        (56, count as u64),
        (64, fini_offset as u64),
        (72, 1),
        (128, 0),
        (136, preinit as *const () as u64),
        (fini_offset, 1),
        (fini_offset + 8, arrays + 8),
    ] {
        put(&mut bytes, at, v);
    }
    for i in 0..count {
        put(&mut bytes, 144 + i * 16, 1);
        put(&mut bytes, 152 + i * 16, arrays);
    }
    for (i, (address, length, flags)) in regions.into_iter().enumerate() {
        put(&mut bytes, 80 + i * 24, address);
        put(&mut bytes, 88 + i * 24, length);
        put(&mut bytes, 96 + i * 24, flags);
    }
    bytes
}
#[test]
fn crt_adapter_captures_before_resolvers_and_freezes_callbacks_before_init() {
    const CASE: &str = "MOCHIOS_LIFECYCLE_ADAPTER_CASE";
    let Ok(case) = std::env::var(CASE) else {
        for case in [
            "absent",
            "v1",
            "late",
            "fault",
            "invalid",
            "v1-large",
            "late-large",
            "late-large-fault",
        ] {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "crt_adapter_captures_before_resolvers_and_freezes_callbacks_before_init",
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
    assert_eq!(implementation::__mochios_lifecycle_v1(), 1);
    assert_eq!(implementation::__mochios_lifecycle_v2(), 2);
    assert_eq!(implementation::finalize(), Ok(false));
    if case == "absent" {
        assert_eq!(implementation::prepare(), Ok(false));
        AUX.set(Some(1));
        assert_eq!(implementation::prepare(), Ok(false));
        assert_eq!(implementation::initialize(), Ok(false));
        assert_eq!(implementation::finalize(), Ok(false));
        return;
    }
    AUX.set(Some(1));
    assert_eq!(implementation::prepare(), Err(ENOEXEC));
    let repetitions = if case.contains("large") { 600 } else { 1 };
    let init_callbacks = vec![init as *const () as u64; repetitions];
    let bytes = if case.starts_with("v1") {
        fixture::encode(
            &[preinit as *const () as u64],
            &[(&init_callbacks, &[fini as *const () as u64])],
        )
    } else {
        late_plan(repetitions)
    };
    METADATA.with_borrow_mut(|m| *m = bytes);
    AUX.set(Some(METADATA.with_borrow(|m| m.as_ptr() as usize)));
    if case == "v1-large" {
        address_space::DENIED.set(true);
        assert_eq!(implementation::prepare(), Err(12));
        address_space::DENIED.set(false);
    }
    assert_eq!(implementation::prepare(), Ok(true));
    let allocations = address_space::ALLOCATIONS.with_borrow(|a| a.len());
    assert_eq!(implementation::finalize(), Ok(true));
    assert!(EVENTS.with_borrow(|e| e.is_empty()));
    if !case.starts_with("v1") {
        use mochios_posix_client::indirect_image::{Access, Fixup, Region, encode};
        let a = resolve_init as *const () as u64;
        let b = resolve_fini as *const () as u64;
        let arrays = ARRAYS.with_borrow(|a| a.as_ptr() as u64);
        let mut regions = [
            Region {
                address: a.min(b),
                length: a.max(b) - a.min(b) + 1,
                access: Access::Executable,
            },
            Region {
                address: arrays,
                length: 16,
                access: Access::Writable,
            },
        ];
        regions.sort_unstable_by_key(|r| r.address);
        let mut fixups = [Fixup::new(arrays, a, 0), Fixup::new(arrays + 8, b, 0)];
        let mut plan = vec![0; 40 + 2 * 24 + 2 * 32];
        assert_eq!(encode(&regions, &mut fixups, &mut plan), Ok(plan.len()));
        INDIRECT_AUX.set(Some(plan.as_ptr() as usize));
        assert_eq!(indirect::initialize(), Ok(true));
        if case == "fault" || case == "late-large-fault" {
            user_copy_native::DENIED
                .with_borrow_mut(|r| *r = Some(arrays as usize + 8..arrays as usize + 16));
        } else if case == "invalid" {
            ARRAYS.with_borrow_mut(|a| a[1] = arrays);
        }
        if case.ends_with("fault") || case == "invalid" {
            assert_eq!(
                implementation::initialize(),
                Err(if case.ends_with("fault") {
                    EFAULT
                } else {
                    ENOEXEC
                })
            );
            user_copy_native::DENIED.with_borrow_mut(|r| *r = None);
            ARRAYS.with_borrow_mut(|a| a[1] = fini as *const () as u64);
            assert_eq!(implementation::initialize(), Err(ENOEXEC));
            assert_eq!(implementation::finalize(), Err(ENOEXEC));
            EVENTS.with_borrow(|e| assert_eq!(*e, [4, 5]));
            assert_eq!(
                address_space::ALLOCATIONS.with_borrow(|a| a.len()),
                allocations
            );
            return;
        }
    } else {
        METADATA.with_borrow_mut(|m| m.fill(0xff));
        AUX.set(Some(1));
    }
    assert_eq!(implementation::initialize(), Ok(true));
    assert_eq!(implementation::initialize(), Ok(true));
    assert_eq!(implementation::finalize(), Ok(true));
    assert_eq!(implementation::finalize(), Ok(true));
    assert_eq!(
        address_space::ALLOCATIONS.with_borrow(|a| a.len()),
        allocations
    );
    EVENTS.with_borrow(|events| {
        assert_eq!(*events, {
            let mut expected = if case.starts_with("v1") {
                vec![]
            } else {
                vec![4, 5]
            };
            expected.push(1);
            expected.extend(std::iter::repeat_n(2, repetitions));
            expected.push(3);
            expected
        })
    });
}
