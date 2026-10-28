//! Run the real runtime allocator with deterministic VM and copy failures.
#![allow(non_camel_case_types)]
#[path = "../../../user/crates/newlib-runtime/src/static_tls.rs"]
mod runtime;
pub use mochios_posix_client::{process_image, static_tls};
use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
type c_int = i32;
const ENOEXEC: i32 = 8;
const ENOENT: i32 = 2;
const EOVERFLOW: i32 = 75;
const PAGE_SIZE: usize = 4096;
const NATIVE_READ_WRITE: u64 = 3;
thread_local! {
    static AUX: Cell<Option<auxiliary::Vector>> = const { Cell::new(None) };
    static MAPPINGS: RefCell<Vec<(usize,usize)>> = const { RefCell::new(Vec::new()) };
    static LIMIT: Cell<Result<(),i32>> = const { Cell::new(Ok(())) };
    static COPY_FAIL: Cell<usize> = const { Cell::new(usize::MAX) };
    static COPIES: Cell<usize> = const { Cell::new(0) };
    static BASE_RESULT: Cell<Result<(),i32>> = const { Cell::new(Ok(())) };
    static INSTALLED_BASE: Cell<u64> = const { Cell::new(0) };
}
#[derive(Default)]
struct ThreadControl {
    tls_mapping_base: AtomicUsize,
    tls_mapping_size: AtomicUsize,
    thread_local_base: AtomicU64,
}
fn map_kernel_errno(error: i64) -> i32 {
    error as i32
}
mod auxiliary {
    #[derive(Clone, Copy)]
    pub struct Vector {
        pub table: usize,
        pub count: usize,
        pub bias: Result<usize, i32>,
    }
    pub fn vector() -> Option<Vector> {
        super::AUX.get()
    }
    impl Vector {
        pub fn lookup(self, key: usize) -> Result<usize, i32> {
            Ok(match key {
                3 => self.table,
                4 => 56,
                5 => self.count,
                key if key == crate::process_image::AT_IMAGE_LOAD_BIAS as usize => {
                    return self.bias;
                }
                _ => panic!(),
            })
        }
    }
}
mod address_space {
    pub struct Limit;
    pub fn current() -> Result<Limit, i32> {
        super::LIMIT.get().map(|()| Limit)
    }
    impl Limit {
        pub fn map(
            self,
            address: u64,
            size: u64,
            access: u64,
            options: u64,
            backing: u64,
            offset: u64,
        ) -> Result<u64, i32> {
            assert_eq!((address, access, options, backing, offset), (0, 3, 0, 0, 0));
            let layout = std::alloc::Layout::from_size_align(size as usize, 4096).unwrap();
            let base = unsafe { std::alloc::alloc_zeroed(layout) } as usize;
            assert_ne!(base, 0);
            super::MAPPINGS.with_borrow_mut(|m| m.push((base, size as usize)));
            Ok(base as u64)
        }
    }
}
mod syscall {
    pub enum SyscallNumber {
        MemoryUnmap,
    }
    pub fn raw_syscall2(_: SyscallNumber, base: u64, size: u64) -> Result<(), i32> {
        super::MAPPINGS.with_borrow_mut(|m| {
            let index = m
                .iter()
                .position(|v| *v == (base as usize, size as usize))
                .unwrap();
            m.remove(index);
        });
        unsafe {
            std::alloc::dealloc(
                base as *mut u8,
                std::alloc::Layout::from_size_align(size as usize, 4096).unwrap(),
            )
        };
        Ok(())
    }
    pub struct Error(pub i32);
    impl Error {
        pub fn raw(self) -> i64 {
            self.0 as i64
        }
    }
    pub mod thread_local {
        pub fn set_base(base: u64) -> Result<(), super::Error> {
            super::super::BASE_RESULT.get().map_err(super::Error)?;
            super::super::INSTALLED_BASE.set(base);
            Ok(())
        }
    }
}
mod user_copy {
    fn check() -> Result<(), i32> {
        let count = super::COPIES.get();
        super::COPIES.set(count + 1);
        if count == super::COPY_FAIL.get() {
            Err(14)
        } else {
            Ok(())
        }
    }
    pub fn read(source: *const u8, bytes: &mut [u8]) -> Result<(), i32> {
        check()?;
        unsafe {
            std::ptr::copy_nonoverlapping(source, bytes.as_mut_ptr(), bytes.len());
        }
        Ok(())
    }
    pub fn write(destination: *mut u8, bytes: &[u8]) -> Result<(), i32> {
        check()?;
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len());
        }
        Ok(())
    }
}
fn destroy(control: &ThreadControl) {
    syscall::raw_syscall2(
        syscall::SyscallNumber::MemoryUnmap,
        control.tls_mapping_base.load(Ordering::Relaxed) as u64,
        control.tls_mapping_size.load(Ordering::Relaxed) as u64,
    )
    .unwrap();
}
fn headers(data: &[u8]) -> [[u64; 7]; 2] {
    let base = data.as_ptr() as u64;
    // ELF64 type/flags, offset, vaddr, paddr, filesz, memsz, alignment.
    [
        [1, 0, base, 0, data.len() as u64, data.len() as u64, 1],
        [
            7,
            0,
            base,
            0,
            data.len() as u64,
            data.len() as u64 + 8192,
            8192,
        ],
    ]
}
#[test]
fn copies_initial_bytes_zeros_tbss_aligns_and_owns_independent_mappings() {
    let data: Vec<u8> = (0..1200).map(|i| (i % 251) as u8).collect();
    let headers = headers(&data);
    AUX.set(Some(auxiliary::Vector {
        table: headers.as_ptr() as usize,
        count: 2,
        bias: Ok(0),
    }));
    let template = static_tls::template(headers.as_ptr() as usize, 56, 2, 0, user_read)
        .unwrap()
        .unwrap();
    let layout = static_tls::Layout::new(Some(template), 4096).unwrap();
    let first = ThreadControl::default();
    let second = ThreadControl::default();
    for control in [&first, &second] {
        runtime::allocate(control).unwrap();
        let base = control.tls_mapping_base.load(Ordering::Acquire);
        let placement = layout.place(base).unwrap();
        let bytes = unsafe {
            std::slice::from_raw_parts(placement.data as *const u8, template.memory_size)
        };
        assert_eq!(&bytes[..data.len()], data);
        assert!(bytes[data.len()..].iter().all(|v| *v == 0));
        assert_eq!(
            unsafe { *(placement.thread_pointer as *const usize) },
            placement.thread_pointer
        );
        runtime::activate(control).unwrap();
        assert_eq!(INSTALLED_BASE.get(), placement.thread_pointer as u64);
    }
    assert_ne!(
        first.thread_local_base.load(Ordering::Relaxed),
        second.thread_local_base.load(Ordering::Relaxed)
    );
    destroy(&first);
    destroy(&second);
    assert!(MAPPINGS.with_borrow(|m| m.is_empty()));
}
fn user_read(address: usize, bytes: &mut [u8]) -> Result<(), i32> {
    user_copy::read(address as *const u8, bytes)
}

#[test]
fn every_copy_failure_unmaps_unpublished_memory() {
    let data = [37u8; 1200];
    let headers = headers(&data);
    AUX.set(Some(auxiliary::Vector {
        table: headers.as_ptr() as usize,
        count: 2,
        bias: Ok(0),
    }));
    // Three header reads, six chunk copies and the self-pointer write.
    for fail in 0..10 {
        COPIES.set(0);
        COPY_FAIL.set(fail);
        let control = ThreadControl::default();
        assert_eq!(runtime::allocate(&control), Err(14), "copy={fail}");
        assert_eq!(control.thread_local_base.load(Ordering::Acquire), 0);
        assert_eq!(control.tls_mapping_base.load(Ordering::Acquire), 0);
        assert!(MAPPINGS.with_borrow(|m| m.is_empty()));
    }
}

#[test]
fn admission_and_activation_errors_propagate_without_silent_fallback() {
    let control = ThreadControl::default();
    LIMIT.set(Err(12));
    assert_eq!(runtime::allocate(&control), Err(12));
    assert!(MAPPINGS.with_borrow(|m| m.is_empty()));
    LIMIT.set(Ok(()));
    runtime::allocate(&control).unwrap();
    BASE_RESULT.set(Err(13));
    assert_eq!(runtime::activate(&control), Err(13));
    assert_eq!(INSTALLED_BASE.get(), 0);
    destroy(&control);
}

#[test]
fn copies_from_a_relocated_program_and_preserves_metadata_errors() {
    let data = [41u8; 32];
    let mut headers = headers(&data);
    let bias = 0x20000000usize;
    for header in &mut headers {
        header[2] -= bias as u64;
    }
    AUX.set(Some(auxiliary::Vector {
        table: headers.as_ptr() as usize,
        count: 2,
        bias: Ok(bias),
    }));
    let template = static_tls::template(headers.as_ptr() as usize, 56, 2, bias, user_read)
        .unwrap()
        .unwrap();
    let layout = static_tls::Layout::new(Some(template), PAGE_SIZE).unwrap();
    let control = ThreadControl::default();
    runtime::allocate(&control).unwrap();
    let placement = layout
        .place(control.tls_mapping_base.load(Ordering::Acquire))
        .unwrap();
    let bytes =
        unsafe { std::slice::from_raw_parts(placement.data as *const u8, template.memory_size) };
    assert_eq!(&bytes[..data.len()], data);
    assert!(bytes[data.len()..].iter().all(|byte| *byte == 0));
    destroy(&control);
    AUX.set(Some(auxiliary::Vector {
        table: headers.as_ptr() as usize,
        count: 2,
        bias: Err(14),
    }));
    assert_eq!(runtime::allocate(&ThreadControl::default()), Err(14));
    assert!(MAPPINGS.with_borrow(|m| m.is_empty()));

    let fixed = self::headers(&data);
    AUX.set(Some(auxiliary::Vector {
        table: fixed.as_ptr() as usize,
        count: 2,
        bias: Err(ENOENT),
    }));
    let control = ThreadControl::default();
    runtime::allocate(&control).unwrap();
    destroy(&control);
    assert!(MAPPINGS.with_borrow(|m| m.is_empty()));
}

#[test]
fn multiple_modules_get_private_initialized_and_zeroed_storage_per_thread() {
    let root = [17u8; 1200];
    let library = [39u8; 513];
    let template = |data: &[u8], memory_size, alignment, residue| static_tls::Template {
        source: data.as_ptr() as usize,
        file_size: data.len(),
        memory_size,
        alignment,
        residue,
    };
    let templates = [
        Some(template(&root, 1203, 16, 3)),
        None,
        Some(template(&library, 9000, 8192, 13)),
        Some(template(&[], 4099, 64, 7)),
    ];
    let plan = static_tls::modules::Plan::new(&templates, PAGE_SIZE).unwrap();
    let threads = [ThreadControl::default(), ThreadControl::default()];
    for thread in &threads {
        runtime::allocate_templates(thread, &templates).unwrap();
        let tp = thread.thread_local_base.load(Ordering::Acquire) as usize;
        assert_eq!(unsafe { *(tp as *const usize) }, tp);
        for module in plan.modules() {
            let start = tp - module.distance;
            assert_eq!(start % module.template.alignment, module.template.residue);
            let bytes = unsafe {
                std::slice::from_raw_parts(start as *const u8, module.template.memory_size)
            };
            let original = match module.index {
                0 => &root[..],
                2 => &library[..],
                3 => &[],
                _ => panic!("no TLS segment"),
            };
            assert_eq!(&bytes[..original.len()], original);
            assert!(bytes[original.len()..].iter().all(|&b| b == 0));
        }
    }
    let library = plan.modules().find(|module| module.index == 2).unwrap();
    let first = threads[0].thread_local_base.load(Ordering::Acquire) as usize - library.distance;
    let second = threads[1].thread_local_base.load(Ordering::Acquire) as usize - library.distance;
    unsafe { *(first as *mut u8) = 61 };
    assert_eq!(unsafe { *(second as *const u8) }, 39);
    for thread in &threads {
        destroy(thread);
    }
    assert!(MAPPINGS.with_borrow(|m| m.is_empty()));
}

#[test]
fn failure_in_any_module_or_tcb_rolls_back_before_publication() {
    let data = [71u8; 1200];
    let template = static_tls::Template {
        source: data.as_ptr() as usize,
        file_size: data.len(),
        memory_size: 4097,
        alignment: 64,
        residue: 3,
    };
    let templates = [Some(template), None, Some(template)];
    // Two modules, each with three read/write chunks, then one TCB write.
    for fail in 0..13 {
        COPY_FAIL.set(fail);
        COPIES.set(0);
        let control = ThreadControl::default();
        assert_eq!(runtime::allocate_templates(&control, &templates), Err(14));
        assert_eq!(control.thread_local_base.load(Ordering::Acquire), 0);
        assert_eq!(control.tls_mapping_base.load(Ordering::Acquire), 0);
        assert_eq!(control.tls_mapping_size.load(Ordering::Acquire), 0);
        assert!(MAPPINGS.with_borrow(|m| m.is_empty()));
    }
}
