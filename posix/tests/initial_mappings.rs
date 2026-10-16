extern crate alloc;
use mnu_abi::process_image::{self as wire, InitialMapping};
use mnu_abi::status::Error;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;

thread_local! {
    static FAIL: Cell<bool> = const { Cell::new(false) };
    static LOOKUPS: Cell<usize> = const { Cell::new(0) };
    static DROPS: Cell<usize> = const { Cell::new(0) };
}
struct Allocator;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if FAIL.with(|state| state.replace(false)) {
            std::ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

mod task {
    use super::Arc;
    #[derive(Clone, Copy)]
    pub struct HandleRights(u64);
    impl HandleRights {
        pub const READ: Self = Self(1);
        pub const WRITE: Self = Self(2);
        pub const MAP: Self = Self(64);
        pub fn union(self, other: Self) -> Self {
            Self(self.0 | other.0)
        }
        pub fn contains(self, other: Self) -> bool {
            self.0 & other.0 == other.0
        }
    }
    pub struct Object(pub Option<u64>);
    impl Object {
        pub fn memory_length(&self) -> Option<u64> {
            self.0
        }
    }
    impl Drop for Object {
        fn drop(&mut self) {
            crate::DROPS.with(|count| count.set(count.get() + 1));
        }
    }
    pub enum KernelObject {
        VmObject(Arc<Object>),
        Other,
    }
    pub struct MemoryRegion {
        pub start: u64,
        pub length: u64,
        pub max: u64,
        pub object: Option<Arc<Object>>,
    }
    impl MemoryRegion {
        pub fn start(&self) -> u64 {
            self.start
        }
        pub fn end(&self) -> Option<u64> {
            self.start.checked_add(self.length)
        }
        pub fn anonymous(start: u64, length: u64, _: u64, _: u64, _: bool, _: bool) -> Self {
            Self {
                start,
                length,
                max: 7,
                object: None,
            }
        }
        pub fn file_backed(
            start: u64,
            length: u64,
            _: u64,
            _: u64,
            object: Arc<Object>,
            _: u64,
            _: bool,
            _: bool,
            max: u64,
        ) -> Self {
            Self {
                start,
                length,
                max,
                object: Some(object),
            }
        }
    }
}
mod syscall {
    pub mod handle {
        use crate::task::*;
        pub fn object_with_rights_native(
            handle: u64,
            needed: HandleRights,
        ) -> Result<(KernelObject, HandleRights), mnu_abi::status::Error> {
            use mnu_abi::status::Error;
            crate::LOOKUPS.with(|count| count.set(count.get() + 1));
            if handle == 99 {
                return Err(Error::InvalidArgument);
            }
            if handle == 98 {
                return Err(Error::NotReady);
            }
            let rights = if handle == 2 {
                HandleRights::READ
                    .union(HandleRights::MAP)
                    .union(HandleRights::WRITE)
            } else {
                HandleRights::READ.union(HandleRights::MAP)
            };
            if !rights.contains(needed) {
                return Err(Error::AccessDenied);
            }
            Ok((
                if handle == 3 {
                    KernelObject::Other
                } else {
                    KernelObject::VmObject(std::sync::Arc::new(Object(
                        (handle != 4).then_some(4096),
                    )))
                },
                rights,
            ))
        }
    }
}
mod mem {
    pub mod paging {
        pub fn is_user_range_occupied_in_table(table: u64, start: u64, _: u64) -> bool {
            assert_eq!(
                table, 17,
                "only the privately prepared target may be inspected"
            );
            start == 0x400000
        }
    }
}
#[path = "../../../core/src/syscall/exec/initial_mappings.rs"]
mod production;

fn mapping() -> InitialMapping {
    InitialMapping {
        address: 0x4000_0000_0000,
        length: 4096,
        access: 1,
        options: mnu_abi::MEMORY_MAP_SHARED,
        backing_handle: 1,
        backing_offset: 0,
    }
}
fn encoded(mappings: &[InitialMapping]) -> (Vec<u8>, usize) {
    let mut bytes = vec![0; 4096];
    let length = wire::encode(0, &[0; 64], &[], &mut bytes).unwrap();
    let end = wire::attach_mappings(&mut bytes, length, mappings).unwrap();
    (bytes, end)
}

#[test]
fn wire_extension_preserves_the_opaque_stack_and_is_strict_and_transactional() {
    let (bytes, length) = encoded(&[mapping()]);
    let image = wire::decode(&bytes[..length]).unwrap();
    assert_eq!(image.stack(), &[0; 64]);
    assert_eq!(image.mappings().collect::<Vec<_>>(), [mapping()]);
    for change in 0..8 {
        let mut bad = mapping();
        match change {
            0 => bad.address += 1,
            1 => bad.length = 0,
            2 => bad.length += 1,
            3 => bad.access = 6,
            4 => bad.options = 128,
            5 => bad.backing_offset = u64::MAX,
            6 => bad.address = 1 << 47,
            _ => {
                bad.backing_handle = 0;
                bad.backing_offset = 4096;
            }
        }
        let mut output = vec![0; 4096];
        let n = wire::encode(0, &[0; 64], &[], &mut output).unwrap();
        let before = output.clone();
        assert_eq!(
            wire::attach_mappings(&mut output, n, &[bad]),
            Err(wire::Error::InvalidMapping)
        );
        assert_eq!(output, before);
    }
    let mut invalid = bytes.clone();
    invalid[4..6].copy_from_slice(&wire::VERSION.to_le_bytes());
    assert_eq!(
        wire::decode(&invalid[..length]),
        Err(wire::Error::InvalidHeader)
    );
    let mut invalid = bytes.clone();
    invalid[24..28].copy_from_slice(&17u32.to_le_bytes());
    assert_eq!(
        wire::decode(&invalid[..length]),
        Err(wire::Error::InvalidHeader)
    );
    assert!(wire::decode(&bytes[..length - 1]).is_err());
    let mut output = vec![0; 4096];
    let n = wire::encode(0, &[0; 64], &[], &mut output).unwrap();
    assert_eq!(
        wire::attach_mappings(&mut output, n, &[mapping(), mapping()]),
        Err(wire::Error::InvalidMapping)
    );
}

#[test]
fn prepared_regions_preserve_ram_authority_and_reject_conflicts_and_invalid_objects() {
    let (bytes, length) = encoded(&[mapping()]);
    let mut regions = vec![];
    production::prepare(17, wire::decode(&bytes[..length]).unwrap(), &mut regions).unwrap();
    assert_eq!(regions[0].max, 1);
    assert!(regions[0].object.is_some());
    for (mut plan, expected) in [
        (mapping(), Error::AccessDenied),
        (mapping(), Error::InvalidArgument),
        (mapping(), Error::InvalidArgument),
        (mapping(), Error::InvalidArgument),
        (mapping(), Error::AccessDenied),
        (mapping(), Error::InvalidArgument),
        (mapping(), Error::InvalidArgument),
        (mapping(), Error::NotReady),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, (mut p, e))| {
        match i {
            0 => p.access = 3,
            1 => p.backing_handle = 99,
            2 => p.backing_handle = 3,
            3 => p.length = 8192,
            4 => p.access = 4,
            5 => p.address = 0x400000,
            6 => p.backing_handle = 4,
            _ => p.backing_handle = 98,
        }
        (p, e)
    }) {
        let (bytes, length) = encoded(&[plan]);
        assert_eq!(
            production::prepare(17, wire::decode(&bytes[..length]).unwrap(), &mut vec![]),
            Err(expected)
        );
        plan.backing_handle = 0;
        plan.backing_offset = 0;
        plan.access = 3;
        plan.options = 0;
        let (bytes, length) = encoded(&[plan]);
        if plan.address != 0x400000 {
            production::prepare(17, wire::decode(&bytes[..length]).unwrap(), &mut vec![]).unwrap();
        }
    }
    assert_eq!(
        production::prepare(17, wire::decode(&bytes[..length]).unwrap(), &mut regions),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn preparation_reserves_before_lookup_and_releases_partial_owned_regions() {
    let (bytes, length) = encoded(&[mapping()]);
    let startup = wire::decode(&bytes[..length]).unwrap();
    let mut regions = Vec::new();
    LOOKUPS.with(|count| count.set(0));
    FAIL.with(|state| state.set(true));
    let result = production::prepare(17, startup, &mut regions);
    assert!(!FAIL.with(|state| state.replace(false)));
    assert_eq!(result, Err(Error::ResourceUnavailable));
    assert_eq!(LOOKUPS.with(Cell::get), 0);
    assert!(regions.is_empty());

    let mut invalid = mapping();
    invalid.address += 4096;
    invalid.backing_handle = 99;
    let (bytes, length) = encoded(&[mapping(), invalid]);
    DROPS.with(|count| count.set(0));
    assert_eq!(
        production::prepare(17, wire::decode(&bytes[..length]).unwrap(), &mut regions),
        Err(Error::InvalidArgument)
    );
    assert_eq!(regions.len(), 1);
    assert_eq!(DROPS.with(Cell::get), 0);
    drop(regions);
    assert_eq!(DROPS.with(Cell::get), 1);
}

#[test]
fn generic_mapping_preparation_precedes_budget_and_destructive_commit() {
    let source = include_str!("../../../core/src/syscall/exec.rs");
    let body = source
        .split("fn replace_current_process_image(")
        .nth(1)
        .unwrap();
    let prepared = body.find("initial_mappings::prepare(").unwrap();
    assert!(prepared < body.find("check_image_byte_ceiling(").unwrap());
    assert!(prepared < body.find("retire_image_siblings(").unwrap());
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = runtime
        .split("pub unsafe extern \"C\" fn _start_c(")
        .nth(1)
        .unwrap();
    assert!(start.find("adopt_initial(").unwrap() < start.find("initialize_runtime(").unwrap());
    assert!(start.contains("setup_signal_delivery(initial_thread, prepared_stack)"));
}

#[test]
fn posix_auxiliary_convention_and_relocations_survive_the_generic_extension() {
    use mochios_posix_client::process_image::{
        AT_INITIAL_HEAP, AT_RESOURCE_POLICY, AT_UPCALL_STACK, encode_initial_stack_with_aux,
    };
    let mut bytes = [0; 9000];
    let auxiliary = [
        (AT_RESOURCE_POLICY, mapping().address),
        (AT_UPCALL_STACK, mapping().address + 4096),
        (AT_INITIAL_HEAP, mapping().address + 65536 + 4096),
    ];
    let length = encode_initial_stack_with_aux(
        &[b"tool", b"argument"],
        &[b"A=B"],
        b"tool",
        [7; 16],
        &auxiliary,
        &mut bytes,
    )
    .unwrap();
    let stack = wire::decode(&bytes[..length]).unwrap().stack().to_vec();
    let relocations = wire::decode(&bytes[..length])
        .unwrap()
        .relocations()
        .collect::<Vec<_>>();
    let end = wire::attach_mappings(&mut bytes, length, &[mapping()]).unwrap();
    let decoded = wire::decode(&bytes[..end]).unwrap();
    assert_eq!(decoded.stack(), stack);
    assert_eq!(decoded.relocations().collect::<Vec<_>>(), relocations);
    for (key, value) in auxiliary {
        assert!(
            decoded
                .stack()
                .chunks_exact(16)
                .any(|pair| pair[..8] == key.to_le_bytes() && pair[8..] == value.to_le_bytes())
                || decoded.stack()[8..]
                    .chunks_exact(16)
                    .any(|pair| pair[..8] == key.to_le_bytes() && pair[8..] == value.to_le_bytes())
        );
    }
    for bad in [
        &[(0, 0)][..],
        &[(31, 1)][..],
        &[(AT_RESOURCE_POLICY, 1), (AT_RESOURCE_POLICY, 2)][..],
    ] {
        assert!(
            encode_initial_stack_with_aux(&[b"tool"], &[], b"tool", [0; 16], bad, &mut bytes)
                .is_err()
        );
    }
}
