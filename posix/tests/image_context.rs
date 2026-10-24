extern crate alloc;
use mnu_abi::process_image::{self as wire, ContextUpdate as U};
use mnu_abi::status::Error;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

#[test]
fn native_context_probe_distinguishes_mechanism_status_from_c_errno() {
    let source = include_str!("native_image_context.h");
    for (name, error) in [
        ("EI_NATIVE_NOT_FOUND", Error::NotFound),
        ("EI_NATIVE_ACCESS_DENIED", Error::AccessDenied),
        ("EI_NATIVE_RESOURCE_UNAVAILABLE", Error::ResourceUnavailable),
    ] {
        assert!(source.contains(&format!(
            "#define {name} INT64_C({})",
            error.into_raw() as i64
        )));
    }
    assert!(source.contains("errno == ENOMEM"));
}

thread_local! { static FAIL_AFTER: Cell<Option<usize>> = const { Cell::new(None) }; }
struct FaultAllocator;
fn reject() -> bool {
    FAIL_AFTER
        .try_with(|slot| match slot.get() {
            Some(0) => {
                slot.set(None);
                true
            }
            Some(count) => {
                slot.set(Some(count - 1));
                false
            }
            None => false,
        })
        .unwrap_or(false)
}
unsafe impl GlobalAlloc for FaultAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if reject() {
            core::ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if reject() {
            core::ptr::null_mut()
        } else {
            unsafe { System.realloc(pointer, layout, size) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: FaultAllocator = FaultAllocator;

mod handle_table {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ObjectHandle(u32);
    impl ObjectHandle {
        pub fn from_raw(raw: u32) -> Option<Self> {
            (raw != 0).then_some(Self(raw))
        }
        pub fn raw(self) -> u32 {
            self.0
        }
    }
}
#[path = "../../../core/src/task/launch_context.rs"]
mod launch_context;
use handle_table::ObjectHandle;
use launch_context::LaunchContext;

fn update(kind: u32, key: u64, value: u64) -> U {
    U { kind, key, value }
}
fn handle(raw: u32) -> ObjectHandle {
    ObjectHandle::from_raw(raw).unwrap()
}

#[test]
fn context_wire_preserves_stack_and_mappings_and_rejects_malformed_edits() {
    let mut bytes = [0u8; 2048];
    let length = wire::encode(0, &[0; 16], &[], &mut bytes).unwrap();
    let mapping = wire::InitialMapping {
        address: 0x10000,
        length: 4096,
        access: 1,
        options: 0,
        backing_handle: 0,
        backing_offset: 0,
    };
    let length = wire::attach_mappings(&mut bytes, length, &[mapping]).unwrap();
    let edits = [
        update(U::SET_HANDLE, 7, 3),
        update(U::SET_VALUE, 7, u64::MAX),
    ];
    let final_length = wire::attach_context(&mut bytes, length, &edits).unwrap();
    let image = wire::decode(&bytes[..final_length]).unwrap();
    assert_eq!(image.stack(), [0; 16]);
    assert_eq!(image.mappings().collect::<Vec<_>>(), [mapping]);
    assert_eq!(image.context_updates().collect::<Vec<_>>(), edits);
    let saved = bytes;
    let context_start = wire::HEADER_LEN + wire::MAPPING_LEN;
    for (offset, value) in [(context_start, 99), (context_start + 4, 1)] {
        bytes = saved;
        bytes[offset] = value;
        assert_eq!(
            wire::decode(&bytes[..final_length]),
            Err(wire::Error::InvalidContext)
        );
    }
    bytes = saved;
    let second = context_start + wire::CONTEXT_UPDATE_LEN;
    bytes[second..second + 4].copy_from_slice(&U::SET_HANDLE.to_le_bytes());
    bytes[second + 16..second + 24].copy_from_slice(&3u64.to_le_bytes());
    assert_eq!(
        wire::decode(&bytes[..final_length]),
        Err(wire::Error::InvalidContext)
    );
    bytes = saved;
    bytes[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        wire::decode(&bytes[..final_length]),
        Err(wire::Error::InvalidHeader)
    );
    bytes = saved;
    bytes[4..6].copy_from_slice(&wire::MAPPED_VERSION.to_le_bytes());
    assert_eq!(
        wire::decode(&bytes[..final_length]),
        Err(wire::Error::InvalidHeader)
    );
    assert_eq!(
        wire::decode(&saved[..final_length - 1]),
        Err(wire::Error::InvalidLength)
    );
}

#[test]
fn invalid_or_oversized_context_attachment_leaves_the_source_unchanged() {
    let mut bytes = [0u8; 128];
    let length = wire::encode(0, &[0; 16], &[], &mut bytes).unwrap();
    let saved = bytes;
    for edits in [
        vec![update(U::SET_HANDLE, 1, 0)],
        vec![update(
            U::SET_HANDLE,
            1,
            mnu_abi::PROCESS_MAX_OBJECT_HANDLES as u64 + 1,
        )],
        vec![update(U::REMOVE_VALUE, 1, 1)],
        vec![update(99, 1, 0)],
        vec![update(U::SET_VALUE, 1, 2), update(U::REMOVE_VALUE, 1, 0)],
    ] {
        assert_eq!(
            wire::attach_context(&mut bytes, length, &edits),
            Err(wire::Error::InvalidContext)
        );
        assert_eq!(bytes, saved);
    }
    assert_eq!(
        wire::attach_context(&mut bytes[..length], length, &[update(U::SET_VALUE, 1, 2)]),
        Err(wire::Error::BufferTooSmall)
    );
    assert_eq!(bytes, saved);
}

#[test]
fn preparation_is_private_and_preserves_unmentioned_keys_and_handle_aliases() {
    let mut live = LaunchContext::new_boxed();
    assert!(live.set(8, handle(3)) && live.set(9, handle(3)));
    assert!(live.set_value(8, 11) && live.set_value(10, 12));
    let edits = [
        update(U::REMOVE_HANDLE, 8, 0),
        update(U::SET_HANDLE, 7, 4),
        update(U::REMOVE_VALUE, 8, 0),
        update(U::SET_VALUE, 10, 99),
    ];
    let prepared = live
        .patched(edits.into_iter(), |object| object.raw() == 4)
        .unwrap();
    assert_eq!(live.get(8), Some(handle(3)));
    assert_eq!(live.value(8), Some(11));
    assert_eq!(live.value(10), Some(12));
    assert_eq!(prepared.get(8), None);
    assert_eq!(prepared.get(9), Some(handle(3)));
    assert_eq!(prepared.get(7), Some(handle(4)));
    assert_eq!(prepared.value(8), None);
    assert_eq!(prepared.value(10), Some(99));
    // Exactly the final image commit performs this infallible replacement.
    *live = prepared;
    assert_eq!(live.get(8), None);
}

#[test]
fn invalid_native_selectors_and_operations_fail_before_allocating_or_editing_context() {
    let mut live = LaunchContext::new_boxed();
    assert!(live.set(1, handle(3)) && live.set_value(1, 44));
    for invalid in [0, 1u64 << 32, (1u64 << 32) | 4, u64::MAX] {
        FAIL_AFTER.with(|slot| slot.set(Some(0)));
        let result = live.patched([update(U::SET_HANDLE, 1, invalid)].into_iter(), |_| true);
        let remaining = FAIL_AFTER.with(|slot| slot.replace(None));
        assert!(matches!(result, Err(Error::InvalidArgument)));
        assert_eq!(remaining, Some(0), "validation must precede reservation");
        assert_eq!(live.get(1), Some(handle(3)));
        assert_eq!(live.value(1), Some(44));
    }
    for kind in [0, u32::MAX] {
        FAIL_AFTER.with(|slot| slot.set(Some(0)));
        let result = live.patched([update(kind, 1, 0)].into_iter(), |_| true);
        let remaining = FAIL_AFTER.with(|slot| slot.replace(None));
        assert!(matches!(result, Err(Error::InvalidArgument)));
        assert_eq!(remaining, Some(0));
        assert_eq!(live.get(1), Some(handle(3)));
        assert_eq!(live.value(1), Some(44));
    }
}

#[test]
fn prepared_commit_is_allocation_free_and_keeps_opaque_scalar_bits() {
    let mut live = LaunchContext::new_boxed();
    assert!(live.set(1, handle(3)) && live.set_value(1, 44));
    let prepared = live
        .patched(
            [
                update(U::REMOVE_HANDLE, 1, 0),
                update(U::SET_HANDLE, u64::MAX, 4),
                update(U::SET_VALUE, u64::MAX, Error::NotFound.into_raw()),
            ]
            .into_iter(),
            |handle| handle.raw() == 4,
        )
        .unwrap();
    assert_eq!(live.get(u64::MAX), None);
    assert_eq!(live.value(u64::MAX), None);
    FAIL_AFTER.with(|slot| slot.set(Some(0)));
    *live = prepared;
    let remaining = FAIL_AFTER.with(|slot| slot.replace(None));
    assert_eq!(remaining, Some(0), "commit must not reserve or allocate");
    assert_eq!(live.get(1), None);
    assert_eq!(live.value(1), Some(44));
    assert_eq!(live.get(u64::MAX), Some(handle(4)));
    assert_eq!(live.value(u64::MAX), Some(Error::NotFound.into_raw()));
}

#[test]
fn invalid_handles_capacity_and_each_allocation_failure_leave_live_context_intact() {
    let mut live = LaunchContext::new_boxed();
    assert!(live.set(1, handle(3)) && live.set_value(1, 44));
    let edits = [update(U::SET_HANDLE, 2, 4), update(U::SET_VALUE, 2, 55)];
    assert!(matches!(
        live.patched(edits.into_iter(), |_| false),
        Err(Error::InvalidArgument)
    ));
    for fail_after in [0, 1] {
        FAIL_AFTER.with(|slot| slot.set(Some(fail_after)));
        let prepared = live.patched(edits.into_iter(), |_| true);
        assert!(matches!(prepared, Err(Error::ResourceUnavailable)));
        assert_eq!(live.get(1), Some(handle(3)));
        assert_eq!(live.get(2), None);
        assert_eq!(live.value(1), Some(44));
        assert_eq!(live.value(2), None);
    }
    assert!(live.patched(edits.into_iter(), |_| true).is_ok());
    for key in 2..=256 {
        assert!(live.set_value(key, key));
    }
    assert!(matches!(
        live.patched([update(U::SET_VALUE, 999, 1)].into_iter(), |_| true),
        Err(Error::ResourceUnavailable)
    ));
    // Serialized additions may precede removals, even at full capacity.
    let prepared = live
        .patched(
            [update(U::SET_VALUE, 999, 1), update(U::REMOVE_VALUE, 1, 0)].into_iter(),
            |_| true,
        )
        .unwrap();
    assert_eq!(prepared.value(1), None);
    assert_eq!(prepared.value(999), Some(1));
    assert_eq!(live.value(1), Some(44));
    for key in 2..=256 {
        assert!(live.set(key, handle(3)));
    }
    assert!(matches!(
        live.patched([update(U::SET_HANDLE, 999, 4)].into_iter(), |_| true),
        Err(Error::ResourceUnavailable)
    ));
    let prepared = live
        .patched(
            [
                update(U::SET_HANDLE, 999, 4),
                update(U::REMOVE_HANDLE, 1, 0),
            ]
            .into_iter(),
            |_| true,
        )
        .unwrap();
    assert_eq!(prepared.get(1), None);
    assert_eq!(prepared.get(999), Some(handle(4)));
    assert!(prepared.references_handle(handle(3)));
    assert_eq!(live.get(1), Some(handle(3)));
}

#[test]
fn native_commit_orders_context_after_all_fallible_preparation_without_fd_policy() {
    let source = include_str!("../../../core/src/syscall/exec.rs");
    let replace = source
        .split("fn replace_current_process_image(")
        .nth(1)
        .unwrap();
    let quiesce = replace
        .find("quiesce_image_siblings(pid, current_tid)")
        .unwrap();
    let prepare = replace.find(".patched(startup.context_updates()").unwrap();
    let revoke = replace
        .find("release_process_borrowed_mappings(pid)?")
        .unwrap();
    let commit = replace
        .find("*process.launch_context_mut() = context")
        .unwrap();
    let retain = replace
        .find("retain_launch_context_handles_for_exec()")
        .unwrap();
    assert!(quiesce < prepare && prepare < revoke && revoke < commit && commit < retain);
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(!runtime.contains("stage_fd_launch_context"));
    let shared = include_str!("../../../user/crates/newlib-runtime/src/exec_handle.rs");
    assert!(shared.contains("attach_fd_launch_context(fds, &mut startup, length)?"));
    assert!(runtime.contains("exec_handle::replace_path(&inputs, fds)"));
    assert!(shared.contains("with_startup(inputs, execfn, fds,"));
}
