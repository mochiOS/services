use mochios_posix_client::memory::{
    MAP_ANONYMOUS, MAP_FIXED, MAP_NORESERVE, MAP_PRIVATE, MAP_SHARED, MAP_STACK, PROT_EXEC,
    PROT_NONE, PROT_READ, PROT_WRITE, native_access, native_map,
};

#[test]
fn posix_protection_flags_translate_to_native_vm_access() {
    assert_eq!(native_access(PROT_NONE), Some(0));
    assert_eq!(native_access(PROT_READ), Some(mnu_abi::MEMORY_ACCESS_READ));
    assert_eq!(
        native_access(PROT_READ | PROT_WRITE),
        Some(mnu_abi::MEMORY_ACCESS_READ | mnu_abi::MEMORY_ACCESS_WRITE)
    );
    assert_eq!(
        native_access(PROT_READ | PROT_EXEC),
        Some(mnu_abi::MEMORY_ACCESS_READ | mnu_abi::MEMORY_ACCESS_EXECUTE)
    );
    assert_eq!(native_access(1 << 8), None);
    assert_eq!(native_access(-1), None);
}

#[test]
fn newlib_heap_growth_commits_its_reserved_arena() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let heap = runtime
        .split("pub extern \"C\" fn _sbrk(")
        .nth(1)
        .unwrap()
        .split("pub extern \"C\" fn sbrk(")
        .next()
        .unwrap();
    assert!(heap.contains(".adjust(increment, image_data_bytes, data_limit, memory_limit)"));
    let arena = include_str!("../../../user/crates/newlib-runtime/src/heap.rs");
    assert!(arena.contains("RESERVATION_BYTES"));
    assert!(arena.contains("SyscallNumber::MemoryProtect"));
    assert!(arena.contains("MEMORY_MAP_EXACT"));
    assert!(arena.contains("if mapped != next.reserved_end"));
    let kernel = include_str!("../../../core/src/syscall/process.rs");
    let mapping = kernel
        .split("pub fn memory_map(")
        .nth(1)
        .unwrap()
        .split("pub fn memory_unmap(")
        .next()
        .unwrap();
    // Shared reservations keep a RAM-object identity before first access.
    assert!(mapping.contains("SharedMemory::new("));
    assert!(mapping.contains("size, size / 4096"));
    assert!(mapping.contains("VmObject::shared_memory(memory)"));
    assert!(!mapping.contains("map_and_copy_segment_to"));
    assert!(kernel.contains("None => Some(Arc::new([0u8; crate::mem::vm_object::PAGE_BYTES]))"));
}

#[test]
fn posix_mapping_flags_translate_to_native_options() {
    assert_eq!(native_map(MAP_PRIVATE | MAP_ANONYMOUS).unwrap().options, 0);
    assert!(native_map(MAP_PRIVATE | MAP_ANONYMOUS).unwrap().anonymous);
    assert_eq!(
        native_map(MAP_SHARED | MAP_FIXED).unwrap().options,
        mnu_abi::MEMORY_MAP_SHARED | mnu_abi::MEMORY_MAP_EXACT
    );
    assert_eq!(
        native_map(MAP_PRIVATE | MAP_STACK | MAP_NORESERVE)
            .unwrap()
            .options,
        0
    );
    assert!(native_map(0).is_none());
    assert!(native_map(MAP_SHARED | MAP_PRIVATE).is_none());
    assert!(native_map(MAP_PRIVATE | (1 << 29)).is_none());
}

#[test]
fn kernel_memory_protection_uses_only_native_access_flags() {
    let native = include_str!("../../../core/src/syscall/memory.rs");
    assert!(native.contains("mnu_abi::MEMORY_ACCESS_ALL"));
    assert!(native.contains("mnu_abi::MEMORY_ACCESS_WRITE"));
    assert!(native.contains("mnu_abi::MEMORY_ACCESS_EXECUTE"));
    assert!(!native.contains("const PROT_"));
    assert!(!native.contains("pub fn mprotect"));

    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(runtime.contains("mochios_posix_client::memory::native_access(prot)"));
}

#[test]
fn kernel_memory_mapping_uses_handles_and_native_options() {
    let native = include_str!("../../../core/src/syscall/process.rs");
    let mapping = native
        .split("pub fn memory_map(")
        .nth(1)
        .and_then(|body| body.split("pub fn memory_unmap(").next())
        .expect("native MemoryMap implementation");
    assert!(mapping.contains("MEMORY_MAP_OPTIONS_ALL"));
    assert!(mapping.contains("handle::object_with_rights(backing_handle"));
    assert!(mapping.contains("KernelObject::Provider"));
    assert!(!mapping.contains("MAX_MEMORY_BACKING_BYTES"));
    assert!(!mapping.contains("PROT_"));
    assert!(!mapping.contains("MAP_ANONYMOUS"));
    assert!(!mapping.contains("fd_table()"));
}

#[test]
fn sequential_write_response_carries_an_atomic_position_when_available() {
    use mnu_abi::provider::{DecodeError, OP_WRITE, RESPONSE_HEADER_LEN, ResponseHeader};
    let header = ResponseHeader {
        opcode: OP_WRITE,
        status: 0,
        object_id: 7,
        value: 3,
        data_length: 8,
    };
    let mut bytes = [0u8; RESPONSE_HEADER_LEN + 8];
    let position = 8192u64.to_le_bytes();
    let length = header.encode(&position, &mut bytes).unwrap();
    let (decoded, payload) = ResponseHeader::decode(&bytes[..length]).unwrap();
    assert_eq!(decoded.value, 3);
    assert_eq!(payload, position);
    assert!(
        ResponseHeader {
            data_length: 0,
            ..header
        }
        .encode(&[], &mut bytes)
        .is_ok()
    );
    assert_eq!(
        ResponseHeader {
            data_length: 4,
            ..header
        }
        .encode(&[0; 4], &mut bytes),
        Err(DecodeError::InvalidFields)
    );
}

#[test]
fn pager_provider_protocol_rejects_ambiguous_fields() {
    use mnu_abi::provider::{
        DecodeError, MAX_DATA_LEN, OP_MEMORY_OBJECT, OP_READ_AT, OP_SYNC, OP_WRITE_AT,
        REQUEST_HEADER_LEN, RESPONSE_HEADER_LEN, RequestHeader, ResponseHeader,
    };

    let read = RequestHeader {
        opcode: OP_READ_AT,
        object_id: 7,
        argument: 0,
        basis: 8192,
        length: 32,
        data_length: 0,
    };
    let mut request = [0u8; REQUEST_HEADER_LEN];
    let encoded = read.encode(&[], &mut request).unwrap();
    assert_eq!(RequestHeader::decode(&request[..encoded]).unwrap().0, read);

    let invalid_read = RequestHeader {
        data_length: 1,
        ..read
    };
    assert_eq!(
        invalid_read.encode(&[0], &mut [0u8; REQUEST_HEADER_LEN + 1]),
        Err(DecodeError::InvalidFields)
    );
    let invalid_write = RequestHeader {
        opcode: OP_WRITE_AT,
        length: 2,
        data_length: 1,
        ..read
    };
    assert_eq!(
        invalid_write.encode(&[0], &mut [0u8; REQUEST_HEADER_LEN + 1]),
        Err(DecodeError::InvalidFields)
    );
    let oversized = RequestHeader {
        length: (MAX_DATA_LEN + 1) as u32,
        data_length: 0,
        ..read
    };
    assert_eq!(
        oversized.encode(&[], &mut request),
        Err(DecodeError::InvalidFields)
    );

    for opcode in [OP_SYNC, OP_MEMORY_OBJECT] {
        let header = RequestHeader {
            opcode,
            object_id: 7,
            argument: 0,
            basis: 0,
            length: 0,
            data_length: 0,
        };
        assert!(header.encode(&[], &mut request).is_ok());
    }
    let identity = ResponseHeader {
        opcode: OP_MEMORY_OBJECT,
        status: 0,
        object_id: 7,
        value: 42,
        data_length: 0,
    };
    let mut response = [0u8; RESPONSE_HEADER_LEN];
    assert!(identity.encode(&[], &mut response).is_ok());
    assert_eq!(
        ResponseHeader {
            value: 0,
            ..identity
        }
        .encode(&[], &mut response),
        Err(DecodeError::InvalidFields)
    );
}
