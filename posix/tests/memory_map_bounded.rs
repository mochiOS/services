use mnu_abi::memory_map::{REQUEST_LEN, Request};

#[test]
fn fixed_native_request_roundtrips_and_rejects_extensions() {
    assert_eq!(mnu_abi::SyscallNumber::MemoryMapBounded as u64, 695);
    assert_eq!(std::mem::size_of::<Request>(), REQUEST_LEN);
    assert_eq!(std::mem::align_of::<Request>(), 8);
    let request = Request {
        address: 0x10000,
        length: 8193,
        access: 3,
        options: 2,
        backing_handle: 17,
        backing_offset: 4096,
        byte_ceiling: 1 << 32,
        reserved: 0,
    };
    let encoded = request.encode();
    assert_eq!(Request::decode(&encoded), Some(request));
    for length in 0..REQUEST_LEN {
        assert_eq!(Request::decode(&encoded[..length]), None);
    }
    assert_eq!(Request::decode(&[0; REQUEST_LEN + 1]), None);
    let mut bad = encoded;
    for index in 56..64 {
        bad[index] = 1;
        assert_eq!(Request::decode(&bad), None);
        bad[index] = 0;
    }
}

type SysResult<T> = Result<T, i32>;
use mnu_abi::SyscallNumber;
fn call2(number: SyscallNumber, pointer: u64, length: u64) -> SysResult<u64> {
    assert_eq!(number, SyscallNumber::MemoryMapBounded);
    assert_eq!(length, 64);
    let bytes = unsafe { std::slice::from_raw_parts(pointer as *const u8, 64) };
    let request = Request::decode(bytes).unwrap();
    if request.byte_ceiling == 0 {
        Err(12)
    } else {
        Ok(0x4000)
    }
}
#[path = "../../../user/crates/syscall/src/memory.rs"]
mod production;
#[test]
fn client_passes_fixed_stack_request_and_propagates_native_failure() {
    let mut request = Request {
        length: 4096,
        byte_ceiling: 4096,
        ..Request::default()
    };
    assert_eq!(production::map_bounded(request), Ok(0x4000));
    request.byte_ceiling = 0;
    assert_eq!(production::map_bounded(request), Err(12));
}
#[test]
fn authoritative_usage_and_insertion_share_the_native_process_lock() {
    let source = include_str!("../../../core/src/syscall/process.rs");
    let body = source
        .split("fn memory_map_impl(")
        .nth(1)
        .unwrap()
        .split("pub fn memory_unmap(")
        .next()
        .unwrap();
    let lock = body.find("with_process_mut(pid").unwrap();
    let accounting = body.find("mapping_usage::bytes(").unwrap();
    let check = body.find("mapping_usage::permits(").unwrap();
    let insertion = body.find("process.add_memory_region(").unwrap();
    assert!(lock < accounting && accounting < check && check < insertion);
    assert!(!body[accounting..insertion].contains("set_mapping_cursor("));
    let wrapper = source
        .split("pub fn memory_map_bounded(")
        .nth(1)
        .unwrap()
        .split("fn memory_map_impl(")
        .next()
        .unwrap();
    assert!(wrapper.find("copy_from_user").unwrap() < wrapper.find("memory_map_impl(").unwrap());
    assert!(wrapper.contains("Request::decode(&bytes)"));
}
