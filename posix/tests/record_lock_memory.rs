#![allow(dead_code)]
use mochios_posix_protocol as posix_protocol;
use posix_protocol::record_lock::{Kind, Operation, Origin, Reply};
use std::ffi::{c_char, c_int};
#[path = "../../../user/crates/newlib-runtime/src/record_lock_memory.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
const EFAULT: c_int = 14;
const EIO: c_int = 5;
const EINVAL: c_int = 22;
const EOVERFLOW: c_int = 139;
const ENAMETOOLONG: c_int = 91;
const ENOENT: c_int = 2;
const PAGE_SIZE: usize = 4096;
const F_GETLK: c_int = 7;
const F_SETLK: c_int = 8;
const F_SETLKW: c_int = 9;
#[repr(align(8))]
struct Buffer([u8; 32]);
fn input(kind: i16, origin: i16, start: i64, length: i64) -> Buffer {
    let mut bytes = [0xa5; 32];
    bytes[..2].copy_from_slice(&kind.to_ne_bytes());
    bytes[2..4].copy_from_slice(&origin.to_ne_bytes());
    bytes[8..16].copy_from_slice(&start.to_ne_bytes());
    bytes[16..24].copy_from_slice(&length.to_ne_bytes());
    Buffer(bytes)
}

#[test]
fn actual_flock_import_preserves_high_pointers_signed_ranges_and_all_valid_operations() {
    assert_eq!(std::mem::size_of::<implementation::Flock>(), 32);
    for (command, kind, operation) in [
        (7, 1, Operation::Query(Kind::Read)),
        (7, 2, Operation::Query(Kind::Write)),
        (8, 1, Operation::Set(Kind::Read)),
        (8, 2, Operation::Set(Kind::Write)),
        (8, 3, Operation::Unlock),
        (9, 3, Operation::Unlock),
    ] {
        for (raw, origin) in [(0, Origin::Start), (1, Origin::Current), (2, Origin::End)] {
            let mut data = input(kind, raw, i64::MIN, i64::MAX);
            let pointer = data.0.as_mut_ptr().cast();
            assert!(pointer as usize > u32::MAX as usize);
            let request = implementation::read_request(command, pointer).unwrap();
            assert_eq!(
                (
                    request.operation,
                    request.origin,
                    request.start,
                    request.length
                ),
                (operation, origin, i64::MIN, i64::MAX)
            );
        }
    }
}

#[test]
fn invalid_kind_origin_command_and_inaccessible_input_are_rejected_without_dereference() {
    for (command, kind, origin) in [(7, 3, 0), (8, 0, 0), (8, 1, 3), (8, 1, -1), (99, 1, 0)] {
        let mut data = input(kind, origin, 0, 0);
        assert_eq!(
            implementation::read_request(command, data.0.as_mut_ptr().cast()),
            Err(EINVAL)
        );
    }
    assert_eq!(
        implementation::read_request(8, std::ptr::null_mut()),
        Err(EFAULT)
    );
    assert_eq!(
        implementation::read_request(8, (usize::MAX - 8) as *mut implementation::Flock),
        Err(EFAULT)
    );
}

#[test]
fn no_conflict_writes_only_type_and_conflict_keeps_a_full_width_pid() {
    let mut data = input(2, 1, 10, 20);
    let original = data.0;
    implementation::write_reply(data.0.as_mut_ptr().cast(), Reply::Unlocked).unwrap();
    assert_eq!(&data.0[2..], &original[2..]);
    assert_eq!(&data.0[..2], &3i16.to_ne_bytes());
    implementation::write_reply(
        data.0.as_mut_ptr().cast(),
        Reply::Conflict {
            owner: 70_000,
            kind: Kind::Write,
            start: 123,
            length: 0,
        },
    )
    .unwrap();
    assert_eq!(&data.0[..2], &2i16.to_ne_bytes());
    assert_eq!(&data.0[2..8], &[0; 6]);
    assert_eq!(&data.0[8..16], &123i64.to_ne_bytes());
    assert_eq!(&data.0[16..24], &[0; 8]);
    assert_eq!(&data.0[24..28], &70_000i32.to_ne_bytes());
    assert_eq!(&data.0[28..], &[0; 4]);
}

#[test]
fn oversized_pid_and_invalid_reply_do_not_partially_modify_flock() {
    let mut data = input(1, 0, 0, 0);
    let original = data.0;
    assert_eq!(
        implementation::write_reply(
            data.0.as_mut_ptr().cast(),
            Reply::Conflict {
                owner: i32::MAX as u64 + 1,
                kind: Kind::Read,
                start: 1,
                length: 1
            }
        ),
        Err(EOVERFLOW)
    );
    assert_eq!(data.0, original);
    assert_eq!(
        implementation::write_reply(data.0.as_mut_ptr().cast(), Reply::Done),
        Err(EIO)
    );
    assert_eq!(data.0, original);
    assert_eq!(
        implementation::write_reply(std::ptr::null_mut(), Reply::Unlocked),
        Err(EFAULT)
    );
}
