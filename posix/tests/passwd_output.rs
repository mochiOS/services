#![allow(dead_code)]
use mochios_posix_client::{Client, ClientError, Transport, newlib_errno::*};
use mochios_posix_protocol::{self as posix_protocol, account as wire};
use std::ffi::{c_char, c_int};
#[path = "../../../user/crates/newlib-runtime/src/passwd.rs"]
mod actual;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
const PAGE_SIZE: usize = 4096;
thread_local! { static MODE: std::cell::Cell<i32> = const { std::cell::Cell::new(0) }; }
struct Accounts;
impl Transport for Accounts {
    type Error = i32;
    fn call(&self, request: &[u8], output: &mut [u8]) -> Result<usize, i32> {
        let (header, payload) = posix_protocol::decode(request).unwrap();
        assert_eq!(header.opcode, posix_protocol::OP_ACCOUNT_LOOKUP);
        let found = matches!(
            wire::decode_query(payload).unwrap(),
            wire::Query::Uid(1000) | wire::Query::Name("testuser")
        );
        let error = MODE.get();
        if error == 32 {
            return Err(32);
        }
        let status = if error != 0 {
            -error
        } else if !found {
            -2
        } else {
            0
        };
        let mut bytes = [0; wire::MAX_RECORD];
        let n = if status == 0 {
            wire::encode_record(
                wire::Record {
                    uid: 1000,
                    gid: 20,
                    name: "testuser",
                    display_name: "テスト利用者",
                    home: "/home/testuser",
                    shell: "/bin/msh",
                },
                &mut bytes,
            )
            .unwrap()
        } else {
            0
        };
        posix_protocol::encode(
            posix_protocol::Header {
                opcode: posix_protocol::OP_STATUS,
                request_id: header.request_id,
                status,
                payload_len: n as u32,
                ..Default::default()
            },
            &bytes[..n],
            output,
        )
        .map_err(|_| 5)
    }
}
fn posix_client() -> Result<Client<Accounts>, ClientError<i32>> {
    Ok(Client::new(Accounts))
}
fn map_posix_client_error(error: ClientError<i32>) -> i32 {
    match error {
        ClientError::Remote(e) => -e,
        ClientError::Transport(e) => e,
        _ => EIO,
    }
}

#[test]
fn actual_reentrant_calls_publish_c_layout_and_strings_in_the_callers_buffer() {
    let mut first = [0xa5; 58];
    let mut second = [0x5a; 58];
    let mut text = [0xa5; 256];
    let mut other = [0x5a; 256];
    let output = first.as_mut_ptr().wrapping_add(1).cast::<actual::Passwd>();
    let second_output = second.as_mut_ptr().wrapping_add(1).cast::<actual::Passwd>();
    let mut result = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            actual::getpwuid_r(
                1000,
                output,
                text.as_mut_ptr().cast(),
                text.len(),
                &mut result,
            )
        },
        0
    );
    assert_eq!(result, output);
    assert_eq!((first[0], first[57]), (0xa5, 0xa5));
    assert_eq!(u32::from_ne_bytes(first[17..21].try_into().unwrap()), 1000);
    assert_eq!(u32::from_ne_bytes(first[21..25].try_into().unwrap()), 20);
    for (offset, expected) in [
        (0, "testuser"),
        (8, "x"),
        (24, "テスト利用者"),
        (32, "テスト利用者"),
        (40, "/home/testuser"),
        (48, "/bin/msh"),
    ] {
        let pointer = usize::from_ne_bytes(first[1 + offset..9 + offset].try_into().unwrap());
        assert!(pointer >= text.as_ptr() as usize && pointer < text.as_ptr() as usize + text.len());
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(pointer as *const c_char) }
                .to_str()
                .unwrap(),
            expected
        );
    }
    let original = first;
    assert_eq!(
        unsafe {
            actual::getpwnam_r(
                c"testuser".as_ptr(),
                second_output,
                other.as_mut_ptr().cast(),
                other.len(),
                &mut result,
            )
        },
        0
    );
    assert_eq!(result, second_output);
    assert_eq!(first, original);
    assert_ne!(&first[1..9], &second[1..9]);
}

#[test]
fn range_missing_service_error_and_bad_pointers_return_an_error_code_without_fake_records() {
    let mut output = [0xa5; 56];
    let mut text = [0x5a; 256];
    let target = output.as_mut_ptr().cast();
    let mut result = target;
    assert_eq!(
        unsafe { actual::getpwuid_r(1000, target, text.as_mut_ptr().cast(), 1, &mut result) },
        ERANGE
    );
    assert!(result.is_null());
    assert_eq!(output, [0xa5; 56]);
    assert_eq!(text, [0x5a; 256]);
    for error in [EIO, EACCES, 32] {
        MODE.set(error);
        result = target;
        assert_eq!(
            unsafe {
                actual::getpwuid_r(
                    1000,
                    target,
                    text.as_mut_ptr().cast(),
                    text.len(),
                    &mut result,
                )
            },
            error
        );
        assert!(result.is_null());
        assert_eq!(output, [0xa5; 56]);
    }
    MODE.set(0);
    for name in [
        c"missing-account".as_ptr(),
        c"".as_ptr(),
        c"a name that cannot exist in the account database".as_ptr(),
    ] {
        result = target;
        assert_eq!(
            unsafe { actual::getpwnam_r(name, target, std::ptr::null_mut(), 0, &mut result) },
            0
        );
        assert!(result.is_null());
        assert_eq!(output, [0xa5; 56]);
    }
    assert_eq!(
        unsafe { actual::getpwuid_r(u32::MAX, target, std::ptr::null_mut(), 0, &mut result) },
        0
    );
    for (buffer, result_pointer) in [
        (1usize as *mut c_char, &mut result as *mut _),
        (text.as_mut_ptr().cast(), 1usize as *mut _),
    ] {
        assert_eq!(
            unsafe { actual::getpwuid_r(1000, target, buffer, text.len(), result_pointer) },
            EFAULT
        );
    }
    assert_eq!(
        unsafe {
            actual::getpwnam_r(
                1usize as *const _,
                target,
                text.as_mut_ptr().cast(),
                text.len(),
                &mut result,
            )
        },
        EFAULT
    );
    assert_eq!(output, [0xa5; 56]);
}
