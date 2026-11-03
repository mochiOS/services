#![allow(dead_code)]
use mochios_posix_client::{Client, ClientError, Transport, newlib_errno::*};
use mochios_posix_protocol::{self as posix_protocol, public_group as wire};
use std::{
    ffi::{CStr, c_char, c_int},
    ptr,
};
#[path = "../../../user/crates/newlib-runtime/src/groups.rs"]
mod groups;
#[path = "../../../user/crates/newlib-runtime/src/group_lookup.rs"]
mod actual;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
const PAGE_SIZE: usize = 4096;
thread_local! {
    static MODE:std::cell::Cell<i32>=const {std::cell::Cell::new(0)};
    static ERRNO:std::cell::Cell<i32>=const {std::cell::Cell::new(0)};
}
fn set_errno(error: c_int) {
    ERRNO.set(error);
}
struct RuntimeMutex<T>(std::sync::Mutex<T>);
impl<T> RuntimeMutex<T> {
    const fn new(value: T) -> Self {
        Self(std::sync::Mutex::new(value))
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, T> {
        self.0.lock().unwrap()
    }
}
struct State {
    group_cache: actual::Cache,
}
static STATE: RuntimeMutex<State> = RuntimeMutex::new(State {
    group_cache: actual::Cache::new(),
});
struct Groups;
impl Transport for Groups {
    type Error = i32;
    fn call(&self, request: &[u8], output: &mut [u8]) -> Result<usize, i32> {
        let (header, payload) = posix_protocol::decode(request).unwrap();
        assert_eq!(header.opcode, posix_protocol::OP_GROUP_LOOKUP);
        let query = wire::decode_query(payload).unwrap();
        let mode = MODE.get();
        if mode == 32 {
            return Err(32);
        }
        let found = matches!(query, wire::Query::Gid(20) | wire::Query::Name("staff"));
        let status = if mode > 0 {
            -mode
        } else if !found {
            -2
        } else {
            0
        };
        let mut body = [0; wire::MAX_RECORD];
        let n = if status == 0 {
            wire::encode_record(
                wire::Record::new(
                    if mode == -1 { 65536 } else { 20 },
                    "staff",
                    &["alice", "bob"],
                )
                .unwrap(),
                &mut body,
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
            &body[..n],
            output,
        )
        .map_err(|_| 5)
    }
}
fn posix_client() -> Result<Client<Groups>, ClientError<i32>> {
    Ok(Client::new(Groups))
}
fn map_posix_client_error(error: ClientError<i32>) -> i32 {
    match error {
        ClientError::Transport(error) => error,
        ClientError::Remote(error) => -error,
        _ => EIO,
    }
}
fn word(bytes: &[u8], offset: usize) -> usize {
    usize::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn actual_group_layout_has_aligned_member_table_and_independent_caller_storage() {
    MODE.set(0);
    let mut object = [0xa5; 34];
    let mut other = [0x5a; 32];
    let mut text = [0x5a; 256];
    let mut second = [0xa5; 256];
    let output = object.as_mut_ptr().wrapping_add(1).cast();
    let mut result = ptr::null_mut();
    assert_eq!(
        unsafe {
            actual::getgrgid_r(
                20,
                output,
                text.as_mut_ptr().wrapping_add(1).cast(),
                255,
                &mut result,
            )
        },
        0
    );
    assert_eq!(result, output);
    assert_eq!((object[0], object[33]), (0xa5, 0xa5));
    let group = &object[1..33];
    assert_eq!(u16::from_ne_bytes(group[16..18].try_into().unwrap()), 20);
    assert_eq!(&group[18..24], &[0; 6]);
    for (offset, expected) in [(0, "staff"), (8, "x")] {
        let pointer = word(group, offset);
        assert!(pointer >= text.as_ptr() as usize && pointer < text.as_ptr() as usize + text.len());
        assert_eq!(
            unsafe { CStr::from_ptr(pointer as *const c_char) }.to_bytes(),
            expected.as_bytes()
        );
    }
    let members = word(group, 24);
    assert_eq!(members % 8, 0);
    assert!(
        members >= text.as_ptr() as usize && members + 24 <= text.as_ptr() as usize + text.len()
    );
    for (index, name) in ["alice", "bob"].iter().enumerate() {
        let pointer = unsafe { (members as *const *const c_char).add(index).read() };
        assert_eq!(
            unsafe { CStr::from_ptr(pointer) }.to_bytes(),
            name.as_bytes()
        );
    }
    assert!(unsafe { (members as *const *const c_char).add(2).read() }.is_null());
    assert_eq!(text[0], 0x5a);
    let saved = object;
    let first_text = text;
    assert_eq!(
        unsafe {
            actual::getgrnam_r(
                c"staff".as_ptr(),
                other.as_mut_ptr().cast(),
                second.as_mut_ptr().cast(),
                second.len(),
                &mut result,
            )
        },
        0
    );
    assert_eq!(object, saved);
    assert_eq!(text, first_text);
    assert_ne!(word(&other, 0), word(&object[1..33], 0));
}

#[test]
fn missing_records_range_overflow_and_native_faults_never_publish_a_group() {
    MODE.set(0);
    let mut object = [0xa5; 32];
    let mut text = [0x5a; 256];
    let output = object.as_mut_ptr().cast();
    let mut result = output;
    assert_eq!(
        unsafe { actual::getgrgid_r(20, output, text.as_mut_ptr().cast(), 1, &mut result) },
        ERANGE
    );
    assert!(result.is_null());
    assert_eq!(object, [0xa5; 32]);
    assert_eq!(text, [0x5a; 256]);
    for mode in [EIO, EACCES, 32, -1] {
        MODE.set(mode);
        let expected = if mode == -1 { EOVERFLOW } else { mode };
        assert_eq!(
            unsafe {
                actual::getgrnam_r(
                    c"staff".as_ptr(),
                    output,
                    text.as_mut_ptr().cast(),
                    text.len(),
                    &mut result,
                )
            },
            expected
        );
        assert!(result.is_null());
        assert_eq!(object, [0xa5; 32]);
        assert_eq!(text, [0x5a; 256]);
    }
    MODE.set(0);
    assert_eq!(
        unsafe { actual::getgrgid_r(999, output, ptr::null_mut(), 0, &mut result) },
        0
    );
    assert!(result.is_null());
    for name in [c"missing".as_ptr(), c"".as_ptr(), c"bad name".as_ptr()] {
        assert_eq!(
            unsafe { actual::getgrnam_r(name, output, ptr::null_mut(), 0, &mut result) },
            0
        );
        assert!(result.is_null());
    }
    assert_eq!(
        unsafe { actual::getgrgid_r(20, output, 1usize as *mut _, text.len(), &mut result) },
        EFAULT
    );
    assert_eq!(
        unsafe {
            actual::getgrgid_r(
                20,
                output,
                text.as_mut_ptr().cast(),
                text.len(),
                1usize as *mut _,
            )
        },
        EFAULT
    );
    assert_eq!(
        unsafe {
            actual::getgrnam_r(
                1usize as *const _,
                output,
                text.as_mut_ptr().cast(),
                text.len(),
                &mut result,
            )
        },
        EFAULT
    );
    assert_eq!(object, [0xa5; 32]);
}

#[test]
fn cached_group_names_survive_input_aliasing_and_preserve_errno_contract() {
    MODE.set(0);
    ERRNO.set(71);
    let pointer = unsafe { actual::getgrgid(20) };
    assert!(!pointer.is_null());
    let name = unsafe { pointer.cast::<*const c_char>().read() };
    assert_eq!(unsafe { CStr::from_ptr(name) }.to_bytes(), b"staff");
    assert_eq!(unsafe { actual::getgrnam(name) }, pointer);
    assert_eq!(ERRNO.get(), 71);
    assert!(unsafe { actual::getgrgid(65535) }.is_null());
    assert_eq!(ERRNO.get(), 71);
    MODE.set(EACCES);
    assert!(unsafe { actual::getgrgid(20) }.is_null());
    assert_eq!(ERRNO.get(), EACCES);
    MODE.set(0);
    assert!(unsafe { actual::getgrnam(1usize as *const _) }.is_null());
    assert_eq!(ERRNO.get(), EFAULT);
}
