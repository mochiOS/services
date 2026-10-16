#![allow(dead_code)]
use mochios_posix_protocol as posix_protocol;
use std::cell::RefCell;
use std::ffi::{c_char, c_int};
#[path = "../../../user/crates/newlib-runtime/src/resource_limit_memory.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
const EFAULT: c_int = 14;
const EINVAL: c_int = 22;
const EPERM: c_int = 1;
const EIO: c_int = 5;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const PAGE_SIZE: usize = 4096;
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewlibRlimit {
    rlim_cur: u64,
    rlim_max: u64,
}
const INITIAL: NewlibRlimit = NewlibRlimit {
    rlim_cur: 1 << 40,
    rlim_max: u64::MAX,
};
thread_local! {
    static VALUE: RefCell<NewlibRlimit> = const { RefCell::new(INITIAL) };
    static REQUESTS: RefCell<Vec<(c_int, c_int, Option<NewlibRlimit>)>> = const { RefCell::new(Vec::new()) };
}
fn resource_limit_impl(
    pid: c_int,
    resource: c_int,
    replacement: Option<NewlibRlimit>,
) -> Result<NewlibRlimit, c_int> {
    REQUESTS.with_borrow_mut(|requests| requests.push((pid, resource, replacement)));
    if resource != 7 {
        return Err(EINVAL);
    }
    if pid == 17 {
        return Err(EPERM);
    }
    VALUE.with_borrow_mut(|value| {
        let previous = *value;
        if let Some(next) = replacement {
            *value = next;
        }
        Ok(previous)
    })
}
fn reset() {
    VALUE.with_borrow_mut(|value| *value = INITIAL);
    REQUESTS.with_borrow_mut(Vec::clear);
    user_copy_native::CALLS.with_borrow_mut(Vec::clear);
}
#[test]
fn abi_and_public_entrypoints_match_production() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let begin = source.find("pub struct NewlibRlimit {").unwrap();
    let end = begin + source[begin..].find("\n}").unwrap() + 2;
    let compact = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    assert_eq!(
        compact(&source[begin..end]),
        compact("pub struct NewlibRlimit { rlim_cur: u64, rlim_max: u64, }")
    );
    for (name, call) in [
        ("getrlimit", "resource_limit_memory::get"),
        ("setrlimit", "resource_limit_memory::set"),
        ("prlimit", "resource_limit_memory::exchange"),
    ] {
        let begin = source
            .find(&format!("pub unsafe extern \"C\" fn {name}("))
            .unwrap();
        let end = begin + source[begin..].find("\n}").unwrap() + 2;
        let body = &source[begin..end];
        assert!(body.contains(call));
        assert!(!body.contains("ptr::"));
    }
}
#[test]
fn unaligned_wide_values_use_explicit_c_fields_and_preserve_canaries() {
    reset();
    let mut bytes = [0xa5; 18];
    let pointer = bytes.as_mut_ptr().wrapping_add(1).cast();
    assert_eq!(implementation::get(7, pointer), Ok(0));
    assert_eq!(&bytes[1..9], INITIAL.rlim_cur.to_ne_bytes());
    assert_eq!(&bytes[9..17], u64::MAX.to_ne_bytes());
    bytes[1..9].copy_from_slice(&42u64.to_ne_bytes());
    assert_eq!(implementation::set(7, pointer), Ok(0));
    VALUE.with_borrow(|value| assert_eq!(value.rlim_cur, 42));
    assert_eq!((bytes[0], bytes[17]), (0xa5, 0xa5));
    user_copy_native::CALLS.with_borrow(|calls| assert_eq!(calls.as_slice(), [16, 16]));
}
#[test]
fn invalid_inputs_never_reach_policy_or_mutate_limits() {
    reset();
    for address in [0, 1, usize::MAX] {
        assert_eq!(implementation::set(7, address as *const _), Err(EFAULT));
        if address != 0 {
            assert_eq!(
                implementation::exchange(0, 7, address as *const _, std::ptr::null_mut()),
                Err(EFAULT)
            );
        }
    }
    REQUESTS.with_borrow(|requests| assert!(requests.is_empty()));
    VALUE.with_borrow(|value| assert_eq!(*value, INITIAL));
}
#[test]
fn invalid_outputs_are_efault_and_optional_outputs_are_not_accessed() {
    reset();
    for address in [0, 1, usize::MAX] {
        assert_eq!(implementation::get(7, address as *mut _), Err(EFAULT));
        if address != 0 {
            assert_eq!(
                implementation::exchange(0, 7, std::ptr::null(), address as *mut _),
                Err(EFAULT)
            );
        }
    }
    user_copy_native::CALLS.with_borrow_mut(Vec::clear);
    assert_eq!(
        implementation::exchange(0, 7, std::ptr::null(), std::ptr::null_mut()),
        Ok(0)
    );
    user_copy_native::CALLS.with_borrow(|calls| assert!(calls.is_empty()));
}
#[test]
fn aliased_exchange_captures_new_value_before_writing_previous() {
    reset();
    let replacement = NewlibRlimit {
        rlim_cur: 32,
        rlim_max: 64,
    };
    let mut value = replacement;
    let pointer = &raw mut value;
    assert_eq!(implementation::exchange(23, 7, pointer, pointer), Ok(0));
    assert_eq!(value, INITIAL);
    VALUE.with_borrow(|value| assert_eq!(*value, replacement));
    REQUESTS.with_borrow(|requests| assert_eq!(requests.as_slice(), [(23, 7, Some(replacement))]));
}
#[test]
fn policy_failure_preserves_output_and_propagates_error() {
    reset();
    let mut output = INITIAL;
    assert_eq!(implementation::get(-1, &mut output), Err(EINVAL));
    assert_eq!(
        implementation::exchange(17, 7, std::ptr::null(), &mut output),
        Err(EPERM)
    );
    assert_eq!(output, INITIAL);
    user_copy_native::CALLS.with_borrow(|calls| assert!(calls.is_empty()));
}
#[test]
fn late_copyout_failure_does_not_fake_policy_rollback() {
    reset();
    let replacement = NewlibRlimit {
        rlim_cur: 32,
        rlim_max: 64,
    };
    assert_eq!(
        implementation::exchange(0, 7, &replacement, 1usize as *mut _),
        Err(EFAULT)
    );
    VALUE.with_borrow(|value| assert_eq!(*value, replacement));
}
