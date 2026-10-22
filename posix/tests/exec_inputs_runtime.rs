#![allow(dead_code)]
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int};
#[path = "../../../user/crates/newlib-runtime/src/exec_inputs.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
const EFAULT: c_int = 14;
const EIO: c_int = 5;
const EINVAL: c_int = 22;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const E2BIG: c_int = 7;
const PAGE_SIZE: usize = 4096;
const MAX_EXEC_VECTOR_ENTRIES: usize = 256;
const MAX_EXECUTABLE_PATH_LEN: usize = 256;

#[test]
fn owned_c_vectors_are_terminated_even_when_reusing_a_longer_snapshot() {
    use std::ffi::CStr;
    let mut inputs = implementation::Inputs::new();
    let long = [c"old argument padding".as_ptr(), std::ptr::null()];
    inputs
        .capture(c"/tool".as_ptr(), long.as_ptr(), long.as_ptr())
        .unwrap();
    let short = [c"x".as_ptr(), c"".as_ptr(), std::ptr::null()];
    inputs
        .capture(c"/new".as_ptr(), short.as_ptr(), short.as_ptr())
        .unwrap();
    let mut args = [1usize as *const c_char; MAX_EXEC_VECTOR_ENTRIES];
    let mut env = args;
    assert_eq!(inputs.c_vectors(&mut args, &mut env), (2, 2));
    for vector in [args, env] {
        assert_eq!(unsafe { CStr::from_ptr(vector[0]) }.to_bytes(), b"x");
        assert_eq!(unsafe { CStr::from_ptr(vector[1]) }.to_bytes(), b"");
        assert!(vector[2..].iter().all(|pointer| pointer.is_null()));
    }
}
fn capture(
    path: *const c_char,
    args: *const *const c_char,
    env: *const *const c_char,
) -> Result<implementation::Inputs, c_int> {
    let mut inputs = implementation::Inputs::new();
    inputs.capture(path, args, env)?;
    Ok(inputs)
}
#[test]
fn snapshots_preserve_empty_and_non_utf8_vector_text_after_caller_mutation() {
    let mut path = b"/bin/tool\0".to_vec();
    let mut arg = b"one\0".to_vec();
    let mut env = b"K=value\0".to_vec();
    let mut argv = [
        arg.as_ptr().cast(),
        c"".as_ptr(),
        b"raw\xff\0".as_ptr().cast(),
        std::ptr::null(),
    ];
    let mut envp = [env.as_ptr().cast(), std::ptr::null()];
    let mut inputs = capture(path.as_ptr().cast(), argv.as_ptr(), envp.as_ptr()).unwrap();
    path.fill(b'x');
    arg.fill(b'y');
    env.fill(b'z');
    argv.fill(std::ptr::null());
    envp.fill(std::ptr::null());
    let mut args = [&[][..]; MAX_EXEC_VECTOR_ENTRIES];
    let mut environment = [&[][..]; MAX_EXEC_VECTOR_ENTRIES];
    assert_eq!(inputs.vectors(&mut args, &mut environment), (3, 1));
    assert_eq!(&args[..3], &[&b"one"[..], &b""[..], &b"raw\xff"[..]]);
    assert_eq!(environment[0], b"K=value");
    assert_eq!(inputs.path(), b"/bin/tool");
    inputs
        .capture(c"/new".as_ptr(), std::ptr::null(), std::ptr::null())
        .unwrap();
    let mut new_args = [&[][..]; MAX_EXEC_VECTOR_ENTRIES];
    let mut new_env = [&[][..]; MAX_EXEC_VECTOR_ENTRIES];
    assert_eq!(inputs.vectors(&mut new_args, &mut new_env), (0, 0));
}
#[test]
fn unaligned_pointer_vectors_are_copied_as_bytes() {
    let mut bytes = [0; 17];
    bytes[1..9].copy_from_slice(&(c"item".as_ptr() as usize).to_ne_bytes());
    let inputs = capture(
        c"/tool".as_ptr(),
        bytes.as_ptr().wrapping_add(1).cast(),
        std::ptr::null(),
    )
    .unwrap();
    let mut args = [&[][..]; MAX_EXEC_VECTOR_ENTRIES];
    let mut env = [&[][..]; MAX_EXEC_VECTOR_ENTRIES];
    assert_eq!(inputs.vectors(&mut args, &mut env), (1, 0));
    assert_eq!(args[0], b"item");
}
#[test]
fn invalid_vectors_and_nested_text_return_efault_without_raw_references() {
    for address in [0, 1, usize::MAX] {
        assert!(matches!(
            capture(address as *const _, std::ptr::null(), std::ptr::null()),
            Err(EFAULT)
        ));
        if address == 0 {
            continue;
        }
        assert!(matches!(
            capture(c"/tool".as_ptr(), address as *const _, std::ptr::null()),
            Err(EFAULT)
        ));
        assert!(matches!(
            capture(c"/tool".as_ptr(), std::ptr::null(), address as *const _),
            Err(EFAULT)
        ));
        let bad = [address as *const c_char, std::ptr::null()];
        assert!(matches!(
            capture(c"/tool".as_ptr(), bad.as_ptr(), std::ptr::null()),
            Err(EFAULT)
        ));
        assert!(matches!(
            capture(c"/tool".as_ptr(), std::ptr::null(), bad.as_ptr()),
            Err(EFAULT)
        ));
    }
}
#[test]
fn vector_count_and_shared_text_budget_are_bounded() {
    let pointers = [c"a".as_ptr(); MAX_EXEC_VECTOR_ENTRIES];
    assert!(matches!(
        capture(c"/tool".as_ptr(), pointers.as_ptr(), std::ptr::null()),
        Err(E2BIG)
    ));
    let mut large = vec![b'a'; 4097];
    large[4096] = 0;
    let pointers = [large.as_ptr().cast(), std::ptr::null()];
    assert!(matches!(
        capture(c"/tool".as_ptr(), pointers.as_ptr(), std::ptr::null()),
        Err(E2BIG)
    ));
    assert!(matches!(
        capture(c"/tool".as_ptr(), std::ptr::null(), pointers.as_ptr()),
        Err(E2BIG)
    ));
    let mut argument = vec![b'a'; 3001];
    argument[3000] = 0;
    let mut variable = vec![b'b'; 1201];
    variable[1200] = 0;
    let argv = [argument.as_ptr().cast(), std::ptr::null()];
    let envp = [variable.as_ptr().cast(), std::ptr::null()];
    assert!(matches!(
        capture(c"/tool".as_ptr(), argv.as_ptr(), envp.as_ptr()),
        Err(E2BIG)
    ));
}
#[test]
fn path_validation_and_null_vectors_preserve_existing_contract() {
    assert!(matches!(
        capture(c"".as_ptr(), std::ptr::null(), std::ptr::null()),
        Err(ENOENT)
    ));
    assert!(matches!(
        capture(
            b"\xff\0".as_ptr().cast(),
            std::ptr::null(),
            std::ptr::null()
        ),
        Err(EINVAL)
    ));
    let mut path = vec![b'a'; 257];
    path[256] = 0;
    assert!(matches!(
        capture(path.as_ptr().cast(), std::ptr::null(), std::ptr::null()),
        Err(ENAMETOOLONG)
    ));
    path[255] = 0;
    assert!(capture(path.as_ptr().cast(), std::ptr::null(), std::ptr::null()).is_ok());
    let mut empty = [];
    assert_eq!(
        user_copy::capture_text(c"".as_ptr(), &mut empty, E2BIG),
        Ok(0)
    );
    assert_eq!(
        user_copy::capture_text(c"x".as_ptr(), &mut empty, E2BIG),
        Err(E2BIG)
    );
}
#[test]
fn capture_precedes_every_policy_callback_and_fixture_limits_match_runtime() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(source.contains("const MAX_EXEC_VECTOR_ENTRIES: usize = 256;"));
    assert!(
        include_str!("../../../user/crates/capability-protocol/src/lib.rs")
            .contains("pub const MAX_EXECUTABLE_PATH_LEN: usize = 256;")
    );
    let start = source.find("fn replace_process_image(").unwrap();
    let end = start
        + source[start..]
            .find("fn execve_with_launch_context(")
            .unwrap();
    let body = &source[start..end];
    assert!(body.find("inputs.capture(").unwrap() < body.find("absolute_exec_identity(").unwrap());
    assert!(!body.contains("c_bytes("));
    assert!(!source.contains("read_exec_vector"));
}
