use mochios_posix_client::newlib_errno::{EFAULT, EINVAL, EIO, ENOSYS, EOVERFLOW};
use mochios_posix_protocol as posix_protocol;
use posix_protocol::interval_timer::Value;
use std::cell::Cell;
use std::ffi::c_int;

#[repr(C)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}

thread_local! {
    static ERRNO: Cell<i32> = const { Cell::new(123) };
    static CALLS: Cell<usize> = const { Cell::new(0) };
    static STATE: Cell<Value> = Cell::new(Value::default());
    static FAILURE: Cell<i32> = const { Cell::new(0) };
}
fn set_errno(value: i32) {
    ERRNO.set(value);
}
fn map_posix_client_error(error: i32) -> i32 {
    error
}
fn result_with_errno(value: Result<i32, i32>, failure: i32) -> i32 {
    match value {
        Ok(value) => value,
        Err(error) => {
            set_errno(error);
            failure
        }
    }
}
struct Client;
fn posix_client() -> Result<Client, i32> {
    Ok(Client)
}
impl Client {
    fn real_timer(&self) -> Result<Value, i32> {
        CALLS.set(CALLS.get() + 1);
        if FAILURE.get() != 0 {
            return Err(FAILURE.get());
        }
        Ok(STATE.get())
    }
    fn set_real_timer(&self, value: Value) -> Result<Value, i32> {
        let old = self.real_timer()?;
        STATE.set(value);
        Ok(old)
    }
}
mod user_copy {
    use super::*;
    // Controlled copy transport only. The production wrappers never directly
    // dereference a C pointer, and null/unmapped sentinels fail here like I/O.
    pub fn read(source: *const u8, bytes: &mut [u8]) -> Result<(), i32> {
        if source.addr() < 4096 {
            return Err(EFAULT);
        }
        unsafe {
            std::ptr::copy_nonoverlapping(source, bytes.as_mut_ptr(), bytes.len());
        }
        Ok(())
    }
    pub fn write(destination: *mut u8, bytes: &[u8]) -> Result<(), i32> {
        if destination.addr() < 4096 {
            return Err(EFAULT);
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len());
        }
        Ok(())
    }
}
#[path = "../../../user/crates/newlib-runtime/src/interval_timer.rs"]
mod production;

fn encoded(fields: [i64; 4]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (bytes, value) in bytes.chunks_exact_mut(8).zip(fields) {
        bytes.copy_from_slice(&value.to_ne_bytes());
    }
    bytes
}
fn reset() {
    ERRNO.set(123);
    CALLS.set(0);
    STATE.set(Value::default());
    FAILURE.set(0);
}

#[test]
fn c_timer_wrappers_convert_canonical_values_and_preserve_errno_and_aliasing() {
    reset();
    let mut bytes = encoded([2, 3, 4, 5]);
    assert_eq!(
        production::setitimer(0, bytes.as_ptr().cast(), bytes.as_mut_ptr().cast()),
        0
    );
    assert_eq!(bytes, [0; 32]);
    assert_eq!(
        STATE.get(),
        Value {
            interval_ns: 2_000_003_000,
            remaining_ns: 4_000_005_000
        }
    );
    assert_eq!(ERRNO.get(), 123);
    assert_eq!(production::getitimer(0, bytes.as_mut_ptr().cast()), 0);
    assert_eq!(bytes, encoded([2, 3, 4, 5]));
    // Round positive fractions upward and carry across the seconds boundary.
    STATE.set(Value {
        interval_ns: 1,
        remaining_ns: 999_999_999,
    });
    assert_eq!(production::getitimer(0, bytes.as_mut_ptr().cast()), 0);
    assert_eq!(bytes, encoded([0, 1, 1, 0]));
    let disabled = encoded([0, 12, 0, 0]);
    assert_eq!(
        production::setitimer(0, disabled.as_ptr().cast(), std::ptr::null_mut()),
        0
    );
    assert_eq!(
        STATE.get(),
        Value {
            interval_ns: 12_000,
            remaining_ns: 0
        }
    );
}

#[test]
fn c_timer_invalid_values_and_kinds_do_not_reach_transport() {
    reset();
    for (fields, error) in [
        ([-1, 0, 0, 1], EINVAL),
        ([0, -1, 0, 1], EINVAL),
        ([0, 1_000_000, 0, 1], EINVAL),
        ([0, 0, -1, 0], EINVAL),
        ([0, 0, 0, -1], EINVAL),
        ([0, 0, 0, 1_000_000], EINVAL),
        ([i64::MAX, 0, 0, 1], EINVAL),
        ([0, 0, i64::MAX, 0], EINVAL),
    ] {
        let bytes = encoded(fields);
        assert_eq!(
            production::setitimer(0, bytes.as_ptr().cast(), std::ptr::null_mut()),
            -1
        );
        assert_eq!(ERRNO.get(), error);
    }
    for (kind, error) in [(-1, EINVAL), (3, EINVAL), (1, ENOSYS), (2, ENOSYS)] {
        assert_eq!(production::getitimer(kind, std::ptr::null_mut()), -1);
        assert_eq!(ERRNO.get(), error);
        assert_eq!(
            production::setitimer(kind, std::ptr::null(), std::ptr::null_mut()),
            -1
        );
        assert_eq!(ERRNO.get(), error);
    }
    assert_eq!(CALLS.get(), 0);
    assert_eq!(STATE.get(), Value::default());
}

#[test]
fn c_timer_copy_and_remote_errors_are_reported_without_false_success() {
    reset();
    assert_eq!(production::getitimer(0, std::ptr::null_mut()), -1);
    assert_eq!(ERRNO.get(), EFAULT);
    assert_eq!(
        production::setitimer(0, std::ptr::null(), std::ptr::null_mut()),
        -1
    );
    assert_eq!(ERRNO.get(), EFAULT);
    assert_eq!(CALLS.get(), 0);
    let input = encoded([0, 0, 1, 0]);
    let mut output = [0xab; 32];
    FAILURE.set(EIO);
    assert_eq!(production::getitimer(0, output.as_mut_ptr().cast()), -1);
    assert_eq!(ERRNO.get(), EIO);
    assert_eq!(
        production::setitimer(0, input.as_ptr().cast(), output.as_mut_ptr().cast()),
        -1
    );
    assert_eq!(ERRNO.get(), EIO);
    assert_eq!(output, [0xab; 32]);
    assert_eq!(STATE.get(), Value::default());
    FAILURE.set(EOVERFLOW);
    assert_eq!(
        production::setitimer(0, input.as_ptr().cast(), output.as_mut_ptr().cast()),
        -1
    );
    assert_eq!(ERRNO.get(), EINVAL);
    assert_eq!(STATE.get(), Value::default());
    FAILURE.set(0);
    assert_eq!(
        production::getitimer(0, std::ptr::without_provenance_mut(1)),
        -1
    );
    assert_eq!(ERRNO.get(), EFAULT);
    assert_eq!(
        production::setitimer(
            0,
            input.as_ptr().cast(),
            std::ptr::without_provenance_mut(1)
        ),
        -1
    );
    assert_eq!(ERRNO.get(), EFAULT);
    // The set was committed before old-value copyout failed; never claim that
    // EFAULT rolled back a successful remote timer replacement.
    assert_eq!(STATE.get().remaining_ns, 1_000_000_000);
}
