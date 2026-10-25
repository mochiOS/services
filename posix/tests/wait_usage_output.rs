#![allow(dead_code)]
use mochios_posix_client::newlib_errno::*;
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int, c_void};
#[path = "../../../user/crates/newlib-runtime/src/wait_usage_output.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/resource_usage_output.rs"]
mod resource_usage_output;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
#[path = "../../../user/crates/newlib-runtime/src/wait_output.rs"]
mod wait_output;
use user_copy_native::{syscall, syscall_errno};
const PAGE_SIZE: usize = 4096;

fn sample() -> posix_protocol::wait_usage::Observation {
    posix_protocol::wait_usage::Observation {
        info: posix_protocol::WaitInfo {
            result: posix_protocol::WaitResult {
                process_id: 42,
                status: 37 << 8,
            },
            real_uid: 505,
        },
        usage: posix_protocol::wait_usage::Usage {
            cpu: posix_protocol::WaitedChildCpuUsage {
                user_ticks: 717,
                kernel_ticks: 23,
                ticks_per_second: 500,
            },
            peak_resident_bytes: 12 * 1024 + 1,
        },
    }
}

#[test]
fn cpu_time_and_status_use_faultable_unaligned_c_storage_without_overwriting_neighbors() {
    let mut usage = [0xa5; 42];
    let mut status = [0x5a; 6];
    assert_eq!(
        implementation::publish(
            sample(),
            status.as_mut_ptr().wrapping_add(1).cast(),
            usage.as_mut_ptr().wrapping_add(1).cast()
        ),
        Ok(42)
    );
    assert_eq!(&status[1..5], &(37u32 << 8).to_ne_bytes());
    for (bytes, expected) in usage[1..41]
        .chunks_exact(8)
        .zip([1i64, 434000, 0, 46000, 13])
    {
        assert_eq!(bytes, expected.to_ne_bytes());
    }
    assert_eq!(
        (usage[0], usage[41], status[0], status[5]),
        (0xa5, 0xa5, 0x5a, 0x5a)
    );
}

#[test]
fn nohang_and_unrepresentable_outputs_do_not_touch_any_c_storage() {
    user_copy_native::CALLS.with_borrow_mut(Vec::clear);
    assert_eq!(
        implementation::publish(Default::default(), 1usize as *mut _, 1usize as *mut _),
        Ok(0)
    );
    let mut value = sample();
    value.info.result.process_id = i32::MAX as u64 + 1;
    assert_eq!(
        implementation::publish(value, 1usize as *mut _, 1usize as *mut _),
        Err(EOVERFLOW)
    );
    value = sample();
    value.usage.cpu.user_ticks = u128::MAX;
    assert_eq!(
        implementation::publish(value, 1usize as *mut _, 1usize as *mut _),
        Err(EOVERFLOW)
    );
    value = sample();
    value.usage.cpu.ticks_per_second = 0;
    assert_eq!(
        implementation::publish(value, 1usize as *mut _, 1usize as *mut _),
        Err(EIO)
    );
    user_copy_native::CALLS.with_borrow(|calls| assert!(calls.is_empty()));
}

#[test]
fn invalid_usage_or_status_is_efault_and_status_is_optional() {
    let mut usage = [0xa5; 40];
    assert_eq!(
        implementation::publish(sample(), 1usize as *mut _, usage.as_mut_ptr().cast()),
        Err(EFAULT)
    );
    assert_eq!(usage, [0xa5; 40]);
    assert_eq!(
        implementation::publish(sample(), std::ptr::null_mut(), 1usize as *mut _),
        Err(EFAULT)
    );
    assert_eq!(
        implementation::publish(sample(), std::ptr::null_mut(), usage.as_mut_ptr().cast()),
        Ok(42)
    );
}
