//! Run the real private startup-stream reader with controlled native wakeups.
#![allow(non_camel_case_types)]
use std::{cell::RefCell, collections::VecDeque};
type c_int = i32;
const EIO: i32 = 5;
#[path = "../../../user/crates/newlib-runtime/src/child_startup.rs"]
mod acknowledgement;
#[path = "../../../user/crates/newlib-runtime/src/startup_stream.rs"]
mod production;

enum Reply {
    Data(Vec<u8>),
    Error(u64),
    Count(u64),
}
#[derive(Default)]
struct Model {
    replies: VecDeque<Reply>,
    notifications: usize,
    pending: bool,
    failure: Option<i32>,
    sizes: Vec<u64>,
}
thread_local! { static MODEL: RefCell<Model> = RefCell::new(Model::default()); }
mod syscall {
    pub use mochi_user_syscall::{NativeError, RawSyscallResult, SyscallNumber};
    pub fn raw_syscall3(
        number: SyscallNumber,
        handle: u64,
        output: u64,
        length: u64,
    ) -> RawSyscallResult {
        assert_eq!(number, SyscallNumber::HandleRead);
        assert_eq!(handle, 33);
        super::MODEL.with_borrow_mut(|model| {
            assert!(
                !model.pending,
                "must dispatch a native wakeup before reading again"
            );
            model.sizes.push(length);
            let raw = match model.replies.pop_front().expect("unexpected extra read") {
                super::Reply::Error(raw) => {
                    model.pending = NativeError::from_raw(raw) == Some(NativeError::NotReady);
                    raw
                }
                super::Reply::Data(bytes) => {
                    assert!(bytes.len() <= length as usize);
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            output as *mut u8,
                            bytes.len(),
                        );
                    }
                    bytes.len() as u64
                }
                super::Reply::Count(count) => count,
            };
            RawSyscallResult::new(raw)
        })
    }
}
fn map_kernel_errno(raw: i64) -> i32 {
    mochios_posix_client::newlib_errno::from_status(raw)
}
fn drain_pending_signals() -> Result<(), i32> {
    MODEL.with_borrow_mut(|model| {
        assert!(model.pending);
        model.pending = false;
        model.notifications += 1;
        model.failure.map_or(Ok(()), Err)
    })
}
fn set(replies: Vec<Reply>, failure: Option<i32>) {
    MODEL.set(Model {
        replies: replies.into(),
        failure,
        ..Default::default()
    });
}
fn wake() -> Reply {
    Reply::Error(syscall::NativeError::NotReady.into_raw())
}

#[test]
fn native_notifications_do_not_consume_or_restart_a_partial_acknowledgement() {
    set(
        vec![
            wake(),
            Reply::Data(vec![0, 0]),
            wake(),
            Reply::Data(vec![0, 0]),
        ],
        None,
    );
    assert_eq!(
        acknowledgement::receive(|bytes| production::read(33, bytes)),
        Ok(())
    );
    MODEL.with_borrow(|model| {
        assert_eq!(model.notifications, 2);
        assert_eq!(model.sizes, [4, 4, 2, 2]);
        assert!(model.replies.is_empty());
    });
}

#[test]
fn exec_success_error_packets_and_truncation_keep_their_meaning_across_notifications() {
    use mochios_posix_client::{newlib_errno::EACCES, spawn::ExecStatus};
    set(vec![wake(), Reply::Count(0)], None);
    assert_eq!(production::exec_status(33), Ok(ExecStatus::Succeeded));
    let error = EACCES.to_ne_bytes();
    set(
        vec![
            Reply::Data(error[..2].to_vec()),
            wake(),
            Reply::Data(error[2..].to_vec()),
        ],
        None,
    );
    assert_eq!(production::exec_status(33), Ok(ExecStatus::Failed(EACCES)));
    set(vec![Reply::Data(vec![0]), wake(), Reply::Count(0)], None);
    assert_eq!(production::exec_status(33), Err(EIO));
    set(vec![wake(), Reply::Count(0)], None);
    assert_eq!(
        acknowledgement::receive(|bytes| production::read(33, bytes)),
        Err(EIO)
    );
}

#[test]
fn only_native_notification_wakeups_are_resumed_not_resource_or_legacy_failures() {
    use syscall::NativeError;
    for raw in [
        NativeError::ResourceUnavailable.into_raw(),
        NativeError::AccessDenied.into_raw(),
        NativeError::InvalidArgument.into_raw(),
        NativeError::PeerClosed.into_raw(),
        (-11i64) as u64,
    ] {
        set(vec![Reply::Error(raw)], None);
        assert_eq!(
            production::read(33, &mut [0; 4]),
            Err(map_kernel_errno(raw as i64))
        );
        MODEL.with_borrow(|model| {
            assert_eq!(model.notifications, 0);
            assert_eq!(model.sizes.len(), 1);
        });
    }
    set(vec![wake()], Some(13));
    assert_eq!(production::read(33, &mut [0; 4]), Err(13));
    MODEL.with_borrow(|model| {
        assert_eq!(model.notifications, 1);
        assert_eq!(model.sizes.len(), 1);
    });
}

#[test]
fn an_impossible_native_length_is_an_io_error() {
    set(vec![Reply::Count(5)], None);
    assert_eq!(production::read(33, &mut [0; 4]), Err(EIO));
}
