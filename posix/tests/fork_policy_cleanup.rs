//! Run the actual runtime owner against controlled service/transport failures.
#![allow(non_camel_case_types)]
use core::ffi::c_int;
use mochios_posix_client::ClientError as PosixClientError;
use mochios_posix_client::ObjectHandleAttachment;
use mochios_posix_client::newlib_errno::{EAGAIN, EINTR};
use mochios_posix_protocol as posix_protocol;
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::sync::Mutex;

struct SyscallEndpointTransport;
struct PosixClient<T>(PhantomData<T>);
static CLIENT: PosixClient<SyscallEndpointTransport> = PosixClient(PhantomData);
static CANCEL: Mutex<VecDeque<Result<(), PosixClientError<c_int>>>> = Mutex::new(VecDeque::new());
static COMMIT: Mutex<Result<(), PosixClientError<c_int>>> = Mutex::new(Ok(()));
static EVENTS: Mutex<Vec<&str>> = Mutex::new(Vec::new());

impl PosixClient<SyscallEndpointTransport> {
    fn prepare_fork(&self) -> Result<u64, PosixClientError<c_int>> {
        Ok(77)
    }
    fn commit_fork(
        &self,
        token: u64,
        child: ObjectHandleAttachment<u32>,
    ) -> Result<(), PosixClientError<c_int>> {
        assert_eq!((token, child.handle), (77, 42));
        EVENTS.lock().unwrap().push("commit");
        *COMMIT.lock().unwrap()
    }
    fn cancel_fork(&self, token: u64) -> Result<(), PosixClientError<c_int>> {
        assert_eq!(token, 77);
        EVENTS.lock().unwrap().push("cancel");
        CANCEL
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected replay")
    }
}
fn map_posix_client_error(error: PosixClientError<c_int>) -> c_int {
    match error {
        PosixClientError::Transport(error) => error,
        PosixClientError::Remote(error) => -error,
        _ => panic!("unexpected fixture error"),
    }
}
fn defer_native_delivery() -> Option<()> {
    Some(())
}
fn syscall_errno(value: Result<u64, c_int>) -> Result<u64, c_int> {
    value
}
mod syscall {
    pub enum SyscallNumber {
        DebugWrite,
        Sleep,
        ThreadYield,
    }
    pub fn raw_syscall0(_: SyscallNumber) -> Result<u64, super::c_int> {
        Ok(0)
    }
    pub fn raw_syscall1(_: SyscallNumber, _: u64) -> Result<u64, super::c_int> {
        Ok(0)
    }
    pub fn raw_syscall2(_: SyscallNumber, _: u64, _: u64) -> Result<u64, super::c_int> {
        Ok(0)
    }
}
#[path = "../../../user/crates/newlib-runtime/src/fork_policy.rs"]
mod fork_policy;

#[test]
fn only_confirmed_commit_cancel_or_remote_absence_releases_parent_ownership() {
    use fork_policy::Preparation;
    let child = ObjectHandleAttachment {
        handle: 42,
        rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
    };
    {
        let mut policy = Preparation::new(&CLIENT).unwrap();
        policy.commit(child).unwrap();
    }
    assert_eq!(*EVENTS.lock().unwrap(), ["commit"]);
    EVENTS.lock().unwrap().clear();
    {
        let mut child_copy = Preparation::new(&CLIENT).unwrap();
        child_copy.disarm_child();
    }
    assert!(EVENTS.lock().unwrap().is_empty());
    *COMMIT.lock().unwrap() = Err(PosixClientError::Transport(EINTR));
    *CANCEL.lock().unwrap() = [
        Err(PosixClientError::Transport(3)), // Transport ESRCH is not remote proof.
        Err(PosixClientError::Remote(-EAGAIN)),
        Ok(()),
    ]
    .into();
    {
        let mut policy = Preparation::new(&CLIENT).unwrap();
        assert_eq!(policy.commit(child), Err(EINTR));
    }
    assert_eq!(
        *EVENTS.lock().unwrap(),
        ["commit", "cancel", "cancel", "cancel"]
    );
    assert!(CANCEL.lock().unwrap().is_empty());
    EVENTS.lock().unwrap().clear();
    *CANCEL.lock().unwrap() = [Err(PosixClientError::Remote(posix_protocol::STATUS_ESRCH))].into();
    drop(Preparation::new(&CLIENT).unwrap());
    assert_eq!(*EVENTS.lock().unwrap(), ["cancel"]);
    // Ordinary early returns own the same cleanup, before any child exists.
    *CANCEL.lock().unwrap() = [Ok(())].into();
    let failed = (|| -> Result<(), c_int> {
        let _policy = Preparation::new(&CLIENT).unwrap();
        Err(22)
    })();
    assert_eq!(failed, Err(22));
    assert!(CANCEL.lock().unwrap().is_empty());
}
