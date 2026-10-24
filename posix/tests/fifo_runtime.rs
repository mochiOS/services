//! Exercise production FIFO loops; only native calls, FD pins and worker RPC
//! are controlled. Real pin-book/fork-scope tests cover resource machinery.
#![allow(dead_code, non_camel_case_types)]
use mochios_posix_client::ObjectHandleAttachment;
use mochios_posix_protocol as posix_protocol;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    ffi::{c_int, c_void},
    sync::atomic::{AtomicU64, Ordering},
};
const EIO: i32 = 5;
const EAGAIN: i32 = 11;
const EINTR: i32 = 4;
const EBADF: i32 = 9;
const EFAULT: i32 = 14;
const EPIPE: i32 = 32;
const O_NONBLOCK: i32 = 0x4000;
struct ThreadControl {
    nonrestart_signal_generation: AtomicU64,
    multiplex_generation: AtomicU64,
}
thread_local! {
 static CONTROL:ThreadControl=const{ThreadControl{nonrestart_signal_generation:AtomicU64::new(0),multiplex_generation:AtomicU64::new(0)}};
 static STATE:RefCell<State>=RefCell::new(State::default());
 static SCOPED:Cell<bool>=const{Cell::new(false)};
}
#[derive(Default)]
struct State {
    results: VecDeque<i64>,
    nonblock: bool,
    cancel: bool,
    interrupt: bool,
    stale: bool,
    owner_dead: bool,
    closed: usize,
    signals: usize,
    waits: Vec<posix_protocol::fifo::WaitCondition>,
}
#[derive(Clone, Copy)]
struct Object {
    lower_handle: u64,
}
#[derive(Clone, Copy)]
struct FdEntry {
    handle: Object,
    rights: u64,
}
enum FdKind {
    ObjectFifo,
}
fn object_entry(handle: u64, rights: u64, _: FdKind, flags: i32) -> FdEntry {
    assert_eq!(rights, posix_protocol::fifo::NOTIFICATION_RIGHTS);
    assert_eq!(flags, O_NONBLOCK);
    FdEntry {
        handle: Object {
            lower_handle: handle,
        },
        rights,
    }
}
fn register_current_thread() -> Option<(u32, &'static ThreadControl)> {
    Some((1, unsafe { &*CONTROL.with(|c| c as *const ThreadControl) }))
}
fn io_cancellation_requested(_: &ThreadControl) -> bool {
    STATE.with(|s| s.borrow().cancel)
}
fn handle_is_nonblocking(_: FdEntry) -> Result<bool, i32> {
    Ok(STATE.with(|s| s.borrow().nonblock))
}
fn map_posix_client_error(error: i32) -> i32 {
    error
}
fn generate_thread_signal(signal: u32) -> Result<(), i32> {
    assert_eq!(signal, posix_protocol::SIGNAL_PIPE);
    STATE.with(|s| s.borrow_mut().signals += 1);
    Ok(())
}
#[derive(Clone, Copy)]
struct Native(i64);
impl Native {
    fn raw(self) -> u64 {
        self.0 as u64
    }
}
fn syscall_errno(result: Native) -> Result<u64, i32> {
    if result.0 < 0 {
        Err((-result.0) as i32)
    } else {
        Ok(result.0 as u64)
    }
}
mod syscall {
    pub use mnu_abi::{
        HANDLE_SIGNAL_PEER_CLOSED, HANDLE_SIGNAL_READABLE, HANDLE_WAIT_INFINITE, HandleWaitItem,
    };
    #[derive(Debug)]
    pub enum SyscallNumber {
        HandleRead,
        HandleWrite,
        HandleWaitManyGuarded,
    }
    pub fn raw_syscall3(_: SyscallNumber, handle: u64, _: u64, length: u64) -> super::Native {
        assert_eq!(handle, 7);
        assert!(length > 0);
        super::Native(super::STATE.with(|s| {
            s.borrow_mut()
                .results
                .pop_front()
                .expect("unexpected data call")
        }))
    }
    pub fn raw_syscall4(
        _: SyscallNumber,
        address: u64,
        count: u64,
        timeout: u64,
        _: u64,
    ) -> super::Native {
        assert_eq!(count, 1);
        assert_eq!(timeout, HANDLE_WAIT_INFINITE);
        assert!(!super::SCOPED.get(), "wait must admit fork");
        let item = unsafe { &mut *(address as *mut HandleWaitItem) };
        assert_eq!(item.handle, 77);
        super::STATE.with(|s| {
            let state = s.borrow();
            item.observed = if state.owner_dead {
                HANDLE_SIGNAL_PEER_CLOSED
            } else {
                HANDLE_SIGNAL_READABLE
            };
            if state.interrupt {
                super::CONTROL.with(|c| {
                    c.nonrestart_signal_generation
                        .fetch_add(1, super::Ordering::AcqRel);
                });
            }
        });
        super::Native(0)
    }
}
mod fd_lease {
    use super::*;
    pub(super) struct Lease(FdEntry);
    impl Lease {
        pub fn adopt_private(entry: FdEntry) -> Result<Self, i32> {
            assert!(SCOPED.get());
            Ok(Self(entry))
        }
        pub fn is_current(&self) -> bool {
            !STATE.with(|s| s.borrow().stale)
        }
    }
    impl std::ops::Deref for Lease {
        type Target = FdEntry;
        fn deref(&self) -> &FdEntry {
            &self.0
        }
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            assert!(SCOPED.get());
            STATE.with(|s| s.borrow_mut().closed += 1);
        }
    }
}
mod io_resources {
    use super::*;
    pub unsafe fn with_fork_opaque<R, T: Copy>(
        prepare: impl FnOnce() -> Result<R, i32>,
        allow: impl FnOnce(&R) -> bool,
        operation: impl FnOnce(&mut R) -> Result<T, i32>,
    ) -> Result<T, i32> {
        assert!(!SCOPED.replace(true));
        let prepared = prepare();
        SCOPED.set(false);
        match prepared {
            Err(e) => Err(e),
            Ok(mut r) => {
                assert!(allow(&r));
                let result = operation(&mut r);
                SCOPED.set(true);
                drop(r);
                SCOPED.set(false);
                result
            }
        }
    }
    pub fn with<R, T>(
        prepare: impl FnOnce() -> Result<R, i32>,
        op: impl FnOnce(&mut R) -> Result<T, i32>,
    ) -> Result<T, i32> {
        let mut r = prepare()?;
        op(&mut r)
    }
}
struct Client;
fn posix_client() -> Result<Client, i32> {
    assert!(SCOPED.get());
    Ok(Client)
}
impl Client {
    fn fifo_wait(
        &self,
        source: ObjectHandleAttachment<u32>,
        condition: posix_protocol::fifo::WaitCondition,
    ) -> Result<ObjectHandleAttachment<u32>, i32> {
        assert_eq!(source.handle, 7);
        STATE.with(|s| s.borrow_mut().waits.push(condition));
        Ok(ObjectHandleAttachment {
            handle: 77,
            rights: posix_protocol::fifo::NOTIFICATION_RIGHTS,
        })
    }
}
#[path = "../../../user/crates/newlib-runtime/src/fifo.rs"]
mod fifo;
fn reset(results: &[i64], nonblock: bool) -> FdEntry {
    STATE.with(|s| {
        *s.borrow_mut() = State {
            results: results.iter().copied().collect(),
            nonblock,
            ..Default::default()
        }
    });
    CONTROL.with(|c| {
        c.nonrestart_signal_generation.store(0, Ordering::Release);
        c.multiplex_generation.store(0, Ordering::Release);
    });
    FdEntry {
        handle: Object { lower_handle: 7 },
        rights: posix_protocol::fifo::data_rights(posix_protocol::OPEN_READ).unwrap(),
    }
}
#[test]
fn reads_wait_once_then_retry_and_retire_private_notification() {
    let entry = reset(&[-11, 3], false);
    assert_eq!(fifo::read(entry, 1usize as *mut _, 3), Ok(3));
    STATE.with(|s| {
        let s = s.borrow();
        assert_eq!(s.waits, vec![posix_protocol::fifo::WaitCondition::Read]);
        assert_eq!(s.closed, 1);
    });
    let entry = reset(&[-11], true);
    assert_eq!(fifo::read(entry, 1usize as *mut _, 3), Err(EAGAIN));
    STATE.with(|s| assert!(s.borrow().waits.is_empty()));
}
#[test]
fn blocking_large_writes_preserve_prefix_and_nonblocking_short_writes_return() {
    let entry = reset(&[512, -11, 512], false);
    assert_eq!(fifo::write(entry, 1usize as *const _, 1024), Ok(1024));
    STATE.with(|s| {
        let s = s.borrow();
        assert_eq!(
            s.waits,
            vec![posix_protocol::fifo::WaitCondition::Write(512)]
        );
        assert_eq!(s.closed, 1);
    });
    for (nonblock, tail) in [(true, 0), (false, -5)] {
        let entry = reset(&[512, tail], nonblock);
        assert_eq!(fifo::write(entry, 1usize as *const _, 1024), Ok(512));
    }
}
#[test]
fn broken_pipe_sends_signal_but_provider_death_does_not() {
    let entry = reset(&[-32], false);
    assert_eq!(fifo::write(entry, 1usize as *const _, 1), Err(EPIPE));
    STATE.with(|s| assert_eq!(s.borrow().signals, 1));
    let entry = reset(
        &[mnu_abi::status::Error::PeerClosed.into_raw() as i64],
        false,
    );
    assert_eq!(fifo::write(entry, 1usize as *const _, 1), Err(EIO));
    STATE.with(|s| assert_eq!(s.borrow().signals, 0));
    let entry = reset(&[512, -32], false);
    assert_eq!(fifo::write(entry, 1usize as *const _, 1024), Ok(512));
    STATE.with(|s| assert_eq!(s.borrow().signals, 1));
}
#[test]
fn interrupted_wait_and_stale_fork_epoch_release_notifications() {
    for (interrupt, stale, owner_dead, error) in [
        (true, false, false, EINTR),
        (false, true, false, EINTR),
        (false, false, true, EIO),
    ] {
        let entry = reset(&[-11], false);
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            s.interrupt = interrupt;
            s.stale = stale;
            s.owner_dead = owner_dead;
        });
        assert_eq!(fifo::read(entry, 1usize as *mut _, 1), Err(error));
        STATE.with(|s| assert_eq!(s.borrow().closed, 1));
    }
}
#[test]
fn atomic_short_reply_and_oversized_reply_are_rejected() {
    let entry = reset(&[1], false);
    assert_eq!(fifo::write(entry, 1usize as *const _, 2), Err(EIO));
    let entry = reset(&[3], false);
    assert_eq!(fifo::read(entry, 1usize as *mut _, 2), Err(EIO));
}
