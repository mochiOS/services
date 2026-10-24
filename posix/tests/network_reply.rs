extern crate self as mochi_user_platform;
use mochi_user_syscall::{NativeError, SysError};
use std::cell::RefCell;
#[derive(Default)]
struct State {
    error: Option<SysError>,
    replies: usize,
    sent: usize,
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}
pub mod ipc {
    pub fn reply(sender: u64, bytes: &[u8]) -> Result<(), mochi_user_syscall::SysError> {
        assert_eq!(sender, 77);
        assert_eq!(bytes, b"completion");
        crate::STATE.with_borrow_mut(|s| {
            s.replies += 1;
            s.error.map_or(Ok(()), Err)
        })
    }
    pub fn send(sender: u64, bytes: &[u8]) -> Result<(), mochi_user_syscall::SysError> {
        assert_eq!(sender, 77);
        assert_eq!(bytes, b"completion");
        crate::STATE.with_borrow_mut(|s| s.sent += 1);
        Ok(())
    }
}
#[path = "../../network/src/reply.rs"]
mod reply;
#[test]
fn only_native_missing_call_reply_authority_uses_the_sender_completion_queue() {
    for (error, sent) in [
        (None, 0),
        (
            Some(SysError::from_raw(
                NativeError::AccessDenied.into_raw() as i64
            )),
            1,
        ),
        (
            Some(SysError::from_raw(NativeError::PeerClosed.into_raw() as i64)),
            0,
        ),
        (
            Some(SysError::from_raw(NativeError::NotReady.into_raw() as i64)),
            0,
        ),
        (Some(SysError::from_raw(-13)), 0),
    ] {
        STATE.with_borrow_mut(|s| {
            *s = State {
                error,
                ..Default::default()
            }
        });
        reply::send(77, b"completion");
        STATE.with_borrow(|s| {
            assert_eq!(s.replies, 1);
            assert_eq!(s.sent, sent);
        });
    }
}
