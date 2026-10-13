use mochios_posix_client::pthread_once::{self as state, Claim};
use std::sync::atomic::{AtomicU32, Ordering};

#[test]
fn initializer_claim_is_unique_and_completion_publishes_its_writes() {
    let once = AtomicU32::new(0);
    let calls = AtomicU32::new(0);
    let published = AtomicU32::new(0);
    std::thread::scope(|scope| {
        for _ in 0..32 {
            scope.spawn(|| {
                loop {
                    match state::claim(&once).unwrap() {
                        Claim::Initialize => {
                            calls.fetch_add(1, Ordering::Relaxed);
                            published.store(42, Ordering::Relaxed);
                            state::complete(&once);
                            break;
                        }
                        Claim::Complete => {
                            assert_eq!(published.load(Ordering::Relaxed), 42);
                            break;
                        }
                        Claim::Wait => std::thread::yield_now(),
                    }
                }
            });
        }
    });
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(state::claim(&once), Ok(Claim::Complete));
}

#[test]
fn aborted_initializer_can_be_retried_and_cleanup_never_erases_completion() {
    let once = AtomicU32::new(0);
    assert_eq!(state::claim(&once), Ok(Claim::Initialize));
    assert_eq!(state::claim(&once), Ok(Claim::Wait));
    state::abort(&once);
    assert_eq!(state::claim(&once), Ok(Claim::Initialize));
    state::complete(&once);
    state::abort(&once);
    assert_eq!(state::claim(&once), Ok(Claim::Complete));
    assert_eq!(state::claim(&AtomicU32::new(3)), Err(22));
}

#[test]
fn runtime_uses_newlib_layout_cleanup_and_non_cancellation_wait() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/pthread_once.rs");
    assert!(runtime.contains("initialized: c_int,"));
    assert!(runtime.contains("executed: AtomicU32,"));
    assert!(runtime.contains("thread_cleanup::push("));
    assert!(runtime.contains("thread_cleanup::pop("));
    assert!(runtime.contains("state::abort(&once.executed)"));
    assert!(runtime.contains("__mochios_wake_address_u32"));
    assert!(!runtime.contains("pthread_testcancel()"));
    assert!(!runtime.contains("posix_client()"));
    assert!(
        include_str!("../../../libraries/newlib/newlib/libc/include/sys/_pthreadtypes.h")
            .contains("#define _PTHREAD_ONCE_INIT  { 1, 0 }")
    );
}

#[test]
fn snapshot_child_preserves_the_calling_threads_live_cleanup_stack() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = runtime.find("if image == 0 {").unwrap();
    let end = start
        + runtime[start..]
            .find("return Ok((0, inherited_fds, None));")
            .unwrap();
    let child = &runtime[start..end];
    assert!(child.contains("!ptr::eq(other, thread_control)"));
    assert!(!child.contains("thread_control.cleanup_head.store"));
    assert!(!child.contains("release_thread_control(thread_control)"));
    // This is a guard against losing the active stack contexts, not proof
    // that multithreaded address-space snapshots are supported.
}
