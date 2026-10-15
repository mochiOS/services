#[path = "../../../user/crates/newlib-runtime/src/child_cleanup.rs"]
mod production;

use mochios_posix_client::newlib_errno::{EAGAIN, EINTR, EIO, ESRCH};
use production::{Backend, Cleanup};

#[derive(Default)]
struct Mock {
    exited: bool,
    delayed_exit: bool,
    status_error: Option<i32>,
    terminate_error: Option<i32>,
    reclaim_error: Option<i32>,
    close_error: Option<i32>,
    events: Vec<&'static str>,
}

impl Backend for Mock {
    fn is_exited(&mut self, handle: u64) -> Result<bool, i32> {
        assert_eq!(handle, 19);
        self.events.push("status");
        self.status_error.map_or(Ok(self.exited), Err)
    }
    fn terminate(&mut self, handle: u64) -> Result<(), i32> {
        assert_eq!(handle, 19);
        self.events.push("terminate");
        if let Some(error) = self.terminate_error {
            return Err(error);
        }
        self.exited = !self.delayed_exit;
        Ok(())
    }
    fn reclaim_registration(&mut self, handle: u64) -> Result<(), i32> {
        assert_eq!(handle, 19);
        assert!(self.exited);
        self.events.push("reclaim");
        self.reclaim_error.map_or(Ok(()), Err)
    }
    fn close(&mut self, handle: u64) -> Result<(), i32> {
        assert_eq!(handle, 19);
        assert!(self.exited);
        self.events.push("close");
        self.close_error.map_or(Ok(()), Err)
    }
}

#[test]
fn running_child_is_confirmed_exited_then_reclaimed_then_closed_once() {
    let mut cleanup = Cleanup::new(19, true);
    let mut backend = Mock::default();
    cleanup.retry(&mut backend).unwrap();
    assert_eq!(
        backend.events,
        ["status", "terminate", "status", "reclaim", "close"]
    );
    cleanup.retry(&mut backend).unwrap();
    assert_eq!(backend.events.len(), 5);
}

#[test]
fn unknown_status_or_failed_termination_cannot_discard_owner() {
    for error in [EIO, EINTR] {
        let mut cleanup = Cleanup::new(19, true);
        let mut backend = Mock {
            status_error: Some(error),
            ..Default::default()
        };
        assert_eq!(cleanup.retry(&mut backend), Err(error));
        assert_eq!(backend.events, ["status"]);
        backend.status_error = None;
        backend.terminate_error = Some(error);
        assert_eq!(cleanup.retry(&mut backend), Err(error));
        assert_eq!(backend.events, ["status", "status", "terminate"]);
        backend.terminate_error = None;
        cleanup.retry(&mut backend).unwrap();
        assert_eq!(backend.events.last(), Some(&"close"));
    }
}

#[test]
fn accepted_termination_without_exit_does_not_reclaim_or_close() {
    let mut cleanup = Cleanup::new(19, true);
    let mut backend = Mock {
        delayed_exit: true,
        ..Default::default()
    };
    assert_eq!(cleanup.retry(&mut backend), Err(EAGAIN));
    assert_eq!(backend.events, ["status", "terminate", "status"]);
    backend.exited = true;
    cleanup.retry(&mut backend).unwrap();
    assert_eq!(&backend.events[3..], ["status", "reclaim", "close"]);
}

#[test]
fn lost_registration_or_reclaim_reply_retains_owner_until_confirmed_absence() {
    let mut cleanup = Cleanup::new(19, true);
    let mut backend = Mock {
        exited: true,
        reclaim_error: Some(EIO),
        ..Default::default()
    };
    assert_eq!(cleanup.retry(&mut backend), Err(EIO));
    assert_eq!(backend.events, ["status", "reclaim"]);
    // Either the registration never arrived or successful reclaim's reply
    // was lost. ESRCH is safe only because exit was already confirmed.
    backend.reclaim_error = Some(ESRCH);
    cleanup.retry(&mut backend).unwrap();
    assert_eq!(backend.events, ["status", "reclaim", "reclaim", "close"]);
}

#[test]
fn close_failure_keeps_confirmed_stages_without_repeating_reclaim() {
    let mut cleanup = Cleanup::new(19, true);
    let mut backend = Mock {
        exited: true,
        close_error: Some(EIO),
        ..Default::default()
    };
    assert_eq!(cleanup.retry(&mut backend), Err(EIO));
    backend.close_error = None;
    cleanup.retry(&mut backend).unwrap();
    assert_eq!(backend.events, ["status", "reclaim", "close", "close"]);
}

#[test]
fn failure_before_registration_needs_native_exit_but_no_posix_rpc() {
    let mut cleanup = Cleanup::new(19, false);
    let mut backend = Mock::default();
    cleanup.retry(&mut backend).unwrap();
    assert_eq!(backend.events, ["status", "terminate", "status", "close"]);
}

#[test]
fn runtime_uses_retained_cleanup_for_all_failed_clone_and_spawn_branches() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = source.find("fn clone_registered_process()").unwrap();
    let end = source[start..]
        .find("struct CloneStartup")
        .unwrap()
        + start;
    let clone = &source[start..end];
    assert!(clone.contains("registration_attempted = true;"));
    assert!(clone.contains("cleanup_failed_child(u64::from(handle), registration_attempted)"));
    assert!(!clone.contains("close_object_handle(handle)"));
    let start = source.find("fn _posix_spawn(").unwrap();
    let end = source[start..]
        .find("pub extern \"C\" fn posix_spawn(")
        .unwrap()
        + start;
    assert_eq!(
        source[start..end]
            .matches("cleanup_failed_child(u64::from(process_handle), true)")
            .count(),
        2
    );
    assert!(!source.contains("fn finish_failed_spawn("));
}
