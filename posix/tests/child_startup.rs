#[path = "../../../user/crates/newlib-runtime/src/child_startup.rs"]
mod production;

use mochios_posix_client::newlib_errno::{EACCES, EINTR, EIO, ENOMEM};

#[test]
fn explicit_ready_and_errors_survive_partial_io_and_interrupts() {
    for status in [0, ENOMEM, EACCES, EIO] {
        let mut packet = [0u8; 4];
        let mut offset = 0;
        let mut interrupt = true;
        production::send(status, |bytes| {
            if core::mem::replace(&mut interrupt, false) {
                return Err(EINTR);
            }
            packet[offset] = bytes[0];
            offset += 1;
            Ok(1)
        })
        .unwrap();
        assert_eq!(offset, 4);
        offset = 0;
        interrupt = true;
        let result = production::receive(|bytes| {
            if core::mem::replace(&mut interrupt, false) {
                return Err(EINTR);
            }
            bytes[0] = packet[offset];
            offset += 1;
            Ok(1)
        });
        assert_eq!(result, if status == 0 { Ok(()) } else { Err(status) });
    }
}

#[test]
fn eof_without_a_complete_acknowledgement_is_failure() {
    for available in 0..4 {
        let mut offset = 0;
        assert_eq!(
            production::receive(|bytes| {
                if offset == available {
                    return Ok(0);
                }
                bytes[0] = 0;
                offset += 1;
                Ok(1)
            }),
            Err(EIO)
        );
    }
    assert_eq!(
        production::receive(|bytes| {
            bytes.copy_from_slice(&(-1i32).to_ne_bytes());
            Ok(4)
        }),
        Err(EIO)
    );
}

#[test]
fn transport_failures_are_not_success_or_unbounded_progress() {
    assert_eq!(production::send(0, |_| Ok(0)), Err(EIO));
    assert_eq!(production::send(0, |_| Ok(5)), Err(EIO));
    assert_eq!(production::send(0, |_| Err(EACCES)), Err(EACCES));
    assert_eq!(
        production::send(-1, |_| panic!("invalid status was written")),
        Err(EIO)
    );
    assert_eq!(production::receive(|_| Ok(5)), Err(EIO));
    assert_eq!(production::receive(|_| Err(EACCES)), Err(EACCES));
}

#[test]
fn runtime_acknowledges_only_after_initialization_and_reaps_failed_children() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let clone = source
        .split("fn clone_registered_process()")
        .nth(1)
        .unwrap()
        .split("struct CloneStartup")
        .next()
        .unwrap();
    assert!(clone.contains("spawn_resources::fork()"));
    let resources = include_str!("../../../user/crates/newlib-runtime/src/spawn_resources.rs");
    let prepare = resources.split("fn for_fork()").nth(1).unwrap();
    let prepare = prepare.split("fn new()").next().unwrap();
    assert!(prepare.contains("startup: Some(CloneStartup::new()?)"));
    let fork = resources.split("pub(super) fn fork()").nth(1).unwrap();
    assert!(fork.contains("io_resources::with(Resources::for_fork,"));
    assert!(fork.contains("resources.clone_registered()?"));
    assert!(
        clone
            .find("setup_signal_delivery(thread_control, None)")
            .unwrap()
            < clone.find("startup.ready()").unwrap()
    );
    assert!(clone.find("drop(allocator_guard)").unwrap() < clone.find("startup.wait()?").unwrap());
    assert!(clone.find("ProcessHandleResume").unwrap() < clone.find("startup.wait()?").unwrap());
    assert!(clone.contains("startup.fail(error)"));
    assert!(!clone.contains("process_exit(127)"));
    assert!(clone.contains("cleanup_failed_child(u64::from(handle), registration_attempted)"));
}
