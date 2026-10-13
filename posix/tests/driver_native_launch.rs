extern crate alloc;

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

mod driver_spawn {
    pub struct DriverProcess {
        pub drops: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        pub ready: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }
    impl DriverProcess {
        pub fn retry_rollback(
            &self,
            endpoint: u32,
        ) -> Result<(), mochi_user_platform::syscall::SysError> {
            assert_eq!(endpoint, 19);
            if self.ready.load(std::sync::atomic::Ordering::Relaxed) {
                Ok(())
            } else {
                Err(mochi_user_platform::syscall::SysError::from_raw(-11))
            }
        }
    }
    impl Drop for DriverProcess {
        fn drop(&mut self) {
            self.drops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}
#[path = "../../drivers/src/driver_registry.rs"]
mod registry;

#[test]
fn production_registry_keeps_live_and_failed_owners_until_confirmed_cleanup() {
    let drops = Arc::new(AtomicUsize::new(0));
    let ready = Arc::new(AtomicBool::new(false));
    let owner = || driver_spawn::DriverProcess {
        drops: drops.clone(),
        ready: ready.clone(),
    };
    let mut registry = registry::StartedDrivers::new();
    registry.record("driver".into(), owner());
    assert!(registry.contains("driver"));
    assert!(!registry.contains("other"));
    registry.retain_failed(owner());
    registry.retry_failed(19);
    assert!(registry.has_failed_cleanup());
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    ready.store(true, Ordering::Relaxed);
    registry.retry_failed(19);
    assert!(!registry.has_failed_cleanup());
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert!(registry.contains("driver"));
    drop(registry);
    assert_eq!(drops.load(Ordering::Relaxed), 2);
}

#[test]
fn driver_launch_has_no_path_syscall_or_security_identity_argument_fallback() {
    let source = include_str!("../../drivers/src/driver_spawn.rs");
    assert!(!source.contains("spawn_manifest("));
    assert!(!source.contains("encode_spawn_args"));
    assert!(!source.contains("security.identity"));
    assert!(source.contains("ExecutionClass::Unprivileged"));
    assert!(source.contains(".find(|part| part.ends_with(\".driver\"))"));
    assert!(source.contains("launch_arguments::encode_native_launch"));
    assert!(source.contains("process_creation::create_with_rollback"));
    assert!(source.contains("platform::process::create_stopped(image.handle, &metadata)"));
    assert!(source.contains("register_spawned_child"));
    assert!(source.contains("CONTROL_HANDLE_KEY"));
    assert!(source.contains("close(image.handle)"));
}

#[test]
fn failed_driver_reclamation_requires_native_exit_before_userspace_cleanup() {
    let source = include_str!("../../drivers/src/driver_spawn.rs");
    let cleanup =
        &source[source.find("fn retry_rollback(").unwrap()..source.find("impl Drop").unwrap()];
    assert!(
        cleanup.find("PROCESS_STATE_EXITED").unwrap()
            < cleanup.find("abort_launched_child").unwrap()
    );
    assert!(cleanup.contains("Err(sys_error(mochi_user_syscall::EAGAIN))"));
    assert!(cleanup.contains("STATUS_ESRCH"));
    assert!(!cleanup.contains("open_handle_for_process_id"));
}

#[test]
fn driver_owners_survive_discovery_and_pending_cleanup_is_retried_while_idle() {
    let worker = include_str!("../../drivers/src/control_worker.rs");
    let registry = worker.find("let mut started_drivers =").unwrap();
    assert!(registry < worker[registry..].find("loop {").unwrap() + registry);
    assert!(worker.contains("started_drivers.retry_failed(posix_endpoint)"));
    assert!(worker.contains("if started_drivers.has_failed_cleanup()"));
    assert!(worker.contains("platform::ipc::try_wait(&mut buffer)"));
    let discovery = include_str!("../../drivers/src/discovery.rs");
    assert!(!discovery.contains("let mut started_drivers ="));
    assert!(discovery.contains("started_drivers.retain_failed(process)"));
    assert!(discovery.contains("started_drivers.record(manifest.package_id.clone(), process)"));
}

#[test]
fn shared_creation_transaction_preserves_first_error_and_exact_rollback_owner() {
    use std::cell::RefCell;
    for failure in 0..=4 {
        let events = RefCell::new(Vec::new());
        let result = mochios_posix_client::process_creation::create_with_rollback(
            || {
                events.borrow_mut().push("create");
                if failure == 1 { Err(1) } else { Ok(7u32) }
            },
            |handle| {
                assert_eq!(handle, 7);
                events.borrow_mut().push("setup");
                if failure == 2 { Err(2) } else { Ok(()) }
            },
            |handle| {
                assert_eq!(handle, 7);
                events.borrow_mut().push("identify");
                if failure == 3 { Err(3) } else { Ok(70) }
            },
            |handle| {
                assert_eq!(handle, 7);
                events.borrow_mut().push("resume");
                if failure == 4 { Err(4) } else { Ok(()) }
            },
            |handle| {
                assert_eq!(handle, 7);
                events.borrow_mut().push("terminate");
            },
            |handle| {
                assert_eq!(handle, 7);
                events.borrow_mut().push("retain");
            },
        );
        let expected = match failure {
            0 => vec!["create", "setup", "identify", "resume"],
            1 => vec!["create"],
            2 => vec!["create", "setup", "terminate", "retain"],
            3 => vec!["create", "setup", "identify", "terminate", "retain"],
            4 => vec![
                "create",
                "setup",
                "identify",
                "resume",
                "terminate",
                "retain",
            ],
            _ => unreachable!(),
        };
        assert_eq!(events.into_inner(), expected);
        assert_eq!(
            result,
            if failure == 0 {
                Ok((7, 70))
            } else {
                Err(failure)
            }
        );
    }
}
