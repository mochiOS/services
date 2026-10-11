const RUNTIME: &str = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");

#[test]
fn signal_suspension_reuses_an_infinite_guarded_wait_without_fd_readiness() {
    let wait = RUNTIME
        .split("fn suspend_with_signal_mask(")
        .nth(1)
        .unwrap()
        .split("fn pause()")
        .next()
        .unwrap();
    assert!(wait.contains("masked_multiplex(mask"));
    assert!(wait
        .contains("wait_for_multiplex(&mut [], syscall::HANDLE_WAIT_INFINITE, control, caught)?"));
    assert!(wait.contains("Err(EIO)"));
    assert!(!wait.contains("Ok(0)"));
    let bridge = RUNTIME
        .split("fn wait_for_multiplex(")
        .nth(1)
        .unwrap()
        .split("fn select_deadline(")
        .next()
        .unwrap();
    assert!(bridge.contains("HandleWaitManyGuarded"));
    assert!(bridge.contains("WaitError::Interrupted => EINTR"));
}

#[test]
fn pause_preserves_the_mask_and_sigsuspend_requires_a_mask_pointer() {
    let pause = RUNTIME
        .split("fn pause()")
        .nth(1)
        .unwrap()
        .split("fn sigsuspend(")
        .next()
        .unwrap();
    assert!(pause.contains("suspend_with_signal_mask(ptr::null())"));
    let suspend = RUNTIME
        .split("fn sigsuspend(")
        .nth(1)
        .unwrap()
        .split("fn getgroups(")
        .next()
        .unwrap();
    assert!(
        suspend.find("mask.is_null()").unwrap()
            < suspend.find("suspend_with_signal_mask(mask)").unwrap()
    );
    assert!(suspend.contains("set_errno(EFAULT)"));
    assert!(suspend.contains("result_with_errno(suspend_with_signal_mask(mask), -1)"));
}
