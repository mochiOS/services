#[path = "../../../user/crates/newlib-runtime/src/stdio_cancellation.rs"]
mod implementation;
use implementation::Scope;

#[test]
fn nested_libc_guards_interrupt_io_but_cancel_only_after_the_outermost_unlock() {
    let scope = Scope::new();
    assert!(scope.enter(true));
    assert!(scope.enter(false)); // libc temporarily disabled cancellation.
    assert!(scope.permits_interrupt());
    scope.note_interruption();
    assert_eq!(scope.leave(), Some(false));
    assert!(scope.active());
    assert_eq!(scope.leave(), Some(true));
    assert!(!scope.active());
    assert_eq!(scope.leave(), None);
}

#[test]
fn application_disabled_cancellation_is_not_overridden_by_nested_stdio() {
    let scope = Scope::new();
    assert!(scope.enter(false));
    assert!(scope.enter(false));
    assert!(!scope.permits_interrupt());
    scope.note_interruption();
    assert_eq!(scope.leave(), Some(false));
    assert_eq!(scope.leave(), Some(false));
}

#[test]
fn committed_progress_is_reported_and_an_unselected_request_is_not_a_cancellation() {
    let scope = Scope::new();
    scope.enter(true);
    scope.note_progress();
    scope.note_interruption();
    assert_eq!(scope.leave(), Some(false));
    scope.enter(true);
    assert_eq!(scope.leave(), Some(false));
    scope.enter(true);
    scope.note_interruption();
    assert_eq!(scope.leave(), Some(true)); // The previous progress flag was cleared.
}

#[test]
fn independent_threads_and_recycled_controls_do_not_share_scope_state() {
    let first = Scope::new();
    let second = Scope::new();
    first.enter(true);
    first.note_interruption();
    second.enter(true);
    assert_eq!(second.leave(), Some(false));
    first.reset();
    assert!(!first.active());
    assert_eq!(first.leave(), None);
    first.enter(false);
    assert!(!first.permits_interrupt());
    assert_eq!(first.leave(), Some(false));
}

#[test]
fn newlib_releases_stream_and_list_locks_before_restoring_and_leaving_the_scope() {
    let source = include_str!("../../../libraries/newlib/newlib/libc/stdio/local.h");
    let section = source
        .split("#elif defined(_STDIO_WITH_THREAD_CANCELLATION_SUPPORT)")
        .nth(1)
        .unwrap()
        .split("#else /* !__SINGLE_THREAD__")
        .next()
        .unwrap();
    for (start, end, unlock) in [
        (
            "# define _newlib_flockfile_exit",
            "/* End a stream oriented",
            "_funlockfile",
        ),
        (
            "# define _newlib_flockfile_end",
            "/* Start a stream list",
            "_funlockfile",
        ),
        (
            "# define _newlib_sfp_lock_exit",
            "/* End a stream list",
            "__sfp_lock_release",
        ),
        (
            "# define _newlib_sfp_lock_end",
            "\n#else",
            "__sfp_lock_release",
        ),
    ] {
        let body = section
            .split(start)
            .nth(1)
            .unwrap()
            .split(end)
            .next()
            .unwrap();
        assert!(body.find(unlock).unwrap() < body.find("pthread_setcancelstate").unwrap());
        assert!(
            body.find("pthread_setcancelstate").unwrap()
                < body.find("_newlib_stdio_cancel_leave").unwrap()
        );
    }
}

#[test]
fn internal_reent_reclamation_and_scope_entry_cannot_abandon_runtime_owned_resources() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let reclaim = source
        .split("fn release_thread_control(")
        .nth(1)
        .unwrap()
        .split("fn allocate_thread_reent(")
        .next()
        .unwrap();
    assert!(
        reclaim.find("swap(PTHREAD_CANCEL_DISABLE").unwrap()
            < reclaim.find("__mochios_reent_destroy(").unwrap()
    );
    assert!(
        reclaim.find("__mochios_reent_destroy(").unwrap()
            < reclaim.find("cancel_state.store(previous").unwrap()
    );
    let enter = source
        .split("fn __mochios_stdio_cancel_enter(")
        .nth(1)
        .unwrap()
        .split("fn __mochios_stdio_cancel_leave(")
        .next()
        .unwrap();
    assert!(!enter.contains("finish_thread("));
    assert!(!enter.contains("pthread_testcancel()"));
}
