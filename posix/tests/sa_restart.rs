use mochios_posix_client::{newlib_errno::EINTR, signal::terminal_operation};
use std::cell::Cell;

#[test]
fn selected_restart_action_survives_a_handler_changing_its_own_flags() {
    let attempts = Cell::new(0);
    let restart = Cell::new(0);
    assert_eq!(
        terminal_operation(
            || {
                attempts.set(attempts.get() + 1);
                if attempts.get() == 1 {
                    Err(EINTR)
                } else {
                    Ok(4)
                }
            },
            || {
                restart.set(restart.get() + 1);
                Ok(())
            },
            || (0, 0, restart.get()),
            || false,
        ),
        Ok(4)
    );
    assert_eq!(attempts.get(), 2);
}

#[test]
fn any_nonrestart_handler_wins_over_restartable_handlers() {
    let generations = Cell::new((0, 0, 0));
    let attempts = Cell::new(0);
    let result: Result<(), _> = terminal_operation(
        || {
            attempts.set(attempts.get() + 1);
            Err(EINTR)
        },
        || {
            generations.set((1, 0, 2));
            Ok(())
        },
        || generations.get(),
        || true,
    );
    assert_eq!(result, Err(EINTR));
    assert_eq!(attempts.get(), 1);
}

#[test]
fn runtime_keeps_sleep_interruptions_separate_from_restartable_io() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let wait = source
        .split("fn wait_for_handle(")
        .nth(1)
        .unwrap()
        .split("fn syscall_write(")
        .next()
        .unwrap();
    assert!(wait.contains("nonrestart_signal_generation.load"));
    let sleep = source
        .split("fn clock_nanosleep(")
        .nth(1)
        .unwrap()
        .split("fn nanosleep(")
        .next()
        .unwrap();
    assert!(sleep.contains("caught_signal_generation.load"));
    assert!(!sleep.contains("nonrestart_signal_generation"));
    let dispatch = source
        .split("fn dispatch_signal(")
        .nth(1)
        .unwrap()
        .split("fn apply_default_signal_action(")
        .next()
        .unwrap();
    assert!(
        dispatch
            .find("restart_signal_generation")
            .unwrap()
            < dispatch.find("signal_stack::invoke").unwrap()
    );
    assert!(source.contains("!(SA_NOCLDSTOP | SA_NOCLDWAIT | SA_RESTART | SA_SIGINFO | SA_ONSTACK)"));
}
