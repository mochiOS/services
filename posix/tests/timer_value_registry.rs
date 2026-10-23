use mochios_posix_client::timer_value::{Error, Registry, ResolveError};

#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn owner_retirement_reclaims_capacity_without_reusing_tokens_or_retiring_other_lifetimes() {
    let mut values = Registry::<usize, 3>::new();
    assert_eq!(values.reserve_owned(1, 0), Err(Error::InvalidOwner));
    let shared = values.reserve(10).unwrap();
    values.bind(shared, 1).unwrap();
    let other = values.reserve_owned(20, 18).unwrap();
    values.bind(other, 2).unwrap();
    let mut old = Vec::new();
    for timer in 3..1003 {
        let token = values.reserve_owned(timer as usize, 17).unwrap();
        values.bind(token, timer).unwrap();
        values.retire_owner(17);
        assert_eq!(
            values.resolve(timer, token.raw()),
            Err(ResolveError::StaleToken)
        );
        old.push((timer, token));
        assert_eq!(values.resolve(1, shared.raw()), Ok(10));
        assert_eq!(values.resolve(2, other.raw()), Ok(20));
    }
    let token = values.reserve_owned(99, 17).unwrap();
    values.bind(token, 1003).unwrap();
    for (timer, token) in old {
        assert_eq!(
            values.resolve(timer, token.raw()),
            Err(ResolveError::StaleToken)
        );
    }
    values.retire_owner(0);
    assert_eq!(values.resolve(1, shared.raw()), Ok(10));
    let mut child = values.clone();
    child.clear_for_fork();
    assert_eq!(
        child.resolve(1003, token.raw()),
        Err(ResolveError::StaleToken)
    );
    assert_eq!(values.resolve(1003, token.raw()), Ok(99));
}

#[test]
fn reserved_values_cannot_be_resolved_or_bound_to_duplicate_or_zero_timer_ids() {
    let mut values = Registry::<usize, 2>::new();
    let first = values.reserve(0x1234).unwrap();
    assert_eq!(
        values.resolve(71, first.raw()),
        Err(ResolveError::UnboundToken)
    );
    assert_eq!(values.bind(first, 0), Err(Error::InvalidTimer));
    values.update_reserved(first, 0x5678).unwrap();
    values.bind(first, 71).unwrap();
    assert_eq!(values.resolve(71, first.raw()), Ok(0x5678));
    assert_eq!(
        values.resolve(72, first.raw()),
        Err(ResolveError::WrongTimer)
    );
    assert_eq!(values.update_reserved(first, 99), Err(Error::AlreadyBound));
    assert_eq!(values.cancel(first), Err(Error::AlreadyBound));
    let second = values.reserve(0x9999).unwrap();
    assert_eq!(values.bind(second, 71), Err(Error::DuplicateTimer));
    assert_eq!(
        values.resolve(71, second.raw()),
        Err(ResolveError::UnboundToken)
    );
    values.bind(second, 72).unwrap();
    assert_eq!(values.resolve(72, second.raw()), Ok(0x9999));
    assert_eq!(values.resolve(71, first.raw()), Ok(0x5678));
}

#[test]
fn recycled_slots_and_even_reused_server_ids_never_resolve_a_late_token_to_new_data() {
    let mut values = Registry::<u64, 1>::new();
    let mut retired = Vec::new();
    for value in 1..=1_000u64 {
        let token = values.reserve(value).unwrap();
        values.bind(token, 71).unwrap();
        assert_eq!(values.resolve(71, token.raw()), Ok(value));
        for old in &retired {
            assert_eq!(values.resolve(71, *old), Err(ResolveError::StaleToken));
        }
        let snapshot = values.resolve(71, token.raw()).unwrap();
        assert_eq!(values.retire(71), Some(value));
        assert_eq!(
            values.resolve(71, token.raw()),
            Err(ResolveError::StaleToken)
        );
        assert_eq!(snapshot, value); // No borrow survives retirement.
        retired.push(token.raw());
    }
}

#[test]
fn capacity_failure_does_not_consume_tokens_and_cancel_cannot_target_a_replacement() {
    let mut values = Registry::<u32, 1>::new();
    let first = values.reserve(17).unwrap();
    assert_eq!(values.reserve(18), Err(Error::Full));
    assert_eq!(values.cancel(first), Ok(17));
    let replacement = values.reserve(19).unwrap();
    assert_eq!(replacement.raw(), first.raw() + 1);
    assert_eq!(values.cancel(first), Err(Error::InvalidToken));
    values.bind(replacement, 71).unwrap();
    assert_eq!(values.resolve(71, replacement.raw()), Ok(19));
    assert_eq!(values.resolve(71, 0), Err(ResolveError::UnknownToken));
    assert_eq!(
        values.resolve(71, replacement.raw() + 1),
        Err(ResolveError::UnknownToken)
    );
    assert_eq!(values.retire(0), None);
    assert_eq!(Registry::<u32, 0>::new().reserve(1), Err(Error::Full));
}

#[test]
fn actual_u64_cookie_exhaustion_never_wraps_even_after_all_slots_are_cleared() {
    let mut program = String::from("#![allow(dead_code)]\n");
    program.push_str(include_str!(
        "../../../user/crates/posix-client/src/timer_value.rs"
    ));
    // Compile the unchanged production module in the same scope. Only the
    // initial counter is seeded near its real limit; no small-width analogue
    // or production test-only constructor substitutes for u64 arithmetic.
    program.push_str(
        r#"
fn main() {
 let mut values = Registry::<u64, 1>::new();
 values.last_token = u64::MAX - 1;
 let token = values.reserve(17).unwrap();
 assert_eq!(token.raw(), u64::MAX);
 values.bind(token, 71).unwrap();
 assert_eq!(values.resolve(71, token.raw()), Ok(17));
 assert_eq!(values.retire(71), Some(17));
 assert_eq!(values.reserve(18), Err(Error::Exhausted));
 values.clear_for_fork();
 assert_eq!(values.reserve(19), Err(Error::Exhausted));
 assert_eq!(values.resolve(71, u64::MAX), Err(ResolveError::StaleToken));
 assert_eq!(values.resolve(71, 0), Err(ResolveError::UnknownToken));
}
"#,
    );
    probe::run(&program);
}

#[test]
fn fork_child_forgets_values_without_rewinding_tokens_or_affecting_the_parent() {
    let mut parent = Registry::<usize, 2>::new();
    let bound = parent.reserve(0x1234).unwrap();
    parent.bind(bound, 71).unwrap();
    let reserved = parent.reserve(0x5678).unwrap();
    let mut child = parent.clone(); // Controlled counterpart of native COW.
    child.clear_for_fork();
    for token in [bound, reserved] {
        assert_eq!(
            child.resolve(71, token.raw()),
            Err(ResolveError::StaleToken)
        );
        assert_eq!(child.cancel(token), Err(Error::InvalidToken));
    }
    let fresh = child.reserve(0x9999).unwrap();
    assert!(fresh.raw() > reserved.raw());
    child.bind(fresh, 72).unwrap();
    assert_eq!(child.resolve(72, fresh.raw()), Ok(0x9999));
    assert_eq!(parent.resolve(71, bound.raw()), Ok(0x1234));
    assert_eq!(parent.cancel(reserved), Ok(0x5678));
}

#[test]
fn only_a_local_snapshot_not_the_wire_token_becomes_a_c_signal_value() {
    use mochios_posix_protocol::{
        process_timer as wire,
        signal_origin::{Origin, TimerStatus, TIMER},
    };
    let mut values = Registry::<usize, 1>::new();
    let raw_value = 0x1122334455667788usize;
    let token = values.reserve(raw_value).unwrap();
    let mut bytes = [0; wire::CREATE_LEN];
    wire::encode_create(
        wire::Clock::Monotonic,
        wire::Notification::Signal {
            signal: 14,
            value: token.raw(),
        },
        &mut bytes,
    )
    .unwrap();
    assert!(!bytes
        .windows(std::mem::size_of::<usize>())
        .any(|bytes| bytes == raw_value.to_le_bytes()));
    values.bind(token, 71).unwrap();
    let origin = Origin {
        source: TIMER,
        timer: Some(TimerStatus {
            timer_id: 71,
            value_token: token.raw(),
            overrun: 3,
        }),
        ..Origin::system()
    };
    let detail = origin.timer.unwrap();
    let snapshot = values.resolve(detail.timer_id, detail.value_token).unwrap();
    values.retire(71).unwrap();
    let info =
        mochios_posix_client::signal_context::SigInfo::from_timer_origin(14, origin, snapshot)
            .unwrap();
    assert_eq!(unsafe { info.si_value.sival_ptr }, raw_value);
    assert_eq!(
        values.resolve(detail.timer_id, detail.value_token),
        Err(ResolveError::StaleToken)
    );
}

#[test]
fn runtime_storage_and_child_reset_are_wired_before_reinstalling_upcalls() {
    // Structural wiring only; this does not prove a native fork ran.
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(
        runtime.contains("timer_values: mochios_posix_client::timer_value::Registry<usize, 128>")
    );
    let reset = runtime
        .find("state().timer_values.clear_for_fork();")
        .unwrap();
    let child = runtime[..reset].rfind("if image == 0 {").unwrap();
    assert!(child < reset);
    let end = reset
        + runtime[reset..]
            .find("return Ok((0, inherited_fds, None));")
            .unwrap();
    let branch = &runtime[child..end];
    assert!(
        branch
            .find("state().timer_values.clear_for_fork();")
            .unwrap()
            < branch
                .find("setup_signal_delivery(thread_control, None)")
                .unwrap()
    );
    assert!(branch.contains("discard_fork_thread_control(other)"));
}
