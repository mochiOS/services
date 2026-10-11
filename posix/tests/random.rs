use mochios_posix_client::newlib_errno::{EACCES, EAGAIN, EINTR, EIO};
use mochios_posix_client::random::{GRND_NONBLOCK, GRND_RANDOM, fill_entropy, flags_are_supported};

#[test]
fn entropy_fills_only_the_remaining_prefix_after_short_transfers_and_interrupts() {
    let mut calls = Vec::new();
    let responses = [Ok(3), Err(EINTR), Ok(2), Ok(3)];
    assert_eq!(
        fill_entropy(8, |offset, remaining| {
            calls.push((offset, remaining));
            responses[calls.len() - 1]
        }),
        Ok(())
    );
    assert_eq!(calls, [(0, 8), (3, 5), (3, 5), (5, 3)]);
}

#[test]
fn entropy_checks_length_before_touching_the_native_source() {
    assert_eq!(
        fill_entropy(0, |_, _| panic!("empty request must not touch memory")),
        Ok(())
    );
    for length in [257, usize::MAX] {
        assert_eq!(
            fill_entropy(length, |_, _| panic!(
                "oversized request must not perform I/O"
            )),
            Err(EIO)
        );
    }
    assert_eq!(
        fill_entropy(256, |offset, remaining| {
            assert_eq!((offset, remaining), (0, 256));
            Ok(256)
        }),
        Ok(())
    );
}

#[test]
fn entropy_never_reports_success_for_zero_progress_or_invalid_native_counts() {
    for count in [0, 9, usize::MAX] {
        assert_eq!(fill_entropy(8, |_, _| Ok(count)), Err(EIO));
    }
    let mut calls = 0;
    assert_eq!(
        fill_entropy(8, |_, _| {
            calls += 1;
            Ok(if calls == 1 { 3 } else { 0 })
        }),
        Err(EIO)
    );
}

#[test]
fn entropy_propagates_source_failures_even_after_partial_progress() {
    for error in [EACCES, EAGAIN, EIO] {
        let mut calls = 0;
        assert_eq!(
            fill_entropy(8, |_, _| {
                calls += 1;
                if calls == 1 { Ok(3) } else { Err(error) }
            }),
            Err(error)
        );
        assert_eq!(calls, 2);
    }
}

#[test]
fn newlib_entropy_uses_completion_policy_without_posix_rpc_or_legacy_fallback() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let implementation = runtime
        .split("pub extern \"C\" fn getentropy(")
        .nth(1)
        .unwrap()
        .split("#[unsafe(no_mangle)]")
        .next()
        .unwrap();
    assert!(implementation.contains("random::fill_entropy"));
    assert!(implementation.contains("SyscallNumber::RandomFill"));
    assert!(implementation.contains("set_errno(EFAULT)"));
    assert!(!implementation.contains("posix_client()"));
    assert!(!implementation.contains("getrandom(buffer, length, 0)"));
}

#[test]
fn getrandom_flags_are_consumed_in_user_space() {
    assert!(flags_are_supported(0));
    assert!(flags_are_supported(GRND_NONBLOCK));
    assert!(flags_are_supported(GRND_RANDOM));
    assert!(flags_are_supported(GRND_NONBLOCK | GRND_RANDOM));
    assert!(!flags_are_supported(1 << 31));
}

#[test]
fn bootstrap_handshake_services_declare_native_random_capability() {
    for manifest in [
        include_str!("../../service-manager/manifest.toml"),
        include_str!("../../drivers/manifest.toml"),
    ] {
        let manifest = mochi_user_platform::package::parse_manifest(manifest)
            .expect("bootstrap service manifest must parse");
        assert!(manifest.binaries.iter().all(|binary| {
            binary
                .requires
                .iter()
                .any(|capability| capability == "system.random.read")
        }));
    }
}
