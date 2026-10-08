use mochios_posix_client::thread::{MAX_THREADS, ThreadToken, next_generation};

#[test]
fn pthread_tokens_round_trip_slot_and_generation() {
    let token = ThreadToken::new(MAX_THREADS - 1, 27).expect("valid thread token");

    assert_eq!(ThreadToken::from_raw(token.raw()), Some(token));
    assert_eq!(token.slot(), MAX_THREADS - 1);
    assert_eq!(token.generation(), 27);
}

#[test]
fn pthread_tokens_reject_invalid_or_stale_shape() {
    assert_eq!(ThreadToken::from_raw(0), None);
    assert_eq!(ThreadToken::new(MAX_THREADS, 1), None);
    assert_eq!(ThreadToken::new(0, 0), None);

    let old = ThreadToken::new(3, 9).expect("old token");
    let reused = ThreadToken::new(3, next_generation(9)).expect("reused token");
    assert_ne!(old, reused);
    assert_eq!(old.slot(), reused.slot());
}

#[test]
fn pthread_generation_wrap_never_produces_zero() {
    assert_ne!(next_generation(u32::MAX), 0);
}
