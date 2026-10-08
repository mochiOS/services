use mochios_posix_client::thread::{
    MAX_THREAD_KEYS, ThreadKeyToken, next_generation,
};

#[test]
fn pthread_key_tokens_round_trip_slot_and_generation() {
    let token = ThreadKeyToken::new(MAX_THREAD_KEYS - 1, 41).expect("valid key token");

    assert_eq!(ThreadKeyToken::from_raw(token.raw()), Some(token));
    assert_eq!(token.slot(), MAX_THREAD_KEYS - 1);
    assert_eq!(token.generation(), 41);
}

#[test]
fn pthread_key_tokens_reject_invalid_shape() {
    assert_eq!(ThreadKeyToken::from_raw(0), None);
    assert_eq!(ThreadKeyToken::new(MAX_THREAD_KEYS, 1), None);
    assert_eq!(ThreadKeyToken::new(0, 0), None);
}

#[test]
fn deleted_and_reused_pthread_keys_have_distinct_identity() {
    let deleted = ThreadKeyToken::new(7, 12).expect("deleted key");
    let reused = ThreadKeyToken::new(7, next_generation(12)).expect("reused key");

    assert_ne!(deleted, reused);
    assert_eq!(deleted.slot(), reused.slot());
}
