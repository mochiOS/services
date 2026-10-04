use mochios_posix_client::random::{GRND_NONBLOCK, GRND_RANDOM, flags_are_supported};

#[test]
fn getrandom_flags_are_consumed_in_user_space() {
    assert!(flags_are_supported(0));
    assert!(flags_are_supported(GRND_NONBLOCK));
    assert!(flags_are_supported(GRND_RANDOM));
    assert!(flags_are_supported(GRND_NONBLOCK | GRND_RANDOM));
    assert!(!flags_are_supported(1 << 31));
}
