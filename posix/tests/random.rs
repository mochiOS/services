use mochios_posix_client::random::{GRND_NONBLOCK, GRND_RANDOM, flags_are_supported};

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
