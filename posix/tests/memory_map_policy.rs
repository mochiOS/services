use mochios_posix_client::memory::{
    MAP_ANONYMOUS, MAP_FIXED, MAP_NORESERVE, MAP_PRIVATE, MAP_SHARED, MAP_STACK, NativeMap,
    native_map,
};

#[test]
fn posix_flags_are_translated_not_forwarded_to_the_native_abi() {
    assert_eq!(
        native_map(MAP_PRIVATE | MAP_ANONYMOUS),
        Some(NativeMap {
            options: 0,
            anonymous: true
        })
    );
    assert_eq!(
        native_map(MAP_SHARED | MAP_FIXED),
        Some(NativeMap {
            options: mnu_abi::MEMORY_MAP_SHARED | mnu_abi::MEMORY_MAP_EXACT,
            anonymous: false,
        })
    );
    assert_eq!(
        native_map(MAP_PRIVATE | MAP_STACK | MAP_NORESERVE),
        Some(NativeMap {
            options: 0,
            anonymous: false
        })
    );
    assert_ne!(MAP_SHARED as u64, mnu_abi::MEMORY_MAP_SHARED);
    assert_ne!(MAP_FIXED as u64, mnu_abi::MEMORY_MAP_EXACT);
}

#[test]
fn unknown_and_conflicting_policies_are_rejected() {
    for flags in [
        0,
        MAP_ANONYMOUS,
        MAP_SHARED | MAP_PRIVATE,
        MAP_PRIVATE | (1 << 29),
        -1,
    ] {
        assert_eq!(native_map(flags), None);
    }
}
