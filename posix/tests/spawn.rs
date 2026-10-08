use mochios_posix_client::spawn::{
    AttributeFlags, KNOWN_ATTRIBUTE_FLAGS, RESET_IDS, SET_PROCESS_GROUP, SET_SCHEDULER,
    SET_SCHEDULING_PARAMETERS, SET_SIGNAL_DEFAULTS, SET_SIGNAL_MASK, classify_attribute_flags,
};

#[test]
fn spawn_attribute_flags_match_the_newlib_posix_abi() {
    assert_eq!(RESET_IDS, 0x01);
    assert_eq!(SET_PROCESS_GROUP, 0x02);
    assert_eq!(SET_SCHEDULING_PARAMETERS, 0x04);
    assert_eq!(SET_SCHEDULER, 0x08);
    assert_eq!(SET_SIGNAL_DEFAULTS, 0x10);
    assert_eq!(SET_SIGNAL_MASK, 0x20);
    assert_eq!(KNOWN_ATTRIBUTE_FLAGS, 0x3f);
}

#[test]
fn spawn_attribute_support_is_explicit() {
    assert_eq!(classify_attribute_flags(0), AttributeFlags::Supported);
    assert_eq!(
        classify_attribute_flags(
            RESET_IDS | SET_PROCESS_GROUP | SET_SIGNAL_DEFAULTS | SET_SIGNAL_MASK
        ),
        AttributeFlags::Supported
    );
    assert_eq!(
        classify_attribute_flags(SET_SCHEDULING_PARAMETERS),
        AttributeFlags::RequiresScheduler
    );
    assert_eq!(
        classify_attribute_flags(SET_SCHEDULER),
        AttributeFlags::RequiresScheduler
    );
    assert_eq!(classify_attribute_flags(0x40), AttributeFlags::Invalid);
}
