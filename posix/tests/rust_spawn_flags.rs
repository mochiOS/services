#[test]
fn rust_libc_spawn_flags_match_newlib_and_the_userspace_decoder() {
    use mochios_posix_client::spawn;
    let rust = include_str!("../../../libraries/libc/newlib/mochios.rs");
    let c = include_str!("../../../libraries/newlib/newlib/libc/include/spawn.h");
    for (name, value) in [
        ("RESETIDS", spawn::RESET_IDS),
        ("SETPGROUP", spawn::SET_PROCESS_GROUP),
        ("SETSCHEDPARAM", spawn::SET_SCHEDULING_PARAMETERS),
        ("SETSCHEDULER", spawn::SET_SCHEDULER),
        ("SETSIGDEF", spawn::SET_SIGNAL_DEFAULTS),
        ("SETSIGMASK", spawn::SET_SIGNAL_MASK),
    ] {
        let symbol = format!("POSIX_SPAWN_{name}");
        let definition = rust
            .lines()
            .find(|line| line.starts_with(&format!("pub const {symbol}:")))
            .unwrap();
        let hex = definition
            .split_once("= 0x")
            .unwrap()
            .1
            .trim_end_matches(';');
        assert_eq!(
            i16::from_str_radix(hex, 16).unwrap(),
            value,
            "Rust {symbol}"
        );
        let definition = c
            .lines()
            .find(|line| line.starts_with(&format!("#define {symbol}\t")))
            .unwrap();
        let hex = definition
            .split_whitespace()
            .last()
            .unwrap()
            .strip_prefix("0x")
            .unwrap();
        assert_eq!(i16::from_str_radix(hex, 16).unwrap(), value, "C {symbol}");
    }
    assert_eq!(
        spawn::classify_attribute_flags(spawn::SET_SIGNAL_DEFAULTS),
        spawn::AttributeFlags::Supported
    );
}
