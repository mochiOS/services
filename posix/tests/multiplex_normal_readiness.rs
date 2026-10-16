use mochios_posix_client::multiplex;

#[test]
fn ordinary_readiness_never_generates_priority_band_or_error_events() {
    assert_eq!(multiplex::NORMAL_READ_EVENTS, 0x41);
    assert_eq!(multiplex::NORMAL_WRITE_EVENTS, 4);
    for bits in 0..=u16::MAX {
        let requested = bits as i16;
        assert_eq!(
            multiplex::immediate_file_events(requested),
            requested & 0x45
        );
        assert_eq!(multiplex::immediate_file_events(requested) & 0x1ba, 0);
    }
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let poll = runtime
        .split("fn poll_with_deadline(")
        .nth(1)
        .unwrap()
        .split("fn timespec_deadline(")
        .next()
        .unwrap();
    assert!(
        poll.contains(
            "const READ_EVENTS: i16 = mochios_posix_client::multiplex::NORMAL_READ_EVENTS;"
        )
    );
    assert!(poll.contains(
        "const WRITE_EVENTS: i16 = mochios_posix_client::multiplex::NORMAL_WRITE_EVENTS;"
    ));
    let compact = poll
        .split_whitespace()
        .collect::<String>()
        .replace(",)", ")");
    assert!(compact.contains("multiplex::immediate_file_events(pollfds[index].events)"));
    assert!(!poll.contains("POLLPRI"));
    assert!(!poll.contains("POLLRDBAND"));
    assert!(!poll.contains("POLLWRBAND"));
}
