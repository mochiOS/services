#[path = "../../../user/crates/posix-client/src/newlib_errno.rs"]
mod errno;

#[test]
fn supported_wire_errors_round_trip_through_the_target_c_namespace() {
    for wire in (1..=14).chain(16..=34).chain([
        35, 36, 37, 38, 39, 40, 42, 43, 60, 61, 62, 63, 67, 71, 72, 74, 75, 84, 88, 89, 90, 91, 92,
        93, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 110, 111, 112, 113, 114,
        115, 116, 122, 125, 130, 131,
    ]) {
        let c_errno = errno::from_status(-i64::from(wire));
        assert_eq!(errno::to_status(c_errno), -wire, "C errno={c_errno}");
    }
}

#[test]
fn overlapping_numbers_are_not_native_or_wire_statuses() {
    for (c_errno, wire) in [
        (91, -36),
        (88, -38),
        (134, -95),
        (139, -75),
        (95, -95),
        (36, -43),
    ] {
        assert_eq!(errno::to_status(c_errno), wire);
    }
    for invalid in [0, -1, -91, i32::MIN, i32::MAX, 65535] {
        assert_eq!(errno::to_status(invalid), -5);
    }
}
