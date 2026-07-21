extern crate alloc;

#[path = "../src/driver_matcher.rs"]
mod driver_matcher;

use driver_matcher::{DriverSearchRoot, MatchResult};

fn usb_match(package_id: &str) -> MatchResult {
    driver_matcher::matches(
        DriverSearchRoot::Usb,
        package_id,
        Some("usb"),
        Some("pci"),
        Some("usb"),
    )
}

fn i8042_match(root: DriverSearchRoot, package_id: &str) -> MatchResult {
    driver_matcher::matches(
        root,
        package_id,
        Some("input"),
        Some("platform"),
        Some("i8042"),
    )
}

#[test]
fn i8042_package_id_matches_in_ps2_root() {
    assert_eq!(
        i8042_match(DriverSearchRoot::Ps2, "org.mochios.ps2.i8042"),
        MatchResult::Matched
    );
}

#[test]
fn wrong_package_id_is_rejected() {
    assert_eq!(
        i8042_match(DriverSearchRoot::Ps2, "org.mochios.ps2.other"),
        MatchResult::PackageIdMismatch
    );
}

#[test]
fn i8042_package_is_rejected_in_usb_root() {
    assert_eq!(
        i8042_match(DriverSearchRoot::Usb, "org.mochios.ps2.i8042"),
        MatchResult::PackageIdMismatch
    );
}

#[test]
fn valid_usb_bundle_matches_in_usb_root() {
    assert_eq!(usb_match("org.mochios.usb.qemu"), MatchResult::Matched);
}

#[test]
fn unknown_package_id_is_rejected() {
    assert_eq!(
        usb_match("org.mochios.usb.unknown"),
        MatchResult::PackageIdMismatch
    );
}

#[test]
fn required_match_fields_are_enforced_in_order() {
    assert_eq!(
        driver_matcher::matches(
            DriverSearchRoot::Ps2,
            "org.mochios.ps2.i8042",
            None,
            Some("platform"),
            Some("i8042")
        ),
        MatchResult::DriverClassMismatch
    );
    assert_eq!(
        driver_matcher::matches(
            DriverSearchRoot::Ps2,
            "org.mochios.ps2.i8042",
            Some("input"),
            None,
            Some("i8042")
        ),
        MatchResult::MatchBusMismatch
    );
    assert_eq!(
        driver_matcher::matches(
            DriverSearchRoot::Ps2,
            "org.mochios.ps2.i8042",
            Some("input"),
            Some("platform"),
            None
        ),
        MatchResult::MatchClassMismatch
    );
}
