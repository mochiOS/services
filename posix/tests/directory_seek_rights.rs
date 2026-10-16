#[path = "../../filesystem/src/handle_access.rs"]
mod implementation;
use mnu_abi::*;
use mochios_filesystem_protocol as wire;

#[test]
fn readable_directory_can_seek_but_never_exposes_pager_backing() {
    let rights = implementation::open_rights(wire::OPEN_AT_DIRECTORY | wire::OPEN_AT_READ);
    assert_ne!(rights & HANDLE_RIGHT_READ, 0);
    assert_ne!(rights & HANDLE_RIGHT_SEEK, 0);
    assert_eq!(rights & (HANDLE_RIGHT_MAP | HANDLE_RIGHT_WRITE), 0);
}

#[test]
fn search_only_directory_does_not_gain_cursor_or_pager_authority() {
    let rights = implementation::open_rights(wire::OPEN_AT_DIRECTORY | wire::OPEN_AT_SEARCH);
    assert_eq!(
        rights & (HANDLE_RIGHT_SEEK | HANDLE_RIGHT_MAP | HANDLE_RIGHT_WRITE),
        0
    );
}

#[test]
fn regular_file_rights_are_unchanged_for_all_access_modes() {
    let common =
        HANDLE_RIGHT_DUPLICATE | HANDLE_RIGHT_CONTROL | HANDLE_RIGHT_TRANSFER | HANDLE_RIGHT_SEEK;
    for (flags, extra) in [
        (wire::OPEN_AT_READ, HANDLE_RIGHT_READ | HANDLE_RIGHT_MAP),
        (wire::OPEN_AT_WRITE, HANDLE_RIGHT_WRITE),
        (
            wire::OPEN_AT_READ | wire::OPEN_AT_WRITE,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE | HANDLE_RIGHT_MAP,
        ),
    ] {
        assert_eq!(implementation::open_rights(flags), common | extra);
    }
}
