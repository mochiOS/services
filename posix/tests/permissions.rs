use filesystem_service::service::permission_allows;
use mochios_filesystem_protocol as filesystem;

#[test]
fn owner_group_and_other_permissions_are_selected_exclusively() {
    let mode = 0o640;
    assert!(permission_allows(
        mode,
        filesystem::NODE_TYPE_REGULAR,
        501,
        20,
        501,
        99,
        &[],
        filesystem::ACCESS_AT_READ | filesystem::ACCESS_AT_WRITE,
    ));
    assert!(!permission_allows(
        mode,
        filesystem::NODE_TYPE_REGULAR,
        501,
        20,
        501,
        20,
        &[],
        filesystem::ACCESS_AT_EXECUTE,
    ));
    assert!(permission_allows(
        mode,
        filesystem::NODE_TYPE_REGULAR,
        501,
        20,
        777,
        20,
        &[],
        filesystem::ACCESS_AT_READ,
    ));
    assert!(!permission_allows(
        mode,
        filesystem::NODE_TYPE_REGULAR,
        501,
        20,
        777,
        99,
        &[],
        filesystem::ACCESS_AT_READ,
    ));
}

#[test]
fn existence_checks_do_not_require_permission_bits() {
    assert!(permission_allows(
        0,
        filesystem::NODE_TYPE_REGULAR,
        501,
        20,
        777,
        99,
        &[],
        0,
    ));
}

#[test]
fn root_execute_still_requires_an_executable_file_or_directory() {
    assert!(!permission_allows(
        0o600,
        filesystem::NODE_TYPE_REGULAR,
        501,
        20,
        0,
        0,
        &[],
        filesystem::ACCESS_AT_EXECUTE,
    ));
    assert!(permission_allows(
        0o601,
        filesystem::NODE_TYPE_REGULAR,
        501,
        20,
        0,
        0,
        &[],
        filesystem::ACCESS_AT_EXECUTE,
    ));
    assert!(permission_allows(
        0,
        filesystem::NODE_TYPE_DIRECTORY,
        501,
        20,
        0,
        0,
        &[],
        filesystem::ACCESS_AT_EXECUTE,
    ));
}

#[test]
fn supplementary_group_selects_group_permissions() {
    assert!(permission_allows(
        0o640,
        filesystem::NODE_TYPE_REGULAR,
        501,
        20,
        777,
        99,
        &[20, 80],
        filesystem::ACCESS_AT_READ,
    ));
    assert!(!permission_allows(
        0o640,
        filesystem::NODE_TYPE_REGULAR,
        501,
        20,
        777,
        99,
        &[80],
        filesystem::ACCESS_AT_READ,
    ));
}
