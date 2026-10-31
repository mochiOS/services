#![allow(dead_code)]
use mochios_posix_protocol as posix_protocol;
use std::ffi::c_int;
const EIO: c_int = 5;
const ENOENT: c_int = 2;
#[path = "../../../user/crates/newlib-runtime/src/executable_name_snapshot.rs"]
mod production;

#[test]
fn snapshot_owns_non_utf8_absolute_path_and_a_terminator() {
    let mut source = b"/directory/program-\xff".to_vec();
    let snapshot = production::Name::capture(|output| {
        output[..source.len()].copy_from_slice(&source);
        Ok(source.len())
    });
    source.fill(b'x');
    assert_eq!(snapshot.value(), Ok(b"/directory/program-\xff".as_slice()));
    assert_eq!(snapshot.bytes[snapshot.value().unwrap().len()], 0);
}

#[test]
fn missing_and_failed_metadata_is_an_error_not_an_environment_fallback() {
    assert_eq!(production::Name::empty().value(), Err(ENOENT));
    for errno in [1, 2, 13, 38] {
        assert_eq!(
            production::Name::capture(|_| Err(errno)).value(),
            Err(errno)
        );
    }
    assert_eq!(production::Name::capture(|_| Err(0)).value(), Err(EIO));
}

#[test]
fn malformed_or_oversized_metadata_cannot_be_published_as_a_c_string() {
    for text in [b"".as_slice(), b"relative", b"/with\0nul"] {
        assert_eq!(
            production::Name::capture(|output| {
                output[..text.len()].copy_from_slice(text);
                Ok(text.len())
            })
            .value(),
            Err(EIO)
        );
    }
    assert_eq!(
        production::Name::capture(|_| Ok(posix_protocol::MAX_PATH_LEN + 1)).value(),
        Err(EIO)
    );
    let snapshot = production::Name::capture(|output| {
        output.fill(b'x');
        output[0] = b'/';
        Ok(output.len())
    });
    assert_eq!(
        snapshot.value().unwrap().len(),
        posix_protocol::MAX_PATH_LEN
    );
    assert_eq!(snapshot.bytes[posix_protocol::MAX_PATH_LEN], 0);
}
