extern crate alloc;

#[allow(dead_code)]
#[path = "../../package/src/posix_io.rs"]
mod posix_io;

#[test]
fn package_reads_without_an_endpoint_fail_before_any_native_file_operation() {
    let expected = mochi_user_syscall::EAGAIN as i64;
    assert_eq!(
        posix_io::index_mpkg("/not-opened").unwrap_err().raw(),
        expected
    );
    assert_eq!(
        posix_io::read_mpkg_range("/not-opened", 0, 8)
            .unwrap_err()
            .raw(),
        expected
    );
}

#[test]
fn metadata_uses_the_open_handle_and_only_its_existing_transfer_authority() {
    let source = include_str!("../../package/src/posix_io.rs");
    assert!(source.contains("client.fstat(attachment(handle))"));
    assert!(source.contains("rights: platform::handle::HANDLE_RIGHT_TRANSFER"));
    assert!(!source.contains("handle::seek"));
    assert!(!source.contains("handle::duplicate"));
}
