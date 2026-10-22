use mnu_abi::status::Error;
use mochios_posix_client::{image_error::errno, newlib_errno};

#[test]
fn exec_format_translation_is_operation_specific_not_a_global_errno_alias() {
    use newlib_errno::ENOEXEC;
    for error in [
        Error::LimitExceeded,
        Error::InvalidAddress,
        Error::ResourceUnavailable,
        Error::BackingFailure,
        Error::InvalidArgument,
        Error::AccessDenied,
        Error::NotReady,
        Error::AlreadyExists,
        Error::NotFound,
        Error::PeerClosed,
        Error::Unsupported,
        Error::InvalidFormat,
    ] {
        let raw = error.into_raw() as i64;
        let expected = if error == Error::InvalidFormat {
            ENOEXEC
        } else {
            newlib_errno::from_status(raw)
        };
        assert_eq!(errno(raw), expected);
        assert_eq!(expected == ENOEXEC, error == Error::InvalidFormat);
    }
    let unknown = (Error::InvalidFormat.into_raw() & !0xffff) | 0xffff;
    for raw in [unknown as i64, i64::MIN, i64::MAX, 0] {
        assert_eq!(errno(raw), newlib_errno::EIO);
    }
    assert_eq!(newlib_errno::to_status(ENOEXEC), -8);
    assert_eq!(newlib_errno::from_status(-8), ENOEXEC);
    // Apply the special mapping only to image admission, not path opening,
    // capability authorization or unrelated native calls.
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let call = runtime
        .split("let result = match syscall::image::replace_bounded(")
        .nth(1)
        .unwrap();
    assert!(
        call.split("close_object_handle(opened.handle)")
            .next()
            .unwrap()
            .contains("image_error::errno(error.raw())")
    );
    assert_eq!(runtime.matches("image_error::errno(").count(), 1);
}
