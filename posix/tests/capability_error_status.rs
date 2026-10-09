use mochi_user_platform::syscall::{self, SysError};

#[test]
fn native_error_constants_are_raw_negative_statuses_not_positive_errno() {
    for (status, errno) in [
        (syscall::ENOENT, 2),
        (syscall::EEXIST, 17),
        (syscall::EACCES, 13),
    ] {
        let error = SysError::from_raw(status as i64);
        assert_eq!(error.raw(), -(errno as i64));
        assert_eq!(error.errno(), Some(errno));
        assert_ne!(error.errno(), Some(status));
    }
}

#[test]
fn capability_file_error_branches_compare_raw_statuses() {
    for source in [
        include_str!("../../capability/src/persistent_grant.rs"),
        include_str!("../../capability/src/resolver.rs"),
    ] {
        assert!(!source.contains("error.errno() == Some(mochi_user_syscall::"));
        assert!(!source.contains("error.errno() != Some(mochi_user_syscall::"));
        assert!(source.contains("error.raw() == mochi_user_syscall::ENOENT as i64"));
    }
    assert!(
        include_str!("../../capability/src/persistent_grant.rs")
            .contains("error.raw() != mochi_user_syscall::EEXIST as i64")
    );
}
