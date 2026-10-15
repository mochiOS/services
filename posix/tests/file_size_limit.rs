use mochios_posix_client::file_size_limit::positioned_length;
use mochios_posix_protocol as wire;

#[test]
fn positioned_write_returns_exact_prefix_without_subtraction_overflow() {
    assert_eq!(
        mochios_posix_client::newlib_errno::from_status(wire::STATUS_FILE_SIZE_LIMIT as i64),
        mochios_posix_client::newlib_errno::EFBIG
    );
    for soft in 0..16u64 {
        for offset in 0..24u64 {
            for length in 0..32usize {
                let expected = if length == 0 {
                    Some(0)
                } else if offset >= soft {
                    None
                } else {
                    Some(length.min((soft - offset) as usize))
                };
                assert_eq!(positioned_length(offset, length, soft), expected);
            }
        }
    }
    assert_eq!(positioned_length(u64::MAX, 0, 0), Some(0));
    assert_eq!(positioned_length(u64::MAX, 1, 0), None);
    assert_eq!(positioned_length(u64::MAX - 2, 10, u64::MAX - 1), Some(1));
    assert_eq!(positioned_length(0, usize::MAX, 1), Some(1));
    // Infinity is not a finite cap: native range validation handles overflow.
    assert_eq!(positioned_length(u64::MAX, 1, wire::RLIM_INFINITY), Some(1));
}

#[test]
fn special_files_keep_their_kind_and_authority_requirement_across_handoff() {
    let metadata = wire::InheritedFdMetadata {
        kind: wire::INHERITED_FD_KIND_SPECIAL,
        open_flags: 2 | 8,
        descriptor_flags: wire::INHERITED_FD_DESCRIPTOR_CLOEXEC,
    };
    let encoded = wire::encode_inherited_fd_metadata(metadata).unwrap();
    assert_eq!(wire::decode_inherited_fd_metadata(encoded), Some(metadata));
    assert_eq!(
        wire::inherited_fd_kind_requires_handle(metadata.kind),
        Some(true)
    );
    assert_ne!(metadata.kind, wire::INHERITED_FD_KIND_FILE);
}

#[test]
fn runtime_checks_access_and_size_limited_object_kind_before_policy_or_signal() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let positioned = runtime
        .split("fn positioned_file_io(")
        .nth(1)
        .unwrap()
        .split("pub extern \"C\" fn pread(")
        .next()
        .unwrap();
    assert!(
        positioned.find("if !allowed").unwrap()
            < positioned.find("resource_policy::read(").unwrap()
    );
    assert!(positioned.contains("FdKind::ObjectFile | FdKind::ObjectSharedMemory"));
    assert!(
        positioned
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .contains("write && length != 0")
    );
    assert!(positioned.contains("generate_thread_signal(posix_protocol::SIGNAL_XFSZ)?"));
    assert!(positioned.contains("return Err(EFBIG)"));
    assert!(!positioned.contains("HandleSeek"));
    assert!(runtime.contains("0o100000 => FdKind::ObjectFile"));
    assert!(runtime.contains("_ => FdKind::ObjectSpecial"));
}
