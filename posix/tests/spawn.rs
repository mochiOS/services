use mochios_posix_client::spawn::{
    AttributeFlags, ExecStatus, ExecStatusError, KNOWN_ATTRIBUTE_FLAGS, PathCandidateError,
    PathSearchError, PathSearchFailure, RESET_IDS, SET_PROCESS_GROUP, SET_SCHEDULER,
    SET_SCHEDULING_PARAMETERS, SET_SIGNAL_DEFAULTS, SET_SIGNAL_MASK, build_path_candidate,
    classify_attribute_flags, classify_path_search_error, decode_exec_status, search_path,
};

#[test]
fn spawn_attribute_flags_match_the_newlib_posix_abi() {
    assert_eq!(RESET_IDS, 0x01);
    assert_eq!(SET_PROCESS_GROUP, 0x02);
    assert_eq!(SET_SCHEDULING_PARAMETERS, 0x04);
    assert_eq!(SET_SCHEDULER, 0x08);
    assert_eq!(SET_SIGNAL_DEFAULTS, 0x10);
    assert_eq!(SET_SIGNAL_MASK, 0x20);
    assert_eq!(KNOWN_ATTRIBUTE_FLAGS, 0x3f);
}

#[test]
fn spawn_attribute_support_is_explicit() {
    assert_eq!(classify_attribute_flags(0), AttributeFlags::Supported);
    assert_eq!(
        classify_attribute_flags(
            RESET_IDS | SET_PROCESS_GROUP | SET_SIGNAL_DEFAULTS | SET_SIGNAL_MASK
        ),
        AttributeFlags::Supported
    );
    assert_eq!(
        classify_attribute_flags(SET_SCHEDULING_PARAMETERS),
        AttributeFlags::RequiresScheduler
    );
    assert_eq!(
        classify_attribute_flags(SET_SCHEDULER),
        AttributeFlags::RequiresScheduler
    );
    assert_eq!(classify_attribute_flags(0x40), AttributeFlags::Invalid);
}

#[test]
fn closed_empty_spawn_status_stream_means_exec_succeeded() {
    assert_eq!(
        decode_exec_status(&[], true),
        Ok(Some(ExecStatus::Succeeded))
    );
    assert_eq!(decode_exec_status(&[], false), Ok(None));
}

#[test]
fn spawn_status_stream_preserves_child_errno() {
    let packet = 13i32.to_ne_bytes();
    assert_eq!(decode_exec_status(&packet[..2], false), Ok(None));
    assert_eq!(
        decode_exec_status(&packet, false),
        Ok(Some(ExecStatus::Failed(13)))
    );
}

#[test]
fn malformed_spawn_status_stream_is_rejected() {
    assert_eq!(
        decode_exec_status(&13i32.to_ne_bytes()[..2], true),
        Err(ExecStatusError::Truncated)
    );
    assert_eq!(
        decode_exec_status(&0i32.to_ne_bytes(), false),
        Err(ExecStatusError::InvalidErrno)
    );
    assert_eq!(
        decode_exec_status(&[1, 2, 3, 4, 5], false),
        Err(ExecStatusError::Oversized)
    );
}

#[test]
fn path_candidates_preserve_empty_and_trailing_slash_components() {
    let mut output = [0u8; 32];
    assert_eq!(build_path_candidate(b"/bin", b"tool", &mut output), Ok(9));
    assert_eq!(&output[..10], b"/bin/tool\0");
    assert_eq!(build_path_candidate(b"/bin/", b"tool", &mut output), Ok(9));
    assert_eq!(&output[..10], b"/bin/tool\0");
    assert_eq!(build_path_candidate(b"", b"tool", &mut output), Ok(4));
    assert_eq!(&output[..5], b"tool\0");
}

#[test]
fn invalid_path_candidates_are_rejected_before_exec() {
    let mut output = [0u8; 8];
    assert_eq!(
        build_path_candidate(b"/bin", b"", &mut output),
        Err(PathCandidateError::EmptyFile)
    );
    assert_eq!(
        build_path_candidate(b"/bin", b"too-long", &mut output),
        Err(PathCandidateError::TooLong)
    );
    assert_eq!(
        build_path_candidate(b"/b\0in", b"x", &mut output),
        Err(PathCandidateError::ContainsNul)
    );
}

#[test]
fn path_search_remembers_access_denial_and_stops_on_other_errors() {
    assert_eq!(classify_path_search_error(2), PathSearchError::Continue);
    assert_eq!(classify_path_search_error(20), PathSearchError::Continue);
    assert_eq!(
        classify_path_search_error(13),
        PathSearchError::ContinueWithAccessDenied
    );
    assert_eq!(classify_path_search_error(12), PathSearchError::Stop(12));
}

#[test]
fn path_search_visits_every_component_in_order() {
    let mut output = [0u8; 32];
    let mut visited = Vec::new();
    let result: Result<(), _> =
        search_path(b":/bin::/usr/bin/", b"tool", &mut output, |candidate| {
            visited.push(candidate.to_vec());
            Err(2)
        });
    assert_eq!(result, Err(PathSearchFailure::Errno(2)));
    assert_eq!(
        visited,
        vec![
            b"tool\0".to_vec(),
            b"/bin/tool\0".to_vec(),
            b"tool\0".to_vec(),
            b"/usr/bin/tool\0".to_vec(),
        ]
    );
}

#[test]
fn path_search_returns_success_and_preserves_access_denial_precedence() {
    let mut output = [0u8; 32];
    let mut attempts = 0;
    let found = search_path(b"/first:/second:/third", b"tool", &mut output, |_| {
        attempts += 1;
        if attempts == 3 { Ok(42) } else { Err(2) }
    });
    assert_eq!(found, Ok(42));
    assert_eq!(attempts, 3);

    let denied: Result<(), _> = search_path(b"/first:/second", b"tool", &mut output, |candidate| {
        if candidate.starts_with(b"/first/") {
            Err(13)
        } else {
            Err(2)
        }
    });
    assert_eq!(denied, Err(PathSearchFailure::Errno(13)));
}
