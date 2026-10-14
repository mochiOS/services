use mochios_posix_client::socket::{
    MSG_DONTWAIT, MSG_NOSIGNAL, MSG_PEEK, MSG_WAITALL, ReceiveError, message_options, receive,
};

#[test]
fn message_flags_are_call_local_and_unsupported_semantics_are_explicit() {
    for sending in [false, true] {
        let options = message_options(MSG_DONTWAIT, sending).unwrap();
        assert!(options.dont_wait);
        assert!(!options.wait_all && !options.no_signal);
        assert!(!options.peek);
        for unsupported in [1, 4, 0x8000, -1, 0x10000] {
            assert_eq!(message_options(unsupported, sending), Err(-95));
        }
    }
    assert!(
        message_options(MSG_NOSIGNAL | MSG_DONTWAIT, true)
            .unwrap()
            .no_signal
    );
    assert!(
        message_options(MSG_WAITALL | MSG_DONTWAIT, false)
            .unwrap()
            .wait_all
    );
    assert_eq!(message_options(MSG_WAITALL, true), Err(-95));
    assert_eq!(message_options(MSG_NOSIGNAL, false), Err(-95));
    assert_eq!(message_options(MSG_PEEK, true), Err(-95));
    let options = message_options(MSG_PEEK | MSG_WAITALL | MSG_DONTWAIT, false).unwrap();
    assert!(options.peek && options.wait_all && options.dont_wait && !options.no_signal);
}

#[test]
fn ordinary_receive_stops_after_first_transfer_and_zero_never_calls_backend() {
    assert_eq!(
        receive(0, true, |_, _| -> Result<usize, ()> { panic!("zero read") }),
        Ok(0)
    );
    assert_eq!(
        receive(8, false, |offset, length| -> Result<usize, ()> {
            assert_eq!((offset, length), (0, 8));
            Ok(3)
        }),
        Ok(3)
    );
}

#[test]
fn wait_all_tracks_offsets_and_preserves_prefix_on_eof_or_error() {
    let mut outcomes = [Ok(3), Ok(2), Ok(3)].into_iter();
    let mut offsets = Vec::new();
    assert_eq!(
        receive(8, true, |offset, remaining| -> Result<usize, i32> {
            offsets.push((offset, remaining));
            outcomes.next().unwrap()
        }),
        Ok(8)
    );
    assert_eq!(offsets, [(0, 8), (3, 5), (5, 3)]);
    for final_result in [Ok(0), Err(11), Err(4), Err(5)] {
        let mut results = [Ok(3), final_result].into_iter();
        assert_eq!(receive(8, true, |_, _| results.next().unwrap()), Ok(3));
    }
    assert_eq!(
        receive(8, true, |_, _| Err::<usize, _>(11)),
        Err(ReceiveError::Io(11))
    );
    assert_eq!(receive(8, true, |_, _| Ok::<_, ()>(0)), Ok(0));
}

#[test]
fn invalid_transfer_counts_cannot_overflow_or_erase_committed_progress() {
    assert_eq!(
        receive(8, true, |_, _| Ok::<_, ()>(9)),
        Err(ReceiveError::InvalidResult)
    );
    let mut results = [Ok::<_, ()>(3), Ok(6)].into_iter();
    assert_eq!(receive(8, true, |_, _| results.next().unwrap()), Ok(3));
}
