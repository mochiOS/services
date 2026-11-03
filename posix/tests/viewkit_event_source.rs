#[path = "../../../libraries/viewkit/src/platform/mochios/event_source.rs"]
mod source;

#[test]
fn all_window_input_focus_close_and_frame_events_require_the_connected_sender() {
    for kind in 2u32..=14 {
        for length in [16, 24, 32] {
            let mut bytes = vec![0; length];
            bytes[..4].copy_from_slice(&kind.to_le_bytes());
            if length >= 24 {
                bytes[16..24].copy_from_slice(&99u64.to_le_bytes());
            }
            assert!(source::accepts(7, 7, &bytes));
            assert!(!source::accepts(8, 7, &bytes));
            assert!(!source::accepts(0, 7, &bytes));
        }
    }
}
#[test]
fn app_protocols_and_wake_notifications_keep_their_separate_admission_boundary() {
    for bytes in [
        b"VKUIWAKE00000000".as_slice(),
        b"MCNCMD01",
        b"workspace-document",
    ] {
        assert!(!source::compositor_event(bytes));
        assert!(source::accepts(8, 7, bytes));
    }
}
