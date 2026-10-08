use mochios_posix_client::signal;
use mochios_posix_protocol::{SIGNAL_KILL, SIGNAL_STOP};

#[test]
fn signal_masks_are_thread_local_policy_and_never_block_kill_or_stop() {
    let requested = signal::signal_bit(2).unwrap()
        | signal::signal_bit(SIGNAL_KILL).unwrap()
        | signal::signal_bit(SIGNAL_STOP).unwrap();
    let blocked = signal::update_mask(0, signal::SIGNAL_BLOCK, requested).unwrap();
    assert_eq!(blocked, signal::signal_bit(2).unwrap());
    assert_eq!(
        signal::update_mask(blocked, signal::SIGNAL_UNBLOCK, requested),
        Some(0)
    );
    assert_eq!(
        signal::update_mask(blocked, signal::SIGNAL_SET_MASK, requested),
        Some(signal::signal_bit(2).unwrap())
    );
    assert_eq!(signal::update_mask(0, 99, requested), None);
}

#[test]
fn child_signal_options_are_synced_and_reset_on_process_image_entry() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(runtime.contains("client.set_signal_child_options(0)"));
    assert!(runtime.contains("SIGNAL_CHILD_OPTION_NOCLDSTOP"));
    assert!(runtime.contains(".set_signal_child_options(options)"));

    let kernel = include_str!("../../../core/src/syscall/handle.rs");
    assert!(!kernel.contains("NOCLDSTOP"));
}

#[test]
fn kill_and_stop_dispositions_cannot_be_replaced() {
    assert!(signal::can_change_disposition(1));
    assert!(!signal::can_change_disposition(0));
    assert!(!signal::can_change_disposition(SIGNAL_KILL));
    assert!(!signal::can_change_disposition(SIGNAL_STOP));
    assert!(!signal::can_change_disposition(65));
}
