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
    assert!(runtime.contains("client.signal_image_started()"));
    assert!(runtime.contains("SIGNAL_CHILD_OPTION_NOCLDSTOP"));
    assert!(runtime.contains(".set_signal_disposition(posix_protocol::SignalDisposition"));
    let replace = runtime
        .split("fn replace_process_image(")
        .nth(1)
        .unwrap()
        .split("fn execve_with_launch_context(")
        .next()
        .unwrap();
    assert!(!replace.contains("signal_image_started"));

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

#[test]
fn newlib_delivery_uses_service_masks_and_initializes_before_installing_upcalls() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let setup = runtime
        .split("fn setup_signal_delivery(")
        .nth(1)
        .unwrap()
        .split("fn ")
        .next()
        .unwrap();
    assert!(
        setup.find("SIGNAL_MASK_INITIALIZE").unwrap() < setup.find("ThreadUpcallInstall").unwrap()
    );
    let pending = runtime
        .split("fn sigpending(")
        .nth(1)
        .unwrap()
        .split("#[unsafe(no_mangle)]")
        .next()
        .unwrap();
    assert!(pending.contains("client.thread_pending_signals()"));
    assert!(!pending.contains("signal_mask.load"));
    let delivery = runtime
        .split("fn drain_pending_signals(")
        .nth(1)
        .unwrap()
        .split("extern \"C\" fn posix_signal_upcall")
        .next()
        .unwrap();
    assert!(delivery.contains(".thread_dequeue_signal_delivery()"));
    assert!(!delivery.contains("signal_mask.load"));
    let fork = runtime
        .split("fn clone_registered_process_owned(")
        .nth(1)
        .unwrap()
        .split("struct CloneStartup")
        .next()
        .unwrap();
    assert!(fork.find("SIGNAL_MASK_QUERY").unwrap() < fork.find("capture_native").unwrap());
}
