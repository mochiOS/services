//! Run without input authority, including when POSIX euid is zero.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("input-authority: SKIP (requires mochiOS)");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform as p;
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    let own_endpoint = p::ipc::create().unwrap();
    assert_eq!(
        p::capability::check_thread(own_endpoint, "capabilities.manage"),
        Ok(0)
    );
    assert!(p::handle::inherited(p::input::RAW_INPUT_HANDLE_KEY).is_err());
    let address = p::process::find_by_name("input.service").unwrap();
    let mut handles = p::ipc::IpcObjectHandles::default();
    let mut reply = [0; 8];
    let message = p::ipc::call_object_handles(
        address.try_into().unwrap(),
        &p::input::RAW_ENDPOINT_REQUEST,
        &mut reply,
        &mut handles,
    )
    .unwrap();
    assert_eq!(message as u32, 8);
    assert_eq!(u64::from_le_bytes(reply), 13);
    assert_eq!(handles.count, 0);
    for packet in [
        vec![p::input::RAW_KIND_KEYBOARD, 0, 0, 0, 0x15, 0, 0, 0],
        vec![
            p::input::RAW_KIND_KEYBOARD,
            p::input::RAW_FLAG_SYNTHETIC,
            0,
            0,
            0x15,
            0,
            0,
            0,
        ],
        vec![p::input::RAW_KIND_MOUSE_PACKET, 0, 0, 0, 9, 1, 2, 0],
        vec![
            p::input::RAW_KIND_POINTER_ABSOLUTE,
            0,
            0,
            0,
            1,
            0,
            2,
            3,
            4,
            5,
            0,
            0,
        ],
    ] {
        reply.fill(0);
        let message = p::ipc::call(address, &packet, &mut reply).unwrap();
        assert_eq!(message as u32, 8);
        assert_eq!(u64::from_le_bytes(reply), 13);
        // Object-transfer IPC addressed globally is still not endpoint authority.
        let message = p::ipc::call_object_handles(
            address.try_into().unwrap(),
            &packet,
            &mut reply,
            &mut handles,
        )
        .unwrap();
        assert_eq!(message as u32, 8);
        assert_eq!(u64::from_le_bytes(reply), 13);
        assert_eq!(handles.count, 0);
    }
    println!(
        "input-authority-native: PASS raw spoof and ingress acquisition denied euid={}",
        unsafe { geteuid() }
    );
}
