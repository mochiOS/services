//! Native negative probes run by the existing manager after Binder is ready.
use mochi_user_platform as p;
use p::capability::input_authority as w;
pub fn run(raw: u32) {
    let input = p::process::find_by_name("input.service").unwrap();
    let broker = p::process::find_by_name("capability.service").unwrap();
    let mut bytes = [0; w::EVENT_BYTES];
    let message = p::ipc::call(
        broker,
        &u32::from_le_bytes(*b"ID06").to_le_bytes(),
        &mut bytes,
    )
    .unwrap();
    assert_eq!(message >> 32, broker);
    assert_eq!(message as u32 as usize, w::EVENT_BYTES);
    let forged = w::decode_event(&bytes).unwrap();
    let mut reply = [0; 8];
    let message = p::ipc::call(broker, &bytes, &mut reply).unwrap();
    assert_eq!(message as u32, 8);
    assert_eq!(u64::from_le_bytes(reply), 13);
    for command in [
        w::Command::Register,
        w::Command::Arm {
            generation: forged.generation,
            correlation: forged.correlation,
        },
    ] {
        let mut reply = [0; w::REPLY_BYTES];
        let message =
            p::ipc::call(input, &w::encode_command(command).unwrap(), &mut reply).unwrap();
        assert_eq!(message >> 32, input);
        assert_eq!(message as u32 as usize, reply.len());
        assert_eq!(
            w::decode_reply(&reply).unwrap().status,
            13,
            "another capabilities.manage process cannot replace the registered owner"
        );
    }
    for byte in [0x15, 0x95] {
        let packet = [
            p::input::RAW_KIND_KEYBOARD,
            p::input::RAW_FLAG_SYNTHETIC,
            0,
            0,
            byte,
            0,
            0,
            0,
        ];
        let mut attached = p::ipc::IpcObjectHandles::default();
        let message = p::ipc::call_object_handles(raw, &packet, &mut reply, &mut attached).unwrap();
        assert_eq!(message as u32, 1);
        assert_eq!(reply[0], 0);
        assert_eq!(attached.count, 0);
    }
    println!(
        "consent-input-306: PASS forged sender and foreign owner refused; synthetic y sent; awaiting physical y"
    );
}
