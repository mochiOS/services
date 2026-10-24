use mnu_abi::provider;
use posix_service::{
    fifo::{Access, BUFFER_CAPACITY, Channel},
    fifo_provider::{Binding, handle_provider_request, native_signals},
};

fn frame(opcode: u16, id: u64, length: usize, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0; provider::REQUEST_HEADER_LEN + payload.len()];
    let count = provider::RequestHeader {
        opcode,
        object_id: id,
        argument: 0,
        basis: if opcode == provider::OP_SEEK {
            mnu_abi::HANDLE_SEEK_START
        } else {
            0
        },
        length: length as u32,
        data_length: payload.len() as u32,
    }
    .encode(payload, &mut data)
    .unwrap();
    data.truncate(count);
    data
}

fn call(
    channel: &mut Channel,
    binding: Binding,
    frame: &[u8],
    flags: u32,
    count: u32,
) -> (provider::ResponseHeader, Vec<u8>) {
    let mut response = vec![0; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];
    let length = handle_provider_request(channel, binding, frame, flags, count, &mut response)
        .unwrap()
        .unwrap();
    let (header, data) = provider::ResponseHeader::decode(&response[..length]).unwrap();
    (header, data.to_vec())
}

#[test]
fn forged_delivery_extra_handles_and_mismatched_binding_never_change_channel() {
    let mut channel = Channel::default();
    let reader = channel.open(Access::Read, true).unwrap();
    let writer = channel.open(Access::Write, true).unwrap();
    let binding = Binding::new(902, writer).unwrap();
    let write = frame(provider::OP_WRITE, 902, 3, b"new");
    for flags in [
        0,
        mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE,
        mnu_abi::IPC_DELIVERY_NATIVE_OBJECT | mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE,
    ] {
        assert_eq!(call(&mut channel, binding, &write, flags, 0).0.status, -13);
    }
    let native = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    assert_eq!(call(&mut channel, binding, &write, native, 1).0.status, -22);
    let wrong = frame(provider::OP_WRITE, 901, 3, b"new");
    assert_eq!(call(&mut channel, binding, &wrong, native, 0).0.status, -22);
    let release = frame(provider::OP_RELEASE, 902, 0, &[]);
    assert_eq!(call(&mut channel, binding, &release, 0, 0).0.status, -13);
    assert_eq!(channel.observe(reader).unwrap().writers, 1);
    assert_eq!(channel.observe(reader).unwrap().buffered_bytes, 0);
}

#[test]
fn response_capacity_is_validated_before_writes_reads_or_release() {
    let mut channel = Channel::default();
    let reader = channel.open(Access::Read, true).unwrap();
    let writer = channel.open(Access::Write, true).unwrap();
    let r = Binding::new(901, reader).unwrap();
    let w = Binding::new(902, writer).unwrap();
    let native = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    let write = frame(provider::OP_WRITE, 902, 4, b"keep");
    assert_eq!(
        handle_provider_request(
            &mut channel,
            w,
            &write,
            native,
            0,
            &mut [0; provider::RESPONSE_HEADER_LEN - 1]
        ),
        Err(-22)
    );
    assert_eq!(channel.observe(reader).unwrap().buffered_bytes, 0);
    assert_eq!(call(&mut channel, w, &write, native, 0).0.value, 4);
    let read = frame(provider::OP_READ, 901, 4, &[]);
    assert_eq!(
        handle_provider_request(
            &mut channel,
            r,
            &read,
            native,
            0,
            &mut [0; provider::RESPONSE_HEADER_LEN + 3]
        ),
        Err(-22)
    );
    assert_eq!(channel.observe(reader).unwrap().buffered_bytes, 4);
    assert_eq!(call(&mut channel, r, &read, native, 0).1, b"keep");
    let release = frame(provider::OP_RELEASE, 902, 0, &[]);
    assert_eq!(
        handle_provider_request(&mut channel, w, &release, native, 0, &mut []),
        Ok(None)
    );
    assert_eq!(channel.observe(reader).unwrap().writers, 0);
    assert_eq!(
        handle_provider_request(&mut channel, w, &release, native, 0, &mut []),
        Err(-9)
    );
}

#[test]
fn native_transfer_has_no_pager_or_positions_and_preserves_atomic_backpressure() {
    let mut channel = Channel::default();
    let reader = channel.open(Access::Read, true).unwrap();
    let writer = channel.open(Access::Write, true).unwrap();
    let r = Binding::new(901, reader).unwrap();
    let w = Binding::new(902, writer).unwrap();
    let native = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    assert_eq!(
        call(
            &mut channel,
            r,
            &frame(provider::OP_MEMORY_OBJECT, 901, 0, &[]),
            native,
            0
        )
        .0
        .value,
        0
    );
    assert_eq!(
        call(
            &mut channel,
            r,
            &frame(provider::OP_READ, 901, 1, &[]),
            native,
            0
        )
        .0
        .status,
        -11
    );
    for opcode in [
        provider::OP_SEEK,
        provider::OP_READ_AT,
        provider::OP_WRITE_AT,
        provider::OP_READ_WITH_POSITION,
        provider::OP_WRITE_BOUNDED,
    ] {
        assert_eq!(
            call(&mut channel, r, &frame(opcode, 901, 0, &[]), native, 0)
                .0
                .status,
            -29
        );
    }
    channel
        .write(writer, &vec![1; BUFFER_CAPACITY - 511])
        .unwrap();
    let write = frame(provider::OP_WRITE, 902, 512, &[2; 512]);
    assert_eq!(call(&mut channel, w, &write, native, 0).0.status, -11);
    assert_eq!(
        channel.observe(reader).unwrap().buffered_bytes,
        BUFFER_CAPACITY - 511
    );
    assert_eq!(
        call(
            &mut channel,
            r,
            &frame(provider::OP_READ, 901, 1, &[]),
            native,
            0
        )
        .1,
        [1]
    );
    assert_eq!(call(&mut channel, w, &write, native, 0).0.value, 512);
    channel.close(reader).unwrap();
    assert_eq!(call(&mut channel, w, &write, native, 0).0.status, -32);
}

#[test]
fn readiness_distinguishes_initial_eof_hangup_and_reconnected_peers() {
    let mut channel = Channel::default();
    let reader = channel.open(Access::Read, true).unwrap();
    let ready = channel.readiness(reader).unwrap();
    assert!(ready.open_ready && ready.end_of_stream);
    assert!(!ready.hangup && !ready.readable);
    assert_eq!(native_signals(ready), mnu_abi::HANDLE_SIGNAL_READABLE);
    let writer = channel.open(Access::Write, true).unwrap();
    assert_eq!(native_signals(channel.readiness(reader).unwrap()), 0);
    channel.write(writer, b"data").unwrap();
    channel.close(writer).unwrap();
    let ready = channel.readiness(reader).unwrap();
    assert!(ready.hangup && ready.readable && ready.end_of_stream);
    assert_eq!(
        native_signals(ready),
        mnu_abi::HANDLE_SIGNAL_READABLE | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED
    );
    let writer = channel.open(Access::Write, true).unwrap();
    assert!(!channel.readiness(reader).unwrap().hangup);
    channel.close(reader).unwrap();
    let ready = channel.readiness(writer).unwrap();
    assert!(ready.write_error && !ready.writable);
    assert_eq!(
        native_signals(ready),
        mnu_abi::HANDLE_SIGNAL_WRITABLE | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED
    );
    let reader = channel.open(Access::Read, true).unwrap();
    assert!(!channel.readiness(writer).unwrap().write_error);
    assert!(!channel.readiness(reader).unwrap().hangup);
}

#[test]
fn pending_open_and_wrong_direction_cannot_consume_or_produce_bytes() {
    let mut channel = Channel::default();
    let writer = channel.open(Access::Write, false).unwrap();
    let binding = Binding::new(902, writer).unwrap();
    assert_eq!(native_signals(channel.readiness(writer).unwrap()), 0);
    assert_eq!(
        call(
            &mut channel,
            binding,
            &frame(provider::OP_WRITE, 902, 1, b"x"),
            mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
            0
        )
        .0
        .status,
        -11
    );
    let reader = channel.open(Access::Read, true).unwrap();
    assert_eq!(
        call(
            &mut channel,
            binding,
            &frame(provider::OP_READ, 902, 1, &[]),
            mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
            0
        )
        .0
        .status,
        -9
    );
    assert_eq!(
        channel.read(reader, &mut [0]),
        Err(posix_service::fifo::Error::WouldBlock)
    );
}

#[test]
fn status_updates_are_shared_by_native_references_and_preserve_other_bits() {
    use mochios_filesystem_protocol::{
        OPEN_STATUS_APPEND as APPEND, OPEN_STATUS_NONBLOCK as NB, description_flags as flags,
    };
    let mut channel = Channel::default();
    let reader = channel.open(Access::Read, true).unwrap();
    let binding = Binding::new(901, reader).unwrap();
    let duplicate = Binding::new(901, reader).unwrap();
    let native = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    let request = |opcode, basis, length, payload: &[u8]| {
        let mut bytes = vec![0; provider::REQUEST_HEADER_LEN + payload.len()];
        provider::RequestHeader {
            opcode,
            object_id: 901,
            argument: 0,
            basis,
            length,
            data_length: payload.len() as u32,
        }
        .encode(payload, &mut bytes)
        .unwrap();
        bytes
    };
    let get = request(provider::OP_QUERY, flags::GET, 4, &[]);
    assert_eq!(
        call(&mut channel, binding, &get, native, 0).1,
        NB.to_le_bytes()
    );
    let set = request(
        provider::OP_CONTROL,
        flags::UPDATE,
        0,
        &flags::encode_update(APPEND, APPEND).unwrap(),
    );
    assert_eq!(call(&mut channel, binding, &set, native, 0).0.status, 0);
    assert_eq!(
        call(&mut channel, duplicate, &get, native, 0).1,
        (NB | APPEND).to_le_bytes()
    );
    let clear = request(
        provider::OP_CONTROL,
        flags::UPDATE,
        0,
        &flags::encode_update(NB, 0).unwrap(),
    );
    assert_eq!(call(&mut channel, duplicate, &clear, native, 0).0.status, 0);
    assert_eq!(
        call(&mut channel, binding, &get, native, 0).1,
        APPEND.to_le_bytes()
    );
    let bad = request(provider::OP_CONTROL, flags::UPDATE, 0, &[255; 8]);
    assert_eq!(call(&mut channel, binding, &bad, native, 0).0.status, -22);
    assert_eq!(
        call(&mut channel, binding, &get, native, 0).1,
        APPEND.to_le_bytes()
    );
    let bad = request(
        provider::OP_QUERY,
        flags::UPDATE,
        0,
        &flags::encode_update(APPEND, 0).unwrap(),
    );
    assert_eq!(call(&mut channel, binding, &bad, native, 0).0.status, -95);
    assert_eq!(
        call(&mut channel, binding, &get, native, 0).1,
        APPEND.to_le_bytes()
    );
}
