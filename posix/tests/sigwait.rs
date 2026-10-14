use mochios_posix_client::{Client, ClientError, Transport};
use mochios_posix_protocol as protocol;

struct SignalReply {
    signal: u64,
    status: i32,
}
impl Transport for SignalReply {
    type Error = ();
    fn call(&self, bytes: &[u8], response: &mut [u8]) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(bytes).unwrap();
        assert_eq!(header.opcode, protocol::OP_SIGNAL_THREAD_WAIT_INFO);
        assert_eq!(header.flags, 0);
        assert_eq!(
            protocol::decode_signal_wait_request(payload).unwrap(),
            (1 << 9, 23)
        );
        let mut output = [0; protocol::signal_wait::LEN];
        // Deliberately permit invalid signals to exercise client validation.
        output[..4].copy_from_slice(&(self.signal as u32).to_le_bytes());
        protocol::signal_origin::encode(
            protocol::signal_origin::Origin::system(),
            &mut output[8..],
        )
        .unwrap();
        let output = if self.status == 0 { &output[..] } else { &[] };
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                status: self.status,
                payload_len: output.len() as u32,
                ..Default::default()
            },
            output,
            response,
        )
        .map_err(|_| ())
    }
}

#[test]
fn wire_contains_only_mask_and_epoch_and_has_strict_length() {
    let mut bytes = [0; protocol::SIGNAL_WAIT_REQUEST_LEN];
    protocol::encode_signal_wait_request(1 << 63, u64::MAX, &mut bytes).unwrap();
    assert_eq!(
        protocol::decode_signal_wait_request(&bytes).unwrap(),
        (1 << 63, u64::MAX)
    );
    assert_eq!(bytes.len(), 16);
    assert!(protocol::decode_signal_wait_request(&bytes[..15]).is_err());
    assert!(protocol::decode_signal_wait_request(&[0; 17]).is_err());
    assert!(protocol::encode_signal_wait_request(0, 0, &mut bytes[..15]).is_err());
}

#[test]
fn client_accepts_selected_signal_and_propagates_interruption() {
    let client = Client::new(SignalReply {
        signal: 10,
        status: 0,
    });
    assert_eq!(client.wait_thread_signal_since(1 << 9, 23), Ok(10));
    let client = Client::new(SignalReply {
        signal: 0,
        status: protocol::STATUS_EINTR,
    });
    assert_eq!(
        client.wait_thread_signal_since(1 << 9, 23),
        Err(ClientError::Remote(protocol::STATUS_EINTR))
    );
}

#[test]
fn client_rejects_zero_out_of_range_and_unselected_backend_replies() {
    for signal in [0, 9, 12, 64, 65, u64::MAX] {
        let client = Client::new(SignalReply { signal, status: 0 });
        assert!(matches!(
            client.wait_thread_signal_since(1 << 9, 23),
            Err(ClientError::Protocol(_))
        ));
    }
}

#[test]
fn runtime_retries_unrelated_handlers_without_changing_mask_or_errno() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let implementation = source
        .split("fn sigwait(")
        .nth(1)
        .unwrap()
        .split("fn _signal_r(")
        .next()
        .unwrap();
    assert!(implementation.contains(".thread_signal_epoch()"));
    assert!(implementation.contains(".wait_thread_signal_since(mask, epoch)"));
    assert!(implementation.contains("drain_pending_signals()?"));
    assert!(implementation.contains("result.err().unwrap_or(0)"));
    assert!(!implementation.contains("set_errno("));
    assert!(!implementation.contains("service_signal_mask("));
    assert!(!implementation.contains("nonrestart_signal_generation"));
}

#[test]
fn server_retains_waits_and_services_them_before_async_notifications() {
    let source = include_str!("../src/main.rs");
    assert!(
        source
            .find("complete_pending_signal_waits(&mut pending_signal_waits")
            .unwrap()
            < source
                .find("deliver_signal_notifications(&mut service")
                .unwrap()
    );
    let initial = source
        .split("if header.opcode == protocol::OP_SIGNAL_THREAD_WAIT_INFO")
        .nth(1)
        .unwrap()
        .split("protocol::OP_WAIT_CHILD | protocol::OP_WAIT_CHILD_GUARDED")
        .next()
        .unwrap();
    assert!(initial.contains("endpoint_execution_identity(sender)"));
    assert!(initial.contains("attachments.is_empty()"));
    assert!(initial.contains("pending_signal_waits.push(PendingSignalWait"));
    assert!(
        initial.find("pending_signal_waits.len() >= 1024").unwrap()
            < initial.find("service.try_wait_signal").unwrap()
    );
    let pending = source
        .split("fn complete_pending_signal_waits(")
        .nth(1)
        .unwrap()
        .split("fn signal_wait_response(")
        .next()
        .unwrap();
    assert!(pending.contains("if result == Err(protocol::STATUS_EAGAIN)"));
    assert!(pending.contains("platform::ipc::reply(wait.sender"));
    assert!(!pending.contains("thread::yield"));
}
