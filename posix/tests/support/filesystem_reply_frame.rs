use super::*;
use mochios_filesystem_protocol as wire;
use posix_service::filesystem_transport::reply_frame;

fn encoded(header: wire::Header, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; wire::HEADER_LEN + payload.len()];
    wire::encode(header, payload, &mut bytes).unwrap();
    bytes
}
fn status() -> wire::Header {
    wire::Header {
        opcode: wire::OP_STATUS,
        request_id: 71,
        ..Default::default()
    }
}
#[test]
fn decodes_exact_delivered_bytes_with_native_sender_in_high_word() {
    for payload in [b"".as_slice(), b"/canonical", &[0; wire::NODE_STATUS_LEN]] {
        let mut bytes = encoded(
            wire::Header {
                length: payload.len() as u32,
                ..status()
            },
            payload,
        );
        let length = bytes.len();
        bytes.resize(length + 32, 0xa5);
        for sender in [0, 1, 17, u32::MAX] {
            let result = ((sender as u64) << 32) | length as u64;
            let (header, decoded) = reply_frame(&bytes, result, 71).unwrap();
            assert_eq!(header.request_id, 71);
            assert_eq!(decoded, payload);
        }
    }
}
#[test]
fn refuses_zero_padding_stale_suffix_and_extra_delivered_bytes() {
    let bytes = encoded(
        wire::Header {
            length: 8,
            ..status()
        },
        b"/payload",
    );
    // Every truncated prefix fails even when the backing capacity contains a
    // complete valid-looking header and payload from this or a previous call.
    for received in 0..bytes.len() {
        assert!(
            reply_frame(&bytes, received as u64, 71).is_err(),
            "{received}"
        );
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(reply_frame(&extra, extra.len() as u64, 71).is_err());
    assert!(reply_frame(&bytes, (bytes.len() + 1) as u64, 71).is_err());
    assert!(reply_frame(&bytes, u32::MAX as u64, 71).is_err());
}
#[test]
fn refuses_wrong_id_opcode_version_magic_positive_status_and_error_payload() {
    for header in [
        wire::Header {
            request_id: 72,
            ..status()
        },
        wire::Header {
            opcode: wire::OP_STAT_AT,
            ..status()
        },
        wire::Header {
            status: 13,
            ..status()
        },
    ] {
        let bytes = encoded(header, &[]);
        assert!(reply_frame(&bytes, bytes.len() as u64, 71).is_err());
    }
    for offset in [0, 4] {
        let mut bytes = encoded(status(), &[]);
        bytes[offset] ^= 0xff;
        assert!(reply_frame(&bytes, bytes.len() as u64, 71).is_err());
    }
    let bytes = encoded(
        wire::Header {
            status: -13,
            length: 1,
            ..status()
        },
        &[1],
    );
    assert!(reply_frame(&bytes, bytes.len() as u64, 71).is_err());
}
#[test]
fn negative_operation_errors_remain_errors_not_transport_failures() {
    for error in [-2, -13, -5, -wire::ERROR_MEMORY_ADMISSION_BUSY] {
        let bytes = encoded(
            wire::Header {
                status: error,
                ..status()
            },
            &[],
        );
        assert_eq!(
            reply_frame(&bytes, bytes.len() as u64, 71)
                .unwrap()
                .0
                .status,
            error
        );
    }
}
#[test]
fn malformed_received_frame_does_not_hide_receiver_owned_handles() {
    let original = borrowed();
    let mut handles = original;
    let mut reply = encoded(
        wire::Header {
            request_id: 72,
            ..status()
        },
        &[],
    );
    let result = call_native(&mut handles, |received| {
        received.count = 1;
        received.handles[0] = IpcObjectHandle {
            handle: 90,
            reserved: 0,
            rights: HANDLE_RIGHT_TRANSFER,
        };
        Ok::<_, i32>(reply.len() as u64)
    })
    .unwrap();
    assert!(reply_frame(&reply, result, 71).is_err());
    // Framing failure is NOT native send failure: cleanup must still see 90.
    assert_eq!(handles.count, 1);
    assert_eq!(handles.handles[0].handle, 90);
    reply.clear();
    assert_eq!(original.handles[0].handle, 7);
}
