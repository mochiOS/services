use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment as Handle, ObjectHandles, ObjectTransport,
    Transport,
};
use mochios_posix_protocol::{self as wire, OPEN_APPEND, OPEN_NONBLOCK, ProtocolError};
use std::cell::Cell;

struct Mock {
    calls: Cell<usize>,
    status: i32,
    fail: bool,
    mismatch: bool,
    incoming: Vec<Handle<u32>>,
}
impl Transport for &Mock {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("explicit Handle required")
    }
}
impl ObjectTransport for &Mock {
    type Handle = u32;

    fn close_received_handle(&self, _: u32) {
        panic!("unexpected owned reply Handle in this fixture");
    }
    fn call_with_handles(
        &self,
        input: &[u8],
        output: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = wire::decode(input).unwrap();
        assert_eq!(header.opcode, wire::OP_FUPDATEFL);
        assert_eq!(
            wire::decode_file_flags_update(payload),
            Ok((OPEN_NONBLOCK, OPEN_NONBLOCK))
        );
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0),
            Some(Handle {
                handle: source().handle,
                rights: mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_TRANSFER,
            })
        );
        self.calls.set(self.calls.get() + 1);
        handles.clear();
        for handle in &self.incoming {
            handles.push(*handle).unwrap();
        }
        if self.fail {
            return Err(());
        }
        wire::encode(
            wire::Header {
                opcode: wire::OP_STATUS,
                request_id: header.request_id + u64::from(self.mismatch),
                status: self.status,
                ..Default::default()
            },
            &[],
            output,
        )
        .map_err(|_| ())
    }
}
fn source() -> Handle<u32> {
    Handle {
        handle: 7,
        rights: mnu_abi::HANDLE_RIGHT_TRANSFER
            | mnu_abi::HANDLE_RIGHT_READ
            | mnu_abi::HANDLE_RIGHT_CONTROL,
    }
}
fn mock() -> Mock {
    Mock {
        calls: Cell::new(0),
        status: 0,
        fail: false,
        mismatch: false,
        incoming: vec![],
    }
}

#[test]
fn masked_flag_codec_rejects_partial_unknown_and_out_of_mask_values() {
    for (mask, flags) in [
        (0, 0),
        (OPEN_NONBLOCK, 0),
        (OPEN_NONBLOCK, OPEN_NONBLOCK),
        (OPEN_APPEND | OPEN_NONBLOCK, OPEN_APPEND),
    ] {
        let mut bytes = [0; wire::FILE_FLAGS_UPDATE_PAYLOAD_LEN];
        wire::encode_file_flags_update(mask, flags, &mut bytes).unwrap();
        assert_eq!(wire::decode_file_flags_update(&bytes), Ok((mask, flags)));
        for length in 0..bytes.len() {
            assert!(wire::decode_file_flags_update(&bytes[..length]).is_err());
        }
        assert!(wire::decode_file_flags_update(&[bytes.as_slice(), &[0]].concat()).is_err());
    }
    for (mask, flags) in [
        (0, OPEN_NONBLOCK),
        (OPEN_NONBLOCK, OPEN_APPEND),
        (u32::MAX, 0),
    ] {
        let mut bytes = [0; 8];
        assert_eq!(
            wire::encode_file_flags_update(mask, flags, &mut bytes),
            Err(ProtocolError::InvalidLength)
        );
        bytes[..4].copy_from_slice(&mask.to_le_bytes());
        bytes[4..].copy_from_slice(&flags.to_le_bytes());
        assert!(wire::decode_file_flags_update(&bytes).is_err());
    }
}

#[test]
fn update_is_one_rpc_with_explicit_authority_not_client_side_read_modify_write() {
    let mock = mock();
    let client = Client::new(&mock);
    assert_eq!(
        client.update_status_flags(source(), OPEN_NONBLOCK, OPEN_NONBLOCK, |_| panic!(
            "borrowed source"
        )),
        Ok(())
    );
    assert_eq!(mock.calls.get(), 1);
}

#[test]
fn malformed_replies_release_only_distinct_new_references_without_replaying() {
    for case in 0..4 {
        let mut mock = mock();
        mock.incoming = vec![
            Handle {
                handle: 42,
                rights: 1,
            },
            Handle {
                handle: 42,
                rights: 1,
            },
            source(),
            Handle {
                handle: 0,
                rights: 0,
            },
        ];
        mock.fail = case == 1;
        mock.mismatch = case == 2;
        mock.status = if case == 3 { -13 } else { 0 };
        let client = Client::new(&mock);
        let mut closed = Vec::new();
        let result = client.update_status_flags(source(), OPEN_NONBLOCK, OPEN_NONBLOCK, |handle| {
            closed.push(handle)
        });
        assert_eq!(
            result,
            Err(if mock.fail {
                ClientError::Transport(())
            } else {
                ClientError::MismatchedResponse
            })
        );
        assert_eq!(closed, [42]);
        assert_eq!(mock.calls.get(), 1);
    }
    let mut mock = mock();
    mock.status = -13;
    assert_eq!(
        Client::new(&mock).update_status_flags(
            source(),
            OPEN_NONBLOCK,
            OPEN_NONBLOCK,
            |_| panic!()
        ),
        Err(ClientError::Remote(-13))
    );
}

#[test]
fn invalid_flags_and_missing_transfer_authority_do_not_issue_ipc() {
    let mock = mock();
    let client = Client::new(&mock);
    for (source, mask, flags) in [
        (
            Handle {
                rights: source().rights & !mnu_abi::HANDLE_RIGHT_CONTROL,
                ..source()
            },
            OPEN_NONBLOCK,
            0,
        ),
        (source(), 0, OPEN_NONBLOCK),
        (
            Handle {
                handle: 7,
                rights: 1,
            },
            OPEN_NONBLOCK,
            0,
        ),
        (
            Handle {
                handle: 0,
                rights: u64::MAX,
            },
            OPEN_NONBLOCK,
            0,
        ),
    ] {
        assert!(
            client
                .update_status_flags(source, mask, flags, |_| panic!())
                .is_err()
        );
    }
    assert_eq!(mock.calls.get(), 0);
}
