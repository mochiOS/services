use mochios_posix_client::{
    ClientError, ObjectHandleAttachment as Handle, ObjectHandles, ObjectTransport, Transport,
    fd::{Entry, FD_CLOEXEC, FdTable},
    socket_transfer,
};
use mochios_posix_protocol::{InheritedFdMetadata, socket::Address, socket_transfer as wire};
use std::cell::Cell;

struct Mock {
    request: wire::Request,
    outgoing: Vec<Handle<u32>>,
    bytes: Vec<u8>,
    incoming: Vec<Handle<u32>>,
    result: Result<usize, ()>,
    calls: Cell<usize>,
}
impl Transport for Mock {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("explicit attachments required")
    }
}
impl ObjectTransport for Mock {
    type Handle = u32;

    fn close_received_handle(&self, _: u32) {
        panic!("unexpected owned reply Handle in this fixture");
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(wire::decode(request), Ok(self.request));
        assert_eq!(handles.iter().collect::<Vec<_>>(), self.outgoing);
        handles.clear();
        for item in &self.incoming {
            handles.push(*item).unwrap();
        }
        response[..self.bytes.len()].copy_from_slice(&self.bytes);
        self.result
    }
}
fn object(handle: u32, rights: u64) -> Handle<u32> {
    Handle { handle, rights }
}
fn source(handle: u32) -> Handle<u32> {
    object(handle, mnu_abi::HANDLE_RIGHT_ALL)
}
fn metadata() -> InheritedFdMetadata {
    InheritedFdMetadata {
        kind: 5,
        open_flags: 0,
        descriptor_flags: 0,
    }
}
fn receive_mock(total: u16, maximum: u16) -> Mock {
    let message = wire::ReceiveReply {
        end_of_record: false,
        copied: 3,
        length: 8,
        total_rights: total,
        available_rights: total.min(maximum),
        source: Address::UnixPath(b"/sender"),
    };
    let mut bytes = vec![0; wire::MAX_RECEIVE_REPLY_LEN];
    let size = message.encode(3, maximum, &mut bytes).unwrap();
    bytes.truncate(size);
    Mock {
        request: wire::Request::Receive {
            offset: 7,
            length: 3,
            maximum_rights: maximum,
        },
        outgoing: vec![
            object(10, mnu_abi::HANDLE_RIGHT_READ),
            object(20, mnu_abi::HANDLE_RIGHT_WRITE | mnu_abi::HANDLE_RIGHT_MAP),
        ],
        bytes,
        incoming: if message.available_rights != 0 {
            vec![object(42, wire::RIGHTS)]
        } else {
            vec![]
        },
        result: Ok(size),
        calls: Cell::new(0),
    }
}
fn delivery_mock(offset: u16, count: u16) -> Mock {
    let mut bytes = vec![0; wire::MAX_DELIVERY_REPLY_LEN];
    let size = wire::delivery_reply(offset, &vec![metadata(); count as usize], &mut bytes).unwrap();
    bytes.truncate(size);
    Mock {
        request: wire::Request::Deliver { offset, maximum: 4 },
        outgoing: vec![object(42, mnu_abi::HANDLE_RIGHT_CONTROL)],
        bytes,
        incoming: (0..count)
            .map(|index| {
                object(
                    1000 + (offset + index) as u32,
                    mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
                )
            })
            .collect(),
        result: Ok(size),
        calls: Cell::new(0),
    }
}

fn peek_mock(total: u16, maximum: u16) -> Mock {
    let mut mock = receive_mock(total, maximum);
    mock.request = wire::Request::Peek {
        offset: 7,
        length: 3,
        maximum_rights: maximum,
    };
    mock.bytes[6..8].copy_from_slice(&6u16.to_le_bytes());
    mock
}

#[test]
fn peek_uses_read_authority_and_returns_a_mode_bound_independently_owned_receipt() {
    for (total, maximum) in [(0, 253), (253, 0), (253, 2), (253, 253)] {
        let mock = peek_mock(total, maximum);
        let mut response = [0; wire::MAX_RECEIVE_REPLY_LEN];
        let received = socket_transfer::peek(
            &mock,
            source(10),
            source(20),
            7,
            3,
            maximum,
            &mut response,
            |_| panic!("successful owned receipt"),
        )
        .unwrap();
        assert_eq!(received.message.total_rights, total);
        assert_eq!(received.message.available_rights, total.min(maximum));
        assert_eq!(received.receipt, mock.incoming.first().copied());
        assert_eq!(mock.calls.get(), 1);
    }
}

#[test]
fn peek_failures_close_only_new_references_and_never_retry_the_rpc() {
    for case in 0..14 {
        let mut mock = peek_mock(2, 2);
        match case {
            0 => mock.incoming.clear(),
            1 => mock.incoming[0].rights |= mnu_abi::HANDLE_RIGHT_WRITE,
            2 => mock.incoming.push(mock.incoming[0]),
            3 => mock.incoming[0].handle = 0,
            4 => mock.incoming[0].handle = 10,
            5 => mock.incoming[0].handle = 20,
            6 => mock.bytes[0] ^= 1,
            7 => mock.bytes[18] = 1,
            8 => mock.result = Err(()),
            9 => mock.result = Ok(wire::MAX_RECEIVE_REPLY_LEN + 1),
            10 => {
                mock.bytes = (-11i32).to_le_bytes().to_vec();
                mock.result = Ok(4);
            }
            11 => mock.result = Ok(0),
            12 => mock.bytes[6..8].copy_from_slice(&4u16.to_le_bytes()),
            13 => mock.bytes[4] = 2,
            _ => unreachable!(),
        }
        let mut expected: Vec<_> = mock
            .incoming
            .iter()
            .map(|item| item.handle)
            .filter(|handle| ![0, 10, 20].contains(handle))
            .collect();
        expected.sort();
        expected.dedup();
        let mut closed = vec![];
        let mut response = [0; wire::MAX_RECEIVE_REPLY_LEN];
        assert!(
            socket_transfer::peek(
                &mock,
                source(10),
                source(20),
                7,
                3,
                2,
                &mut response,
                |handle| closed.push(handle)
            )
            .is_err(),
            "case {case}"
        );
        closed.sort();
        assert_eq!(closed, expected, "case {case}");
        assert_eq!(mock.calls.get(), 1);
    }
    let mut mock = peek_mock(0, 0);
    mock.bytes = (-11i32).to_le_bytes().to_vec();
    mock.result = Ok(4);
    let mut response = [0; wire::MAX_RECEIVE_REPLY_LEN];
    assert_eq!(
        socket_transfer::peek(
            &mock,
            source(10),
            source(20),
            7,
            3,
            0,
            &mut response,
            |_| panic!("no receipt")
        )
        .unwrap_err(),
        ClientError::Remote(-11)
    );
}

fn send_mock(operation: u8) -> Mock {
    let mut mock = delivery_mock(0, 1);
    mock.incoming.clear();
    mock.bytes = 0i32.to_le_bytes().to_vec();
    mock.result = Ok(4);
    match operation {
        1 => {
            mock.request = wire::Request::Begin {
                length: 8,
                descriptors: 2,
            };
            mock.outgoing = vec![object(10, mnu_abi::HANDLE_RIGHT_WRITE)];
            mock.incoming = vec![object(42, wire::RIGHTS)];
        }
        2 => {
            mock.request = wire::Request::Append {
                offset: 3,
                count: 2,
                metadata: [Some(metadata()), Some(metadata()), None],
            };
            mock.outgoing = vec![
                object(42, mnu_abi::HANDLE_RIGHT_CONTROL),
                object(10, mnu_abi::HANDLE_RIGHT_TRANSFER),
                object(10, mnu_abi::HANDLE_RIGHT_TRANSFER),
            ];
            mock.bytes = 5i32.to_le_bytes().to_vec();
        }
        3 => {
            mock.request = wire::Request::Commit { offset: 7 };
            mock.outgoing = vec![
                object(42, mnu_abi::HANDLE_RIGHT_CONTROL),
                object(20, mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_MAP),
            ];
            mock.bytes = 8i32.to_le_bytes().to_vec();
        }
        _ => unreachable!(),
    }
    mock
}

fn send_call(mock: &Mock, operation: u8, close: impl FnMut(u32)) -> Result<(), ClientError<()>> {
    match operation {
        1 => socket_transfer::begin(mock, source(10), 8, 2, close).map(|job| {
            assert_eq!(job, object(42, wire::RIGHTS));
        }),
        2 => {
            let mut info = metadata();
            info.descriptor_flags = 1;
            let file = socket_transfer::SendFile {
                object: object(10, mnu_abi::HANDLE_RIGHT_TRANSFER),
                metadata: info,
            };
            socket_transfer::append(mock, source(42), 3, &[file, file], close)
        }
        3 => socket_transfer::commit(mock, source(42), source(20), 7, 8, close),
        _ => unreachable!(),
    }
}

#[test]
fn send_stages_borrowed_authority_strips_cloexec_and_keeps_duplicate_source_references() {
    for operation in 1..=3 {
        let mock = send_mock(operation);
        send_call(&mock, operation, |_| {
            panic!("borrowed source or successful result")
        })
        .unwrap();
        assert_eq!(mock.calls.get(), 1);
    }
}

#[test]
fn invalid_begin_responses_release_only_distinct_new_references() {
    for case in 0..10 {
        let mut mock = send_mock(1);
        match case {
            0 => mock.incoming.clear(),
            1 => mock.incoming[0].rights |= mnu_abi::HANDLE_RIGHT_READ,
            2 => mock.incoming.push(mock.incoming[0]),
            3 => mock.incoming[0].handle = 0,
            4 => mock.incoming[0].handle = 10,
            5 => mock.bytes = 1i32.to_le_bytes().to_vec(),
            6 => mock.bytes = (-11i32).to_le_bytes().to_vec(),
            7 => mock.result = Err(()),
            8 => mock.result = Ok(3),
            9 => mock.result = Ok(5),
            _ => unreachable!(),
        }
        let mut closed = vec![];
        assert!(send_call(&mock, 1, |handle| closed.push(handle)).is_err());
        assert_eq!(
            closed,
            if matches!(case, 0 | 3 | 4) {
                vec![]
            } else {
                vec![42]
            }
        );
        assert_eq!(mock.calls.get(), 1);
    }
}

#[test]
fn append_and_commit_require_exact_progress_and_clean_unexpected_owned_results() {
    for operation in 2..=3 {
        for case in 0..8 {
            let mut mock = send_mock(operation);
            match case {
                0 => mock.bytes = 0i32.to_le_bytes().to_vec(),
                1 => mock.bytes = 99i32.to_le_bytes().to_vec(),
                2 => mock.incoming = vec![source(70), source(70)],
                3 => mock.incoming = vec![source(42)],
                4 => {
                    mock.incoming = vec![source(70)];
                    mock.result = Err(());
                }
                5 => mock.result = Ok(3),
                6 => mock.result = Ok(5),
                7 => {
                    mock.bytes = (-11i32).to_le_bytes().to_vec();
                    mock.incoming = vec![source(70)];
                }
                _ => unreachable!(),
            }
            let mut closed = vec![];
            assert!(send_call(&mock, operation, |handle| closed.push(handle)).is_err());
            assert_eq!(
                closed,
                if matches!(case, 2 | 4 | 7) {
                    vec![70]
                } else {
                    vec![]
                }
            );
            assert_eq!(mock.calls.get(), 1);
        }
    }
}

#[test]
fn explicit_remote_send_pressure_is_distinguishable_from_ambiguous_transport_failure() {
    for operation in 1..=3 {
        let mut mock = send_mock(operation);
        mock.incoming.clear();
        mock.bytes = (-11i32).to_le_bytes().to_vec();
        assert_eq!(
            send_call(&mock, operation, |_| panic!()),
            Err(ClientError::Remote(-11))
        );
        mock.result = Err(());
        assert_eq!(
            send_call(&mock, operation, |_| panic!()),
            Err(ClientError::Transport(()))
        );
        assert_eq!(mock.calls.get(), 2);
    }
}

#[test]
fn send_validates_lengths_ranges_and_all_attachment_authority_before_ipc() {
    let mock = send_mock(1);
    assert!(
        socket_transfer::begin(
            &mock,
            object(10, mnu_abi::HANDLE_RIGHT_WRITE),
            8,
            2,
            |_| panic!()
        )
        .is_err()
    );
    assert!(
        socket_transfer::begin(
            &mock,
            source(10),
            wire::MAX_PAYLOAD_LEN + 1,
            2,
            |_| panic!()
        )
        .is_err()
    );
    assert!(socket_transfer::begin(&mock, source(10), 8, 254, |_| panic!()).is_err());
    let mut file = socket_transfer::SendFile {
        object: source(10),
        metadata: metadata(),
    };
    for files in [&[][..], &[file; 4][..]] {
        assert!(socket_transfer::append(&mock, source(42), 0, files, |_| panic!()).is_err());
    }
    file.object.rights = mnu_abi::HANDLE_RIGHT_READ;
    assert!(socket_transfer::append(&mock, source(42), 0, &[file], |_| panic!()).is_err());
    file.object = source(42);
    assert!(socket_transfer::append(&mock, source(42), 0, &[file], |_| panic!()).is_err());
    file.object = source(10);
    assert!(socket_transfer::append(&mock, source(42), 253, &[file], |_| panic!()).is_err());
    file.metadata.kind = 255;
    assert!(socket_transfer::append(&mock, source(42), 0, &[file], |_| panic!()).is_err());
    assert!(socket_transfer::commit(&mock, source(42), source(42), 7, 8, |_| panic!()).is_err());
    assert!(
        socket_transfer::commit(&mock, source(42), source(20), u64::MAX, 8, |_| panic!()).is_err()
    );
    assert!(
        socket_transfer::commit(
            &mock,
            source(42),
            object(20, mnu_abi::HANDLE_RIGHT_READ),
            7,
            8,
            |_| panic!()
        )
        .is_err()
    );
    assert_eq!(mock.calls.get(), 0);
}

#[test]
fn stream_commit_accepts_only_valid_nonempty_prefixes_and_preserves_transport_errors() {
    for value in [-11i32, 0, 1, 3, 8, 9] {
        let mut mock = send_mock(3);
        mock.bytes = value.to_le_bytes().to_vec();
        let result =
            socket_transfer::commit_prefix(&mock, source(42), source(20), 7, 8, |_| panic!());
        match value {
            -11 => assert_eq!(result, Err(ClientError::Remote(-11))),
            1..=8 => assert_eq!(result, Ok(value as u32)),
            _ => assert_eq!(result, Err(ClientError::MismatchedResponse)),
        }
        assert_eq!(mock.calls.get(), 1);
    }
    let mut mock = send_mock(3);
    mock.bytes = 3i32.to_le_bytes().to_vec();
    mock.incoming = vec![source(70), source(70)];
    let mut closed = vec![];
    assert!(
        socket_transfer::commit_prefix(&mock, source(42), source(20), 7, 8, |handle| closed
            .push(handle))
        .is_err()
    );
    assert_eq!(closed, [70]);
}

#[test]
fn consuming_receive_binds_capacity_and_returns_only_an_owned_receipt() {
    for (total, maximum) in [(0, 253), (253, 0), (253, 2), (253, 253)] {
        let mock = receive_mock(total, maximum);
        let mut response = [0; wire::MAX_RECEIVE_REPLY_LEN];
        let mut closed = vec![];
        let received = socket_transfer::receive(
            &mock,
            source(10),
            source(20),
            7,
            3,
            maximum,
            &mut response,
            |handle| closed.push(handle),
        )
        .unwrap();
        assert_eq!(received.message.copied, 3);
        assert_eq!(received.message.length, 8);
        assert_eq!(received.message.total_rights, total);
        assert_eq!(received.message.available_rights, total.min(maximum));
        assert_eq!(received.message.source, Address::UnixPath(b"/sender"));
        assert_eq!(received.receipt, mock.incoming.first().copied());
        assert!(closed.is_empty());
        assert_eq!(mock.calls.get(), 1);
    }
}

#[test]
fn invalid_receive_replies_close_distinct_owned_handles_once_not_borrowed_sources() {
    for case in 0..12 {
        let mut mock = receive_mock(2, 2);
        match case {
            0 => mock.incoming.clear(),
            1 => mock.incoming[0].rights |= mnu_abi::HANDLE_RIGHT_WRITE,
            2 => mock.incoming.push(mock.incoming[0]),
            3 => mock.incoming[0].handle = 0,
            4 => mock.incoming[0].handle = 10,
            5 => mock.incoming[0].handle = 20,
            6 => mock.bytes[0] ^= 1,
            7 => mock.bytes[18] = 1, // Does not match min(request capacity, total).
            8 => mock.result = Err(()),
            9 => mock.result = Ok(wire::MAX_RECEIVE_REPLY_LEN + 1),
            10 => {
                mock.bytes = (-11i32).to_le_bytes().to_vec();
                mock.result = Ok(4);
            }
            11 => mock.result = Ok(0),
            _ => unreachable!(),
        }
        let mut expected: Vec<_> = mock
            .incoming
            .iter()
            .map(|item| item.handle)
            .filter(|handle| ![0, 10, 20].contains(handle))
            .collect();
        expected.sort();
        expected.dedup();
        let mut closed = vec![];
        let mut response = [0; wire::MAX_RECEIVE_REPLY_LEN];
        assert!(
            socket_transfer::receive(
                &mock,
                source(10),
                source(20),
                7,
                3,
                2,
                &mut response,
                |handle| closed.push(handle),
            )
            .is_err(),
            "case {case}"
        );
        closed.sort();
        assert_eq!(closed, expected, "case {case}");
        assert_eq!(mock.calls.get(), 1); // Never replay a consuming call.
    }
}

#[test]
fn every_truncated_receive_reply_releases_its_receipt() {
    let size = receive_mock(2, 2).bytes.len();
    for length in 0..size {
        let mut mock = receive_mock(2, 2);
        mock.result = Ok(length);
        let mut response = [0; wire::MAX_RECEIVE_REPLY_LEN];
        let mut closed = vec![];
        assert!(
            socket_transfer::receive(
                &mock,
                source(10),
                source(20),
                7,
                3,
                2,
                &mut response,
                |handle| closed.push(handle),
            )
            .is_err()
        );
        assert_eq!(closed, [42]);
    }
}

#[test]
fn remote_errors_are_propagated_only_without_unexpected_attachments() {
    let mut mock = receive_mock(0, 0);
    mock.bytes = (-11i32).to_le_bytes().to_vec();
    mock.result = Ok(4);
    let mut response = [0; wire::MAX_RECEIVE_REPLY_LEN];
    let error = socket_transfer::receive(
        &mock,
        source(10),
        source(20),
        7,
        3,
        0,
        &mut response,
        |_| panic!("no ownership"),
    )
    .unwrap_err();
    assert_eq!(error, ClientError::Remote(-11));
    let mut mock = delivery_mock(0, 1);
    mock.bytes = (-61i32).to_le_bytes().to_vec();
    mock.result = Ok(4);
    mock.incoming.clear();
    assert_eq!(
        socket_transfer::deliver(&mock, source(42), 0, 4, |_| panic!()).unwrap_err(),
        ClientError::Remote(-61)
    );
}

#[test]
fn delivery_preserves_attenuated_rights_and_sender_dispatch_metadata_not_cloexec() {
    let mock = delivery_mock(249, 4);
    let batch = socket_transfer::deliver(&mock, source(42), 249, 4, |_| panic!()).unwrap();
    assert_eq!(batch.count, 4);
    for (index, item) in batch.files.into_iter().enumerate() {
        let item = item.unwrap();
        assert_eq!(item.object, mock.incoming[index]);
        assert_eq!(item.metadata, metadata());
        assert_eq!(item.object.rights & mnu_abi::HANDLE_RIGHT_DUPLICATE, 0);
    }
}

#[test]
fn malformed_delivery_never_exposes_a_valid_prefix_or_closes_borrowed_receipt() {
    for case in 0..16 {
        let mut mock = delivery_mock(0, 4);
        match case {
            0 => mock.incoming.clear(),
            1 => {
                mock.incoming.pop();
            }
            2 => mock.incoming[3] = mock.incoming[0],
            3 => mock.incoming[3].handle = 0,
            4 => mock.incoming[3].handle = 42,
            5 => mock.incoming[3].rights = mnu_abi::HANDLE_RIGHT_READ,
            6 => mock.incoming[3].rights |= 1 << 61,
            7 => mock.bytes[0] ^= 1,
            8 => mock.bytes[4] = 2,
            9 => mock.bytes[8] = 1,
            10 => mock.bytes[12] = 1,
            11 => mock.bytes[40] = 0xff, // Malformed last descriptor metadata.
            12 => mock.result = Err(()),
            13 => mock.result = Ok(wire::MAX_DELIVERY_REPLY_LEN + 1),
            14 => mock.result = Ok(0),
            15 => {
                mock.bytes = (-11i32).to_le_bytes().to_vec();
                mock.result = Ok(4);
            }
            _ => unreachable!(),
        }
        let mut expected: Vec<_> = mock
            .incoming
            .iter()
            .map(|item| item.handle)
            .filter(|handle| ![0, 42].contains(handle))
            .collect();
        expected.sort();
        expected.dedup();
        let mut closed = vec![];
        assert!(
            socket_transfer::deliver(&mock, source(42), 0, 4, |handle| closed.push(handle))
                .is_err(),
            "case {case}"
        );
        closed.sort();
        assert_eq!(closed, expected, "case {case}");
        assert_eq!(mock.calls.get(), 1);
    }
}

#[test]
fn every_truncated_delivery_releases_all_attachments() {
    for size in 0..wire::MAX_DELIVERY_REPLY_LEN {
        let mut mock = delivery_mock(0, 4);
        mock.result = Ok(size);
        let mut closed = vec![];
        assert!(
            socket_transfer::deliver(&mock, source(42), 0, 4, |handle| closed.push(handle))
                .is_err()
        );
        assert_eq!(closed, [1000, 1001, 1002, 1003]);
    }
}

#[test]
fn missing_authority_and_bad_local_arguments_never_issue_ipc_or_close_borrowed_handles() {
    let mock = receive_mock(2, 2);
    let mut response = [0; wire::MAX_RECEIVE_REPLY_LEN];
    for (socket, buffer, offset, length, maximum) in [
        (source(0), source(20), 7, 3, 2),
        (object(10, mnu_abi::HANDLE_RIGHT_READ), source(20), 7, 3, 2),
        (
            source(10),
            object(20, mnu_abi::HANDLE_RIGHT_TRANSFER),
            7,
            3,
            2,
        ),
        (source(10), source(10), 7, 3, 2),
        (source(10), source(20), u64::MAX, 3, 2),
        (source(10), source(20), 7, 65537, 2),
        (source(10), source(20), 7, 3, 254),
    ] {
        assert!(
            socket_transfer::receive(
                &mock,
                socket,
                buffer,
                offset,
                length,
                maximum,
                &mut response,
                |_| panic!("borrowed"),
            )
            .is_err()
        );
    }
    assert!(
        socket_transfer::receive(&mock, source(10), source(20), 7, 3, 2, &mut [], |_| panic!(
            "borrowed"
        ),)
        .is_err()
    );
    assert_eq!(mock.calls.get(), 0);
    let mock = delivery_mock(0, 1);
    for (receipt, offset, maximum) in [
        (source(0), 0, 4),
        (object(42, mnu_abi::HANDLE_RIGHT_CONTROL), 0, 4),
        (source(42), 254, 4),
        (source(42), 0, 0),
        (source(42), 0, 5),
    ] {
        assert!(
            socket_transfer::deliver(&mock, receipt, offset, maximum, |_| panic!("borrowed"))
                .is_err()
        );
    }
    assert_eq!(mock.calls.get(), 0);
}

#[test]
fn all_253_delivered_files_are_published_together_or_rolled_back_on_late_failure() {
    for fail_last in [false, true] {
        let mut table = FdTable::<u32>::new();
        let group = table.reserve_up_to(3, 256, 253).unwrap();
        for index in 0..253 {
            assert_eq!(group.descriptor(index), Some(3 + index as i32));
            assert!(table.get(group.descriptor(index).unwrap()).is_none());
        }
        assert_eq!(group.descriptor(253), None);
        assert_eq!(group.descriptor(usize::MAX), None);
        let mut entries = vec![];
        let mut closed = vec![];
        let mut offset = 0;
        while offset < 253 {
            let count = 4.min(253 - offset);
            let mut mock = delivery_mock(offset, count);
            if fail_last && offset == 252 {
                mock.bytes[16] = 0xff;
            }
            let result = socket_transfer::deliver(&mock, source(42), offset, 4, |handle| {
                closed.push(handle)
            });
            assert!((3..256).all(|fd| table.get(fd).is_none()));
            match result {
                Ok(batch) => {
                    entries.extend(batch.files.into_iter().flatten().map(|file| Entry {
                        handle: file.object.handle,
                        rights: file.object.rights,
                        descriptor_flags: FD_CLOEXEC, // Receiver-selected MSG_CMSG_CLOEXEC.
                    }));
                    offset += batch.count as u16;
                }
                Err(_) => break,
            }
        }
        if fail_last {
            closed.extend(entries.iter().map(|entry| entry.handle));
            assert_eq!(table.cancel_group(&group), 253);
            closed.sort();
            assert_eq!(closed, (1000..1253).collect::<Vec<_>>());
            assert!((0..256).all(|fd| table.get(fd).is_none()));
        } else {
            let mut fds = [-1; 253];
            table.commit_group(&group, &entries, &mut fds).unwrap();
            assert_eq!(fds, core::array::from_fn(|index| 3 + index as i32));
            for (fd, entry) in fds.into_iter().zip(entries) {
                assert_eq!(table.get(fd), Some(entry));
                assert_eq!(entry.descriptor_flags, FD_CLOEXEC);
            }
            assert!(closed.is_empty());
        }
        // Receipt ownership remains with the caller on both success and abort.
        closed.push(42);
        assert_eq!(closed.iter().filter(|handle| **handle == 42).count(), 1);
    }
}
