//! Execute the service's connection-mode record policy, not a parallel model.
use mochios_posix_protocol::{
    socket::{Create, Domain, Kind, NONBLOCKING},
    socket_record::{MAX_REPLY_LEN, Operation, Reply, Request},
};
use posix_service::{
    AuthenticatedProcess, PeerIdentity, PosixService,
    socket::{Shutdown, Streams},
    socket_record_io::RecordBuffer,
};
struct Buffer(Vec<u8>);
impl RecordBuffer for Buffer {
    fn extent(&self) -> Result<u64, i32> {
        Ok(self.0.len() as u64)
    }
    fn read(&mut self, offset: u64, output: &mut [u8]) -> Result<(), i32> {
        let n = output.len();
        output.copy_from_slice(
            self.0
                .get(offset as usize..offset as usize + n)
                .ok_or(-14)?,
        );
        Ok(())
    }
    fn write(&mut self, offset: u64, input: &[u8]) -> Result<(), i32> {
        self.0
            .get_mut(offset as usize..offset as usize + input.len())
            .ok_or(-14)?
            .copy_from_slice(input);
        Ok(())
    }
}
fn fixture() -> (PosixService<u32>, PeerIdentity, Streams, Create) {
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 1,
                process_id: 1,
            },
            501,
            20,
            &[],
        )
        .unwrap();
    (
        service,
        PeerIdentity {
            process_id: 1,
            effective_uid: 0,
            effective_gid: 0,
        },
        Streams::new(),
        Create {
            domain: Domain::Unix,
            kind: Kind::SequencedPacket,
            protocol: 0,
            options: 0,
        },
    )
}
fn record(
    s: &mut Streams,
    id: u64,
    op: Operation,
    data: &mut [u8],
    peek: bool,
) -> Result<(usize, usize), i32> {
    let mut b = Buffer(data.to_vec());
    let r = Request {
        operation: op,
        offset: 0,
        length: data.len() as u32,
        peek,
    };
    let mut response = [0; MAX_REPLY_LEN];
    let n = s.transfer_record(id, r, &mut b, &mut response)?;
    let result = Reply::decode(r, &response[..n]).unwrap();
    data.copy_from_slice(&b.0);
    Ok((result.copied as usize, result.length as usize))
}
#[test]
fn record_pairs_preserve_empty_records_order_peek_and_truncation() {
    let (svc, p, mut s, c) = fixture();
    let [a, b] = svc.create_socket_pair(p, c, &mut s).unwrap();
    assert_eq!(s.kind(a), Ok(Kind::SequencedPacket));
    assert_eq!(s.options(a), Ok(0));
    for data in [b"alpha".as_slice(), b"", b"beta"] {
        record(&mut s, a, Operation::Send, &mut data.to_vec(), false).unwrap();
    }
    let mut short = [0; 2];
    assert_eq!(
        record(&mut s, b, Operation::Receive, &mut short, true),
        Ok((2, 5))
    );
    assert_eq!(&short, b"al");
    assert_eq!(
        record(&mut s, b, Operation::Receive, &mut short, false),
        Ok((2, 5))
    );
    assert_eq!(
        record(&mut s, b, Operation::Receive, &mut short, false),
        Ok((0, 0))
    );
    let mut large = [0; 32];
    assert_eq!(
        record(&mut s, b, Operation::Receive, &mut large, false),
        Ok((4, 4))
    );
    assert_eq!(&large[..4], b"beta");
    assert_eq!(
        record(&mut s, b, Operation::Receive, &mut large, false),
        Err(-11)
    );
}
#[test]
fn listen_accept_inherit_type_and_limits_but_not_nonblocking_or_peer_binding() {
    let (svc, p, mut s, c) = fixture();
    let listener = svc.create_socket(p, c, &mut s).unwrap();
    let client = svc.create_socket(p, c, &mut s).unwrap();
    s.set_options(listener, NONBLOCKING).unwrap();
    s.set_receive_capacity(listener, 512).unwrap();
    s.set_send_timeout(listener, 5000).unwrap();
    s.listen(listener, 1).unwrap();
    assert!(!s.readiness(listener).unwrap().readable);
    let server = s.connect(client, listener).unwrap();
    assert!(s.readiness(listener).unwrap().readable);
    let ticket = s.begin_accept(listener).unwrap();
    assert_eq!(ticket.endpoint(), server);
    s.commit_accept(ticket, (501, 20), 0).unwrap();
    assert_eq!(s.kind(server), Ok(Kind::SequencedPacket));
    assert_eq!(s.receive_capacity(server), Ok(512));
    assert_eq!(s.send_timeout(server), Ok(5000));
    assert_eq!(s.options(server), Ok(0));
    assert!(!s.readiness(listener).unwrap().readable);
    record(&mut s, client, Operation::Send, &mut b"one".to_vec(), false).unwrap();
    let mut b = [0; 16];
    assert_eq!(
        record(&mut s, server, Operation::Receive, &mut b, false),
        Ok((3, 3))
    );
}
#[test]
fn incompatible_types_never_connect_or_cross_record_routes() {
    let (svc, p, mut s, c) = fixture();
    let seq = svc.create_socket(p, c, &mut s).unwrap();
    let stream = svc
        .create_socket(
            p,
            Create {
                kind: Kind::Stream,
                ..c
            },
            &mut s,
        )
        .unwrap();
    s.listen(stream, 1).unwrap();
    assert_eq!(s.connect(seq, stream), Err(-91));
    assert_eq!(s.peer_address(seq), Err(-107));
    let datagram = svc
        .create_socket(
            p,
            Create {
                kind: Kind::Datagram,
                ..c
            },
            &mut s,
        )
        .unwrap();
    assert_eq!(
        s.connect_datagram_named(datagram, seq, None, b"/seq"),
        Err(-91)
    );
    assert_eq!(s.disconnect_datagram(seq), Err(-95));
    let [a, b] = svc.create_socket_pair(p, c, &mut s).unwrap();
    assert_eq!(s.record_send_to_ready(a, seq, 1), Err(-106));
    assert_eq!(s.record_send_to_ready(datagram, b, 1), Err(-91));
}
#[test]
fn queued_records_drain_before_eof_and_shutdown_wakes_receive_jobs() {
    use posix_service::socket_receive_wait::ReceiveWaits;
    let (svc, p, mut s, c) = fixture();
    let [a, b] = svc.create_socket_pair(p, c, &mut s).unwrap();
    let mut waits = ReceiveWaits::new();
    let job = waits.start(&s, b, 1, 7u32).unwrap();
    assert_eq!(waits.ready(job), Ok(false));
    record(&mut s, a, Operation::Send, &mut b"tail".to_vec(), false).unwrap();
    s.shutdown(a, Shutdown::Write).unwrap();
    waits.pump(&s, |id| assert_eq!(id, job));
    assert_eq!(waits.ready(job), Ok(true));
    let mut data = [0; 16];
    assert_eq!(
        record(&mut s, b, Operation::Receive, &mut data, false),
        Ok((4, 4))
    );
    assert_eq!(
        record(&mut s, b, Operation::Receive, &mut data, false),
        Ok((0, 0))
    );
    assert!(s.readiness(b).unwrap().read_closed);
    assert_eq!(
        record(&mut s, a, Operation::Send, &mut [1], false),
        Err(-32)
    );
}
#[test]
fn never_connected_record_socket_reports_not_connected_and_rejected_accept_is_retryable() {
    let (svc, p, mut s, c) = fixture();
    let a = svc.create_socket(p, c, &mut s).unwrap();
    assert_eq!(
        record(&mut s, a, Operation::Send, &mut [1], false),
        Err(-107)
    );
    assert_eq!(
        record(&mut s, a, Operation::Receive, &mut [0], false),
        Err(-107)
    );
    s.listen(a, 1).unwrap();
    let client = svc.create_socket(p, c, &mut s).unwrap();
    let server = s.connect(client, a).unwrap();
    let ticket = s.begin_accept(a).unwrap();
    let replacement = s.abort_accept(ticket).unwrap();
    assert_ne!(replacement, server);
    let retry = s.begin_accept(a).unwrap();
    s.commit_accept(retry, (501, 20), NONBLOCKING).unwrap();
    assert_eq!(s.kind(replacement), Ok(Kind::SequencedPacket));
}
#[test]
fn peer_close_with_unread_records_resets_sender_after_queued_input() {
    let (svc, p, mut s, c) = fixture();
    let [a, b] = svc.create_socket_pair(p, c, &mut s).unwrap();
    record(&mut s, a, Operation::Send, &mut [42], false).unwrap();
    record(&mut s, b, Operation::Send, &mut [17], false).unwrap();
    s.release(b).unwrap();
    assert_eq!(s.pending_error(a), Ok(104));
    let mut data = [0; 8];
    assert_eq!(
        record(&mut s, a, Operation::Receive, &mut data, false),
        Ok((1, 1))
    );
    assert_eq!(data[0], 17);
    assert_eq!(
        record(&mut s, a, Operation::Receive, &mut data, false),
        Err(-104)
    );
    assert_eq!(
        record(&mut s, a, Operation::Receive, &mut data, false),
        Ok((0, 0))
    );
    assert_eq!(
        record(&mut s, a, Operation::Send, &mut [0], false),
        Err(-32)
    );
}

#[test]
fn ancillary_record_metadata_distinguishes_empty_message_from_eof() {
    let (svc, p, mut s, c) = fixture();
    let [a, b] = svc.create_socket_pair(p, c, &mut s).unwrap();
    record(&mut s, a, Operation::Send, &mut [], false).unwrap();
    let mut buffer = Buffer(vec![0; 8]);
    let (message, rights) = s
        .receive_record_with_rights(b, 0, 8, &mut buffer, |r, n| {
            assert!(r.end_of_record);
            assert_eq!(n, 0);
            Ok(())
        })
        .unwrap();
    assert!(message.end_of_record);
    assert!(rights.is_none());
    s.shutdown(a, Shutdown::Write).unwrap();
    let (eof, rights) = s
        .receive_record_with_rights(b, 0, 8, &mut buffer, |r, n| {
            assert!(!r.end_of_record);
            assert_eq!(n, 0);
            Ok(())
        })
        .unwrap();
    assert!(!eof.end_of_record);
    assert_eq!((eof.copied, eof.length), (0, 0));
    assert!(rights.is_none());
}

#[test]
fn record_end_flag_survives_the_wire_and_unknown_flags_are_rejected() {
    use mochios_posix_protocol::{ProtocolError, socket::Address, socket_transfer::ReceiveReply};
    let mut output = [0; 128];
    for end in [false, true] {
        let r = ReceiveReply {
            end_of_record: end,
            copied: 0,
            length: 0,
            total_rights: 0,
            available_rights: 0,
            source: Address::UnixUnnamed,
        };
        let n = r.encode(8, 0, &mut output).unwrap();
        assert_eq!(ReceiveReply::decode(8, 0, &output[..n]), Ok(r));
        output[22] = 2;
        assert_eq!(
            ReceiveReply::decode(8, 0, &output[..n]),
            Err(ProtocolError::InvalidLength)
        );
    }
    let metadata = mochios_posix_protocol::InheritedFdMetadata {
        kind: mochios_posix_protocol::INHERITED_FD_KIND_SEQPACKET,
        open_flags: 2,
        descriptor_flags: 0,
    };
    let word = mochios_posix_protocol::encode_inherited_fd_metadata(metadata).unwrap();
    assert_eq!(
        mochios_posix_protocol::decode_inherited_fd_metadata(word),
        Some(metadata)
    );
}
