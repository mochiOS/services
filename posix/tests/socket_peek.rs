use mochios_posix_protocol::socket::{Create, Domain, Kind};
use posix_service::socket::{RECEIVE_CAPACITY, Shutdown, Streams};
use posix_service::{AuthenticatedProcess, PeerIdentity, PosixService};

fn request() -> Create {
    Create {
        domain: Domain::Unix,
        kind: Kind::Stream,
        protocol: 0,
        options: 0,
    }
}

fn pair() -> (Streams, u64, u64) {
    let mut streams = Streams::new();
    let (service, peer) = session();
    let [a, b] = service
        .create_socket_pair(peer, request(), &mut streams)
        .unwrap();
    (streams, a, b)
}

fn session() -> (PosixService<u32>, PeerIdentity) {
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
            effective_uid: 501,
            effective_gid: 20,
        },
    )
}

#[test]
fn repeated_inspection_preserves_the_shared_queue_and_output_tail() {
    let (mut streams, a, b) = pair();
    streams.write(a, b"abcdef").unwrap();
    let ready = streams.readiness(b).unwrap();
    for _ in 0..3 {
        let mut output = [0x55; 8];
        assert_eq!(streams.peek(b, 0, &mut output), Ok(6));
        assert_eq!(&output[..6], b"abcdef");
        assert_eq!(&output[6..], &[0x55; 2]);
        assert_eq!(streams.readiness(b).unwrap(), ready);
    }
    let mut prefix = [0; 2];
    assert_eq!(streams.read(b, &mut prefix), Ok(2));
    assert_eq!(&prefix, b"ab");
    let mut suffix = [0; 4];
    assert_eq!(streams.peek(b, 0, &mut suffix), Ok(4));
    assert_eq!(&suffix, b"cdef");
    assert_eq!(streams.read(b, &mut suffix), Ok(4));
    assert_eq!(&suffix, b"cdef");
    assert_eq!(streams.peek(b, 0, &mut suffix), Err(-11));
}

#[test]
fn inspection_does_not_relieve_backpressure_or_touch_the_reverse_direction() {
    let (mut streams, a, b) = pair();
    let bytes = vec![7; RECEIVE_CAPACITY];
    assert_eq!(streams.write(a, &bytes), Ok(bytes.len()));
    assert!(!streams.readiness(a).unwrap().writable);
    let mut output = vec![0; bytes.len()];
    assert_eq!(streams.peek(b, 0, &mut output), Ok(bytes.len()));
    assert_eq!(output, bytes);
    assert!(!streams.readiness(a).unwrap().writable);
    assert_eq!(streams.write(a, b"!"), Err(-11));
    assert_eq!(streams.write(b, b"reverse"), Ok(7));
    assert_eq!(streams.read(a, &mut output), Ok(7));
    assert_eq!(&output[..7], b"reverse");
    assert_eq!(streams.read(b, &mut output[..1]), Ok(1));
    assert!(streams.readiness(a).unwrap().writable);
}

#[test]
fn offsets_are_bounded_and_track_the_current_head_not_previous_inspections() {
    let (mut streams, a, b) = pair();
    streams.write(a, b"abcd").unwrap();
    let mut output = [0x55; 3];
    assert_eq!(streams.peek(b, 2, &mut output), Ok(2));
    assert_eq!(&output, b"cdU");
    for offset in [4, 5, usize::MAX] {
        let mut untouched = [0x55; 3];
        assert_eq!(streams.peek(b, offset, &mut untouched), Err(-11));
        assert_eq!(untouched, [0x55; 3]);
    }
    streams.write(a, b"ef").unwrap();
    assert_eq!(streams.peek(b, 4, &mut output), Ok(2));
    assert_eq!(&output[..2], b"ef");
    streams.read(b, &mut [0; 2]).unwrap();
    assert_eq!(streams.peek(b, 2, &mut output), Ok(2));
    assert_eq!(&output[..2], b"ef");
    assert_eq!(streams.read(b, &mut [0; 8]), Ok(4));
}

#[test]
fn queued_bytes_remain_inspectable_after_half_close_or_final_peer_release() {
    for release in [false, true] {
        let (mut streams, a, b) = pair();
        streams.write(a, b"data").unwrap();
        if release {
            streams.release(a).unwrap();
        } else {
            streams.shutdown(a, Shutdown::Write).unwrap();
        }
        let mut output = [0; 8];
        for _ in 0..2 {
            assert_eq!(streams.peek(b, 0, &mut output), Ok(4));
            assert_eq!(&output[..4], b"data");
        }
        assert_eq!(streams.peek(b, 4, &mut output), Ok(0));
        assert_eq!(streams.peek(b, usize::MAX, &mut output), Ok(0));
        assert_eq!(streams.read(b, &mut output), Ok(4));
        assert_eq!(&output[..4], b"data");
        assert_eq!(streams.peek(b, 0, &mut output), Ok(0));
    }
}

#[test]
fn pending_reset_is_not_consumed_behind_a_queued_prefix() {
    let (mut streams, a, b) = pair();
    streams.write(a, b"data").unwrap();
    streams.write(b, b"unread at departing peer").unwrap();
    streams.release(a).unwrap();
    let mut output = [0x55; 8];
    assert_eq!(streams.peek(b, 4, &mut output), Ok(0));
    assert_eq!(streams.pending_error(b), Ok(104));
    assert_eq!(streams.peek(b, 0, &mut output), Ok(4));
    assert_eq!(streams.pending_error(b), Ok(104));
    assert_eq!(streams.read(b, &mut output), Ok(4));
    assert_eq!(streams.peek(b, 0, &mut output), Err(-104));
    assert_eq!(streams.pending_error(b), Ok(0));
    assert_eq!(streams.peek(b, 0, &mut output), Ok(0));
    assert_eq!(streams.read(b, &mut output), Ok(0));
}

#[test]
fn invalid_unconnected_zero_length_and_local_shutdown_match_read_semantics() {
    let (mut streams, a, b) = pair();
    let mut output = [0x55; 8];
    assert_eq!(streams.peek(u64::MAX, 0, &mut output), Err(-9));
    assert_eq!(output, [0x55; 8]);
    let (service, peer) = session();
    let unconnected = service
        .create_socket(peer, request(), &mut streams)
        .unwrap();
    assert_eq!(streams.peek(unconnected, 0, &mut output), Err(-107));
    assert_eq!(streams.peek(unconnected, usize::MAX, &mut []), Ok(0));
    streams.write(a, b"data").unwrap();
    assert_eq!(streams.peek(b, usize::MAX, &mut []), Ok(0));
    streams.shutdown(b, Shutdown::Read).unwrap();
    assert_eq!(streams.peek(b, 0, &mut output), Ok(0));
    assert_eq!(output, [0x55; 8]);
    streams.release(b).unwrap();
    assert_eq!(streams.peek(b, 0, &mut []), Err(-9));
}

#[test]
fn inspection_and_consumption_match_a_reference_queue_across_wraparound() {
    let (mut streams, a, b) = pair();
    let mut expected = std::collections::VecDeque::new();
    for round in 0..1000usize {
        let bytes: Vec<u8> = (0..(round % 71 + 1)).map(|n| (round + n) as u8).collect();
        let written = streams.write(a, &bytes).unwrap();
        expected.extend(&bytes[..written]);
        let offset = round % (expected.len() + 3);
        let mut output = [0x55; 73];
        let count = expected.len().saturating_sub(offset).min(output.len());
        if count == 0 {
            assert_eq!(streams.peek(b, offset, &mut output), Err(-11));
            assert_eq!(output, [0x55; 73]);
        } else {
            assert_eq!(streams.peek(b, offset, &mut output), Ok(count));
            assert_eq!(
                output[..count],
                expected
                    .iter()
                    .skip(offset)
                    .take(count)
                    .copied()
                    .collect::<Vec<_>>()
            );
            assert!(output[count..].iter().all(|byte| *byte == 0x55));
        }
        let count = (round % 67 + 8).min(expected.len());
        assert_eq!(streams.read(b, &mut output[..count]), Ok(count));
        for byte in &output[..count] {
            assert_eq!(Some(*byte), expected.pop_front());
        }
    }
    let mut output = vec![0; expected.len()];
    assert_eq!(streams.read(b, &mut output), Ok(expected.len()));
    assert_eq!(output, expected.into_iter().collect::<Vec<_>>());
}
