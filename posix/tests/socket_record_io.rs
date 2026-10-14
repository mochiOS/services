use mochios_posix_protocol::{
    socket::Address,
    socket_record::{Operation, Reply, Request, MAX_RECORD_SIZE, MAX_REPLY_LEN},
};
use posix_service::{
    socket_record::{RecordQueue, SourceAddress},
    socket_record_io::{authorize, transfer, RecordBuffer},
    AttachedObject,
};

fn request(operation: Operation, length: usize) -> Request {
    Request {
        operation,
        offset: 17,
        length: length as u32,
        peek: false,
    }
}

fn source() -> SourceAddress {
    SourceAddress::new(Address::UnixAbstract(b"sender\0identity")).unwrap()
}

struct Buffer {
    bytes: Vec<u8>,
    error: i32,
    reads: usize,
    writes: usize,
}

impl Buffer {
    fn new(length: usize) -> Self {
        Self {
            bytes: vec![0x55; length],
            error: 0,
            reads: 0,
            writes: 0,
        }
    }
}

impl RecordBuffer for Buffer {
    fn extent(&self) -> Result<u64, i32> {
        Ok(self.bytes.len() as u64)
    }
    fn read(&mut self, offset: u64, output: &mut [u8]) -> Result<(), i32> {
        self.reads += 1;
        if self.error != 0 {
            return Err(self.error);
        }
        output.copy_from_slice(&self.bytes[offset as usize..offset as usize + output.len()]);
        Ok(())
    }
    fn write(&mut self, offset: u64, input: &[u8]) -> Result<(), i32> {
        self.writes += 1;
        if self.error != 0 {
            return Err(self.error);
        }
        self.bytes[offset as usize..offset as usize + input.len()].copy_from_slice(input);
        Ok(())
    }
}

#[test]
fn request_codec_rejects_unknown_fields_and_overflow_without_native_pointers() {
    for operation in [Operation::Send, Operation::Receive] {
        for length in [0, 1, 4096, MAX_RECORD_SIZE] {
            let request = request(operation, length);
            let encoded = request.encode().unwrap();
            assert_eq!(Request::decode(&encoded), Ok(request));
            for size in 0..encoded.len() {
                assert!(Request::decode(&encoded[..size]).is_err());
            }
            for (index, value) in [(0, 0), (4, 2), (6, 9), (20, 2), (24, 1), (31, 1)] {
                let mut invalid = encoded;
                invalid[index] = value;
                assert!(Request::decode(&invalid).is_err());
            }
        }
    }
    let mut invalid = request(Operation::Send, 1);
    invalid.peek = true;
    assert!(invalid.encode().is_err());
    invalid = request(Operation::Receive, MAX_RECORD_SIZE + 1);
    assert!(invalid.encode().is_err());
    invalid = request(Operation::Receive, 1);
    invalid.offset = u64::MAX;
    assert!(invalid.encode().is_err());
    let mut peek = request(Operation::Receive, 1);
    peek.peek = true;
    assert_eq!(Request::decode(&peek.encode().unwrap()), Ok(peek));
}

#[test]
fn reply_codec_binds_counts_source_and_operation_to_the_request() {
    let request = request(Operation::Receive, 3);
    let reply = Reply {
        copied: 3,
        length: 8,
        source: Some(Address::UnixUnnamed),
    };
    let mut bytes = [0x55; MAX_REPLY_LEN];
    let count = reply.encode(request, &mut bytes).unwrap();
    assert_eq!(Reply::decode(request, &bytes[..count]), Ok(reply));
    for size in 0..count {
        assert!(Reply::decode(request, &bytes[..size]).is_err());
    }
    for index in [0, 4, 6, 8, 16, 20, 24] {
        let mut invalid = bytes;
        invalid[index] ^= 0x80;
        assert!(Reply::decode(request, &invalid[..count]).is_err());
    }
    for length in [0, MAX_RECORD_SIZE as u32 + 1] {
        let mut invalid = bytes;
        invalid[12..16].copy_from_slice(&length.to_le_bytes());
        assert!(Reply::decode(request, &invalid[..count]).is_err());
    }
    assert!(Reply::decode(request, &bytes[..count + 1]).is_err());
    let mut too_small = [0x55; 1];
    assert!(reply.encode(request, &mut too_small).is_err());
    assert_eq!(too_small, [0x55]);
    for invalid in [
        Reply { copied: 4, ..reply },
        Reply { copied: 2, ..reply },
        Reply { length: 2, ..reply },
        Reply {
            source: None,
            ..reply
        },
        Reply {
            source: Some(Address::Ipv4 {
                address: [0; 4],
                port: 0,
            }),
            ..reply
        },
    ] {
        bytes.fill(0x55);
        assert!(invalid.encode(request, &mut bytes).is_err());
        assert_eq!(bytes, [0x55; MAX_REPLY_LEN]);
    }
    let send = Request {
        operation: Operation::Send,
        ..request
    };
    let sent = Reply {
        copied: 3,
        length: 3,
        source: None,
    };
    let count = sent.encode(send, &mut bytes).unwrap();
    assert_eq!(Reply::decode(send, &bytes[..count]), Ok(sent));
    assert!(Reply::decode(request, &bytes[..count]).is_err());
}

#[test]
fn only_explicit_attenuated_socket_and_buffer_attachments_authorize_transfer() {
    for operation in [Operation::Send, Operation::Receive] {
        let request = request(operation, 4);
        let attachments = [
            AttachedObject {
                handle: 1u32,
                rights: request.socket_rights(),
            },
            AttachedObject {
                handle: 2u32,
                rights: request.buffer_rights(),
            },
        ];
        let delivery = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
        assert!(authorize(request, delivery, &attachments).is_ok());
        for flags in [0, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, delivery | 0x8000] {
            assert!(authorize(request, flags, &attachments).is_err());
        }
        assert!(authorize(request, delivery, &[] as &[AttachedObject<u32>]).is_err());
        assert!(authorize(request, delivery, &attachments[..1]).is_err());
        for index in 0..2 {
            let mut invalid = attachments;
            invalid[index].handle = 0;
            assert!(authorize(request, delivery, &invalid).is_err());
            for rights in [0, mnu_abi::HANDLE_RIGHT_CONTROL, mnu_abi::HANDLE_RIGHT_ALL] {
                invalid = attachments;
                invalid[index].rights = rights;
                assert!(authorize(request, delivery, &invalid).is_err());
            }
        }
        assert_eq!(request.socket_rights() & mnu_abi::HANDLE_RIGHT_TRANSFER, 0);
        assert_eq!(request.buffer_rights() & mnu_abi::HANDLE_RIGHT_CONTROL, 0);
    }
}

#[test]
fn full_sized_record_uses_shared_buffer_and_one_queue_commit() {
    let mut queue = RecordQueue::new();
    let mut buffer = Buffer::new(MAX_RECORD_SIZE + 40);
    for (index, byte) in buffer.bytes[17..17 + MAX_RECORD_SIZE]
        .iter_mut()
        .enumerate()
    {
        *byte = index.wrapping_mul(71) as u8;
    }
    let original = buffer.bytes.clone();
    let mut response = [0; MAX_REPLY_LEN];
    let send = request(Operation::Send, MAX_RECORD_SIZE);
    let count = transfer(
        &mut queue,
        send,
        source(),
        MAX_RECORD_SIZE,
        &mut buffer,
        &mut response,
    )
    .unwrap();
    assert_eq!(
        Reply::decode(send, &response[..count]).unwrap().copied as usize,
        MAX_RECORD_SIZE
    );
    assert_eq!((queue.len(), buffer.reads), (1, 1));
    buffer.bytes.fill(0);
    let recv = request(Operation::Receive, MAX_RECORD_SIZE);
    let count = transfer(
        &mut queue,
        recv,
        source(),
        MAX_RECORD_SIZE,
        &mut buffer,
        &mut response,
    )
    .unwrap();
    let reply = Reply::decode(recv, &response[..count]).unwrap();
    assert_eq!(
        reply.source,
        Some(Address::UnixAbstract(b"sender\0identity"))
    );
    assert_eq!(reply.length as usize, MAX_RECORD_SIZE);
    assert_eq!(
        &buffer.bytes[17..17 + MAX_RECORD_SIZE],
        &original[17..17 + MAX_RECORD_SIZE]
    );
    assert_eq!(&buffer.bytes[..17], &[0; 17]);
    assert!(buffer.bytes[17 + MAX_RECORD_SIZE..]
        .iter()
        .all(|byte| *byte == 0));
    assert_eq!((queue.len(), buffer.writes), (0, 1));
}

#[test]
fn failed_copies_bounds_and_reply_validation_never_consume_or_append_records() {
    let mut queue = RecordQueue::new();
    let mut buffer = Buffer::new(100);
    let mut response = [0; MAX_REPLY_LEN];
    let send = request(Operation::Send, 4);
    buffer.error = -5;
    assert_eq!(
        transfer(
            &mut queue,
            send,
            source(),
            MAX_RECORD_SIZE,
            &mut buffer,
            &mut response
        ),
        Err(-5)
    );
    assert!(queue.is_empty());
    queue.push(source(), b"data", MAX_RECORD_SIZE).unwrap();
    let recv = request(Operation::Receive, 4);
    assert_eq!(
        transfer(
            &mut queue,
            recv,
            source(),
            MAX_RECORD_SIZE,
            &mut buffer,
            &mut response
        ),
        Err(-5)
    );
    assert_eq!((queue.len(), queue.charged()), (1, 4));
    buffer.error = 0;
    for operation in [Operation::Send, Operation::Receive] {
        let valid = request(operation, 4);
        let calls = (buffer.reads, buffer.writes);
        assert_eq!(
            transfer(
                &mut queue,
                valid,
                source(),
                MAX_RECORD_SIZE,
                &mut buffer,
                &mut response[..10]
            ),
            Err(-22)
        );
        let invalid = Request {
            offset: 99,
            ..valid
        };
        assert_eq!(
            transfer(
                &mut queue,
                invalid,
                source(),
                MAX_RECORD_SIZE,
                &mut buffer,
                &mut response
            ),
            Err(-22)
        );
        assert_eq!((buffer.reads, buffer.writes), calls);
        assert_eq!((queue.len(), queue.charged()), (1, 4));
    }
    let count = transfer(
        &mut queue,
        recv,
        source(),
        MAX_RECORD_SIZE,
        &mut buffer,
        &mut response,
    )
    .unwrap();
    assert_eq!(Reply::decode(recv, &response[..count]).unwrap().length, 4);
    assert_eq!(&buffer.bytes[17..21], b"data");
    assert!(queue.is_empty());
}

#[test]
fn peek_truncation_empty_records_and_queue_pressure_are_not_stream_operations() {
    let mut queue = RecordQueue::new();
    let mut buffer = Buffer::new(MAX_RECORD_SIZE + 17);
    let mut response = [0; MAX_REPLY_LEN];
    queue.push(source(), b"first", MAX_RECORD_SIZE).unwrap();
    queue.push(source(), b"second", MAX_RECORD_SIZE).unwrap();
    let recv = request(Operation::Receive, 2);
    for _ in 0..3 {
        let peek = Request { peek: true, ..recv };
        transfer(
            &mut queue,
            peek,
            source(),
            MAX_RECORD_SIZE,
            &mut buffer,
            &mut response,
        )
        .unwrap();
        assert_eq!((queue.len(), queue.charged()), (2, 11));
    }
    transfer(
        &mut queue,
        recv,
        source(),
        MAX_RECORD_SIZE,
        &mut buffer,
        &mut response,
    )
    .unwrap();
    let count = transfer(
        &mut queue,
        request(Operation::Receive, 10),
        source(),
        MAX_RECORD_SIZE,
        &mut buffer,
        &mut response,
    )
    .unwrap();
    assert_eq!(
        Reply::decode(request(Operation::Receive, 10), &response[..count])
            .unwrap()
            .length,
        6
    );
    assert_eq!(&buffer.bytes[17..23], b"second");
    for operation in [Operation::Send, Operation::Receive] {
        let empty = request(operation, 0);
        let count = transfer(
            &mut queue,
            empty,
            source(),
            MAX_RECORD_SIZE,
            &mut buffer,
            &mut response,
        )
        .unwrap();
        assert_eq!(Reply::decode(empty, &response[..count]).unwrap().length, 0);
    }
    assert!(queue.is_empty());
    queue
        .push(source(), &vec![1; MAX_RECORD_SIZE], MAX_RECORD_SIZE)
        .unwrap();
    let reads = buffer.reads;
    assert_eq!(
        transfer(
            &mut queue,
            request(Operation::Send, 1),
            source(),
            MAX_RECORD_SIZE,
            &mut buffer,
            &mut response
        ),
        Err(-11)
    );
    assert_eq!(buffer.reads, reads);
    assert_eq!(queue.charged(), MAX_RECORD_SIZE);
}
