use mochios_posix_client::{
    Client, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol::{self as protocol, cpu_sleep as wire};
use std::cell::RefCell;

fn request() -> wire::Request {
    wire::Request {
        process: 42,
        absolute: false,
        nanoseconds: 1_234_567_890,
    }
}

#[test]
fn request_frames_are_canonical_bounded_and_preserve_full_timespec_range() {
    for request in [
        request(),
        wire::Request {
            process: 0,
            absolute: true,
            nanoseconds: protocol::process_timer::MAX_DURATION_NS,
        },
    ] {
        let mut packet = [0xa5; wire::REQUEST_LEN + 1];
        wire::encode_request(request, &mut packet).unwrap();
        assert_eq!(packet[wire::REQUEST_LEN], 0xa5);
        assert_eq!(
            wire::decode_request(&packet[..wire::REQUEST_LEN]),
            Ok(request)
        );
        for length in 0..wire::REQUEST_LEN {
            assert!(wire::decode_request(&packet[..length]).is_err());
        }
        assert!(wire::decode_request(&packet).is_err());
        for offset in [0, 1, 2, 3, 4, 5, 6, 7] {
            let mut corrupt = packet;
            corrupt[offset] = 3;
            assert!(wire::decode_request(&corrupt[..wire::REQUEST_LEN]).is_err());
        }
    }
    for invalid in [
        wire::Request {
            process: 1 << 31,
            ..request()
        },
        wire::Request {
            nanoseconds: protocol::process_timer::MAX_DURATION_NS + 1,
            ..request()
        },
    ] {
        let mut packet = [0xa5; wire::REQUEST_LEN];
        assert!(wire::encode_request(invalid, &mut packet).is_err());
        assert_eq!(packet, [0xa5; wire::REQUEST_LEN]);
    }
    assert!(wire::encode_request(request(), &mut [0; wire::REQUEST_LEN - 1]).is_err());
}

#[test]
fn replies_and_completion_records_reject_noncanonical_or_native_error_values() {
    for deadline in [0, 1, u128::MAX] {
        let mut packet = [0xa5; wire::REPLY_LEN + 1];
        wire::encode_reply(deadline, &mut packet).unwrap();
        assert_eq!(wire::decode_reply(&packet[..wire::REPLY_LEN]), Ok(deadline));
        assert_eq!(packet[wire::REPLY_LEN], 0xa5);
        assert!(wire::decode_reply(&packet).is_err());
        for length in 0..wire::REPLY_LEN {
            assert!(wire::decode_reply(&packet[..length]).is_err());
        }
        for offset in 0..8 {
            let mut corrupt = packet;
            corrupt[offset] ^= 2;
            assert!(wire::decode_reply(&corrupt[..wire::REPLY_LEN]).is_err());
        }
    }
    for result in [Ok(()), Err(-5), Err(-3), Err(-4095)] {
        let mut packet = [0xa5; wire::COMPLETION_LEN + 1];
        wire::encode_completion(result, &mut packet).unwrap();
        assert_eq!(
            wire::decode_completion(&packet[..wire::COMPLETION_LEN]),
            Ok(result)
        );
        assert_eq!(packet[wire::COMPLETION_LEN], 0xa5);
        for length in 0..wire::COMPLETION_LEN {
            assert!(wire::decode_completion(&packet[..length]).is_err());
        }
        assert!(wire::decode_completion(&packet).is_err());
    }
    for status in [1, i32::MAX, i32::MIN, -4096] {
        assert!(wire::encode_completion(Err(status), &mut [0; wire::COMPLETION_LEN]).is_err());
        let mut packet = [1, 0, 0, 0, 0, 0, 0, 0];
        packet[4..8].copy_from_slice(&status.to_le_bytes());
        assert!(wire::decode_completion(&packet).is_err());
    }
}

struct Reply {
    handles: Vec<ObjectHandleAttachment<u32>>,
    payload: Vec<u8>,
    status: i32,
    transport_error: bool,
    wrong_request: bool,
    closed: RefCell<Vec<u32>>,
    requests: RefCell<Vec<wire::Request>>,
}
impl Reply {
    fn valid() -> Self {
        let mut payload = vec![0; wire::REPLY_LEN];
        wire::encode_reply(u128::MAX, &mut payload).unwrap();
        Self {
            handles: vec![ObjectHandleAttachment {
                handle: 77,
                rights: wire::COMPLETION_RIGHTS,
            }],
            payload,
            status: 0,
            transport_error: false,
            wrong_request: false,
            closed: RefCell::new(Vec::new()),
            requests: RefCell::new(Vec::new()),
        }
    }
}
impl Transport for Reply {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("CPU sleep must use explicit Handle transfer")
    }
}
impl ObjectTransport for Reply {
    type Handle = u32;
    fn close_received_handle(&self, handle: u32) {
        self.closed.borrow_mut().push(handle);
    }
    fn call_with_handles(
        &self,
        input: &[u8],
        output: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(input).unwrap();
        if header.opcode == protocol::OP_THREAD_CPU_SLEEP {
            assert_eq!(handles.len(), 1);
            assert_eq!(
                handles.get(0),
                Some(ObjectHandleAttachment {
                    handle: 88,
                    rights: mnu_abi::HANDLE_RIGHT_WAIT
                })
            );
            assert_eq!(wire::decode_thread_request(payload).unwrap().process, 0);
        } else {
            assert!(handles.is_empty());
            assert_eq!(header.opcode, protocol::OP_PROCESS_CPU_SLEEP);
        }
        handles.clear();
        assert_eq!(header.flags, 0);
        self.requests
            .borrow_mut()
            .push(wire::decode_request(payload).unwrap());
        for handle in &self.handles {
            handles.push(*handle).unwrap();
        }
        if self.transport_error {
            return Err(());
        }
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id + u64::from(self.wrong_request),
                payload_len: self.payload.len() as u32,
                status: self.status,
                ..Default::default()
            },
            &self.payload,
            output,
        )
        .map_err(|_| ())
    }
}

#[test]
fn client_returns_only_the_private_read_wait_handle_and_full_deadline() {
    let client = Client::new(Reply::valid());
    let pending = client.begin_process_cpu_sleep(request()).unwrap();
    assert_eq!(pending.completion.handle, 77);
    assert_eq!(pending.completion.rights, wire::COMPLETION_RIGHTS);
    assert_eq!(pending.deadline_ns, u128::MAX);
    assert_eq!(*client.transport().requests.borrow(), [request()]);
    assert!(client.transport().closed.borrow().is_empty());
}

#[test]
fn invalid_replies_and_transport_failures_release_every_received_handle_once() {
    for case in 0..10 {
        let mut reply = Reply::valid();
        match case {
            0 => reply.handles.clear(),
            1 => reply.handles[0].rights |= mnu_abi::HANDLE_RIGHT_TRANSFER,
            2 => reply.handles[0].rights &= !mnu_abi::HANDLE_RIGHT_WAIT,
            3 => reply.handles.push(ObjectHandleAttachment {
                handle: 78,
                rights: wire::COMPLETION_RIGHTS,
            }),
            4 => reply.handles[0].handle = 0,
            5 => reply.payload[0] = 2,
            6 => reply.status = protocol::STATUS_EPERM,
            7 => reply.transport_error = true,
            8 => reply.wrong_request = true,
            9 => reply.handles.push(reply.handles[0]),
            _ => unreachable!(),
        }
        let mut expected: Vec<_> = reply
            .handles
            .iter()
            .map(|handle| handle.handle)
            .filter(|handle| *handle != 0)
            .collect();
        expected.sort_unstable();
        expected.dedup();
        let client = Client::new(reply);
        assert!(
            client.begin_process_cpu_sleep(request()).is_err(),
            "case {case}"
        );
        let mut closed = client.transport().closed.borrow().clone();
        closed.sort_unstable();
        assert_eq!(closed, expected, "case {case}");
    }
}

#[test]
fn invalid_client_input_never_performs_a_transport_operation() {
    let client = Client::new(Reply::valid());
    assert!(
        client
            .begin_process_cpu_sleep(wire::Request {
                process: u64::MAX,
                ..request()
            })
            .is_err()
    );
    assert!(client.transport().requests.borrow().is_empty());
    assert!(client.transport().closed.borrow().is_empty());
}

#[test]
fn thread_client_delegates_only_wait_and_never_closes_the_borrowed_source() {
    for case in 0..7 {
        let mut reply = Reply::valid();
        match case {
            1 => reply.handles[0].handle = 88,
            2 => reply.handles.push(ObjectHandleAttachment {
                handle: 88,
                rights: wire::COMPLETION_RIGHTS,
            }),
            3 => reply.status = protocol::STATUS_EPERM,
            4 => reply.transport_error = true,
            5 => reply.payload[0] = 2,
            6 => reply.handles[0].rights |= mnu_abi::HANDLE_RIGHT_TRANSFER,
            _ => {}
        }
        let client = Client::new(reply);
        let result =
            client.begin_thread_cpu_sleep(88, true, protocol::process_timer::MAX_DURATION_NS);
        if case == 0 {
            let pending = result.unwrap();
            assert_eq!(pending.completion.handle, 77);
            assert_eq!(pending.deadline_ns, u128::MAX);
            assert!(client.transport().closed.borrow().is_empty());
        } else {
            assert!(result.is_err());
            assert_eq!(
                *client.transport().closed.borrow(),
                if case == 1 { vec![] } else { vec![77] }
            );
        }
    }
    let client = Client::new(Reply::valid());
    assert!(client.begin_thread_cpu_sleep(0, false, 1).is_err());
    assert!(
        client
            .begin_thread_cpu_sleep(88, false, protocol::process_timer::MAX_DURATION_NS + 1)
            .is_err()
    );
    assert!(client.transport().requests.borrow().is_empty());
}

#[test]
fn thread_wire_has_no_caller_selected_process_or_thread_id() {
    let mut bytes = [0; wire::REQUEST_LEN];
    wire::encode_request(
        wire::Request {
            process: 0,
            absolute: true,
            nanoseconds: 1,
        },
        &mut bytes,
    )
    .unwrap();
    assert!(wire::decode_thread_request(&bytes).is_ok());
    bytes[8] = 1;
    assert!(wire::decode_thread_request(&bytes).is_err());
}
