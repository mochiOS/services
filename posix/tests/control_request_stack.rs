use mochios_posix_client::{Client, ClientError, Transport};
use mochios_posix_protocol as wire;
use std::cell::Cell;

struct Observe {
    capacity: Cell<usize>,
    calls: Cell<usize>,
    payload: Vec<u8>,
    status: i32,
    reported_length: Option<usize>,
}
impl Transport for Observe {
    type Error = ();
    fn call(&self, request: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        self.capacity.set(output.len());
        self.calls.set(self.calls.get() + 1);
        let (header, _) = wire::decode(request).unwrap();
        if let Some(length) = self.reported_length {
            return Ok(length);
        }
        wire::encode(
            wire::Header {
                opcode: wire::OP_STATUS,
                request_id: header.request_id,
                status: self.status,
                payload_len: self.payload.len() as u32,
                ..Default::default()
            },
            &self.payload,
            output,
        )
        .map_err(|_| ())
    }
}
fn transport(payload: Vec<u8>) -> Observe {
    Observe {
        capacity: Cell::new(0),
        calls: Cell::new(0),
        payload,
        status: 0,
        reported_length: None,
    }
}

#[test]
fn small_controls_use_a_small_frame_but_long_requests_and_replies_keep_the_full_limit() {
    let client = Client::new(transport(vec![1; 8]));
    let mut reply = [0; 8];
    assert_eq!(client.request(17, 0, &[0; 16], &mut reply), Ok(8));
    assert_eq!(reply, [1; 8]);
    assert!(client.transport().capacity.get() <= 512);
    let long = vec![0; wire::MAX_CONTROL_PAYLOAD_LEN];
    assert_eq!(client.request(17, 0, &long, &mut reply), Ok(8));
    assert_eq!(client.transport().capacity.get(), wire::CONTROL_MESSAGE_LEN);
    let client = Client::new(transport(vec![7; wire::MAX_CONTROL_PAYLOAD_LEN]));
    let mut reply = vec![0; wire::MAX_CONTROL_PAYLOAD_LEN];
    assert_eq!(client.request(17, 0, &[], &mut reply), Ok(reply.len()));
    assert!(reply.iter().all(|byte| *byte == 7));
    assert_eq!(client.transport().capacity.get(), wire::CONTROL_MESSAGE_LEN);
}

#[test]
fn malformed_or_oversized_small_replies_are_never_replayed_with_a_bigger_buffer() {
    let mut observe = transport(vec![]);
    observe.reported_length = Some(usize::MAX);
    let client = Client::new(observe);
    assert_eq!(
        client.request(17, 0, &[], &mut []),
        Err(ClientError::ResponseTooLarge)
    );
    assert_eq!(client.transport().calls.get(), 1);
    let client = Client::new(transport(vec![0; 16]));
    assert_eq!(
        client.request(17, 0, &[], &mut [0; 8]),
        Err(ClientError::ResponseTooLarge)
    );
    assert_eq!(client.transport().calls.get(), 1);
}

#[test]
fn remote_errors_and_request_bounds_remain_explicit() {
    let mut observe = transport(vec![]);
    observe.status = wire::STATUS_EPERM;
    let client = Client::new(observe);
    assert_eq!(
        client.request(17, 0, &[], &mut []),
        Err(ClientError::Remote(wire::STATUS_EPERM))
    );
    assert_eq!(
        client.request(17, 0, &vec![0; wire::MAX_CONTROL_PAYLOAD_LEN + 1], &mut []),
        Err(ClientError::RequestTooLarge)
    );
    assert_eq!(client.transport().calls.get(), 1);
}
