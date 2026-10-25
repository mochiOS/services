use mochios_posix_client::{Client, Transport};
use mochios_posix_protocol::{
    self as protocol,
    wait_usage::{self as wire, Observation},
};

fn sample() -> Observation {
    Observation {
        info: protocol::WaitInfo {
            result: protocol::WaitResult {
                process_id: 42,
                status: 37 << 8,
            },
            real_uid: 505,
        },
        usage: protocol::wait_usage::Usage {
            cpu: protocol::WaitedChildCpuUsage {
                user_ticks: u128::from(u64::MAX) + 7,
                kernel_ticks: 23,
                ticks_per_second: 500,
            },
            peak_resident_bytes: 12 * 1024 + 1,
        },
    }
}

#[test]
fn observation_preserves_wide_cpu_counts_and_rejects_missing_units_or_malformed_nohang() {
    let mut bytes = [0xa5; wire::LEN + 1];
    wire::encode(sample(), &mut bytes).unwrap();
    assert_eq!(bytes[wire::LEN], 0xa5);
    assert_eq!(wire::decode(&bytes[..wire::LEN]), Ok(sample()));
    for length in [0, wire::LEN - 1, wire::LEN + 1] {
        assert!(wire::decode(&bytes[..length]).is_err());
    }
    for index in [12, 20] {
        let mut corrupted = bytes;
        corrupted[index] = 1;
        assert!(wire::decode(&corrupted[..wire::LEN]).is_err());
    }
    let mut invalid = sample();
    invalid.usage.cpu.ticks_per_second = 0;
    assert!(wire::encode(invalid, &mut bytes).is_err());
    invalid = sample();
    invalid.info.result.process_id = 0;
    assert!(wire::encode(invalid, &mut bytes).is_err());
    wire::encode(Observation::default(), &mut bytes).unwrap();
    assert_eq!(
        wire::decode(&bytes[..wire::LEN]),
        Ok(Observation::default())
    );
}

struct UsageTransport;
impl Transport for UsageTransport {
    type Error = ();
    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, protocol::OP_WAIT_CHILD_USAGE);
        let (request, epoch) = protocol::decode_guarded_wait_request(payload).unwrap();
        assert_eq!((request.selector, request.options, epoch), (-1, 1, 23));
        assert_eq!(payload.len(), protocol::WAIT_GUARDED_REQUEST_LEN);
        let mut bytes = [0; wire::LEN];
        wire::encode(sample(), &mut bytes).unwrap();
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                payload_len: bytes.len() as u32,
                ..Default::default()
            },
            &bytes,
            response,
        )
        .map_err(|_| ())
    }
}

#[test]
fn client_gets_one_guarded_event_and_usage_without_sending_identity_or_pointer() {
    assert_eq!(
        Client::new(UsageTransport).wait_child_usage_since(-1, 1, 23),
        Ok(sample())
    );
}

struct AggregateTransport;
impl Transport for AggregateTransport {
    type Error = ();
    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, protocol::OP_WAITED_CHILD_USAGE);
        assert_eq!(header.flags, 0);
        assert!(payload.is_empty());
        let mut bytes = [0; wire::USAGE_LEN];
        wire::encode_usage(sample().usage, &mut bytes).unwrap();
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                payload_len: bytes.len() as u32,
                ..Default::default()
            },
            &bytes,
            response,
        )
        .map_err(|_| ())
    }
}

#[test]
fn client_fetches_cpu_and_peak_in_one_authenticated_snapshot() {
    assert_eq!(
        Client::new(AggregateTransport).waited_child_usage(),
        Ok(sample().usage)
    );
    let mut bytes = [0xa5; wire::USAGE_LEN + 1];
    wire::encode_usage(sample().usage, &mut bytes).unwrap();
    assert_eq!(bytes[wire::USAGE_LEN], 0xa5);
    assert_eq!(
        wire::decode_usage(&bytes[..wire::USAGE_LEN]),
        Ok(sample().usage)
    );
    for size in [0, wire::USAGE_LEN - 1, wire::USAGE_LEN + 1] {
        assert!(wire::decode_usage(&bytes[..size]).is_err());
    }
    let mut invalid = sample().usage;
    invalid.cpu = Default::default();
    assert!(wire::encode_usage(invalid, &mut bytes).is_err());
    bytes[..protocol::WAITED_CHILD_CPU_USAGE_LEN].fill(0);
    assert!(wire::decode_usage(&bytes[..wire::USAGE_LEN]).is_err());
}
