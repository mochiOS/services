use mochios_posix_protocol::{self as wire, system_identity as identity};
use posix_service::{AuthenticatedProcess, PeerIdentity, PosixService};
#[path = "../src/system_identity_metadata.rs"]
mod metadata;

fn peer(pid: u64) -> PeerIdentity {
    // Deliberately lie about the UID. Only service-owned sessions authorize.
    PeerIdentity {
        process_id: pid,
        effective_uid: 0,
        effective_gid: 0,
    }
}
fn service() -> PosixService {
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 7,
                process_id: 70,
            },
            0,
            0,
            &[],
        )
        .unwrap();
    service
        .initialize_process(
            peer(70),
            AuthenticatedProcess {
                handle: 8,
                process_id: 80,
            },
            501,
            501,
            &[],
        )
        .unwrap();
    service
}
fn request(
    service: &mut PosixService,
    pid: u64,
    opcode: u16,
    payload: &[u8],
) -> posix_service::Response {
    service.handle(
        peer(pid),
        wire::Header {
            opcode,
            request_id: 41,
            payload_len: payload.len() as u32,
            ..Default::default()
        },
        payload,
    )
}
#[test]
fn wire_is_exact_bounded_and_allows_non_utf8_node_bytes() {
    let record = identity::Record {
        system: b"mochiOS",
        node: b"node\xff",
        release: b"26",
        version: b"build 8",
        machine: b"x86_64",
    };
    let mut bytes = [0; identity::MAX_RECORD];
    let size = identity::encode(record, &mut bytes).unwrap();
    assert_eq!(identity::decode(&bytes[..size]), Ok(record));
    for length in 0..size {
        assert!(identity::decode(&bytes[..length]).is_err());
    }
    assert!(identity::decode(&bytes[..size + 1]).is_err());
    assert!(identity::encode(record, &mut bytes[..size - 1]).is_err());
    let long = [b'a'; identity::FIELD_CAPACITY];
    for node in [&long[..], b"nul\0byte"] {
        assert!(identity::encode(identity::Record { node, ..record }, &mut bytes).is_err());
    }
    let max = [b'a'; identity::HOST_NAME_MAX];
    let record = identity::Record {
        system: &max,
        node: &max,
        release: &max,
        version: &max,
        machine: &max,
    };
    assert_eq!(
        identity::encode(record, &mut bytes),
        Ok(identity::MAX_RECORD)
    );
    assert_eq!(identity::decode(&bytes), Ok(record));
}
#[test]
fn published_release_comes_from_manifest_and_namespace_is_shared() {
    let mut service = service();
    let response = request(&mut service, 80, wire::OP_SYSTEM_IDENTITY, &[]);
    assert_eq!(response.header.status, 0);
    assert_eq!(response.header.request_id, 41);
    let record = identity::decode(&response.payload).unwrap();
    assert_eq!(record.system, b"mochiOS");
    assert_eq!(record.node, b"localhost");
    assert_eq!(record.machine, std::env::consts::ARCH.as_bytes());
    let actual =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../version.toml"))
            .unwrap();
    let expected = metadata::generate(&actual, std::env::consts::ARCH).unwrap();
    assert!(expected.contains(std::str::from_utf8(record.release).unwrap()));
    assert!(expected.contains(std::str::from_utf8(record.version).unwrap()));
    assert_eq!(
        request(&mut service, 70, wire::OP_HOSTNAME_SET, b"developer-node")
            .header
            .status,
        0
    );
    let response = request(&mut service, 80, wire::OP_SYSTEM_IDENTITY, &[]);
    assert_eq!(
        identity::decode(&response.payload).unwrap().node,
        b"developer-node"
    );
}
#[test]
fn service_credentials_authorize_mutation_not_claimed_peer_uid() {
    let mut service = service();
    assert_eq!(
        request(&mut service, 80, wire::OP_HOSTNAME_SET, b"forged-root")
            .header
            .status,
        -1
    );
    assert_eq!(
        request(&mut service, 999, wire::OP_HOSTNAME_SET, b"unregistered")
            .header
            .status,
        -1
    );
    assert_eq!(
        request(&mut service, 999, wire::OP_SYSTEM_IDENTITY, &[])
            .header
            .status,
        -1
    );
    let false_unprivileged = PeerIdentity {
        effective_uid: 501,
        ..peer(70)
    };
    let response = service.handle(
        false_unprivileged,
        wire::Header {
            opcode: wire::OP_HOSTNAME_SET,
            ..Default::default()
        },
        b"authorized",
    );
    assert_eq!(response.header.status, 0);
    for bad in [&[b'a'; 256][..], b"nul\0name"] {
        assert_eq!(
            request(&mut service, 70, wire::OP_HOSTNAME_SET, bad)
                .header
                .status,
            -22
        );
    }
    let response = request(&mut service, 70, wire::OP_SYSTEM_IDENTITY, &[]);
    assert_eq!(
        identity::decode(&response.payload).unwrap().node,
        b"authorized"
    );
    assert_eq!(
        request(&mut service, 70, wire::OP_HOSTNAME_SET, &[])
            .header
            .status,
        0
    );
    let response = request(&mut service, 70, wire::OP_SYSTEM_IDENTITY, &[]);
    assert_eq!(identity::decode(&response.payload).unwrap().node, b"");
}
#[test]
fn rejects_nonzero_flags_status_and_unexpected_payloads() {
    let mut service = service();
    for opcode in [wire::OP_HOSTNAME_SET, wire::OP_SYSTEM_IDENTITY] {
        assert!(wire::is_request_opcode(opcode));
        for (flags, status) in [(1, 0), (0, -1), (u32::MAX, 0)] {
            let response = service.handle(
                peer(70),
                wire::Header {
                    opcode,
                    flags,
                    status,
                    ..Default::default()
                },
                &[],
            );
            assert_eq!(response.header.status, -22);
        }
    }
    assert_eq!(
        request(&mut service, 70, wire::OP_SYSTEM_IDENTITY, b"junk")
            .header
            .status,
        -22
    );
}
#[test]
fn release_generation_fails_explicitly_for_missing_duplicate_and_unsupported_values() {
    let valid =
        "release = \"26.0.0\"\nbuild_date = \"2026-10-25\"\nchannel = \"preview\"\nbuild = 8\n";
    assert!(
        metadata::generate(valid, "x86_64")
            .unwrap()
            .contains("build 8 preview 2026-10-25")
    );
    for bad in [
        valid.replace("build = 8", "build = nope"),
        valid.replace("release = \"26.0.0\"", ""),
        format!("{valid}build = 9\n"),
        valid.replace("preview", "bad\\escape"),
        valid.replace("26.0.0", &"x".repeat(256)),
    ] {
        assert!(metadata::generate(&bad, "x86_64").is_err());
    }
    assert!(metadata::generate(valid, "").is_err());
}
