use mochios_posix_protocol as wire;
use posix_service::{AttachedObject, AuthenticatedProcess, PeerIdentity, PosixService};
fn peer(pid: u64) -> PeerIdentity {
    PeerIdentity {
        process_id: pid,
        effective_uid: 0,
        effective_gid: 0,
    }
}
fn service() -> PosixService<u32> {
    let mut s = PosixService::new();
    s.initialize_bootstrap_process(
        AuthenticatedProcess {
            handle: 7,
            process_id: 70,
        },
        0,
        0,
        &[],
    )
    .unwrap();
    s
}
fn install(
    s: &mut PosixService<u32>,
    pid: u64,
    header: wire::Header,
    payload: &[u8],
    attachments: &[AttachedObject<u32>],
) -> Result<(), i32> {
    posix_service::account_bootstrap::install(s, peer(pid), header, payload, attachments)
}
fn header() -> wire::Header {
    wire::Header {
        opcode: wire::OP_ACCOUNT_ENDPOINT_INSTALL,
        ..Default::default()
    }
}
fn endpoint() -> AttachedObject<u32> {
    AttachedObject {
        handle: 41,
        rights: wire::ACCOUNT_ENDPOINT_RIGHTS,
    }
}
#[test]
fn only_the_inherited_bootstrap_process_can_publish_even_among_posix_root_processes() {
    let mut s = service();
    s.initialize_process(
        peer(70),
        AuthenticatedProcess {
            handle: 8,
            process_id: 80,
        },
        0,
        0,
        &[],
    )
    .unwrap();
    assert_eq!(install(&mut s, 80, header(), &[], &[endpoint()]), Err(-1));
    assert_eq!(install(&mut s, 999, header(), &[], &[endpoint()]), Err(-1));
    assert_eq!(s.account_endpoint(), None);
    assert_eq!(install(&mut s, 70, header(), &[], &[endpoint()]), Ok(()));
    assert_eq!(s.account_endpoint(), Some(41));
    let replacement = AttachedObject {
        handle: 42,
        ..endpoint()
    };
    assert_eq!(install(&mut s, 70, header(), &[], &[replacement]), Err(-17));
    assert_eq!(s.account_endpoint(), Some(41));
}
#[test]
fn malformed_handoffs_cannot_publish_or_replace_authority() {
    let mut s = service();
    for flags in [1, 2, u32::MAX] {
        assert_eq!(
            install(
                &mut s,
                70,
                wire::Header { flags, ..header() },
                &[],
                &[endpoint()]
            ),
            Err(-22)
        );
    }
    assert_eq!(
        install(
            &mut s,
            70,
            wire::Header {
                status: -5,
                ..header()
            },
            &[],
            &[endpoint()]
        ),
        Err(-22)
    );
    assert_eq!(
        install(&mut s, 70, header(), b"pid=70", &[endpoint()]),
        Err(-22)
    );
    assert_eq!(install(&mut s, 70, header(), &[], &[]), Err(-22));
    assert_eq!(
        install(&mut s, 70, header(), &[], &[endpoint(), endpoint()]),
        Err(-22)
    );
    for rights in [
        0,
        mnu_abi::HANDLE_RIGHT_SEND,
        wire::ACCOUNT_ENDPOINT_RIGHTS | mnu_abi::HANDLE_RIGHT_RECEIVE,
    ] {
        assert_eq!(
            install(
                &mut s,
                70,
                header(),
                &[],
                &[AttachedObject {
                    rights,
                    ..endpoint()
                }]
            ),
            Err(-13)
        );
    }
    assert_eq!(
        install(
            &mut s,
            70,
            header(),
            &[],
            &[AttachedObject {
                handle: 0,
                ..endpoint()
            }]
        ),
        Err(-13)
    );
    assert_eq!(s.account_endpoint(), None);
}

#[test]
fn claimed_root_credentials_cannot_override_the_registered_bootstrap_session() {
    let mut s = PosixService::new();
    s.initialize_bootstrap_process(
        AuthenticatedProcess {
            handle: 7,
            process_id: 70,
        },
        501,
        20,
        &[],
    )
    .unwrap();
    assert_eq!(install(&mut s, 70, header(), &[], &[endpoint()]), Err(-1));
    assert_eq!(s.account_endpoint(), None);
}
