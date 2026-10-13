use posix_service::named_semaphore::{Create, MAX_NAME_BYTES, MAX_NAMES};
use posix_service::{AuthenticatedProcess, PeerIdentity, PosixService};

fn peer(process_id: u64) -> PeerIdentity {
    // Deliberately claim UID/GID zero; the service must ignore these fields.
    PeerIdentity {
        process_id,
        effective_uid: 0,
        effective_gid: 0,
    }
}
fn service() -> PosixService {
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 1,
                process_id: 1,
            },
            0,
            0,
            &[],
        )
        .unwrap();
    for (pid, uid, gid, groups) in [
        (2, 501, 20, &[][..]),
        (3, 502, 21, &[20][..]),
        (4, 503, 22, &[][..]),
    ] {
        service
            .initialize_process(
                peer(1),
                AuthenticatedProcess {
                    handle: pid as u32,
                    process_id: pid,
                },
                uid,
                gid,
                groups,
            )
            .unwrap();
    }
    service
}
fn create(mode: u32) -> Option<Create> {
    Some(Create {
        mode,
        value: 7,
        exclusive: false,
    })
}

fn set_umask(service: &mut PosixService, pid: u64, mask: u32) {
    use mochios_posix_protocol as protocol;
    let mut payload = [0; protocol::UMASK_PAYLOAD_LEN];
    protocol::encode_umask(mask, &mut payload).unwrap();
    let response = service.handle(
        peer(pid),
        protocol::Header {
            opcode: protocol::OP_UMASK_SET,
            payload_len: payload.len() as u32,
            ..Default::default()
        },
        &payload,
    );
    assert_eq!(response.header.status, 0);
}

#[test]
fn atomic_create_reuses_backing_and_exclusive_create_never_allocates() {
    let mut service = service();
    let first = service
        .open_named_semaphore(peer(2), b"/gate", create(0o600), |value| {
            assert_eq!(value, 7);
            Ok(41)
        })
        .unwrap();
    assert!(first.created);
    let second = service
        .open_named_semaphore(
            peer(2),
            b"/gate",
            Some(Create {
                mode: 0,
                value: u32::MAX,
                exclusive: false,
            }),
            |_| panic!("existing object allocated"),
        )
        .unwrap();
    assert!(!second.created);
    assert_eq!(first.handle, second.handle);
    assert_eq!(
        service
            .open_named_semaphore(
                peer(2),
                b"/gate",
                Some(Create {
                    mode: 0,
                    value: 0,
                    exclusive: true
                }),
                |_| panic!("exclusive collision allocated")
            )
            .unwrap_err(),
        -17
    );
    assert_eq!(
        service
            .open_named_semaphore(peer(2), b"/absent", None, |_| panic!("absent allocated"))
            .unwrap_err(),
        -2
    );
}

#[test]
fn service_credentials_umask_and_group_classes_control_access() {
    let mut service = service();
    service
        .open_named_semaphore(peer(2), b"/mask", create(0o666), |_| Ok(41))
        .unwrap();
    // Default umask 022 strips group/other write: self-claimed root cannot bypass it.
    for pid in [3, 4] {
        assert_eq!(
            service
                .open_named_semaphore(peer(pid), b"/mask", None, |_| panic!())
                .unwrap_err(),
            -13
        );
    }
    service
        .open_named_semaphore(peer(2), b"/group", create(0o660), |_| Ok(42))
        .unwrap();
    // 022 also strips group write from 660. Root credentials really stored in
    // the service, not the forged peer fields, can still open the object.
    assert_eq!(
        service
            .open_named_semaphore(peer(3), b"/group", None, |_| panic!())
            .unwrap_err(),
        -13
    );
    assert_eq!(
        service
            .open_named_semaphore(peer(1), b"/group", None, |_| panic!())
            .unwrap()
            .handle,
        42
    );
    // An owner does not fall through to permissive other bits.
    service
        .open_named_semaphore(peer(2), b"/owner", create(0o006), |_| Ok(43))
        .unwrap();
    assert_eq!(
        service
            .open_named_semaphore(peer(2), b"/owner", None, |_| panic!())
            .unwrap_err(),
        -13
    );
    assert_eq!(
        service
            .open_named_semaphore(peer(99), b"/owner", None, |_| panic!())
            .unwrap_err(),
        -3
    );
    set_umask(&mut service, 2, 0);
    service
        .open_named_semaphore(peer(2), b"/supplementary", create(0o660), |_| Ok(44))
        .unwrap();
    assert_eq!(
        service
            .open_named_semaphore(peer(3), b"/supplementary", None, |_| panic!())
            .unwrap()
            .handle,
        44
    );
    assert_eq!(
        service
            .open_named_semaphore(peer(4), b"/supplementary", None, |_| panic!())
            .unwrap_err(),
        -13
    );
    service
        .open_named_semaphore(peer(2), b"/public", create(0o666), |_| Ok(45))
        .unwrap();
    assert_eq!(
        service
            .open_named_semaphore(peer(4), b"/public", None, |_| panic!())
            .unwrap()
            .handle,
        45
    );
}

#[test]
fn competing_creators_publish_exactly_one_initialized_backing() {
    use std::sync::{
        Mutex,
        atomic::{AtomicU32, Ordering},
    };
    let service = Mutex::new(service());
    let allocations = AtomicU32::new(0);
    let publications = AtomicU32::new(0);
    std::thread::scope(|scope| {
        for _ in 0..32 {
            scope.spawn(|| {
                let opened = service
                    .lock()
                    .unwrap()
                    .open_named_semaphore(peer(2), b"/race", create(0o600), |_| {
                        allocations.fetch_add(1, Ordering::Relaxed);
                        Ok(42)
                    })
                    .unwrap();
                assert_eq!(opened.handle, 42);
                if opened.created {
                    publications.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });
    assert_eq!(allocations.load(Ordering::Acquire), 1);
    assert_eq!(publications.load(Ordering::Acquire), 1);
}

#[test]
fn validation_and_failed_initialization_leave_no_published_name() {
    let mut service = service();
    for name in [&b""[..], b"/", b"gate", b"/nested/gate", b"/nul\0gate"] {
        assert_eq!(
            service
                .open_named_semaphore(peer(2), name, create(0o600), |_| panic!())
                .unwrap_err(),
            -22
        );
    }
    let too_long = format!("/{}", "x".repeat(MAX_NAME_BYTES + 1));
    assert_eq!(
        service
            .open_named_semaphore(peer(2), too_long.as_bytes(), create(0o600), |_| panic!())
            .unwrap_err(),
        -36
    );
    assert_eq!(
        service
            .open_named_semaphore(
                peer(2),
                b"/bad",
                Some(Create {
                    mode: 0o600,
                    value: u32::MAX,
                    exclusive: false
                }),
                |_| panic!()
            )
            .unwrap_err(),
        -22
    );
    assert_eq!(
        service
            .open_named_semaphore(peer(2), b"/gate", create(0o600), |_| Err(-12))
            .unwrap_err(),
        -12
    );
    assert_eq!(
        service
            .open_named_semaphore(peer(2), b"/gate", None, |_| panic!())
            .unwrap_err(),
        -2
    );
    let maximum = format!("/{}", "x".repeat(MAX_NAME_BYTES));
    assert!(
        service
            .open_named_semaphore(peer(2), maximum.as_bytes(), create(0o600), |_| Ok(40))
            .unwrap()
            .created
    );
}

#[test]
fn unlink_requires_owner_and_recreation_never_reuses_old_backing() {
    let mut service = service();
    let old = service
        .open_named_semaphore(peer(2), b"/gate", create(0o600), |_| Ok(41))
        .unwrap();
    assert_eq!(service.unlink_named_semaphore(peer(3), b"/gate"), Err(-13));
    assert_eq!(service.unlink_named_semaphore(peer(99), b"/gate"), Err(-3));
    assert_eq!(service.unlink_named_semaphore(peer(2), b"/gate"), Ok(41));
    assert_eq!(service.unlink_named_semaphore(peer(2), b"/gate"), Err(-2));
    let new = service
        .open_named_semaphore(peer(2), b"/gate", create(0o600), |_| Ok(42))
        .unwrap();
    assert_eq!(old.handle, 41);
    assert_eq!(new.handle, 42);
    assert_eq!(service.unlink_named_semaphore(peer(1), b"/gate"), Ok(42));
}

#[test]
fn bounded_namespace_still_allows_existing_opens_and_reclaims_unlinked_names() {
    let mut service = service();
    for index in 0..MAX_NAMES {
        let name = format!("/gate-{index}");
        service
            .open_named_semaphore(peer(2), name.as_bytes(), create(0o600), |_| {
                Ok(index as u32 + 10)
            })
            .unwrap();
    }
    assert_eq!(
        service
            .open_named_semaphore(peer(2), b"/overflow", create(0o600), |_| panic!())
            .unwrap_err(),
        -28
    );
    assert_eq!(
        service
            .open_named_semaphore(peer(2), b"/gate-0", None, |_| panic!())
            .unwrap()
            .handle,
        10
    );
    assert_eq!(service.unlink_named_semaphore(peer(2), b"/gate-0"), Ok(10));
    assert!(
        service
            .open_named_semaphore(peer(2), b"/overflow", create(0o600), |_| Ok(99))
            .unwrap()
            .created
    );
}
