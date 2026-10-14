use posix_service::shared_memory::{Access, Backing, MAX_NAMES, Open};
use posix_service::{AuthenticatedProcess, PeerIdentity, PosixService};
use std::sync::{Arc, Mutex};

fn peer(pid: u64) -> PeerIdentity {
    // Client-claimed root identity must not bypass registered credentials.
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
fn options(access: Access, create: bool, mode: u32) -> Open {
    Open {
        access,
        create,
        exclusive: false,
        truncate: false,
        mode,
    }
}
#[derive(Default)]
struct Objects {
    objects: Vec<Arc<Mutex<Vec<u8>>>>,
    fail_create: bool,
    fail_truncate: bool,
    truncations: usize,
}
impl Backing<u32> for Objects {
    fn create_zero_length(&mut self) -> Result<u32, i32> {
        if self.fail_create {
            return Err(-12);
        }
        self.objects.push(Arc::new(Mutex::new(Vec::new())));
        Ok(self.objects.len() as u32)
    }
    fn truncate_zero(&mut self, backing: u32) -> Result<(), i32> {
        if self.fail_truncate {
            return Err(-5);
        }
        self.truncations += 1;
        self.objects[backing as usize - 1].lock().unwrap().clear();
        Ok(())
    }
}

#[test]
fn atomic_create_zero_length_reuse_and_exclusive_conflict() {
    let mut service = service();
    let mut objects = Objects::default();
    let create = options(Access::ReadWrite, true, 0o600);
    let first = service
        .open_shared_memory(peer(2), b"/buffer", create, &mut objects)
        .unwrap();
    assert!(first.created);
    assert!(objects.objects[0].lock().unwrap().is_empty());
    let reopened = service
        .open_shared_memory(peer(2), b"/buffer", create, &mut objects)
        .unwrap();
    assert!(!reopened.created);
    assert_eq!(reopened.backing, first.backing);
    let exclusive = Open {
        exclusive: true,
        ..create
    };
    assert_eq!(
        service.open_shared_memory(peer(2), b"/buffer", exclusive, &mut objects),
        Err(-17)
    );
    assert_eq!(objects.objects.len(), 1);
}

#[test]
fn registered_credentials_umask_and_access_specific_attenuation() {
    use mochios_posix_protocol as wire;
    let mut service = service();
    let mut objects = Objects::default();
    let mut payload = [0; wire::UMASK_PAYLOAD_LEN];
    wire::encode_umask(0o027, &mut payload).unwrap();
    assert_eq!(
        service
            .handle(
                peer(2),
                wire::Header {
                    opcode: wire::OP_UMASK_SET,
                    payload_len: payload.len() as u32,
                    ..Default::default()
                },
                &payload
            )
            .header
            .status,
        0
    );
    let rw = options(Access::ReadWrite, true, 0o666);
    let opened = service
        .open_shared_memory(peer(2), b"/buffer", rw, &mut objects)
        .unwrap();
    assert_ne!(opened.rights & mnu_abi::HANDLE_RIGHT_WRITE, 0);
    let ro = options(Access::ReadOnly, false, 0);
    let reader = service
        .open_shared_memory(peer(3), b"/buffer", ro, &mut objects)
        .unwrap();
    assert_eq!(reader.rights & mnu_abi::HANDLE_RIGHT_WRITE, 0);
    assert_eq!(reader.rights & mnu_abi::HANDLE_RIGHT_MAP, 0);
    assert_ne!(reader.rights & mnu_abi::HANDLE_RIGHT_SEEK, 0);
    assert_eq!(
        service.open_shared_memory(
            peer(3),
            b"/buffer",
            Open {
                create: false,
                ..rw
            },
            &mut objects
        ),
        Err(-13)
    );
    assert_eq!(
        service.open_shared_memory(peer(4), b"/buffer", ro, &mut objects),
        Err(-13)
    );
    assert_eq!(
        service.open_shared_memory(peer(999), b"/buffer", ro, &mut objects),
        Err(-3)
    );
    // UID zero bypasses POSIX mode only, not native attenuation.
    assert_eq!(
        service
            .open_shared_memory(peer(1), b"/buffer", ro, &mut objects)
            .unwrap()
            .rights,
        reader.rights
    );
}

#[test]
fn failed_allocation_is_not_published_and_failed_truncate_preserves_object() {
    let mut service = service();
    let mut objects = Objects {
        fail_create: true,
        ..Default::default()
    };
    let rw = options(Access::ReadWrite, true, 0o600);
    assert_eq!(
        service.open_shared_memory(peer(2), b"/buffer", rw, &mut objects),
        Err(-12)
    );
    assert_eq!(
        service.open_shared_memory(
            peer(2),
            b"/buffer",
            Open {
                create: false,
                ..rw
            },
            &mut objects
        ),
        Err(-2)
    );
    objects.fail_create = false;
    let first = service
        .open_shared_memory(peer(2), b"/buffer", rw, &mut objects)
        .unwrap();
    objects.objects[0]
        .lock()
        .unwrap()
        .extend_from_slice(b"retained");
    objects.fail_truncate = true;
    let trunc = Open {
        truncate: true,
        create: false,
        ..rw
    };
    assert_eq!(
        service.open_shared_memory(peer(2), b"/buffer", trunc, &mut objects),
        Err(-5)
    );
    assert_eq!(&*objects.objects[0].lock().unwrap(), b"retained");
    objects.fail_truncate = false;
    assert_eq!(
        service
            .open_shared_memory(peer(2), b"/buffer", trunc, &mut objects)
            .unwrap()
            .backing,
        first.backing
    );
    assert!(objects.objects[0].lock().unwrap().is_empty());
    assert_eq!(objects.truncations, 1);
}

#[test]
fn unlink_keeps_existing_references_and_recreation_has_fresh_identity() {
    let mut service = service();
    let mut objects = Objects::default();
    let create = options(Access::ReadWrite, true, 0o666);
    let first = service
        .open_shared_memory(peer(2), b"/buffer", create, &mut objects)
        .unwrap();
    let mapping = objects.objects[0].clone();
    mapping.lock().unwrap().extend_from_slice(b"old");
    assert_eq!(service.unlink_shared_memory(peer(3), b"/buffer"), Err(-13));
    assert_eq!(
        service.unlink_shared_memory(peer(2), b"/buffer"),
        Ok(first.backing)
    );
    assert_eq!(service.unlink_shared_memory(peer(2), b"/buffer"), Err(-2));
    let fresh = service
        .open_shared_memory(peer(2), b"/buffer", create, &mut objects)
        .unwrap();
    assert_ne!(first.backing, fresh.backing);
    assert_eq!(&*mapping.lock().unwrap(), b"old");
    assert!(objects.objects[1].lock().unwrap().is_empty());
}

#[test]
fn invalid_names_options_and_namespace_quota_do_not_allocate() {
    let mut service = service();
    let mut objects = Objects::default();
    let create = options(Access::ReadWrite, true, 0o600);
    for name in [&b""[..], b"/", b"relative", b"/nested/name", b"/nul\0name"] {
        assert_eq!(
            service.open_shared_memory(peer(2), name, create, &mut objects),
            Err(-22)
        );
    }
    assert_eq!(
        service.open_shared_memory(
            peer(2),
            &[b'/'].into_iter().chain([b'a'; 256]).collect::<Vec<_>>(),
            create,
            &mut objects
        ),
        Err(-36)
    );
    for invalid in [
        Open {
            create: false,
            exclusive: true,
            ..create
        },
        Open {
            access: Access::ReadOnly,
            truncate: true,
            ..create
        },
    ] {
        assert_eq!(
            service.open_shared_memory(peer(2), b"/buffer", invalid, &mut objects),
            Err(-22)
        );
    }
    assert!(objects.objects.is_empty());
    for i in 0..MAX_NAMES {
        service
            .open_shared_memory(
                peer(2),
                format!("/item{i}").as_bytes(),
                create,
                &mut objects,
            )
            .unwrap();
    }
    assert_eq!(
        service.open_shared_memory(peer(2), b"/full", create, &mut objects),
        Err(-28)
    );
    service.unlink_shared_memory(peer(2), b"/item0").unwrap();
    assert!(
        service
            .open_shared_memory(peer(2), b"/full", create, &mut objects)
            .unwrap()
            .created
    );
}

#[test]
fn concurrent_creators_allocate_exactly_one_backing() {
    let state = Arc::new(Mutex::new((service(), Objects::default())));
    let threads: Vec<_> = (0..32)
        .map(|_| {
            let state = state.clone();
            std::thread::spawn(move || {
                let mut state = state.lock().unwrap();
                let (service, backend) = &mut *state;
                service
                    .open_shared_memory(
                        peer(2),
                        b"/race",
                        options(Access::ReadWrite, true, 0o600),
                        backend,
                    )
                    .unwrap()
            })
        })
        .collect();
    let opened: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(opened.iter().filter(|entry| entry.created).count(), 1);
    assert!(
        opened
            .iter()
            .all(|entry| entry.backing == opened[0].backing)
    );
    assert_eq!(state.lock().unwrap().1.objects.len(), 1);
}

#[test]
fn denied_truncation_is_not_executed_and_read_only_creation_is_zero_length() {
    let mut service = service();
    let mut objects = Objects::default();
    let ro = options(Access::ReadOnly, true, 0o440);
    let created = service
        .open_shared_memory(peer(2), b"/readonly", ro, &mut objects)
        .unwrap();
    assert_eq!(created.rights & mnu_abi::HANDLE_RIGHT_WRITE, 0);
    assert!(objects.objects[0].lock().unwrap().is_empty());
    objects.objects[0]
        .lock()
        .unwrap()
        .extend_from_slice(b"unchanged");
    let truncate = Open {
        truncate: true,
        ..options(Access::ReadWrite, false, 0)
    };
    assert_eq!(
        service.open_shared_memory(peer(3), b"/readonly", truncate, &mut objects),
        Err(-13)
    );
    assert_eq!(objects.truncations, 0);
    assert_eq!(&*objects.objects[0].lock().unwrap(), b"unchanged");
    // Different POSIX facilities have separate namespaces, even for the same
    // spelling: unlinking a semaphore must not affect shared memory.
    service
        .open_named_semaphore(
            peer(2),
            b"/readonly",
            Some(posix_service::named_semaphore::Create {
                mode: 0o600,
                value: 1,
                exclusive: true,
            }),
            |_| Ok(999),
        )
        .unwrap();
    assert_eq!(
        service.unlink_named_semaphore(peer(2), b"/readonly"),
        Ok(999)
    );
    assert_eq!(
        service
            .open_shared_memory(
                peer(2),
                b"/readonly",
                Open {
                    create: false,
                    ..ro
                },
                &mut objects
            )
            .unwrap()
            .backing,
        created.backing
    );
}
