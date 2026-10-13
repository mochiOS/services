use mochios_posix_client::semaphore::Semaphore;
use mochios_posix_protocol::{self as protocol, named_semaphore as wire};
use posix_service::named_semaphore::{Backing, CLIENT_RIGHTS};
use posix_service::{AuthenticatedProcess, PeerIdentity, PosixService};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Default)]
struct Objects {
    next: u32,
    handles: BTreeMap<u32, Arc<Semaphore>>,
    fail_duplicate: bool,
}
impl Backing<u32> for Objects {
    fn create_initialized(&mut self, value: u32) -> Result<u32, i32> {
        self.next += 1;
        self.handles
            .insert(self.next, Arc::new(Semaphore::new(value, true).unwrap()));
        Ok(self.next)
    }
    fn duplicate(&mut self, handle: u32, rights: u64) -> Result<u32, i32> {
        assert_eq!(rights, CLIENT_RIGHTS);
        if self.fail_duplicate {
            return Err(-24);
        }
        let object = Arc::clone(self.handles.get(&handle).unwrap());
        self.next += 1;
        self.handles.insert(self.next, object);
        Ok(self.next)
    }
    fn close(&mut self, handle: u32) -> Result<(), i32> {
        self.handles.remove(&handle).map(|_| ()).ok_or(-9)
    }
}
fn setup() -> (PosixService, PeerIdentity) {
    let peer = PeerIdentity {
        process_id: 1,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 91,
                process_id: 1,
            },
            501,
            20,
            &[],
        )
        .unwrap();
    (service, peer)
}
fn header(opcode: u16, length: usize) -> protocol::Header {
    protocol::Header {
        opcode,
        payload_len: length as u32,
        request_id: 123,
        ..Default::default()
    }
}

#[test]
fn codec_round_trips_bytes_rejects_noncanonical_options_and_exact_lengths() {
    let request = wire::Open {
        options: wire::CREATE | wire::EXCLUSIVE,
        mode: 0o660,
        value: 9,
        name: b"/nonutf8-\xff",
    };
    let mut bytes = [0; 512];
    let length = wire::encode_open(request, &mut bytes).unwrap();
    assert_eq!(wire::decode_open(&bytes[..length]), Ok(request));
    for end in 0..length {
        assert!(wire::decode_open(&bytes[..end]).is_err());
    }
    assert!(wire::decode_open(&bytes[..length + 1]).is_err());
    for options in [wire::EXCLUSIVE, 4, u32::MAX] {
        assert!(wire::encode_open(wire::Open { options, ..request }, &mut bytes).is_err());
    }
    assert!(
        wire::encode_open(
            wire::Open {
                options: 0,
                mode: 0,
                value: 1,
                ..request
            },
            &mut bytes
        )
        .is_err()
    );
    assert!(wire::encode_open(request, &mut [0; 15]).is_err());
    bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(wire::decode_open(&bytes[..length]).is_err());
    let length = wire::encode_name(b"/gate", &mut bytes).unwrap();
    assert_eq!(wire::decode_name(&bytes[..length]), Ok(&b"/gate"[..]));
    assert!(wire::decode_name(&bytes[..length - 1]).is_err());
    for name in [&b"gate"[..], b"/", b"/nested/gate", b"/nul\0gate"] {
        assert!(wire::encode_name(name, &mut bytes).is_err());
    }
}

#[test]
fn response_reference_is_independent_of_namespace_and_unlink_keeps_mapped_state_alive() {
    let (mut service, peer) = setup();
    let mut objects = Objects::default();
    let mut bytes = [0; 512];
    let request = wire::Open {
        options: wire::CREATE,
        mode: 0o600,
        value: 7,
        name: b"/gate",
    };
    let length = wire::encode_open(request, &mut bytes).unwrap();
    let opened = service.handle_named_semaphore(
        peer,
        header(protocol::OP_SEMAPHORE_OPEN, length),
        &bytes[..length],
        &[],
        &mut objects,
    );
    assert_eq!(opened.response.header.status, 0);
    assert_eq!(opened.response.header.request_id, 123);
    assert!(opened.response.payload.is_empty());
    assert_eq!(opened.handles.len(), 1);
    assert_eq!(opened.handles[0].rights, CLIENT_RIGHTS);
    let reference = Arc::clone(&objects.handles[&opened.handles[0].handle]);
    objects.close(opened.handles[0].handle).unwrap(); // Reply temporary reference is closed.
    assert_eq!(objects.handles.len(), 1); // Name still retains initialized backing.
    let length = wire::encode_open(
        wire::Open {
            options: 0,
            mode: 0,
            value: 0,
            ..request
        },
        &mut bytes,
    )
    .unwrap();
    let reopened = service.handle_named_semaphore(
        peer,
        header(protocol::OP_SEMAPHORE_OPEN, length),
        &bytes[..length],
        &[],
        &mut objects,
    );
    assert_eq!(reopened.response.header.status, 0);
    assert!(Arc::ptr_eq(
        &reference,
        &objects.handles[&reopened.handles[0].handle]
    ));
    objects.close(reopened.handles[0].handle).unwrap();
    let length = wire::encode_name(request.name, &mut bytes).unwrap();
    let unlinked = service.handle_named_semaphore(
        peer,
        header(protocol::OP_SEMAPHORE_UNLINK, length),
        &bytes[..length],
        &[],
        &mut objects,
    );
    assert_eq!(unlinked.response.header.status, 0);
    assert!(unlinked.handles.is_empty());
    assert!(objects.handles.is_empty());
    assert_eq!(reference.value(), Ok(7));
    assert_eq!(reference.try_take(), Ok(true));
    let length = wire::encode_open(
        wire::Open {
            value: 0,
            ..request
        },
        &mut bytes,
    )
    .unwrap();
    let fresh = service.handle_named_semaphore(
        peer,
        header(protocol::OP_SEMAPHORE_OPEN, length),
        &bytes[..length],
        &[],
        &mut objects,
    );
    assert_eq!(fresh.response.header.status, 0);
    let fresh_reference = &objects.handles[&fresh.handles[0].handle];
    assert!(!Arc::ptr_eq(&reference, fresh_reference));
    assert_eq!(fresh_reference.value(), Ok(0));
    assert_eq!(reference.value(), Ok(6));
}

#[test]
fn malformed_or_unregistered_requests_cannot_allocate_or_attach_backing() {
    let (mut service, peer) = setup();
    let mut objects = Objects::default();
    let mut bytes = [0; 512];
    let length = wire::encode_open(
        wire::Open {
            options: wire::CREATE,
            mode: 0o600,
            value: 0,
            name: b"/gate",
        },
        &mut bytes,
    )
    .unwrap();
    let base = header(protocol::OP_SEMAPHORE_OPEN, length);
    for bad in [
        protocol::Header { flags: 1, ..base },
        protocol::Header { status: 1, ..base },
        protocol::Header {
            payload_len: length as u32 + 1,
            ..base
        },
    ] {
        assert_eq!(
            service
                .handle_named_semaphore(peer, bad, &bytes[..length], &[], &mut objects)
                .response
                .header
                .status,
            -22
        );
    }
    assert_eq!(
        service
            .handle_named_semaphore(
                peer,
                base,
                &bytes[..length],
                &[posix_service::AttachedObject {
                    handle: 999,
                    rights: CLIENT_RIGHTS
                }],
                &mut objects
            )
            .response
            .header
            .status,
        -22
    );
    assert_eq!(
        service
            .handle_named_semaphore(
                PeerIdentity {
                    process_id: 99,
                    ..peer
                },
                base,
                &bytes[..length],
                &[],
                &mut objects
            )
            .response
            .header
            .status,
        -3
    );
    assert!(objects.handles.is_empty());
    objects.fail_duplicate = true;
    assert_eq!(
        service
            .handle_named_semaphore(peer, base, &bytes[..length], &[], &mut objects)
            .response
            .header
            .status,
        -24
    );
    assert_eq!(objects.handles.len(), 1); // Failed delivery does not publish uninitialized state or leak a reply ref.
    objects.fail_duplicate = false;
    let opened = service.handle_named_semaphore(peer, base, &bytes[..length], &[], &mut objects);
    assert_eq!(opened.response.header.status, 0);
    assert_eq!(objects.handles.len(), 2);
}
