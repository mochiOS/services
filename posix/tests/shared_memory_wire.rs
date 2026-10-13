use mochios_posix_protocol::{self as protocol, shared_memory as wire};
use posix_service::shared_memory::{Backing, Delegation};
use posix_service::{AttachedObject, AuthenticatedProcess, PeerIdentity, PosixService};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Objects {
    next: u32,
    handles: BTreeMap<u32, Arc<Mutex<Vec<u8>>>>,
    rights: BTreeMap<u32, u64>,
    fail_duplicate: bool,
    fail_close: bool,
}
impl Backing<u32> for Objects {
    fn create_zero_length(&mut self) -> Result<u32, i32> {
        self.next += 1;
        self.handles
            .insert(self.next, Arc::new(Mutex::new(Vec::new())));
        self.rights.insert(self.next, mnu_abi::HANDLE_RIGHT_ALL);
        Ok(self.next)
    }
    fn truncate_zero(&mut self, handle: u32) -> Result<(), i32> {
        self.handles.get(&handle).ok_or(-9)?.lock().unwrap().clear();
        Ok(())
    }
}
impl Delegation<u32> for Objects {
    fn duplicate(&mut self, handle: u32, rights: u64) -> Result<u32, i32> {
        if self.fail_duplicate {
            return Err(-24);
        }
        assert_eq!(rights & !self.rights[&handle], 0);
        self.next += 1;
        self.handles
            .insert(self.next, Arc::clone(&self.handles[&handle]));
        self.rights.insert(self.next, rights);
        Ok(self.next)
    }
    fn close(&mut self, handle: u32) -> Result<(), i32> {
        if self.fail_close {
            return Err(-5);
        }
        self.handles.remove(&handle).ok_or(-9)?;
        self.rights.remove(&handle);
        Ok(())
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
fn open(
    service: &mut PosixService,
    peer: PeerIdentity,
    objects: &mut Objects,
    options: u32,
) -> posix_service::ObjectResponse<u32> {
    let mut bytes = [0; 512];
    let length = wire::encode_open(
        wire::Open {
            options,
            mode: if options & wire::CREATE != 0 {
                0o600
            } else {
                0
            },
            name: b"/buffer",
        },
        &mut bytes,
    )
    .unwrap();
    service.handle_shared_memory(
        peer,
        header(protocol::OP_SHARED_MEMORY_OPEN, length),
        &bytes[..length],
        &[],
        objects,
    )
}

#[test]
fn codec_enforces_lengths_reserved_fields_names_and_canonical_access_options() {
    let request = wire::Open {
        options: wire::CREATE | wire::EXCLUSIVE | wire::READ_WRITE,
        mode: 0o660,
        name: b"/nonutf8-\xff",
    };
    let mut bytes = [0; 512];
    let length = wire::encode_open(request, &mut bytes).unwrap();
    assert_eq!(wire::decode_open(&bytes[..length]), Ok(request));
    for end in 0..length {
        assert!(wire::decode_open(&bytes[..end]).is_err());
    }
    assert!(wire::decode_open(&bytes[..length + 1]).is_err());
    for options in [wire::EXCLUSIVE, wire::TRUNCATE, 16, u32::MAX] {
        assert!(wire::encode_open(wire::Open { options, ..request }, &mut bytes).is_err());
    }
    let length = wire::encode_open(request, &mut bytes).unwrap();
    bytes[8] = 1;
    assert!(wire::decode_open(&bytes[..length]).is_err());
    for name in [&b"buffer"[..], b"/", b"/nested/buffer", b"/nul\0buffer"] {
        assert!(wire::encode_open(wire::Open { name, ..request }, &mut bytes).is_err());
    }
}

#[test]
fn response_references_are_attenuated_and_survive_unlink_and_recreation() {
    let (mut service, peer) = setup();
    let mut objects = Objects::default();
    let first = open(
        &mut service,
        peer,
        &mut objects,
        wire::CREATE | wire::READ_WRITE,
    );
    assert_eq!(first.response.header.status, 0);
    assert_eq!(first.handles.len(), 1);
    let first = first.handles[0];
    assert_eq!(
        first.rights,
        mochios_posix_client::shared_memory::rights(true)
    );
    objects.handles[&first.handle]
        .lock()
        .unwrap()
        .extend_from_slice(b"data");
    let reader = open(&mut service, peer, &mut objects, 0);
    let reader = reader.handles[0];
    assert_eq!(
        reader.rights,
        mochios_posix_client::shared_memory::rights(false)
    );
    assert_eq!(
        reader.rights & (mnu_abi::HANDLE_RIGHT_WRITE | mnu_abi::HANDLE_RIGHT_CONTROL),
        0
    );
    assert!(Arc::ptr_eq(
        &objects.handles[&first.handle],
        &objects.handles[&reader.handle]
    ));
    let exclusive = open(
        &mut service,
        peer,
        &mut objects,
        wire::CREATE | wire::EXCLUSIVE | wire::READ_WRITE,
    );
    assert_eq!(exclusive.response.header.status, -17);
    assert!(exclusive.handles.is_empty());
    let mut bytes = [0; 512];
    let length = wire::encode_name(b"/buffer", &mut bytes).unwrap();
    let response = service.handle_shared_memory(
        peer,
        header(protocol::OP_SHARED_MEMORY_UNLINK, length),
        &bytes[..length],
        &[],
        &mut objects,
    );
    assert_eq!(response.response.header.status, 0);
    assert!(response.handles.is_empty());
    assert_eq!(&*objects.handles[&first.handle].lock().unwrap(), b"data");
    assert_eq!(
        open(&mut service, peer, &mut objects, 0)
            .response
            .header
            .status,
        -2
    );
    let fresh = open(
        &mut service,
        peer,
        &mut objects,
        wire::CREATE | wire::READ_WRITE,
    )
    .handles[0];
    assert!(!Arc::ptr_eq(
        &objects.handles[&first.handle],
        &objects.handles[&fresh.handle]
    ));
    assert!(objects.handles[&fresh.handle].lock().unwrap().is_empty());
}

#[test]
fn truncation_mutates_original_backing_and_duplicate_failure_rolls_back_new_names() {
    let (mut service, peer) = setup();
    let mut objects = Objects::default();
    objects.fail_duplicate = true;
    let response = open(
        &mut service,
        peer,
        &mut objects,
        wire::CREATE | wire::READ_WRITE,
    );
    assert_eq!(response.response.header.status, -24);
    assert!(response.handles.is_empty());
    assert!(objects.handles.is_empty());
    objects.fail_duplicate = false;
    assert_eq!(
        open(&mut service, peer, &mut objects, 0)
            .response
            .header
            .status,
        -2
    );
    let first = open(
        &mut service,
        peer,
        &mut objects,
        wire::CREATE | wire::READ_WRITE,
    )
    .handles[0];
    objects.handles[&first.handle]
        .lock()
        .unwrap()
        .extend_from_slice(b"data");
    let truncated = open(
        &mut service,
        peer,
        &mut objects,
        wire::TRUNCATE | wire::READ_WRITE,
    );
    assert_eq!(truncated.response.header.status, 0);
    assert!(Arc::ptr_eq(
        &objects.handles[&first.handle],
        &objects.handles[&truncated.handles[0].handle]
    ));
    assert!(objects.handles[&first.handle].lock().unwrap().is_empty());
}

#[test]
fn malformed_or_unregistered_requests_allocate_no_backing_and_failed_close_retains_owner() {
    let (mut service, peer) = setup();
    let mut objects = Objects::default();
    let mut bytes = [0; 512];
    let length = wire::encode_open(
        wire::Open {
            options: wire::CREATE | wire::READ_WRITE,
            mode: 0o600,
            name: b"/buffer",
        },
        &mut bytes,
    )
    .unwrap();
    let valid = header(protocol::OP_SHARED_MEMORY_OPEN, length);
    for bad in [
        protocol::Header { flags: 1, ..valid },
        protocol::Header {
            status: -1,
            ..valid
        },
        protocol::Header {
            payload_len: 0,
            ..valid
        },
    ] {
        assert_eq!(
            service
                .handle_shared_memory(peer, bad, &bytes[..length], &[], &mut objects)
                .response
                .header
                .status,
            -22
        );
    }
    assert_eq!(
        service
            .handle_shared_memory(
                peer,
                valid,
                &bytes[..length],
                &[AttachedObject {
                    handle: 55,
                    rights: mnu_abi::HANDLE_RIGHT_ALL
                }],
                &mut objects
            )
            .response
            .header
            .status,
        -22
    );
    let unregistered = PeerIdentity {
        process_id: 999,
        ..peer
    };
    assert_eq!(
        service
            .handle_shared_memory(unregistered, valid, &bytes[..length], &[], &mut objects)
            .response
            .header
            .status,
        -3
    );
    assert!(objects.handles.is_empty());
    open(
        &mut service,
        peer,
        &mut objects,
        wire::CREATE | wire::READ_WRITE,
    );
    objects.fail_close = true;
    let length = wire::encode_name(b"/buffer", &mut bytes).unwrap();
    assert_eq!(
        service
            .handle_shared_memory(
                peer,
                header(protocol::OP_SHARED_MEMORY_UNLINK, length),
                &bytes[..length],
                &[],
                &mut objects
            )
            .response
            .header
            .status,
        -5
    );
    assert_eq!(
        open(&mut service, peer, &mut objects, 0)
            .response
            .header
            .status,
        0
    );
}

#[test]
fn native_namespace_probe_uses_current_protocol_and_generic_handle_abi() {
    use mnu_abi::SyscallNumber as Number;
    let source = include_str!("native_named_shared_memory.c");
    for (name, number) in [
        ("OPEN", protocol::OP_SHARED_MEMORY_OPEN as u64),
        ("UNLINK", protocol::OP_SHARED_MEMORY_UNLINK as u64),
        ("CONTEXT_GET", Number::LaunchHandleGet as u64),
        ("IPC_CALL", Number::IpcCallObjectHandles as u64),
        ("MAP", Number::MemoryMap as u64),
        ("UNMAP", Number::MemoryUnmap as u64),
        ("CLOSE", Number::HandleClose as u64),
        ("RIGHTS", Number::HandleRightsGet as u64),
        ("SAME", Number::HandleSameObject as u64),
        ("LENGTH", Number::MemoryObjectLength as u64),
        ("RESIZE", Number::MemoryObjectResize as u64),
    ] {
        assert!(source.contains(&format!("{name} = {number}")));
    }
}
