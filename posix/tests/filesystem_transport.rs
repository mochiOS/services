use mnu_abi::{HANDLE_RIGHT_READ, HANDLE_RIGHT_TRANSFER, IpcObjectHandle, IpcObjectHandles};
use posix_service::filesystem_transport::call_native;

fn borrowed() -> IpcObjectHandles {
    let mut handles = IpcObjectHandles::default();
    handles.count = 2;
    for (slot, handle) in handles.handles.iter_mut().zip([7, 8]) {
        *slot = IpcObjectHandle {
            handle,
            reserved: 0,
            rights: HANDLE_RIGHT_READ | HANDLE_RIGHT_TRANSFER,
        };
    }
    handles
}

#[test]
fn native_send_failure_never_returns_borrowed_root_or_cwd_as_owned() {
    for errno in [-9, -13, -22, -32] {
        let original = borrowed();
        let mut handles = original;
        let result = call_native(&mut handles, |native| {
            assert_eq!(*native, original);
            Err::<u64, _>(errno)
        });
        assert_eq!(result, Err(errno));
        assert_eq!(handles, IpcObjectHandles::default());
        // The cleanup loop receives no references to close. Request handles
        // belong to the session and still have their original values.
        assert_eq!(original.handles[0].handle, 7);
        assert_eq!(original.handles[1].handle, 8);
    }
}

#[test]
fn successful_reply_publishes_only_new_receiver_owned_references() {
    let mut handles = borrowed();
    let result = call_native(&mut handles, |native| {
        assert_eq!(native.count, 2);
        *native = IpcObjectHandles::default();
        native.count = 1;
        native.handles[0] = IpcObjectHandle {
            handle: 90,
            reserved: 0,
            rights: HANDLE_RIGHT_TRANSFER,
        };
        Ok::<_, i32>((17u64 << 32) | 176)
    });
    assert_eq!(result, Ok((17u64 << 32) | 176));
    assert_eq!(handles.count, 1);
    assert_eq!(handles.handles[0].handle, 90);
    assert_eq!(handles.handles[0].rights, HANDLE_RIGHT_TRANSFER);
}

#[test]
fn empty_successful_reply_does_not_republish_request_attachments() {
    let mut handles = borrowed();
    assert_eq!(
        call_native(&mut handles, |native| {
            *native = IpcObjectHandles::default();
            Ok::<_, i32>(64)
        }),
        Ok(64)
    );
    assert_eq!(handles, IpcObjectHandles::default());
}

#[test]
fn queued_mutation_reply_requires_an_exact_empty_authenticated_envelope() {
    use mochios_filesystem_protocol as wire;
    use posix_service::filesystem_transport::{MutationReply, mutation_status};
    let header = wire::Header {
        opcode: wire::OP_STATUS,
        request_id: 7,
        status: -wire::ERROR_MEMORY_ADMISSION_BUSY,
        ..Default::default()
    };
    let mut objects = IpcObjectHandles::default();
    objects.count = 1;
    objects.handles[0] = IpcObjectHandle {
        handle: 90,
        reserved: 0,
        rights: posix_service::mutation_admission::TICKET_RIGHTS,
    };
    for success_objects in [0, 1] {
        assert_eq!(
            mutation_status(header, 7, &[], &objects, success_objects),
            Ok(MutationReply::Wait)
        );
        assert_eq!(
            mutation_status(header, 8, &[], &objects, success_objects),
            Err(-5)
        );
        assert_eq!(
            mutation_status(header, 7, &[1], &objects, success_objects),
            Err(-5)
        );
    }
    for malformed in [
        wire::Header {
            opcode: wire::OP_READ,
            ..header
        },
        wire::Header { flags: 1, ..header },
        wire::Header {
            length: 1,
            ..header
        },
        wire::Header {
            status: 11,
            ..header
        },
        wire::Header {
            status: -11,
            ..header
        },
    ] {
        assert_eq!(mutation_status(malformed, 7, &[], &objects, 0), Err(-5));
    }
    for count in [0, 2, u32::MAX] {
        let mut bad = objects;
        bad.count = count;
        assert_eq!(mutation_status(header, 7, &[], &bad, 0), Err(-5));
    }
    for bad_object in [
        IpcObjectHandle {
            handle: 0,
            ..objects.handles[0]
        },
        IpcObjectHandle {
            reserved: 1,
            ..objects.handles[0]
        },
        IpcObjectHandle {
            rights: HANDLE_RIGHT_TRANSFER,
            ..objects.handles[0]
        },
        IpcObjectHandle {
            rights: objects.handles[0].rights | HANDLE_RIGHT_READ,
            ..objects.handles[0]
        },
    ] {
        let mut bad = objects;
        bad.handles[0] = bad_object;
        assert_eq!(mutation_status(header, 7, &[], &bad, 0), Err(-5));
    }
    assert_eq!(
        objects.handles[0].handle, 90,
        "validation never steals ownership"
    );
}

#[test]
fn ordinary_errors_and_successes_do_not_become_wait_replies() {
    use mochios_filesystem_protocol as wire;
    use posix_service::filesystem_transport::{MutationReply, mutation_status};
    let header = wire::Header {
        opcode: wire::OP_STATUS,
        request_id: 7,
        ..Default::default()
    };
    let mut objects = IpcObjectHandles::default();
    assert_eq!(
        mutation_status(header, 7, &[], &objects, 0),
        Ok(MutationReply::Ready)
    );
    assert_eq!(mutation_status(header, 7, &[], &objects, 1), Err(-5));
    for status in [-11, -5, -wire::ERROR_GROWTH_LIMIT] {
        assert_eq!(
            mutation_status(wire::Header { status, ..header }, 7, &[], &objects, 0),
            Err(status)
        );
    }
    objects.count = 1;
    objects.handles[0] = IpcObjectHandle {
        handle: 90,
        rights: HANDLE_RIGHT_READ | HANDLE_RIGHT_TRANSFER,
        reserved: 0,
    };
    assert_eq!(
        mutation_status(header, 7, &[], &objects, 1),
        Ok(MutationReply::Ready)
    );
    assert_eq!(mutation_status(header, 7, &[], &objects, 0), Err(-5));
    objects.handles[0].handle = 0;
    assert_eq!(mutation_status(header, 7, &[], &objects, 1), Err(-5));
}
