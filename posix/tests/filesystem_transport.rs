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
