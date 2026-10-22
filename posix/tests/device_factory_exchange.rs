//! Common filesystem factory client -> actual PTY admission/open state machine.
//! Native Handle renumbering/transfer is modeled, not claimed as an OS IPC run.
use filesystem_service::device_factory::open_with;
use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_DUPLICATE as D, HANDLE_RIGHT_READ as R,
    HANDLE_RIGHT_TRANSFER as T, IpcObjectHandle, IpcObjectHandles,
};
use mochios_filesystem_protocol::device_open::Request;
use posix_service::{
    pty::PtyManager,
    pty_metadata::{Backend, Reference},
    pty_open::{Publisher, open},
};
use std::{
    cell::Cell,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

fn metadata() -> IpcObjectHandle {
    IpcObjectHandle {
        handle: 40,
        reserved: 0,
        rights: D | T | C,
    }
}
fn request() -> Request {
    Request {
        rights: R | D | T,
        options: mnu_abi::HANDLE_OPTION_NONBLOCKING,
    }
}
fn reply_object(handle: u32, rights: u64) -> IpcObjectHandle {
    IpcObjectHandle {
        handle,
        reserved: 0,
        rights,
    }
}
#[derive(Debug)]
struct Metadata(Arc<AtomicUsize>);
impl Backend for Metadata {
    fn duplicate(&self, _: u64) -> Result<u32, i32> {
        Ok(92)
    }
}
impl Drop for Metadata {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
struct Publish(u64);
impl Publisher for Publish {
    fn create(&mut self, object: u64, _: u64) -> Result<u32, i32> {
        self.0 = object;
        Ok(91)
    }
    fn options(&mut self, handle: u32, options: u64) -> Result<(), i32> {
        assert_eq!((handle, options), (91, request().options));
        Ok(())
    }
    fn signal(&mut self, _: u64, _: u64) -> Result<(), i32> {
        Ok(())
    }
    fn close(&mut self, _: u32) {
        panic!("successful open must retain its outgoing reference")
    }
}

#[test]
fn common_factory_exchange_creates_distinct_direct_terminal_handles_and_retains_metadata() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let factory = manager.create_slave_factory(pair.master_object_id).unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut opens = Vec::new();
    for _ in 0..2 {
        let mut publisher = Publish(0);
        let opened = open_with(
            11,
            30,
            metadata(),
            request(),
            |endpoint, bytes, reply, objects| {
                assert_eq!(endpoint, 11);
                assert_eq!(Request::decode(bytes), Ok(request()));
                assert_eq!(objects.count, 2);
                assert_eq!(objects.delivery_flags, 0);
                assert_eq!(objects.handles[0], reply_object(30, T));
                assert_eq!(objects.handles[1], metadata());
                // Native transfer creates receiver-local numbers and provenance.
                let mut incoming = *objects;
                incoming.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
                incoming.handles[0].handle = 73;
                incoming.handles[1].handle = 74;
                let opened = open(
                    &mut manager,
                    bytes,
                    &mut incoming,
                    |handle| {
                        assert_eq!(handle, 73);
                        Ok(factory)
                    },
                    |received| {
                        assert_eq!(received.handle, 74);
                        Reference::new(Box::new(Metadata(dropped.clone())), received.rights)
                    },
                    &mut publisher,
                )?;
                assert_eq!(incoming.handles[1].handle, 0);
                assert_eq!(opened.handle, 91);
                *objects = IpcObjectHandles::default();
                objects.count = 1;
                objects.handles[0] = reply_object(100, opened.rights);
                reply.copy_from_slice(&0i64.to_le_bytes());
                Ok((19u64 << 32) | 8)
            },
            |_| panic!("must not close borrowed inputs or successful output"),
        )
        .unwrap();
        assert_eq!(opened, reply_object(100, request().rights));
        assert!(!opens.contains(&publisher.0));
        opens.push(publisher.0);
    }
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    manager.write(pair.master_object_id, b"hello\n").unwrap();
    assert_eq!(manager.read(opens[0], 16), Ok(b"hello\n".to_vec()));
    manager.release(opens[0]).unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(manager.duplicate_slave_metadata(opens[1], T, T), Ok(92));
    manager.release(opens[1]).unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
}

#[test]
fn native_failure_never_closes_borrowed_inputs_even_when_exchange_buffer_was_changed() {
    for overwrite in [false, true] {
        assert_eq!(
            open_with(
                11,
                30,
                metadata(),
                request(),
                |_, _, _, objects| {
                    if overwrite {
                        objects.handles[0] = reply_object(70, T);
                    }
                    Err(32)
                },
                |_| panic!("failed native installation is rolled back by the kernel")
            ),
            Err(32)
        );
    }
}

#[test]
fn malformed_success_or_error_replies_reclaim_only_installed_reply_references() {
    // status, byte count, object count, flags, returned rights, reserved.
    for (status, length, count, flags, rights, reserved, expected) in [
        (0i64, 8u64, 1, 0, request().rights, 0, 0),
        (0, 7, 1, 0, request().rights, 0, 5),
        (0, 9, 1, 0, request().rights, 0, 5),
        (0, 8, 2, 0, request().rights, 0, 5),
        (0, 8, 1, 1, request().rights, 0, 5),
        (0, 8, 1, 0, request().rights | C, 0, 5),
        (0, 8, 1, 0, T, 0, 5),
        (0, 8, 1, 0, request().rights, 1, 5),
        (-13, 8, 1, 0, T, 0, 5),
        (-13, 8, 0, 0, T, 0, 13),
        (13, 8, 0, 0, T, 0, 5),
        (i64::MIN, 8, 0, 0, T, 0, 5),
        (0, 8, u32::MAX, 0, request().rights, 0, 5),
    ] {
        let mut closed = Vec::new();
        let result = open_with(
            11,
            30,
            metadata(),
            request(),
            |_, _, reply, objects| {
                *objects = IpcObjectHandles::default();
                objects.count = count;
                objects.delivery_flags = flags;
                objects.handles[0] = IpcObjectHandle {
                    handle: 70,
                    reserved,
                    rights,
                };
                objects.handles[1] = reply_object(70, T); // Duplicate malformed slot: close once.
                reply.copy_from_slice(&status.to_le_bytes());
                Ok(length)
            },
            |handle| closed.push(handle),
        );
        if expected == 0 {
            assert_eq!(result, Ok(reply_object(70, request().rights)));
            assert!(closed.is_empty());
        } else {
            assert_eq!(result, Err(expected));
            assert_eq!(closed, if count == 0 { vec![] } else { vec![70] });
        }
    }
}

#[test]
fn invalid_metadata_authority_is_rejected_without_contacting_a_factory() {
    let called = Cell::new(false);
    for object in [
        reply_object(0, D | T),
        reply_object(40, T),
        reply_object(40, D | T | R),
        IpcObjectHandle {
            reserved: 1,
            ..metadata()
        },
    ] {
        assert_eq!(
            open_with(
                11,
                30,
                object,
                request(),
                |_, _, _, _| {
                    called.set(true);
                    Ok(8)
                },
                |_| panic!("borrowed metadata must not be closed")
            ),
            Err(13)
        );
    }
    assert!(!called.get());
}
