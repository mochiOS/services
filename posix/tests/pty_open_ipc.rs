use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_DUPLICATE as D, HANDLE_RIGHT_READ as R,
    HANDLE_RIGHT_TRANSFER as T, HANDLE_RIGHT_WRITE as W, IpcObjectHandle, IpcObjectHandles,
};
use mochios_filesystem_protocol::device_open::Request;
use posix_service::{
    pty::{EBADF, PtyManager},
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
fn adopt(dropped: &Arc<AtomicUsize>, object: IpcObjectHandle) -> Result<Reference, i32> {
    assert_eq!(object.handle, 74);
    Reference::new(Box::new(Metadata(dropped.clone())), object.rights)
}
#[derive(Default)]
struct Published {
    fail_at: usize,
    calls: usize,
    created: Vec<(u64, u64)>,
    options: Vec<(u32, u64)>,
    signals: Vec<(u64, u64)>,
    closed: Vec<u32>,
}
impl Published {
    fn step(&mut self) -> Result<(), i32> {
        self.calls += 1;
        if self.calls == self.fail_at {
            Err(12)
        } else {
            Ok(())
        }
    }
}
impl Publisher for Published {
    fn create(&mut self, object: u64, rights: u64) -> Result<u32, i32> {
        self.created.push((object, rights));
        self.step()?;
        Ok(91)
    }
    fn options(&mut self, handle: u32, options: u64) -> Result<(), i32> {
        self.options.push((handle, options));
        self.step()
    }
    fn signal(&mut self, object: u64, signals: u64) -> Result<(), i32> {
        self.signals.push((object, signals));
        self.step()
    }
    fn close(&mut self, handle: u32) {
        self.closed.push(handle);
    }
}
fn attachments() -> IpcObjectHandles {
    let mut objects = IpcObjectHandles::default();
    objects.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
    objects.count = 2;
    objects.handles[0] = IpcObjectHandle {
        handle: 73,
        reserved: 0,
        rights: T,
    };
    objects.handles[1] = IpcObjectHandle {
        handle: 74,
        reserved: 0,
        rights: D | T | C,
    };
    objects
}
fn request(rights: u64) -> Request {
    Request {
        rights,
        options: mnu_abi::HANDLE_OPTION_NONBLOCKING,
    }
}

#[test]
fn independent_opens_consume_only_metadata_and_publish_exact_requested_rights() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let factory = manager.create_slave_factory(pair.master_object_id).unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut ids = Vec::new();
    for rights in [R | D | T, W | C | D | T] {
        let mut attached = attachments();
        let mut publisher = Published::default();
        let opened = open(
            &mut manager,
            &request(rights).encode(),
            &mut attached,
            |handle| {
                assert_eq!(handle, 73);
                Ok(factory)
            },
            |object| adopt(&dropped, object),
            &mut publisher,
        )
        .unwrap();
        assert_eq!(opened.handle, 91);
        assert_eq!(opened.rights, rights);
        assert_eq!(attached.handles[0].handle, 73);
        assert_eq!(attached.handles[1].handle, 0);
        assert_eq!(publisher.created[0].1, rights | C);
        assert_eq!(
            publisher.options,
            vec![(91, mnu_abi::HANDLE_OPTION_NONBLOCKING)]
        );
        let id = publisher.created[0].0;
        assert!(!ids.contains(&id));
        assert!(
            publisher
                .signals
                .contains(&(id, manager.signals(id).unwrap()))
        );
        assert!(publisher.signals.contains(&(
            pair.master_object_id,
            manager.signals(pair.master_object_id).unwrap()
        )));
        assert_eq!(manager.duplicate_slave_metadata(id, T, T), Ok(92));
        assert!(publisher.closed.is_empty());
        ids.push(id);
    }
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    for id in ids {
        manager.release(id).unwrap();
    }
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
}

#[test]
fn each_publication_failure_reclaims_open_and_metadata_and_restores_master_peer_closed() {
    // With no other slave: create, options, master signal, new-slave signal.
    for fail_at in 1..=4 {
        let mut manager = PtyManager::new();
        let pair = manager.open().unwrap();
        manager.release(pair.slave_object_id).unwrap();
        let factory = manager.create_slave_factory(pair.master_object_id).unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut attached = attachments();
        let mut publisher = Published {
            fail_at,
            ..Published::default()
        };
        assert_eq!(
            open(
                &mut manager,
                &request(R | T).encode(),
                &mut attached,
                |_| Ok(factory),
                |object| adopt(&dropped, object),
                &mut publisher
            ),
            Err(12)
        );
        assert_eq!(manager.release(publisher.created[0].0), Err(EBADF));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(
            publisher.closed,
            if fail_at == 1 { vec![] } else { vec![91] }
        );
        let restored = manager.signals(pair.master_object_id).unwrap();
        assert_ne!(restored & mnu_abi::HANDLE_SIGNAL_PEER_CLOSED, 0);
        assert_eq!(
            publisher.signals.last(),
            Some(&(pair.master_object_id, restored))
        );
        assert_eq!(manager.take_terminal_signal(), None);
    }
}

#[test]
fn malformed_attachments_never_reach_identify_or_adoption() {
    let mut cases = Vec::new();
    for flags in [0, 1, 3, u32::MAX] {
        let mut a = attachments();
        a.delivery_flags = flags;
        cases.push(a);
    }
    for count in [0, 1, 3, u32::MAX] {
        let mut a = attachments();
        a.count = count;
        cases.push(a);
    }
    for index in 0..2 {
        let mut a = attachments();
        a.handles[index].handle = 0;
        cases.push(a);
        let mut a = attachments();
        a.handles[index].reserved = 1;
        cases.push(a);
        let mut a = attachments();
        a.handles[index].rights = 0;
        cases.push(a);
    }
    for rights in [D, T, D | T | R, D | T | W] {
        let mut a = attachments();
        a.handles[1].rights = rights;
        cases.push(a);
    }
    for mut attached in cases {
        let original = attached;
        let mut manager = PtyManager::new();
        let mut publisher = Published::default();
        assert!(
            open(
                &mut manager,
                &request(R | T).encode(),
                &mut attached,
                |_| panic!("invalid admission"),
                |_| panic!("invalid admission"),
                &mut publisher
            )
            .is_err()
        );
        assert_eq!(attached, original);
        assert_eq!(publisher.calls, 0);
    }
}

#[test]
fn only_an_explicitly_identified_live_factory_can_open_and_failures_preserve_ownership() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let factory = manager.create_slave_factory(pair.master_object_id).unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    manager.release(pair.master_object_id).unwrap();
    for id in [
        pair.master_object_id,
        pair.slave_object_id,
        factory,
        u64::MAX,
    ] {
        let mut attached = attachments();
        assert_eq!(
            open(
                &mut manager,
                &request(R | T).encode(),
                &mut attached,
                |_| Ok(id),
                |object| adopt(&dropped, object),
                &mut Published::default()
            ),
            Err(EBADF)
        );
        assert_eq!(attached.handles[1].handle, 0);
    }
    assert_eq!(dropped.load(Ordering::SeqCst), 4);
    let mut attached = attachments();
    assert_eq!(
        open(
            &mut manager,
            &request(R | T).encode(),
            &mut attached,
            |_| Err(EBADF),
            |_| panic!("foreign native owner"),
            &mut Published::default()
        ),
        Err(EBADF)
    );
    assert_eq!(attached.handles[1].handle, 74);
    let called = Cell::new(false);
    assert_eq!(
        open(
            &mut manager,
            &request(R | T).encode(),
            &mut attached,
            |_| Ok(factory),
            |_| {
                called.set(true);
                Err(13)
            },
            &mut Published::default()
        ),
        Err(13)
    );
    assert!(called.get());
    assert_eq!(attached.handles[1].handle, 0);
}

#[test]
fn wire_roundtrip_rejects_bad_version_reserved_trailing_rights_and_options() {
    let valid = request(R | W | D | T);
    let encoded = valid.encode();
    assert_eq!(Request::decode(&encoded), Ok(valid));
    for index in [0, 4, 6] {
        let mut bytes = encoded;
        bytes[index] ^= 0x80;
        assert_eq!(Request::decode(&bytes), Err(-22));
    }
    assert_eq!(Request::decode(&encoded[..23]), Err(-22));
    let mut extra = encoded.to_vec();
    extra.push(0);
    assert_eq!(Request::decode(&extra), Err(-22));
    let mut rejected = Vec::new();
    for rights in [
        0,
        R,
        T,
        T | C,
        R | T | mnu_abi::HANDLE_RIGHT_RECEIVE,
        u64::MAX,
    ] {
        rejected.push(request(rights).encode());
    }
    rejected.push(
        Request {
            options: 2,
            ..valid
        }
        .encode(),
    );
    let mut bytes = encoded;
    bytes[23] |= 0x80;
    rejected.push(bytes);
    for bytes in rejected {
        // Generic framing accepts opaque rights/options. The PTY resource
        // owner rejects unsupported authority before touching attachments.
        assert!(Request::decode(&bytes).is_ok());
        assert_eq!(
            open(
                &mut PtyManager::new(),
                &bytes,
                &mut attachments(),
                |_| panic!("unsupported terminal authority"),
                |_| panic!("unsupported terminal authority"),
                &mut Published::default()
            ),
            Err(22)
        );
    }
}
