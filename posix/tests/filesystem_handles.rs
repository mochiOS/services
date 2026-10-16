use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ext4plus::{Ext4, Ext4Read, Ext4Write};
use filesystem_service::service::{FilesystemService, PathAnchors, RenameAnchors};
use mochi_user_platform::handle::HANDLE_SEEK_START;
use mochios_filesystem_protocol as protocol;

#[path = "support/unmapped_updates.rs"]
mod unmapped_updates;
use unmapped_updates::UnmappedUpdates;

fn credentials(uid: u32, gid: u32, groups: &[u32]) -> protocol::Credentials {
    let mut payload = [0u8; protocol::CREDENTIALS_MAX_LEN];
    let length = protocol::encode_credentials_payload(uid, gid, groups, &[], &mut payload).unwrap();
    protocol::decode_credentials_payload(&payload[..length])
        .unwrap()
        .0
}

fn root_credentials() -> protocol::Credentials {
    credentials(0, 0, &[])
}

#[derive(Clone)]
struct SharedImage(
    Arc<Mutex<Vec<u8>>>,
    Arc<Mutex<Option<usize>>>,
    Arc<Mutex<WriteFault>>,
);

#[derive(Default)]
struct WriteFault {
    remaining: Option<usize>,
    attempts: usize,
}

impl Ext4Read for SharedImage {
    fn read(
        &self,
        start_byte: u64,
        destination: &mut [u8],
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let mut remaining = self.1.lock().unwrap();
        if let Some(remaining) = remaining.as_mut() {
            if *remaining == 0 {
                return Err(io::Error::other("injected read failure").into());
            }
            *remaining -= 1;
        }
        drop(remaining);
        let start = usize::try_from(start_byte)?;
        let end = start
            .checked_add(destination.len())
            .ok_or_else(|| io::Error::other("image offset overflow"))?;
        let image = self
            .0
            .lock()
            .map_err(|_| io::Error::other("poisoned image"))?;
        destination.copy_from_slice(
            image
                .get(start..end)
                .ok_or_else(|| io::Error::other("read outside image"))?,
        );
        Ok(())
    }
}

impl Ext4Write for SharedImage {
    fn write(
        &self,
        start_byte: u64,
        source: &[u8],
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let mut fault = self.2.lock().unwrap();
        fault.attempts += 1;
        if let Some(remaining) = fault.remaining.as_mut() {
            if *remaining == 0 {
                return Err(io::Error::other("injected write failure").into());
            }
            *remaining -= 1;
        }
        drop(fault);
        let start = usize::try_from(start_byte)?;
        let end = start
            .checked_add(source.len())
            .ok_or_else(|| io::Error::other("image offset overflow"))?;
        let mut image = self
            .0
            .lock()
            .map_err(|_| io::Error::other("poisoned image"))?;
        image
            .get_mut(start..end)
            .ok_or_else(|| io::Error::other("write outside image"))?
            .copy_from_slice(source);
        Ok(())
    }
}

struct TempTree(PathBuf);

impl TempTree {
    fn create() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("mochios-posix-fs-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn test_filesystem() -> FilesystemService {
    test_filesystem_with_read_failure().0
}

#[test]
fn independent_provider_descriptions_observe_current_data_size_and_extents() {
    let mut fs = test_filesystem();
    let header = protocol::Header {
        opcode: protocol::OP_OPEN_AT,
        flags: protocol::OPEN_AT_READ
            | protocol::OPEN_AT_WRITE
            | protocol::OPEN_AT_CREATE
            | protocol::OPEN_AT_APPEND,
        mode: 0o600,
        ..Default::default()
    };
    let a = fs
        .open_at(
            header,
            b"/current-inode",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    let b = fs
        .open_at(
            header,
            b"/current-inode",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    assert_eq!(fs.provider_write(a, b"abc"), Ok(3));
    assert_eq!(fs.provider_write(b, b"def"), Ok(3));
    assert_eq!(fs.provider_read(a, 3).unwrap(), b"def");
    assert_eq!(fs.provider_write_at(b, 100, b"x"), Ok(1));
    assert_eq!(fs.provider_seek(a, 0, mnu_abi::HANDLE_SEEK_END), Ok(101));
    assert_eq!(fs.provider_write_at(a, 0, b"X"), Ok(1));
    assert_eq!(fs.provider_read_at(b, 100, 1).unwrap(), b"x");
    assert_eq!(fs.provider_seek(b, 0, HANDLE_SEEK_START), Ok(0));
    let mut output = [0; 6];
    assert_eq!(fs.provider_read_into(b, &mut output), Ok((6, 0)));
    assert_eq!(&output, b"Xbcdef");
    assert_eq!(
        fs.provider_seek(a, 0, mnu_abi::HANDLE_SEEK_CURRENT),
        Ok(101)
    );
}

#[test]
fn bounded_provider_writes_select_current_append_position_and_exact_prefix_atomically() {
    let mut fs = test_filesystem();
    let header = protocol::Header {
        opcode: protocol::OP_OPEN_AT,
        flags: protocol::OPEN_AT_READ
            | protocol::OPEN_AT_WRITE
            | protocol::OPEN_AT_CREATE
            | protocol::OPEN_AT_APPEND,
        mode: 0o600,
        ..Default::default()
    };
    let a = fs
        .open_at(
            header,
            b"/bounded-write",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    let b = fs
        .open_at(
            header,
            b"/bounded-write",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    assert_eq!(fs.provider_write_bounded(a, b"abc", 5), Ok((3, 0)));
    assert_eq!(fs.provider_write_bounded(b, b"defgh", 5), Ok((2, 3)));
    assert_eq!(fs.provider_read_at(a, 0, 20).unwrap(), b"abcde");
    assert_eq!(fs.provider_read_at(b, 0, 20).unwrap(), b"abcde");
    assert_eq!(fs.provider_seek(a, 0, mnu_abi::HANDLE_SEEK_CURRENT), Ok(3));
    let bound_error = (-mnu_abi::provider::STATUS_BOUND_REACHED) as i32;
    assert_eq!(fs.provider_write_bounded(a, b"!", 5), Err(bound_error));
    assert_eq!(fs.provider_seek(a, 0, mnu_abi::HANDLE_SEEK_CURRENT), Ok(3));
    assert_eq!(fs.provider_write_bounded(a, b"", 0), Ok((0, 3)));
    assert_eq!(fs.provider_seek(a, 0, mnu_abi::HANDLE_SEEK_END), Ok(5));
    // An unbounded write through the other description is immediately visible
    // to this one's append selection and extent/size reads.
    assert_eq!(fs.provider_write(b, b"FG"), Ok(2));
    assert_eq!(fs.provider_write_bounded(a, b"HIJ", 9), Ok((2, 7)));
    assert_eq!(fs.provider_read_at(b, 0, 20).unwrap(), b"abcdeFGHI");
    assert_eq!(fs.provider_write_bounded(a, b"!", 9), Err(bound_error));
    assert_eq!(fs.provider_write_bounded(u64::MAX, b"", 0), Err(9));
}

#[test]
fn truncate_zeroes_retained_tail_without_materializing_sparse_growth() {
    let mut filesystem = test_filesystem();
    let file = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
                mode: 0o600,
                ..Default::default()
            },
            b"/truncate-tail",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    filesystem.provider_write(file, b"abcdefgh").unwrap();
    filesystem
        .truncate_handle(
            protocol::Header {
                offset: 2,
                ..Default::default()
            },
            file,
        )
        .unwrap();
    filesystem
        .truncate_handle(
            protocol::Header {
                offset: 4,
                ..Default::default()
            },
            file,
        )
        .unwrap();
    assert_eq!(filesystem.provider_read_at(file, 0, 20).unwrap(), b"ab\0\0");
    // Larger than this test volume: growing a sparse extent must not write
    // zeroes across the entire range or allocate data blocks for its holes.
    filesystem
        .truncate_handle(
            protocol::Header {
                offset: 16 * 1024 * 1024,
                ..Default::default()
            },
            file,
        )
        .unwrap();
    assert_eq!(
        filesystem
            .provider_read_at(file, 14 * 1024 * 1024, 2)
            .unwrap(),
        b"\0\0"
    );
}

#[test]
fn truncate_once_preserves_data_with_stale_independent_descriptions() {
    let mut filesystem = test_filesystem();
    let open = protocol::Header {
        opcode: protocol::OP_OPEN_AT,
        flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
        mode: 0o600,
        ..Default::default()
    };
    let first = filesystem
        .open_at(
            open,
            b"/truncate-once",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    let second = filesystem
        .open_at(
            open,
            b"/truncate-once",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    filesystem.provider_write(first, b"abcdefgh").unwrap();
    filesystem
        .provider_seek(first, 2, HANDLE_SEEK_START)
        .unwrap();
    filesystem
        .truncate_handle(
            protocol::Header {
                offset: 6,
                ..Default::default()
            },
            second,
        )
        .unwrap();
    for description in [first, second] {
        assert_eq!(
            filesystem.provider_read_at(description, 0, 20).unwrap(),
            b"abcdef"
        );
    }
    assert_eq!(filesystem.provider_read(first, 2).unwrap(), b"cd");
    filesystem
        .truncate_handle(
            protocol::Header {
                offset: 2,
                ..Default::default()
            },
            first,
        )
        .unwrap();
    filesystem
        .truncate_handle(
            protocol::Header {
                offset: 4,
                ..Default::default()
            },
            second,
        )
        .unwrap();
    for description in [first, second] {
        assert_eq!(
            filesystem.provider_read_at(description, 0, 20).unwrap(),
            b"ab\0\0"
        );
    }
}

#[test]
fn truncate_growth_ceiling_is_atomic_with_current_inode_size_and_permissions() {
    let mut filesystem = test_filesystem();
    let header = protocol::Header {
        opcode: protocol::OP_OPEN_AT,
        flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
        mode: 0o600,
        ..Default::default()
    };
    let first = filesystem
        .open_at(
            header,
            b"/growth-bound",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    // This second description predates the write; its open-time inode size is
    // stale. The bound must compare against current backing, not that cache.
    let second = filesystem
        .open_at(
            header,
            b"/growth-bound",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    filesystem.provider_write(first, b"abcdefgh").unwrap();
    let bounded = protocol::Header {
        opcode: protocol::OP_TRUNCATE_HANDLE,
        flags: protocol::TRUNCATE_GROWTH_BOUNDED,
        node_id: 4,
        offset: 6,
        ..Default::default()
    };
    filesystem.truncate_handle(bounded, second).unwrap();
    assert_eq!(
        filesystem.provider_read_at(first, 0, 20).unwrap(),
        b"abcdef"
    );
    assert!(matches!(
        filesystem.truncate_handle(
            protocol::Header {
                offset: 7,
                ..bounded
            },
            first
        ),
        Err(protocol::ERROR_GROWTH_LIMIT)
    ));
    assert_eq!(
        filesystem.provider_read_at(second, 0, 20).unwrap(),
        b"abcdef"
    );
    // Equal size and shrink remain legal even if the process lowered its cap.
    filesystem.truncate_handle(bounded, first).unwrap();
    filesystem
        .truncate_handle(
            protocol::Header {
                offset: 3,
                ..bounded
            },
            second,
        )
        .unwrap();
    filesystem
        .truncate_handle(
            protocol::Header {
                offset: 4,
                ..bounded
            },
            first,
        )
        .unwrap();
    assert!(matches!(
        filesystem.truncate_handle(
            protocol::Header {
                offset: 5,
                ..bounded
            },
            first
        ),
        Err(protocol::ERROR_GROWTH_LIMIT)
    ));
    let at = protocol::Header {
        opcode: protocol::OP_TRUNCATE_AT,
        flags: protocol::TRUNCATE_GROWTH_BOUNDED,
        node_id: 4,
        open_id: 5,
        ..Default::default()
    };
    assert!(matches!(
        filesystem.truncate_at(
            at,
            b"/growth-bound",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(protocol::ERROR_GROWTH_LIMIT)
    ));
    assert!(matches!(
        filesystem.truncate_at(
            at,
            b"/growth-bound",
            PathAnchors::default(),
            credentials(501, 20, &[])
        ),
        Err(13)
    ));
    filesystem
        .truncate_at(
            protocol::Header { open_id: 2, ..at },
            b"/growth-bound",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    assert_eq!(filesystem.provider_read_at(first, 0, 20).unwrap(), b"ab");
    assert!(matches!(
        filesystem.truncate_handle(
            protocol::Header {
                flags: 1 << 31,
                ..bounded
            },
            first
        ),
        Err(22)
    ));
}

fn test_filesystem_with_read_failure() -> (FilesystemService, Arc<Mutex<Option<usize>>>) {
    test_filesystem_with_updates(Some(Box::new(UnmappedUpdates)))
}

fn test_filesystem_with_updates(
    updates: Option<Box<dyn filesystem_service::memory_updates::MemoryUpdates>>,
) -> (FilesystemService, Arc<Mutex<Option<usize>>>) {
    let (service, image) = test_filesystem_with_storage(updates);
    (service, image.1)
}

fn test_filesystem_with_storage(
    updates: Option<Box<dyn filesystem_service::memory_updates::MemoryUpdates>>,
) -> (FilesystemService, SharedImage) {
    let temporary = TempTree::create();
    let source = temporary.0.join("source");
    let directory = source.join("removed");
    let blocked = source.join("blocked");
    let create_base = source.join("create-base");
    let jail = source.join("jail");
    let search_only = source.join("search-only");
    let image_path = temporary.0.join("filesystem.ext4");
    fs::create_dir_all(&directory).unwrap();
    fs::create_dir_all(&blocked).unwrap();
    fs::create_dir_all(&create_base).unwrap();
    fs::create_dir_all(jail.join("inside")).unwrap();
    fs::create_dir_all(&search_only).unwrap();
    fs::create_dir_all(source.join("outside")).unwrap();
    fs::write(blocked.join("child"), b"private").unwrap();
    symlink("/blocked/child", source.join("redirect")).unwrap();
    symlink("target", create_base.join("dangling")).unwrap();
    symlink("/outside", jail.join("escape")).unwrap();
    let output = Command::new("mke2fs")
        .args(["-q", "-t", "ext4", "-F", "-d"])
        .arg(&source)
        .arg(&image_path)
        .arg("8192")
        .output()
        .expect("mke2fs is required for filesystem integration tests");
    assert!(
        output.status.success(),
        "mke2fs failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let failure = Arc::new(Mutex::new(None));
    let image = SharedImage(
        Arc::new(Mutex::new(fs::read(image_path).unwrap())),
        failure.clone(),
        Arc::new(Mutex::new(WriteFault::default())),
    );
    let filesystem =
        Ext4::load_with_writer(Box::new(image.clone()), Some(Box::new(image.clone()))).unwrap();
    let mut service = FilesystemService::new(filesystem);
    if let Some(updates) = updates {
        service.configure_memory_updates(updates).unwrap();
    }
    let restricted = service.handle(
        protocol::Header {
            opcode: protocol::OP_SETATTR,
            flags: protocol::SETATTR_MODE,
            mode: 0,
            ..protocol::Header::default()
        },
        b"/blocked",
    );
    assert_eq!(restricted.header.status, 0);
    let search_only = service.handle(
        protocol::Header {
            opcode: protocol::OP_SETATTR,
            flags: protocol::SETATTR_MODE,
            mode: 0o111,
            ..protocol::Header::default()
        },
        b"/search-only",
    );
    assert_eq!(search_only.header.status, 0);
    (service, image)
}

#[derive(Debug, PartialEq, Eq)]
enum UpdateEvent {
    Prepare(u64, u64, u64),
    Admit(u64, u64, u64, Option<u32>),
    Queue(u64),
    Begin,
    Publish,
    Drop { begun: bool, published: bool },
}

#[derive(Default)]
struct UpdateTrace {
    events: Vec<UpdateEvent>,
    fail: Option<&'static str>,
}

struct RecordingUpdates(Arc<Mutex<UpdateTrace>>);
struct RecordingUpdate {
    trace: Arc<Mutex<UpdateTrace>>,
    begun: bool,
    published: bool,
}
impl filesystem_service::memory_updates::MemoryUpdates for RecordingUpdates {
    fn queue(
        &self,
        identity: u64,
    ) -> Result<filesystem_service::memory_updates::AdmissionReference, i32> {
        self.0
            .lock()
            .unwrap()
            .events
            .push(UpdateEvent::Queue(identity));
        Ok(filesystem_service::memory_updates::AdmissionReference::Borrowed(900))
    }

    fn prepare_admitted(
        &self,
        identity: u64,
        old: u64,
        new: u64,
        incoming: Option<u32>,
    ) -> Result<filesystem_service::memory_updates::Preparation, i32> {
        use filesystem_service::memory_updates::{AdmissionReference, Preparation};
        let mut trace = self.0.lock().unwrap();
        trace
            .events
            .push(UpdateEvent::Admit(identity, old, new, incoming));
        if trace.fail == Some("admitted_wait") {
            return Ok(Preparation::Wait(AdmissionReference::Borrowed(
                incoming.unwrap_or(900),
            )));
        }
        drop(trace);
        self.prepare(identity, old, new).map(Preparation::Ready)
    }

    fn prepare(
        &self,
        identity: u64,
        old: u64,
        new: u64,
    ) -> Result<Box<dyn filesystem_service::memory_updates::Update>, i32> {
        let mut trace = self.0.lock().unwrap();
        trace.events.push(UpdateEvent::Prepare(identity, old, new));
        if trace.fail == Some("prepare") {
            return Err(11);
        }
        Ok(Box::new(RecordingUpdate {
            trace: self.0.clone(),
            begun: false,
            published: false,
        }))
    }
}
impl filesystem_service::memory_updates::Update for RecordingUpdate {
    fn begin(&mut self) -> Result<(), i32> {
        let mut trace = self.trace.lock().unwrap();
        trace.events.push(UpdateEvent::Begin);
        if trace.fail == Some("begin") {
            return Err(5);
        }
        if trace.fail == Some("begin_busy") {
            return Err(11);
        }
        self.begun = true;
        Ok(())
    }
    fn publish(&mut self) -> Result<(), i32> {
        let mut trace = self.trace.lock().unwrap();
        trace.events.push(UpdateEvent::Publish);
        self.published = true; // the native request is irrevocable even on error
        if trace.fail == Some("publish") {
            return Err(5);
        }
        if trace.fail == Some("publish_busy") {
            return Err(11);
        }
        Ok(())
    }
}
impl Drop for RecordingUpdate {
    fn drop(&mut self) {
        self.trace.lock().unwrap().events.push(UpdateEvent::Drop {
            begun: self.begun,
            published: self.published,
        });
    }
}

fn open_update_file(service: &mut FilesystemService, flags: u32) -> u64 {
    service
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags,
                mode: 0o600,
                ..Default::default()
            },
            b"/update-order",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id
}

fn seed_update_file(service: &mut FilesystemService, opened: u64) {
    for _ in 0..2 {
        assert_eq!(service.provider_write(opened, &[0x55; 4096]), Ok(4096));
    }
}

#[test]
fn admitted_mutations_return_before_storage_and_resume_with_same_backing() {
    use filesystem_service::memory_updates::MutationResult;
    for operation in 0..3 {
        let trace = Arc::new(Mutex::new(UpdateTrace::default()));
        let (mut service, image) =
            test_filesystem_with_storage(Some(Box::new(RecordingUpdates(trace.clone()))));
        let opened = open_update_file(
            &mut service,
            protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
        );
        seed_update_file(&mut service, opened);
        let identity = service.provider_memory_object(opened).unwrap();
        let before = image.0.lock().unwrap().clone();
        image.2.lock().unwrap().attempts = 0;
        trace.lock().unwrap().fail = Some("admitted_wait");
        let invoke = |service: &mut FilesystemService, incoming| match operation {
            0 => service.truncate_handle_admitted(
                protocol::Header {
                    offset: 5000,
                    ..Default::default()
                },
                opened,
                incoming,
            ),
            1 => service.truncate_at_admitted(
                protocol::Header {
                    open_id: 5000,
                    ..Default::default()
                },
                b"/update-order",
                PathAnchors::default(),
                root_credentials(),
                incoming,
            ),
            _ => service.open_at_admitted(
                protocol::Header {
                    flags: protocol::OPEN_AT_READ
                        | protocol::OPEN_AT_WRITE
                        | protocol::OPEN_AT_TRUNCATE,
                    ..Default::default()
                },
                b"/update-order",
                PathAnchors::default(),
                root_credentials(),
                incoming,
            ),
        };
        let ticket = match invoke(&mut service, None) {
            MutationResult::Wait(ticket) => ticket,
            _ => panic!("expected nonblocking admission"),
        };
        assert_eq!(ticket.handle(), 900);
        assert_eq!(*image.0.lock().unwrap(), before);
        assert_eq!(image.2.lock().unwrap().attempts, 0);
        assert_eq!(
            trace.lock().unwrap().events,
            [UpdateEvent::Admit(
                identity,
                8192,
                if operation == 2 { 0 } else { 5000 },
                None
            )]
        );
        // The service is free to handle other requests while the client waits.
        assert_eq!(service.provider_read_at(opened, 0, 1).unwrap(), [0x55]);
        trace.lock().unwrap().fail = None;
        assert!(matches!(
            invoke(&mut service, Some(ticket.handle())),
            MutationResult::Complete(Ok(_))
        ));
        assert_eq!(
            service.provider_read_at(opened, 4999, 2).unwrap().len(),
            if operation == 2 { 0 } else { 1 }
        );
        assert!(trace.lock().unwrap().events.contains(&UpdateEvent::Admit(
            identity,
            8192,
            if operation == 2 { 0 } else { 5000 },
            Some(900)
        )));
        // Request scope must be gone after both Wait and Complete.
        trace.lock().unwrap().events.clear();
        service
            .truncate_handle(
                protocol::Header {
                    offset: 2,
                    ..Default::default()
                },
                opened,
            )
            .unwrap();
        assert!(matches!(
            trace.lock().unwrap().events.first(),
            Some(UpdateEvent::Prepare(_, _, 2))
        ));
    }
}

#[test]
fn admitted_begin_contention_requeues_but_publication_errors_never_retry() {
    use filesystem_service::memory_updates::MutationResult;
    for failure in ["begin_busy", "publish_busy"] {
        let trace = Arc::new(Mutex::new(UpdateTrace::default()));
        let (mut service, image) =
            test_filesystem_with_storage(Some(Box::new(RecordingUpdates(trace.clone()))));
        let opened = open_update_file(
            &mut service,
            protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
        );
        seed_update_file(&mut service, opened);
        let identity = service.provider_memory_object(opened).unwrap();
        image.2.lock().unwrap().attempts = 0;
        trace.lock().unwrap().fail = Some(failure);
        let result = service.truncate_handle_admitted(
            protocol::Header {
                offset: 5000,
                ..Default::default()
            },
            opened,
            Some(42),
        );
        if failure == "begin_busy" {
            assert!(matches!(result, MutationResult::Wait(_)));
            assert_eq!(image.2.lock().unwrap().attempts, 0);
            assert_eq!(
                trace.lock().unwrap().events,
                [
                    UpdateEvent::Admit(identity, 8192, 5000, Some(42)),
                    UpdateEvent::Prepare(identity, 8192, 5000),
                    UpdateEvent::Begin,
                    UpdateEvent::Drop {
                        begun: false,
                        published: false
                    },
                    UpdateEvent::Queue(identity)
                ]
            );
        } else {
            assert!(matches!(result, MutationResult::Complete(Err(11))));
            assert!(image.2.lock().unwrap().attempts > 0);
            assert!(
                !trace
                    .lock()
                    .unwrap()
                    .events
                    .iter()
                    .any(|event| matches!(event, UpdateEvent::Queue(_)))
            );
            assert_eq!(service.provider_read_at(opened, 4999, 2).unwrap().len(), 1);
        }
    }
}

#[test]
fn admitted_permissions_and_limits_are_checked_before_queueing() {
    use filesystem_service::memory_updates::MutationResult;
    let trace = Arc::new(Mutex::new(UpdateTrace {
        fail: Some("admitted_wait"),
        ..Default::default()
    }));
    let (mut service, _) =
        test_filesystem_with_storage(Some(Box::new(RecordingUpdates(trace.clone()))));
    let opened = open_update_file(
        &mut service,
        protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
    );
    seed_update_file(&mut service, opened);
    assert!(matches!(
        service.truncate_handle_admitted(
            protocol::Header {
                flags: protocol::TRUNCATE_GROWTH_BOUNDED,
                node_id: 8192,
                offset: 8193,
                ..Default::default()
            },
            opened,
            Some(42)
        ),
        MutationResult::Complete(Err(protocol::ERROR_GROWTH_LIMIT))
    ));
    assert!(matches!(
        service.truncate_at_admitted(
            protocol::Header {
                open_id: 1,
                ..Default::default()
            },
            b"/update-order",
            PathAnchors::default(),
            credentials(501, 20, &[]),
            Some(42)
        ),
        MutationResult::Complete(Err(13))
    ));
    assert!(trace.lock().unwrap().events.is_empty());
    // Neither rejection may leave a borrowed reference in the next scope.
    assert!(matches!(
        service.truncate_handle_admitted(
            protocol::Header {
                offset: 1,
                ..Default::default()
            },
            opened,
            None
        ),
        MutationResult::Wait(_)
    ));
    assert!(matches!(
        trace.lock().unwrap().events.as_slice(),
        [UpdateEvent::Admit(_, 8192, 1, None)]
    ));
}

#[test]
fn truncate_requires_configured_updates_and_configuration_cannot_change_after_open() {
    let (mut service, image) = test_filesystem_with_storage(None);
    let opened = open_update_file(
        &mut service,
        protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
    );
    service.provider_write(opened, b"original").unwrap();
    let before = image.0.lock().unwrap().clone();
    assert!(matches!(
        service.truncate_handle(
            protocol::Header {
                offset: 1,
                ..Default::default()
            },
            opened
        ),
        Err(95)
    ));
    assert_eq!(*image.0.lock().unwrap(), before);
    assert_eq!(
        service.provider_read_at(opened, 0, 20).unwrap(),
        b"original"
    );
    assert_eq!(
        service.configure_memory_updates(Box::new(UnmappedUpdates)),
        Err(16)
    );
}

#[test]
fn truncate_preparation_and_begin_failures_precede_all_storage_writes() {
    for failure in ["prepare", "begin", "begin_busy"] {
        let trace = Arc::new(Mutex::new(UpdateTrace {
            fail: Some(failure),
            ..Default::default()
        }));
        let (mut service, image) =
            test_filesystem_with_storage(Some(Box::new(RecordingUpdates(trace.clone()))));
        let opened = open_update_file(
            &mut service,
            protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
        );
        seed_update_file(&mut service, opened);
        let identity = service.provider_memory_object(opened).unwrap();
        let before = image.0.lock().unwrap().clone();
        image.2.lock().unwrap().attempts = 0;
        let result = service.truncate_handle(
            protocol::Header {
                offset: 5000,
                ..Default::default()
            },
            opened,
        );
        assert!(
            matches!(result, Err(error) if error == if failure == "begin" {5} else {protocol::ERROR_MEMORY_ADMISSION_BUSY})
        );
        assert_eq!(image.2.lock().unwrap().attempts, 0);
        assert_eq!(*image.0.lock().unwrap(), before);
        let mut expected = vec![UpdateEvent::Prepare(identity, 8192, 5000)];
        if failure != "prepare" {
            expected.extend([
                UpdateEvent::Begin,
                UpdateEvent::Drop {
                    begun: false,
                    published: false,
                },
            ]);
        }
        assert_eq!(trace.lock().unwrap().events, expected);
    }
}

#[test]
fn truncating_open_retries_only_before_mutation_and_never_replays_creation() {
    let trace = Arc::new(Mutex::new(UpdateTrace {
        fail: Some("prepare"),
        ..Default::default()
    }));
    let (mut service, image) =
        test_filesystem_with_storage(Some(Box::new(RecordingUpdates(trace.clone()))));
    let access = protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE;
    // The file is new and already empty: O_EXCL|O_TRUNC must not enter
    // admission after creation and then ask the client to repeat O_EXCL.
    let opened = open_update_file(
        &mut service,
        access | protocol::OPEN_AT_EXCLUSIVE | protocol::OPEN_AT_TRUNCATE,
    );
    assert!(trace.lock().unwrap().events.is_empty());
    seed_update_file(&mut service, opened);
    let header = protocol::Header {
        opcode: protocol::OP_OPEN_AT,
        flags: access | protocol::OPEN_AT_TRUNCATE,
        mode: 0o600,
        ..Default::default()
    };
    let before = image.0.lock().unwrap().clone();
    image.2.lock().unwrap().attempts = 0;
    assert!(matches!(
        service.open_at(
            header,
            b"/update-order",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(protocol::ERROR_MEMORY_ADMISSION_BUSY)
    ));
    assert_eq!(image.2.lock().unwrap().attempts, 0);
    assert_eq!(*image.0.lock().unwrap(), before);
    assert!(matches!(
        service.open_at(
            protocol::Header {
                flags: header.flags | protocol::OPEN_AT_EXCLUSIVE,
                ..header
            },
            b"/update-order",
            PathAnchors::default(),
            root_credentials()
        ),
        Err(17)
    ));
    trace.lock().unwrap().fail = None;
    let retried = service
        .open_at(
            header,
            b"/update-order",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    assert_eq!(retried.header.open_id, opened + 1);
    assert_eq!(service.provider_read_at(opened, 0, 8192).unwrap(), b"");
}

#[test]
fn partial_truncate_storage_failure_drops_uncertain_owner_without_publication() {
    let trace = Arc::new(Mutex::new(UpdateTrace::default()));
    let (mut service, image) =
        test_filesystem_with_storage(Some(Box::new(RecordingUpdates(trace.clone()))));
    let opened = open_update_file(
        &mut service,
        protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
    );
    seed_update_file(&mut service, opened);
    let identity = service.provider_memory_object(opened).unwrap();
    let before = image.0.lock().unwrap().clone();
    image.2.lock().unwrap().remaining = Some(1);
    let result = service.truncate_handle(
        protocol::Header {
            offset: 5000,
            ..Default::default()
        },
        opened,
    );
    image.2.lock().unwrap().remaining = None;
    assert!(matches!(result, Err(5)));
    assert_ne!(
        *image.0.lock().unwrap(),
        before,
        "failure must follow an actual partial write"
    );
    assert_eq!(
        trace.lock().unwrap().events,
        [
            UpdateEvent::Prepare(identity, 8192, 5000),
            UpdateEvent::Begin,
            UpdateEvent::Drop {
                begun: true,
                published: false
            }
        ]
    );
}

#[test]
fn open_truncate_uses_existing_backing_identity_and_refreshes_every_description_once() {
    let trace = Arc::new(Mutex::new(UpdateTrace::default()));
    let (mut service, _) =
        test_filesystem_with_storage(Some(Box::new(RecordingUpdates(trace.clone()))));
    let access = protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE;
    let a = open_update_file(&mut service, access);
    let b = open_update_file(&mut service, access);
    seed_update_file(&mut service, a);
    let identity = service.provider_memory_object(a).unwrap();
    let c = open_update_file(&mut service, access | protocol::OPEN_AT_TRUNCATE);
    for opened in [a, b, c] {
        assert_eq!(service.provider_memory_object(opened), Ok(identity));
        assert_eq!(
            service.provider_seek(opened, 0, mnu_abi::HANDLE_SEEK_END),
            Ok(0)
        );
    }
    assert_eq!(
        trace.lock().unwrap().events,
        [
            UpdateEvent::Prepare(identity, 8192, 0),
            UpdateEvent::Begin,
            UpdateEvent::Publish,
            UpdateEvent::Drop {
                begun: true,
                published: true
            }
        ]
    );
    service.provider_write_at(c, 0, b"new").unwrap();
    assert_eq!(service.provider_read_at(a, 0, 20).unwrap(), b"new");
    assert_eq!(service.provider_read_at(b, 0, 20).unwrap(), b"new");
}

#[test]
fn publication_error_does_not_restore_old_storage_or_stale_open_metadata() {
    for (failure, expected_error) in [("publish", 5), ("publish_busy", 11)] {
        let trace = Arc::new(Mutex::new(UpdateTrace {
            fail: Some(failure),
            ..Default::default()
        }));
        let (mut service, _) =
            test_filesystem_with_storage(Some(Box::new(RecordingUpdates(trace.clone()))));
        let access = protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE;
        let a = open_update_file(&mut service, access);
        let b = open_update_file(&mut service, access);
        service.provider_write(a, b"original").unwrap();
        assert!(matches!(
            service.truncate_handle(
                protocol::Header {
                    offset: 3,
                    ..Default::default()
                },
                b
            ),
            Err(error) if error == expected_error
        ));
        assert_eq!(service.provider_read_at(a, 0, 20).unwrap(), b"ori");
        assert_eq!(service.provider_read_at(b, 0, 20).unwrap(), b"ori");
        assert!(trace.lock().unwrap().events.ends_with(&[
            UpdateEvent::Publish,
            UpdateEvent::Drop {
                begun: true,
                published: true
            }
        ]));
    }
}

#[test]
fn readonly_and_immutable_failures_do_not_begin_or_quarantine_live_backing() {
    for readonly in [false, true] {
        let (_, image) = test_filesystem_with_storage(None);
        let disk = if readonly {
            Ext4::load(Box::new(image.clone())).unwrap()
        } else {
            Ext4::load_with_writer(Box::new(image.clone()), Some(Box::new(image))).unwrap()
        };
        assert_eq!(disk.is_read_only(), readonly);
        if !readonly {
            let mut inode = disk
                .path_to_inode(
                    "/blocked/child".try_into().unwrap(),
                    ext4plus::FollowSymlinks::All,
                )
                .unwrap();
            inode.set_flags(inode.flags() | ext4plus::inode::InodeFlags::IMMUTABLE);
            inode.write(&disk).unwrap();
        }
        let trace = Arc::new(Mutex::new(UpdateTrace::default()));
        let mut service = FilesystemService::new(disk);
        service
            .configure_memory_updates(Box::new(RecordingUpdates(trace.clone())))
            .unwrap();
        let opened = service
            .open_at(
                protocol::Header {
                    flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE,
                    ..Default::default()
                },
                b"/blocked/child",
                PathAnchors::default(),
                root_credentials(),
            )
            .unwrap()
            .header
            .open_id;
        assert!(
            matches!(service.truncate_handle(protocol::Header { offset:1, ..Default::default() }, opened),
            Err(error) if error == if readonly {30} else {1})
        );
        assert!(trace.lock().unwrap().events.is_empty());
        assert_eq!(service.provider_read_at(opened, 0, 20).unwrap(), b"private");
    }
}

#[test]
fn permission_and_growth_ceiling_rejections_precede_memory_update_admission() {
    let trace = Arc::new(Mutex::new(UpdateTrace::default()));
    let (mut service, _) =
        test_filesystem_with_storage(Some(Box::new(RecordingUpdates(trace.clone()))));
    let opened = open_update_file(
        &mut service,
        protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
    );
    seed_update_file(&mut service, opened);
    assert!(matches!(
        service.truncate_handle(
            protocol::Header {
                flags: protocol::TRUNCATE_GROWTH_BOUNDED,
                node_id: 8192,
                offset: 8193,
                ..Default::default()
            },
            opened
        ),
        Err(protocol::ERROR_GROWTH_LIMIT)
    ));
    assert!(matches!(
        service.truncate_at(
            protocol::Header {
                open_id: 0,
                ..Default::default()
            },
            b"/update-order",
            PathAnchors::default(),
            credentials(501, 20, &[])
        ),
        Err(13)
    ));
    assert!(trace.lock().unwrap().events.is_empty());
}

#[test]
fn provider_reads_return_the_completed_prefix_after_a_storage_failure() {
    for shared in [false, true] {
        let (mut filesystem, failure) = test_filesystem_with_read_failure();
        let open_id = filesystem
            .open_at(
                protocol::Header {
                    opcode: protocol::OP_OPEN_AT,
                    flags: protocol::OPEN_AT_READ
                        | protocol::OPEN_AT_WRITE
                        | protocol::OPEN_AT_CREATE,
                    mode: 0o644,
                    ..protocol::Header::default()
                },
                b"/partial.txt",
                PathAnchors::default(),
                root_credentials(),
            )
            .unwrap()
            .header
            .open_id;
        let contents: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        for chunk in contents.chunks(1024) {
            filesystem.provider_write(open_id, chunk).unwrap();
        }
        filesystem
            .provider_seek(open_id, 0, HANDLE_SEEK_START)
            .unwrap();
        // Warm the retained File's block lookup before failing its data reads.
        assert_eq!(
            filesystem.provider_read_at(open_id, 0, 4096).unwrap(),
            contents[..4096]
        );
        // Begin inside a block so even a 4 KiB inline request spans two blocks.
        filesystem
            .provider_seek(open_id, 1, HANDLE_SEEK_START)
            .unwrap();
        // One inode reload and one successful data read precede the injected
        // failure. The refreshed description must still report that prefix.
        *failure.lock().unwrap() = Some(2);
        let mut output = vec![0xa5; 4096];
        let done = if shared {
            let (done, start) = filesystem.provider_read_into(open_id, &mut output).unwrap();
            assert_eq!(start, 1);
            assert!(output[done..].iter().all(|byte| *byte == 0xa5));
            done
        } else {
            let bytes = filesystem.provider_read(open_id, output.len()).unwrap();
            output[..bytes.len()].copy_from_slice(&bytes);
            bytes.len()
        };
        assert!(done > 0 && done < output.len());
        assert_eq!(output[..done], contents[1..1 + done]);
        assert!(filesystem.provider_read(open_id, 1).is_err());
        assert_eq!(
            filesystem
                .provider_seek(open_id, 0, mnu_abi::HANDLE_SEEK_CURRENT)
                .unwrap(),
            1 + done as u64
        );
        *failure.lock().unwrap() = None;
        assert_eq!(
            filesystem.provider_read(open_id, 3).unwrap(),
            contents[1 + done..1 + done + 3]
        );
    }
}

#[test]
fn internal_directory_search_open_checks_execute_instead_of_read_permission() {
    let mut filesystem = test_filesystem();
    let searched = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_DIRECTORY | protocol::OPEN_AT_SEARCH,
                ..protocol::Header::default()
            },
            b"/search-only",
            PathAnchors::default(),
            credentials(501, 501, &[]),
        )
        .unwrap();
    assert_ne!(searched.header.open_id, 0);

    assert!(matches!(
        filesystem.open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_DIRECTORY | protocol::OPEN_AT_READ,
                ..protocol::Header::default()
            },
            b"/search-only",
            PathAnchors::default(),
            credentials(501, 501, &[]),
        ),
        Err(13)
    ));
    assert!(matches!(
        filesystem.open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_DIRECTORY
                    | protocol::OPEN_AT_SEARCH
                    | protocol::OPEN_AT_READ,
                ..protocol::Header::default()
            },
            b"/search-only",
            PathAnchors::default(),
            credentials(501, 501, &[]),
        ),
        Err(22)
    ));
}

#[test]
fn an_open_directory_remains_a_valid_object_after_unlink() {
    let mut filesystem = test_filesystem();
    let opened = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/removed",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let open_id = opened.header.open_id;

    let removed = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_UNLINK,
            flags: protocol::NODE_TYPE_DIRECTORY,
            ..protocol::Header::default()
        },
        b"/removed",
    );
    assert_eq!(removed.header.status, 0);

    let status = filesystem
        .stat_handle(
            protocol::Header {
                opcode: protocol::OP_STAT_HANDLE,
                ..protocol::Header::default()
            },
            open_id,
        )
        .unwrap();
    let status = protocol::decode_node_status(&status.payload).unwrap();
    assert_eq!(status.kind, protocol::NODE_TYPE_DIRECTORY);

    let entries = filesystem
        .provider_read(open_id, protocol::MAX_IO_LEN)
        .unwrap();
    assert!(!entries.is_empty());
}

#[test]
fn truncate_and_sync_address_an_open_object_without_a_path() {
    let mut filesystem = test_filesystem();
    let opened = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
                mode: 0o644,
                ..protocol::Header::default()
            },
            b"/truncate.txt",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let open_id = opened.header.open_id;
    filesystem.provider_write(open_id, b"abcdefgh").unwrap();

    filesystem
        .truncate_handle(
            protocol::Header {
                opcode: protocol::OP_TRUNCATE_HANDLE,
                offset: 3,
                ..protocol::Header::default()
            },
            open_id,
        )
        .unwrap();
    filesystem
        .provider_seek(open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    assert_eq!(filesystem.provider_read(open_id, 8).unwrap(), b"abc");
    filesystem
        .sync_handle(
            protocol::Header {
                opcode: protocol::OP_SYNC_HANDLE,
                ..protocol::Header::default()
            },
            open_id,
        )
        .unwrap();
}

#[test]
fn pager_positioned_io_does_not_change_the_open_description_offset() {
    let mut filesystem = test_filesystem();
    let open_id = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
                mode: 0o644,
                ..protocol::Header::default()
            },
            b"/pager.txt",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    filesystem.provider_write(open_id, b"abcdef").unwrap();
    filesystem
        .provider_seek(open_id, 2, HANDLE_SEEK_START)
        .unwrap();

    assert_eq!(filesystem.provider_read_at(open_id, 0, 2).unwrap(), b"ab");
    assert_eq!(filesystem.provider_read(open_id, 2).unwrap(), b"cd");
    filesystem.provider_write_at(open_id, 0, b"ZZ").unwrap();
    assert_eq!(filesystem.provider_read(open_id, 2).unwrap(), b"ef");
    assert_eq!(
        filesystem.provider_read_at(open_id, 0, 6).unwrap(),
        b"ZZcdef"
    );
    assert_eq!(
        filesystem
            .provider_write_with_offset(open_id, b"gh")
            .unwrap(),
        (2, 6)
    );
    // A later seek cannot change the offset captured in the write result.
    filesystem
        .provider_seek(open_id, 1, HANDLE_SEEK_START)
        .unwrap();
    assert_eq!(
        filesystem
            .provider_write_with_offset(open_id, b"X")
            .unwrap(),
        (1, 1)
    );
    assert_eq!(
        filesystem.provider_read_at(open_id, 0, 8).unwrap(),
        b"ZXcdefgh"
    );
    assert_eq!(filesystem.provider_read_at(open_id, u64::MAX, 1), Err(27));
    assert_eq!(
        filesystem.provider_write_at(open_id, u64::MAX, b"!"),
        Err(27)
    );
    assert_eq!(
        filesystem.provider_read_at(open_id, 0, 8).unwrap(),
        b"ZXcdefgh"
    );
    // Neither positioned operation, including its rejected range, changes
    // the sequential cursor left at 2 by the write above.
    assert_eq!(filesystem.provider_read(open_id, 2).unwrap(), b"cd");
}

#[test]
fn sequential_read_returns_its_original_position_and_preserves_offset_on_error() {
    let mut filesystem = test_filesystem();
    let open_id = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
                mode: 0o644,
                ..protocol::Header::default()
            },
            b"/read-position.txt",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    filesystem.provider_write(open_id, b"abcdef").unwrap();
    filesystem
        .provider_seek(open_id, 2, HANDLE_SEEK_START)
        .unwrap();
    let first = filesystem.provider_read_with_offset(open_id, 2).unwrap();
    assert_eq!(first, (b"cd".to_vec(), 2));
    assert_eq!(
        filesystem
            .provider_read_with_offset(open_id, mnu_abi::provider::MAX_POSITIONED_READ_LEN + 1),
        Err(22)
    );
    assert_eq!(
        filesystem.provider_read_with_offset(open_id, 8).unwrap(),
        (b"ef".to_vec(), 4)
    );
    assert_eq!(
        filesystem.provider_read_with_offset(open_id, 8).unwrap(),
        (Vec::new(), 6)
    );
    filesystem
        .provider_seek(open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    assert_eq!(first, (b"cd".to_vec(), 2));
}

#[test]
fn legacy_directory_descriptions_keep_the_original_stream_format() {
    let mut filesystem = test_filesystem();
    let opened = filesystem
        .open_at(
            protocol::Header {
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..Default::default()
            },
            b"/",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let bytes = filesystem.provider_read(opened.header.open_id, 4096).unwrap();
    assert!(!bytes.is_empty());
    let mut remaining = bytes.as_slice();
    while !remaining.is_empty() {
        let (header, name, consumed) = protocol::decode_dir_entry(remaining).unwrap();
        assert_eq!(header.next_position, None);
        assert_eq!(consumed, protocol::DIRENT_HEADER_LEN + name.len());
        remaining = &remaining[consumed..];
    }
    filesystem.provider_close(opened.header.open_id).unwrap();
}

#[test]
fn directory_provider_declines_pager_identity_without_disabling_stream_reads() {
    let mut filesystem = test_filesystem();
    let open_id = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_DIRECTORY
                    | protocol::OPEN_AT_CURSOR_RECORDS,
                ..protocol::Header::default()
            },
            b"/",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    assert_eq!(filesystem.provider_memory_object(open_id), Err(95));
    let bytes = filesystem.provider_read(open_id, 4096).unwrap();
    assert!(!bytes.is_empty());
    let mut remaining = bytes.as_slice();
    let mut records = Vec::new();
    while !remaining.is_empty() {
        let (header, name, consumed) = protocol::decode_dir_entry(remaining).unwrap();
        records.push((header.next_position.unwrap(), name.to_vec()));
        remaining = &remaining[consumed..];
    }
    for (index, (position, _)) in records.iter().enumerate() {
        assert_eq!(
            filesystem.provider_seek(open_id, *position as i64, HANDLE_SEEK_START),
            Ok(*position)
        );
        let rest = filesystem.provider_read(open_id, 4096).unwrap();
        if let Some((_, next_name)) = records.get(index + 1) {
            assert_eq!(protocol::decode_dir_entry(&rest).unwrap().1, next_name);
        } else {
            assert!(rest.is_empty());
        }
    }
    assert_eq!(filesystem.provider_memory_object(u64::MAX), Err(9));
}

#[test]
fn pager_identity_is_stable_across_open_descriptions() {
    let mut filesystem = test_filesystem();
    let create = |filesystem: &mut FilesystemService, path: &[u8]| {
        filesystem
            .open_at(
                protocol::Header {
                    opcode: protocol::OP_OPEN_AT,
                    flags: protocol::OPEN_AT_READ
                        | protocol::OPEN_AT_WRITE
                        | protocol::OPEN_AT_CREATE,
                    mode: 0o644,
                    ..protocol::Header::default()
                },
                path,
                PathAnchors::default(),
                root_credentials(),
            )
            .unwrap()
            .header
            .open_id
    };
    let first = create(&mut filesystem, b"/identity.txt");
    let second = create(&mut filesystem, b"/identity.txt");
    let other = create(&mut filesystem, b"/other.txt");

    assert_eq!(
        filesystem.provider_memory_object(first).unwrap(),
        filesystem.provider_memory_object(second).unwrap()
    );
    assert_ne!(
        filesystem.provider_memory_object(first).unwrap(),
        filesystem.provider_memory_object(other).unwrap()
    );
    let identity = filesystem.provider_memory_object(first).unwrap();
    for open_id in [first, second] {
        let response = filesystem.handle(
            protocol::Header {
                opcode: protocol::OP_CLOSE,
                open_id,
                ..protocol::Header::default()
            },
            &[],
        );
        assert_eq!(response.header.status, 0);
        if open_id == first {
            assert_eq!(filesystem.provider_memory_object(second).unwrap(), identity);
        }
    }
    let reopened = create(&mut filesystem, b"/identity.txt");
    assert_ne!(
        filesystem.provider_memory_object(reopened).unwrap(),
        identity
    );
}

#[test]
fn bulk_read_into_exceeds_inline_ipc_limit_and_advances_one_description() {
    let mut filesystem = test_filesystem();
    let open_id = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
                mode: 0o644,
                ..protocol::Header::default()
            },
            b"/bulk-read.txt",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    let contents: Vec<u8> = (0..3 * 4096 + 71).map(|i| (i % 251) as u8).collect();
    for chunk in contents.chunks(4096) {
        filesystem.provider_write(open_id, chunk).unwrap();
    }
    filesystem
        .provider_seek(open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    let mut output = vec![0xa5; 8192];
    assert_eq!(
        filesystem.provider_read_into(open_id, &mut output),
        Ok((8192, 0))
    );
    assert_eq!(output, contents[..8192]);
    assert_eq!(filesystem.provider_read_into(open_id, &mut []), Err(22));
    let mut oversized = vec![0; mnu_abi::provider::MAX_SHARED_READ_LEN + 1];
    assert_eq!(
        filesystem.provider_read_into(open_id, &mut oversized),
        Err(22)
    );
    output.fill(0xa5);
    let remaining = contents.len() - 8192;
    assert_eq!(
        filesystem.provider_read_into(open_id, &mut output),
        Ok((remaining, 8192))
    );
    assert_eq!(&output[..remaining], &contents[8192..]);
    assert!(output[remaining..].iter().all(|byte| *byte == 0xa5));
    assert_eq!(
        filesystem.provider_read_into(open_id, &mut output),
        Ok((0, contents.len() as u64))
    );
    assert_eq!(filesystem.provider_read_into(u64::MAX, &mut output), Err(9));
}

#[test]
fn duplicated_open_descriptions_share_mutable_status_flags() {
    let mut filesystem = test_filesystem();
    let opened = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
                mode: 0o644,
                ..protocol::Header::default()
            },
            b"/flags.txt",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let open_id = opened.header.open_id;
    let wanted = protocol::OPEN_STATUS_APPEND | protocol::OPEN_STATUS_NONBLOCK;
    filesystem
        .set_flags_handle(
            protocol::Header {
                opcode: protocol::OP_SET_FLAGS_HANDLE,
                flags: wanted,
                ..protocol::Header::default()
            },
            open_id,
        )
        .unwrap();

    let flags = filesystem
        .get_flags_handle(
            protocol::Header {
                opcode: protocol::OP_GET_FLAGS_HANDLE,
                ..protocol::Header::default()
            },
            open_id,
        )
        .unwrap();
    assert_eq!(flags.header.flags, wanted);

    for (mask, value, expected) in [
        (
            protocol::OPEN_STATUS_NONBLOCK,
            0,
            protocol::OPEN_STATUS_APPEND,
        ),
        (protocol::OPEN_STATUS_APPEND, 0, 0),
        (
            protocol::OPEN_STATUS_NONBLOCK,
            protocol::OPEN_STATUS_NONBLOCK,
            protocol::OPEN_STATUS_NONBLOCK,
        ),
        (
            protocol::OPEN_STATUS_APPEND,
            protocol::OPEN_STATUS_APPEND,
            wanted,
        ),
    ] {
        filesystem
            .update_flags_handle(
                protocol::Header {
                    opcode: protocol::OP_UPDATE_FLAGS_HANDLE,
                    flags: value,
                    ..Default::default()
                },
                open_id,
                mask,
            )
            .unwrap();
        assert_eq!(
            filesystem
                .get_flags_handle(protocol::Header::default(), open_id)
                .unwrap()
                .header
                .flags,
            expected
        );
    }
    for (mask, flags) in [
        (u32::MAX, 0),
        (protocol::OPEN_STATUS_NONBLOCK, protocol::OPEN_STATUS_APPEND),
    ] {
        assert_eq!(
            filesystem
                .update_flags_handle(
                    protocol::Header {
                        flags,
                        ..Default::default()
                    },
                    open_id,
                    mask
                )
                .err(),
            Some(22)
        );
        assert_eq!(
            filesystem
                .get_flags_handle(protocol::Header::default(), open_id)
                .unwrap()
                .header
                .flags,
            wanted
        );
    }

    filesystem.provider_write(open_id, b"a").unwrap();
    filesystem
        .provider_seek(open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    assert_eq!(
        filesystem.provider_write_with_offset(open_id, &[]),
        Ok((0, 0))
    );
    assert_eq!(
        filesystem.provider_seek(open_id, 0, mnu_abi::HANDLE_SEEK_CURRENT),
        Ok(0)
    );
    filesystem.provider_write(open_id, b"b").unwrap();
    filesystem
        .provider_seek(open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    assert_eq!(filesystem.provider_read(open_id, 2).unwrap(), b"ab");
}

#[test]
fn mkdir_at_is_anchored_to_an_open_directory() {
    let mut filesystem = test_filesystem();
    let base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/removed",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    filesystem
        .mkdir_at(
            protocol::Header {
                opcode: protocol::OP_MKDIR_AT,
                flags: protocol::MKDIR_AT_BASE_ATTACHED,
                mode: 0o755,
                ..protocol::Header::default()
            },
            b"child",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
            credentials(1000, 1000, &[]),
        )
        .unwrap();

    let status = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_LOOKUP,
            flags: protocol::LOOKUP_FOLLOW_SYMLINKS,
            ..protocol::Header::default()
        },
        b"/removed/child",
    );
    assert_eq!(status.header.status, 0);
    assert_eq!(status.header.flags, protocol::NODE_TYPE_DIRECTORY);
}

#[test]
fn orphan_cleanup_uses_parent_inode_after_parent_rename() {
    let mut filesystem = test_filesystem();
    filesystem
        .mkdir_at(
            protocol::Header {
                opcode: protocol::OP_MKDIR_AT,
                mode: 0o755,
                ..protocol::Header::default()
            },
            b"/create-base/parent",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let opened = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
                mode: 0o644,
                ..protocol::Header::default()
            },
            b"/create-base/parent/file",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let removed = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_UNLINK,
            flags: protocol::NODE_TYPE_REGULAR,
            ..protocol::Header::default()
        },
        b"/create-base/parent/file",
    );
    assert_eq!(removed.header.status, 0);

    let old = b"/create-base/parent";
    let new = b"/create-base/renamed";
    let mut paths = old.to_vec();
    paths.extend_from_slice(new);
    let renamed = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_RENAME,
            offset: old.len() as u64,
            ..protocol::Header::default()
        },
        &paths,
    );
    assert_eq!(renamed.header.status, 0);
    filesystem.provider_close(opened.header.open_id).unwrap();
}

#[test]
fn unlink_at_removes_entries_relative_to_an_open_directory() {
    let mut filesystem = test_filesystem();
    let base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/create-base",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    filesystem
        .mkdir_at(
            protocol::Header {
                opcode: protocol::OP_MKDIR_AT,
                flags: protocol::MKDIR_AT_BASE_ATTACHED,
                mode: 0o755,
                ..protocol::Header::default()
            },
            b"victim",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    filesystem
        .unlink_at(
            protocol::Header {
                opcode: protocol::OP_UNLINK_AT,
                flags: protocol::UNLINK_AT_BASE_ATTACHED | protocol::UNLINK_AT_REMOVE_DIRECTORY,
                ..protocol::Header::default()
            },
            b"victim",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();

    let missing = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_LOOKUP,
            flags: protocol::LOOKUP_FOLLOW_SYMLINKS,
            ..protocol::Header::default()
        },
        b"/create-base/victim",
    );
    assert_eq!(missing.header.status, -2);
}

#[test]
fn unlink_at_keeps_an_open_file_description_alive() {
    let mut filesystem = test_filesystem();
    let base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/create-base",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let file = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE
                    | protocol::OPEN_AT_BASE_ATTACHED,
                mode: 0o644,
                ..protocol::Header::default()
            },
            b"open-victim",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    filesystem
        .provider_write(file.header.open_id, b"alive")
        .unwrap();
    filesystem
        .unlink_at(
            protocol::Header {
                opcode: protocol::OP_UNLINK_AT,
                flags: protocol::UNLINK_AT_BASE_ATTACHED,
                ..protocol::Header::default()
            },
            b"open-victim",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    filesystem
        .provider_seek(file.header.open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    assert_eq!(
        filesystem.provider_read(file.header.open_id, 5).unwrap(),
        b"alive"
    );
    filesystem.provider_close(file.header.open_id).unwrap();
}

#[test]
fn rename_at_moves_between_two_open_directories_and_replaces_atomically() {
    let mut filesystem = test_filesystem();
    let old_base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/create-base",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let new_base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/removed",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let source = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE
                    | protocol::OPEN_AT_BASE_ATTACHED,
                mode: 0o644,
                ..protocol::Header::default()
            },
            b"source",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(old_base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    filesystem
        .provider_write(source.header.open_id, b"source-data")
        .unwrap();
    let destination = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE
                    | protocol::OPEN_AT_BASE_ATTACHED,
                mode: 0o644,
                ..protocol::Header::default()
            },
            b"destination",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(new_base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    filesystem
        .provider_write(destination.header.open_id, b"old")
        .unwrap();
    let mut payload = b"source".to_vec();
    payload.extend_from_slice(b"destination");
    filesystem
        .rename_at(
            protocol::Header {
                opcode: protocol::OP_RENAME_AT,
                flags: protocol::RENAME_AT_OLD_BASE_ATTACHED
                    | protocol::RENAME_AT_NEW_BASE_ATTACHED,
                mode: 6,
                ..protocol::Header::default()
            },
            &payload,
            RenameAnchors {
                root_open_id: None,
                old_base_open_id: Some(old_base.header.open_id),
                new_base_open_id: Some(new_base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();

    filesystem
        .provider_seek(source.header.open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    assert_eq!(
        filesystem.provider_read(source.header.open_id, 11).unwrap(),
        b"source-data"
    );
    filesystem
        .provider_seek(destination.header.open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    assert_eq!(
        filesystem
            .provider_read(destination.header.open_id, 3)
            .unwrap(),
        b"old"
    );
    filesystem
        .provider_close(destination.header.open_id)
        .unwrap();
}

#[test]
fn link_at_creates_one_inode_across_two_open_directories() {
    let mut filesystem = test_filesystem();
    let old_base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/create-base",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let new_base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/removed",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let source = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE
                    | protocol::OPEN_AT_BASE_ATTACHED,
                mode: 0o640,
                ..protocol::Header::default()
            },
            b"hard-link-source",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(old_base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    filesystem
        .provider_write(source.header.open_id, b"shared")
        .unwrap();
    let mut payload = b"hard-link-source".to_vec();
    payload.extend_from_slice(b"hard-link-destination");
    filesystem
        .link_at(
            protocol::Header {
                opcode: protocol::OP_LINK_AT,
                flags: protocol::LINK_AT_OLD_BASE_ATTACHED | protocol::LINK_AT_NEW_BASE_ATTACHED,
                mode: b"hard-link-source".len() as u32,
                ..protocol::Header::default()
            },
            &payload,
            RenameAnchors {
                root_open_id: None,
                old_base_open_id: Some(old_base.header.open_id),
                new_base_open_id: Some(new_base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();

    let source_status = filesystem
        .stat_at(
            protocol::Header {
                opcode: protocol::OP_STAT_AT,
                flags: protocol::STAT_AT_BASE_ATTACHED,
                ..protocol::Header::default()
            },
            b"hard-link-source",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(old_base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    let destination_status = filesystem
        .stat_at(
            protocol::Header {
                opcode: protocol::OP_STAT_AT,
                flags: protocol::STAT_AT_BASE_ATTACHED,
                ..protocol::Header::default()
            },
            b"hard-link-destination",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(new_base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    let source_status = protocol::decode_node_status(&source_status.payload).unwrap();
    let destination_status = protocol::decode_node_status(&destination_status.payload).unwrap();
    assert_eq!(source_status.node_id, destination_status.node_id);
    assert_eq!(source_status.link_count, 2);
    assert_eq!(destination_status.link_count, 2);

    let destination = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_BASE_ATTACHED,
                ..protocol::Header::default()
            },
            b"hard-link-destination",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(new_base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    filesystem
        .provider_write(destination.header.open_id, b"alias!")
        .unwrap();
    filesystem
        .provider_seek(source.header.open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    assert_eq!(
        filesystem.provider_read(source.header.open_id, 6).unwrap(),
        b"alias!"
    );

    assert!(matches!(
        filesystem.link_at(
            protocol::Header {
                opcode: protocol::OP_LINK_AT,
                flags: protocol::LINK_AT_OLD_BASE_ATTACHED | protocol::LINK_AT_NEW_BASE_ATTACHED,
                mode: b"hard-link-source".len() as u32,
                ..protocol::Header::default()
            },
            &payload,
            RenameAnchors {
                root_open_id: None,
                old_base_open_id: Some(old_base.header.open_id),
                new_base_open_id: Some(new_base.header.open_id),
            },
            root_credentials(),
        ),
        Err(17)
    ));
}

#[test]
fn link_at_only_follows_the_source_symlink_when_requested() {
    let mut filesystem = test_filesystem();
    filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
                mode: 0o640,
                ..protocol::Header::default()
            },
            b"/create-base/target",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    for (destination, follow) in [
        (b"/removed/symlink-alias".as_slice(), false),
        (b"/removed/target-alias".as_slice(), true),
    ] {
        let mut payload = b"/create-base/dangling".to_vec();
        payload.extend_from_slice(destination);
        filesystem
            .link_at(
                protocol::Header {
                    opcode: protocol::OP_LINK_AT,
                    flags: if follow {
                        protocol::LINK_AT_FOLLOW_SOURCE
                    } else {
                        0
                    },
                    mode: b"/create-base/dangling".len() as u32,
                    ..protocol::Header::default()
                },
                &payload,
                RenameAnchors::default(),
                root_credentials(),
            )
            .unwrap();
    }
    let status = |filesystem: &mut FilesystemService, path: &[u8], nofollow: bool| {
        let response = filesystem
            .stat_at(
                protocol::Header {
                    opcode: protocol::OP_STAT_AT,
                    flags: if nofollow {
                        protocol::STAT_AT_NOFOLLOW
                    } else {
                        0
                    },
                    ..protocol::Header::default()
                },
                path,
                PathAnchors::default(),
                root_credentials(),
            )
            .unwrap();
        protocol::decode_node_status(&response.payload).unwrap()
    };
    let source_link = status(&mut filesystem, b"/create-base/dangling", true);
    let linked_link = status(&mut filesystem, b"/removed/symlink-alias", true);
    assert_eq!(source_link.kind, protocol::NODE_TYPE_SYMLINK);
    assert_eq!(source_link.node_id, linked_link.node_id);
    assert_eq!(source_link.link_count, 2);

    let target = status(&mut filesystem, b"/create-base/target", false);
    let followed_link = status(&mut filesystem, b"/removed/target-alias", false);
    assert_eq!(target.kind, protocol::NODE_TYPE_REGULAR);
    assert_eq!(target.node_id, followed_link.node_id);
    assert_eq!(target.link_count, 2);
}

#[test]
fn truncate_at_resolves_and_mutates_in_one_anchored_operation() {
    let mut filesystem = test_filesystem();
    let base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/create-base",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let file = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE
                    | protocol::OPEN_AT_BASE_ATTACHED,
                mode: 0o666,
                ..protocol::Header::default()
            },
            b"truncate-path",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    filesystem
        .provider_write(file.header.open_id, b"abcdefgh")
        .unwrap();
    filesystem
        .truncate_at(
            protocol::Header {
                opcode: protocol::OP_TRUNCATE_AT,
                open_id: 3,
                flags: protocol::TRUNCATE_AT_BASE_ATTACHED,
                ..protocol::Header::default()
            },
            b"truncate-path",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    filesystem
        .provider_seek(file.header.open_id, 0, HANDLE_SEEK_START)
        .unwrap();
    assert_eq!(
        filesystem.provider_read(file.header.open_id, 8).unwrap(),
        b"abc"
    );
}

#[test]
fn symlink_at_creates_a_literal_target_under_the_open_directory() {
    let mut filesystem = test_filesystem();
    let base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/create-base",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let target = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE
                    | protocol::OPEN_AT_BASE_ATTACHED,
                mode: 0o644,
                ..protocol::Header::default()
            },
            b"symlink-target",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    filesystem
        .provider_write(target.header.open_id, b"linked")
        .unwrap();
    let mut payload = b"symlink-target".to_vec();
    payload.extend_from_slice(b"created-link");
    filesystem
        .symlink_at(
            protocol::Header {
                opcode: protocol::OP_SYMLINK_AT,
                flags: protocol::SYMLINK_AT_BASE_ATTACHED,
                mode: 14,
                ..protocol::Header::default()
            },
            &payload,
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    let response = filesystem
        .readlink_at(
            protocol::Header {
                opcode: protocol::OP_READLINK_AT,
                flags: protocol::READLINK_AT_BASE_ATTACHED,
                ..protocol::Header::default()
            },
            b"created-link",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    assert_eq!(response.payload, b"symlink-target");
    let link = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_BASE_ATTACHED,
                ..protocol::Header::default()
            },
            b"created-link",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    assert_eq!(
        filesystem.provider_read(link.header.open_id, 6).unwrap(),
        b"linked"
    );
}

#[test]
fn chmod_at_changes_only_permissions_on_an_anchored_path() {
    let mut filesystem = test_filesystem();
    let base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/create-base",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let file = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE
                    | protocol::OPEN_AT_BASE_ATTACHED,
                mode: 0o600,
                ..protocol::Header::default()
            },
            b"chmod-file",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    filesystem
        .chmod_at(
            protocol::Header {
                opcode: protocol::OP_CHMOD_AT,
                flags: protocol::CHMOD_AT_BASE_ATTACHED,
                mode: 0o750,
                ..protocol::Header::default()
            },
            b"chmod-file",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    let status = filesystem
        .stat_handle(protocol::Header::default(), file.header.open_id)
        .unwrap();
    let status = protocol::decode_node_status(&status.payload).unwrap();
    assert_eq!(status.mode & 0o7777, 0o750);
}

#[test]
fn chown_at_updates_ownership_and_rejects_a_non_owner() {
    let mut filesystem = test_filesystem();
    let base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/create-base",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let file = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE
                    | protocol::OPEN_AT_BASE_ATTACHED,
                mode: 0o6750,
                ..protocol::Header::default()
            },
            b"chown-file",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    filesystem
        .chown_at(
            protocol::Header {
                opcode: protocol::OP_CHOWN_AT,
                flags: protocol::CHOWN_AT_BASE_ATTACHED,
                node_id: u64::from(100u32) | (u64::from(200u32) << 32),
                ..protocol::Header::default()
            },
            b"chown-file",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(base.header.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    let status = filesystem
        .stat_handle(protocol::Header::default(), file.header.open_id)
        .unwrap();
    let status = protocol::decode_node_status(&status.payload).unwrap();
    assert_eq!(status.uid, 100);
    assert_eq!(status.gid, 200);
    assert_eq!(status.mode & 0o6000, 0);

    let error = match filesystem.chown_at(
        protocol::Header {
            opcode: protocol::OP_CHOWN_AT,
            flags: protocol::CHOWN_AT_BASE_ATTACHED,
            node_id: u64::from(u32::MAX) | (u64::from(101u32) << 32),
            ..protocol::Header::default()
        },
        b"chown-file",
        PathAnchors {
            root_open_id: None,
            base_open_id: Some(base.header.open_id),
        },
        credentials(101, 200, &[]),
    ) {
        Ok(_) => panic!("non-owner chown unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(error, 1);
}

#[test]
fn open_directory_paths_follow_rename_and_reject_unlinked_cwds() {
    check_open_directory_path_lifetime(false);
    check_open_directory_path_lifetime(true);
}

fn check_open_directory_path_lifetime(mounted_namespace: bool) {
    let mut filesystem = test_filesystem();
    if mounted_namespace {
        filesystem
            .mount_devices(b"/dev", filesystem_service::devfs::DeviceFilesystem::default())
            .unwrap();
    }
    let root = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    let cwd = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/jail/inside",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;

    let initial = filesystem
        .path_handle(
            protocol::Header {
                opcode: protocol::OP_PATH_HANDLE,
                ..protocol::Header::default()
            },
            root,
            cwd,
        )
        .unwrap();
    assert_eq!(initial.payload, b"/jail/inside");

    let old = b"/jail/inside";
    let new = b"/jail/moved";
    let mut rename = Vec::from(old.as_slice());
    rename.extend_from_slice(new);
    let renamed = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_RENAME,
            offset: old.len() as u64,
            ..protocol::Header::default()
        },
        &rename,
    );
    assert_eq!(renamed.header.status, 0);
    let current = filesystem
        .path_handle(
            protocol::Header {
                opcode: protocol::OP_PATH_HANDLE,
                ..protocol::Header::default()
            },
            root,
            cwd,
        )
        .unwrap();
    assert_eq!(current.payload, b"/jail/moved");

    let removed = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_UNLINK,
            flags: protocol::NODE_TYPE_DIRECTORY,
            ..protocol::Header::default()
        },
        b"/jail/moved",
    );
    assert_eq!(removed.header.status, 0);
    let missing = filesystem.path_handle(
        protocol::Header {
            opcode: protocol::OP_PATH_HANDLE,
            ..protocol::Header::default()
        },
        root,
        cwd,
    );
    assert!(matches!(missing, Err(2)), "mounted namespace: {mounted_namespace}");
}

#[test]
fn symlink_targets_enforce_search_permission_on_the_actual_directory() {
    let mut filesystem = test_filesystem();
    let result = filesystem.stat_at(
        protocol::Header {
            opcode: protocol::OP_STAT_AT,
            ..protocol::Header::default()
        },
        b"/redirect",
        PathAnchors::default(),
        credentials(501, 20, &[]),
    );
    assert!(matches!(result, Err(13)));

    let result = filesystem.open_at(
        protocol::Header {
            opcode: protocol::OP_OPEN_AT,
            flags: protocol::OPEN_AT_READ,
            ..protocol::Header::default()
        },
        b"/redirect",
        PathAnchors::default(),
        credentials(501, 20, &[]),
    );
    assert!(matches!(result, Err(13)));
}

#[test]
fn supplementary_group_grants_directory_search_during_path_resolution() {
    let mut filesystem = test_filesystem();
    let response = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_SETATTR,
            flags: protocol::SETATTR_MODE | protocol::SETATTR_GID,
            offset: u64::from(20u32) << 32,
            mode: 0o050,
            ..protocol::Header::default()
        },
        b"/blocked",
    );
    assert_eq!(response.header.status, 0);

    let without_group = filesystem.stat_at(
        protocol::Header {
            opcode: protocol::OP_STAT_AT,
            ..protocol::Header::default()
        },
        b"/blocked/child",
        PathAnchors::default(),
        credentials(501, 99, &[]),
    );
    assert!(matches!(without_group, Err(13)));

    let with_group = filesystem.stat_at(
        protocol::Header {
            opcode: protocol::OP_STAT_AT,
            ..protocol::Header::default()
        },
        b"/blocked/child",
        PathAnchors::default(),
        credentials(501, 99, &[20]),
    );
    assert!(with_group.is_ok());
}

#[test]
fn filesystem_node_ids_are_stable_ext4_inode_numbers() {
    let mut filesystem = test_filesystem();
    let mounted = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_MOUNT,
            ..protocol::Header::default()
        },
        &[],
    );
    let root = filesystem
        .stat_at(
            protocol::Header {
                opcode: protocol::OP_STAT_AT,
                ..protocol::Header::default()
            },
            b"/",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let root = protocol::decode_node_status(&root.payload).unwrap();
    assert_eq!(mounted.header.node_id, root.node_id);
    assert_eq!(root.node_id, 2);

    let lookup = filesystem.handle(
        protocol::Header {
            opcode: protocol::OP_LOOKUP,
            flags: protocol::LOOKUP_FOLLOW_SYMLINKS,
            ..protocol::Header::default()
        },
        b"/blocked/child",
    );
    let status = filesystem
        .stat_at(
            protocol::Header {
                opcode: protocol::OP_STAT_AT,
                offset: u64::from(0u32),
                ..protocol::Header::default()
            },
            b"/blocked/child",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    let status = protocol::decode_node_status(&status.payload).unwrap();
    assert_eq!(lookup.header.node_id, status.node_id);
}

#[test]
fn create_at_uses_the_open_parent_inode_and_follows_a_dangling_symlink() {
    let mut filesystem = test_filesystem();
    let base = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/create-base",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;

    let directory_only = filesystem.open_at(
        protocol::Header {
            opcode: protocol::OP_OPEN_AT,
            flags: protocol::OPEN_AT_BASE_ATTACHED
                | protocol::OPEN_AT_READ
                | protocol::OPEN_AT_CREATE
                | protocol::OPEN_AT_DIRECTORY,
            mode: 0o755,
            ..protocol::Header::default()
        },
        b"directory-only",
        PathAnchors {
            base_open_id: Some(base),
            ..PathAnchors::default()
        },
        root_credentials(),
    );
    assert!(matches!(directory_only, Err(2)));
    let absent = filesystem.stat_at(
        protocol::Header {
            opcode: protocol::OP_STAT_AT,
            flags: protocol::STAT_AT_BASE_ATTACHED,
            ..protocol::Header::default()
        },
        b"directory-only",
        PathAnchors {
            base_open_id: Some(base),
            ..PathAnchors::default()
        },
        root_credentials(),
    );
    assert!(matches!(absent, Err(2)));

    let exclusive = filesystem.open_at(
        protocol::Header {
            opcode: protocol::OP_OPEN_AT,
            flags: protocol::OPEN_AT_BASE_ATTACHED
                | protocol::OPEN_AT_READ
                | protocol::OPEN_AT_WRITE
                | protocol::OPEN_AT_CREATE
                | protocol::OPEN_AT_EXCLUSIVE,
            mode: 0o640,
            ..protocol::Header::default()
        },
        b"dangling",
        PathAnchors {
            base_open_id: Some(base),
            ..PathAnchors::default()
        },
        root_credentials(),
    );
    assert!(matches!(exclusive, Err(17)));

    filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_BASE_ATTACHED
                    | protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_WRITE
                    | protocol::OPEN_AT_CREATE,
                mode: 0o640,
                ..protocol::Header::default()
            },
            b"dangling",
            PathAnchors {
                base_open_id: Some(base),
                ..PathAnchors::default()
            },
            root_credentials(),
        )
        .unwrap();

    let target = filesystem
        .stat_at(
            protocol::Header {
                opcode: protocol::OP_STAT_AT,
                flags: protocol::STAT_AT_BASE_ATTACHED,
                ..protocol::Header::default()
            },
            b"target",
            PathAnchors {
                base_open_id: Some(base),
                ..PathAnchors::default()
            },
            root_credentials(),
        )
        .unwrap();
    let target = protocol::decode_node_status(&target.payload).unwrap();
    assert_eq!(target.kind, protocol::NODE_TYPE_REGULAR);
    assert_eq!(target.mode & 0o777, 0o640);

    let link = filesystem
        .stat_at(
            protocol::Header {
                opcode: protocol::OP_STAT_AT,
                flags: protocol::STAT_AT_BASE_ATTACHED | protocol::STAT_AT_NOFOLLOW,
                ..protocol::Header::default()
            },
            b"dangling",
            PathAnchors {
                base_open_id: Some(base),
                ..PathAnchors::default()
            },
            root_credentials(),
        )
        .unwrap();
    let link = protocol::decode_node_status(&link.payload).unwrap();
    assert_eq!(link.kind, protocol::NODE_TYPE_SYMLINK);
}

#[test]
fn root_anchor_confines_absolute_paths_symlinks_and_parent_components() {
    let mut filesystem = test_filesystem();
    let root = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..protocol::Header::default()
            },
            b"/jail",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    let inside = filesystem
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ
                    | protocol::OPEN_AT_DIRECTORY
                    | protocol::OPEN_AT_ROOT_ATTACHED,
                ..protocol::Header::default()
            },
            b"/inside",
            PathAnchors {
                root_open_id: Some(root),
                ..PathAnchors::default()
            },
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;

    for path in [b"/../outside".as_slice(), b"/escape".as_slice()] {
        let escaped = filesystem.stat_at(
            protocol::Header {
                opcode: protocol::OP_STAT_AT,
                flags: protocol::STAT_AT_ROOT_ATTACHED,
                ..protocol::Header::default()
            },
            path,
            PathAnchors {
                root_open_id: Some(root),
                ..PathAnchors::default()
            },
            root_credentials(),
        );
        assert!(matches!(escaped, Err(2)));
    }

    let escaped = filesystem.stat_at(
        protocol::Header {
            opcode: protocol::OP_STAT_AT,
            flags: protocol::STAT_AT_ROOT_ATTACHED | protocol::STAT_AT_BASE_ATTACHED,
            ..protocol::Header::default()
        },
        b"../../outside",
        PathAnchors {
            root_open_id: Some(root),
            base_open_id: Some(inside),
        },
        root_credentials(),
    );
    assert!(matches!(escaped, Err(2)));
}
