#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("record-lock: SKIP (requires mochiOS)");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform as platform;
    use mochios_posix_client::{
        Client, ClientError, ObjectHandleAttachment, ObjectHandles, OpenAtBase,
    };
    use mochios_posix_protocol::{
        self as protocol,
        record_lock::{self as wire, Kind, Operation, Origin, Reply, Request},
    };
    unsafe extern "C" {
        fn fork() -> i32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn _exit(code: i32) -> !;
    }
    fn request(operation: Operation) -> Request {
        Request {
            operation,
            origin: Origin::Start,
            start: 10,
            length: 20,
        }
    }
    fn release() -> Request {
        Request {
            operation: Operation::ReleaseFile,
            origin: Origin::Start,
            start: 0,
            length: 0,
        }
    }
    fn child_check(file: ObjectHandleAttachment<u32>, owner: u64, path: Option<&str>) {
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let client = Client::from_launch_context().unwrap();
            let opened = path.map(|path| {
                client
                    .open_at(
                        OpenAtBase::ProcessRoot,
                        protocol::OPEN_READ | protocol::OPEN_WRITE,
                        0,
                        path,
                    )
                    .unwrap()
            });
            let selected = opened.unwrap_or(file);
            assert_eq!(
                client
                    .record_lock(selected, request(Operation::Query(Kind::Read)))
                    .unwrap(),
                Reply::Conflict {
                    owner,
                    kind: Kind::Write,
                    start: 10,
                    length: 20
                }
            );
            assert!(matches!(
                client.record_lock(selected, request(Operation::Set(Kind::Write))),
                Err(ClientError::Remote(-11))
            ));
            client.record_lock(selected, release()).unwrap();
            assert!(matches!(
                client
                    .record_lock(selected, request(Operation::Query(Kind::Write)))
                    .unwrap(),
                Reply::Conflict { .. }
            ));
            let independent = Request {
                start: 100,
                length: 10,
                ..request(Operation::Set(Kind::Write))
            };
            client.record_lock(selected, independent).unwrap();
            // Deliberately leave a process-owned lock to native exit cleanup.
            unsafe { _exit(0) }
        }
        let mut status = -1;
        let waited = unsafe { waitpid(pid, &mut status, 0) };
        assert_eq!((waited, status), (pid, 0), "child lock probe failed");
        let client = Client::from_launch_context().unwrap();
        let query = Request {
            start: 100,
            length: 10,
            ..request(Operation::Query(Kind::Write))
        };
        assert_eq!(client.record_lock(file, query).unwrap(), Reply::Unlocked);
    }
    platform::io::stdout(b"record-lock: starting native FileHandle IPC checks\n").unwrap();
    let client = Client::from_launch_context().unwrap();
    let owner = platform::process::current_execution_identity()
        .unwrap()
        .process_id;
    let path = "/tmp/native-record-lock-153";
    let renamed = "/tmp/native-record-lock-renamed-153";
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(renamed);
    let file = client
        .open_at(
            OpenAtBase::ProcessRoot,
            protocol::OPEN_READ
                | protocol::OPEN_WRITE
                | protocol::OPEN_CREATE
                | protocol::OPEN_EXCLUSIVE,
            0o600,
            path,
        )
        .unwrap();
    assert_eq!(
        platform::handle::write(file.handle, &[0; 200]).unwrap(),
        200
    );
    let read_only = client
        .open_at(OpenAtBase::ProcessRoot, protocol::OPEN_READ, 0, path)
        .unwrap();
    let write_only = client
        .open_at(OpenAtBase::ProcessRoot, protocol::OPEN_WRITE, 0, path)
        .unwrap();
    let write = request(Operation::Set(Kind::Write));
    assert!(matches!(
        client.record_lock(read_only, write),
        Err(ClientError::Remote(-13))
    ));
    let mut payload = [0; wire::REQUEST_LEN];
    wire::encode_request(write, &mut payload).unwrap();
    let mut handles = ObjectHandles::new();
    handles
        .push(ObjectHandleAttachment {
            handle: read_only.handle,
            rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
        })
        .unwrap();
    assert!(matches!(
        client.request_with_handles(
            protocol::OP_RECORD_LOCK,
            0,
            &payload,
            &mut [0; wire::REPLY_LEN],
            &mut handles
        ),
        Err(ClientError::Remote(-13))
    ));
    assert!(handles.is_empty());
    client.record_lock(write_only, write).unwrap();
    assert_eq!(
        client
            .record_lock(read_only, request(Operation::Query(Kind::Write)))
            .unwrap(),
        Reply::Unlocked
    );
    child_check(file, owner, Some(path));
    println!(
        "record-lock: PASS attenuated write-only Handle, independent open, conflict, owner isolation and native exit release"
    );

    std::fs::rename(path, renamed).unwrap();
    child_check(file, owner, Some(renamed));
    std::fs::remove_file(renamed).unwrap();
    assert_eq!(client.fstat(file).unwrap().link_count, 0);
    child_check(file, owner, None);
    println!(
        "record-lock: PASS stable file identity across rename and unlink with a retained reference"
    );

    client.record_lock(read_only, release()).unwrap();
    let seek = Request {
        origin: Origin::Current,
        start: -10,
        length: -20,
        ..write
    };
    platform::handle::seek(file.handle, 100, platform::handle::HANDLE_SEEK_START).unwrap();
    client.record_lock(file, seek).unwrap();
    assert_eq!(
        platform::handle::seek(file.handle, 0, platform::handle::HANDLE_SEEK_CURRENT).unwrap(),
        100
    );
    client.record_lock(file, release()).unwrap();
    for file in [read_only, write_only, file] {
        platform::handle::close(file.handle).unwrap();
    }
    println!(
        "record-lock: PASS cursor snapshot, negative length, release through another open description"
    );
}
