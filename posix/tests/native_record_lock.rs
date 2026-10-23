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
        fn pipe(fds: *mut i32) -> i32;
        fn read(fd: i32, bytes: *mut u8, length: usize) -> isize;
        #[link_name = "write"]
        fn pipe_write(fd: i32, bytes: *const u8, length: usize) -> isize;
        fn close(fd: i32) -> i32;
        fn execv(path: *const i8, argv: *const *const i8) -> i32;
    }
    let arguments: Vec<_> = std::env::args().collect();
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--record-lock-after-exec")
    {
        let output: i32 = arguments[2].parse().unwrap();
        let input: i32 = arguments[3].parse().unwrap();
        assert_eq!(unsafe { pipe_write(output, b"E".as_ptr(), 1) }, 1);
        let mut byte = 0;
        assert_eq!(unsafe { read(input, &mut byte, 1) }, 1);
        unsafe { _exit(0) }
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

    // Explicit preparation API, not yet libc's automatic CLOEXEC integration.
    for fail_exec in [false, true] {
        let mut paths = Vec::new();
        let mut files = Vec::new();
        for index in 0..3 {
            let path = format!("/tmp/native-record-lock-exec-156-{index}");
            let _ = std::fs::remove_file(&path);
            let opened = client
                .open_at(
                    OpenAtBase::ProcessRoot,
                    protocol::OPEN_READ
                        | protocol::OPEN_WRITE
                        | protocol::OPEN_CREATE
                        | protocol::OPEN_EXCLUSIVE,
                    0o600,
                    &path,
                )
                .unwrap();
            paths.push(path);
            files.push(opened);
        }
        let mut ready = [0; 2];
        let mut go = [0; 2];
        assert_eq!(unsafe { pipe(ready.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { pipe(go.as_mut_ptr()) }, 0);
        let pid = unsafe { fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                close(ready[0]);
                close(go[1]);
            }
            let client = Client::from_launch_context().unwrap();
            for &file in &files {
                client
                    .record_lock(file, request(Operation::Set(Kind::Write)))
                    .unwrap();
            }
            let token = client
                .prepare_record_lock_exec(&files[..1], None)
                .unwrap()
                .unwrap();
            assert_eq!(
                client
                    .prepare_record_lock_exec(&files[1..2], Some(token))
                    .unwrap(),
                Some(token)
            );
            let executable = std::ffi::CString::new("/system/services/compositor.service").unwrap();
            let argv = [
                std::ffi::CString::new("record-lock-exec").unwrap(),
                std::ffi::CString::new("--record-lock-after-exec").unwrap(),
                std::ffi::CString::new(ready[1].to_string()).unwrap(),
                std::ffi::CString::new(go[0].to_string()).unwrap(),
            ];
            let pointers = [
                argv[0].as_ptr(),
                argv[1].as_ptr(),
                argv[2].as_ptr(),
                argv[3].as_ptr(),
                std::ptr::null(),
            ];
            if fail_exec {
                let old = client.resource_limit(0, protocol::RLIMIT_AS, None).unwrap();
                client
                    .resource_limit(
                        0,
                        protocol::RLIMIT_AS,
                        Some(protocol::ResourceLimit { soft: 0, ..old }),
                    )
                    .unwrap();
                let result = unsafe { execv(executable.as_ptr(), pointers.as_ptr()) };
                let error = std::io::Error::last_os_error().raw_os_error();
                client
                    .resource_limit(0, protocol::RLIMIT_AS, Some(old))
                    .unwrap();
                assert_eq!(
                    (result, error),
                    (-1, Some(12)),
                    "native image replacement must fail atomically"
                );
                client.cancel_record_lock_exec(token).unwrap();
                assert_eq!(unsafe { pipe_write(ready[1], b"F".as_ptr(), 1) }, 1);
                let mut byte = 0;
                assert_eq!(unsafe { read(go[0], &mut byte, 1) }, 1);
                unsafe { _exit(0) }
            }
            unsafe {
                execv(executable.as_ptr(), pointers.as_ptr());
            }
            panic!("exec failed: {}", std::io::Error::last_os_error());
        }
        unsafe {
            close(ready[1]);
            close(go[0]);
        }
        let mut byte = 0;
        assert_eq!(unsafe { read(ready[0], &mut byte, 1) }, 1);
        assert_eq!(byte, if fail_exec { b'F' } else { b'E' });
        for (index, &file) in files.iter().enumerate() {
            let result = client
                .record_lock(file, request(Operation::Query(Kind::Read)))
                .unwrap();
            if fail_exec || index == 2 {
                assert_eq!(
                    result,
                    Reply::Conflict {
                        owner: pid as u64,
                        kind: Kind::Write,
                        start: 10,
                        length: 20
                    }
                );
            } else {
                assert_eq!(result, Reply::Unlocked);
            }
        }
        assert_eq!(unsafe { pipe_write(go[1], b"G".as_ptr(), 1) }, 1);
        let mut status = -1;
        assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0);
        for (file, path) in files.iter().zip(&paths) {
            assert_eq!(
                client
                    .record_lock(*file, request(Operation::Query(Kind::Read)))
                    .unwrap(),
                Reply::Unlocked
            );
            platform::handle::close(file.handle).unwrap();
            std::fs::remove_file(path).unwrap();
        }
        unsafe {
            close(ready[0]);
            close(go[1]);
        }
        println!(
            "record-lock: PASS {}",
            if fail_exec {
                "failed bounded native exec plus cancellation preserves all process locks"
            } else {
                "successful native exec consumes batched preparations and preserves unselected locks"
            }
        );
    }
}
