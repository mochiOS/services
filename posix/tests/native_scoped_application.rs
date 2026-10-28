//! Actual Binder/workspace launch protocol, prepared output authorization,
//! scoped permissions and child registration across the real service boundary.
use mochi_user_platform as p;
use mochios_posix_client::{Client, ObjectHandleAttachment as Object, SyscallEndpointTransport};
use mochios_posix_protocol::{self as w, read_scope};

unsafe extern "C" {
    fn fork() -> i32;
    fn waitpid(child: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(code: i32) -> !;
    fn seteuid(uid: u16) -> i32;
    fn setegid(gid: u16) -> i32;
    fn setgroups(count: i32, groups: *const u16) -> i32;
    fn chdir(path: *const core::ffi::c_char) -> i32;
    fn chroot(path: *const core::ffi::c_char) -> i32;
    fn chmod(path: *const core::ffi::c_char, mode: u32) -> i32;
    fn umask(mask: u32) -> u32;
}
const BASE: &str = "/tmp/scoped-application-263";
const APP: &str = "/system/applications/ScopeDynamic.app/entry.elf";

pub(super) fn launch(
    service: u32,
    posix: u32,
    scope: Object<u32>,
    path: &str,
    case: u8,
) -> (i64, u64) {
    let parent = p::process::current_execution_identity().unwrap().process_id;
    let mut request = vec![0; 24];
    request[..4].copy_from_slice(&0x4150_5053u32.to_le_bytes());
    for item in [
        path.to_string(),
        if case == 0 {
            "--expect-euid=0".into()
        } else {
            "--expect-euid=501".into()
        },
        format!("__MNU_EXEC_ENV=EXPECT_PARENT={parent}"),
        "__MNU_EXEC_ENV=KEEP=1".into(),
        format!("__MNU_EXEC_ENV=LD_LIBRARY_PATH={BASE}/evil"),
    ] {
        // Case zero checks ordinary approved search without an override.
        if ![1, 2].contains(&case) && item.starts_with("__MNU_EXEC_ENV=LD_LIBRARY_PATH=") {
            continue;
        }
        request.extend_from_slice(item.as_bytes());
        request.push(0);
    }
    let mut handles = p::ipc::IpcObjectHandles::default();
    handles.count = 2;
    handles.handles[0].handle = posix;
    handles.handles[0].rights = p::handle::HANDLE_RIGHT_SEND
        | p::handle::HANDLE_RIGHT_DUPLICATE
        | p::handle::HANDLE_RIGHT_TRANSFER;
    handles.handles[1].handle = scope.handle;
    handles.handles[1].rights = read_scope::ATTACH_RIGHTS;
    let mut reply = [0; 16];
    let result = p::ipc::call_object_handles(service, &request, &mut reply, &mut handles).unwrap();
    assert_eq!(result as u32 as usize, reply.len());
    assert_eq!(handles.count, 0);
    (
        i64::from_le_bytes(reply[..8].try_into().unwrap()),
        u64::from_le_bytes(reply[8..].try_into().unwrap()),
    )
}

pub fn run(posix: u32) {
    let client = Client::new(SyscallEndpointTransport::new(posix));
    let service = u32::try_from(p::process::find_by_name("capability.service").unwrap()).unwrap();
    for directory in [
        BASE.to_string(),
        format!("{BASE}/lib"),
        format!("{BASE}/evil"),
        format!("{BASE}/new"),
    ] {
        std::fs::create_dir_all(&directory).unwrap();
        let path = std::ffi::CString::new(directory).unwrap();
        assert_eq!(unsafe { chmod(path.as_ptr(), 0o755) }, 0);
    }
    for leaf in ["libtls-gd.so", "libtls-ie.so"] {
        let bytes = std::fs::read(format!("/system/tests/scoped-application-263/{leaf}")).unwrap();
        std::fs::write(format!("{BASE}/lib/{leaf}"), &bytes).unwrap();
        let mut changed = bytes;
        changed[32] ^= 1;
        std::fs::write(format!("{BASE}/evil/{leaf}"), &changed).unwrap();
        for directory in ["lib", "evil"] {
            let path = std::ffi::CString::new(format!("{BASE}/{directory}/{leaf}")).unwrap();
            assert_eq!(unsafe { chmod(path.as_ptr(), 0o644) }, 0);
        }
    }
    let fake_path = format!("{BASE}/root{APP}");
    std::fs::create_dir_all(std::path::Path::new(&fake_path).parent().unwrap()).unwrap();
    let mut wrong_root = std::fs::read(APP).unwrap();
    wrong_root[32] ^= 1;
    std::fs::write(&fake_path, wrong_root).unwrap();
    let fake_path = std::ffi::CString::new(fake_path).unwrap();
    assert_eq!(unsafe { chmod(fake_path.as_ptr(), 0o755) }, 0);
    let foreign = client.create_read_scope().unwrap();
    for case in 0u8..9 {
        if case == 8 {
            // Same approved path, different bytes: path membership alone is
            // insufficient, including when the ELF header has been corrupted.
            let path = format!("{BASE}/lib/libtls-gd.so");
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[32] ^= 1;
            std::fs::write(path, bytes).unwrap();
        }
        let source = unsafe { fork() };
        assert!(source >= 0);
        if source == 0 {
            assert_eq!(unsafe { setgroups(2, [20u16, 42].as_ptr()) }, 0);
            if case != 2 {
                assert_eq!(unsafe { setegid(20) }, 0);
            }
            unsafe {
                umask(0o027);
            }
            client
                .resource_limit(
                    0,
                    w::RLIMIT_NOFILE,
                    Some(w::ResourceLimit { soft: 64, hard: 64 }),
                )
                .unwrap();
            if [1, 3, 5, 7].contains(&case) {
                assert_eq!(unsafe { seteuid(501) }, 0);
            }
            if case == 6 {
                assert_eq!(
                    unsafe { chroot(c"/tmp/scoped-application-263/root".as_ptr()) },
                    0
                );
                assert_eq!(unsafe { chdir(c"/".as_ptr()) }, 0);
            } else {
                assert_eq!(unsafe { chdir(c"/tmp/scoped-application-263".as_ptr()) }, 0);
            }
            let own = client.create_read_scope().unwrap();
            let scope = if case == 4 { foreign } else { own };
            if case == 3 {
                assert_eq!(
                    unsafe { chdir(c"/tmp/scoped-application-263/new".as_ptr()) },
                    0
                );
            }
            let path = match case {
                5 => "/system/applications/ScopeNoExec.app/entry.elf",
                7 => "/system/applications/ScopeStatic.app/entry.elf",
                _ => APP,
            };
            let (status, child) = launch(service, posix, scope, path, case);
            p::handle::close(own.handle).unwrap();
            if [0, 1, 7].contains(&case) {
                assert_eq!(status, 0, "case {case}");
                assert_ne!(child, 0);
                let mut result = -1;
                assert_eq!(
                    unsafe { waitpid(child as i32, &mut result, 0) },
                    child as i32
                );
                assert_eq!(result, 42 << 8, "case {case}");
            } else {
                let expected = match case {
                    3 => 11,
                    4 => 1,
                    _ => 13,
                };
                assert_eq!(status, expected, "case {case}");
                assert_eq!(child, 0);
                let mut result = -1;
                assert_eq!(
                    unsafe { waitpid(-1, &mut result, 1) },
                    -1,
                    "failed launch must not leave a POSIX child"
                );
            }
            unsafe {
                _exit(0);
            }
        }
        let mut status = -1;
        assert_eq!(unsafe { waitpid(source, &mut status, 0) }, source);
        assert_eq!(status, 0, "launch source case {case}");
        p::io::stdout(format!("scoped-application: case {case} PASS\n").as_bytes()).unwrap();
    }
    p::handle::close(foreign.handle).unwrap();
    p::io::stdout(b"scoped-application: PASS real launch protocol, UID0/501 DSO TLS/thread/fork, static package, tampered library/root, executable permission, stale and foreign scopes\n").unwrap();
}
