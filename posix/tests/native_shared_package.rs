//! Two applications share one authenticated library package graph. All file
//! access and process creation still use the normal scoped launch protocol.
#[path = "native_scoped_application.rs"]
mod launch_protocol;
use mochi_user_platform as p;
use mochios_posix_client::{Client, SyscallEndpointTransport};
use mochios_posix_protocol as w;

unsafe extern "C" {
    fn fork() -> i32;
    fn waitpid(child: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(code: i32) -> !;
    fn seteuid(uid: u16) -> i32;
    fn setegid(gid: u16) -> i32;
    fn setgroups(count: i32, groups: *const u16) -> i32;
    fn chdir(path: *const core::ffi::c_char) -> i32;
    fn chmod(path: *const core::ffi::c_char, mode: u32) -> i32;
    fn umask(mask: u32) -> u32;
}

const BASE: &str = "/tmp/scoped-application-263";

pub fn run(posix: u32) {
    let client = Client::new(SyscallEndpointTransport::new(posix));
    let service = u32::try_from(p::process::find_by_name("capability.service").unwrap()).unwrap();
    std::fs::create_dir_all(format!("{BASE}/lib")).unwrap();
    for path in [
        c"/tmp/scoped-application-263",
        c"/tmp/scoped-application-263/lib",
    ] {
        assert_eq!(unsafe { chmod(path.as_ptr(), 0o755) }, 0);
    }
    let mut images = Vec::new();
    for leaf in ["libtls-gd.so", "libtls-ie.so"] {
        let bytes = std::fs::read(format!("/system/tests/shared-package-264/{leaf}")).unwrap();
        let target = format!("{BASE}/lib/{leaf}");
        std::fs::write(&target, &bytes).unwrap();
        let path = std::ffi::CString::new(target).unwrap();
        assert_eq!(unsafe { chmod(path.as_ptr(), 0o644) }, 0);
        images.push(bytes);
    }
    for (case, name, expected) in [
        (0, "SharedOne", 0),
        (1, "SharedTwo", 0),
        (2, "SharedWrongKey", 13),
        (3, "SharedWrongAbi", 13),
        (4, "SharedMissing", 2),
        (5, "SharedUndeclared", 13),
        (6, "SharedOne", 13),
        (7, "SharedTwo", 0),
        (8, "SharedWrongProvenance", 13),
    ] {
        if case == 6 || case == 7 {
            let mut bytes = images[1].clone();
            if case == 6 {
                bytes[32] ^= 1;
            }
            std::fs::write(format!("{BASE}/lib/libtls-ie.so"), bytes).unwrap();
        }
        let source = unsafe { fork() };
        assert!(source >= 0);
        if source == 0 {
            assert_eq!(unsafe { setgroups(2, [20u16, 42].as_ptr()) }, 0);
            assert_eq!(unsafe { setegid(20) }, 0);
            unsafe {
                umask(0o027);
            }
            assert_eq!(unsafe { chdir(c"/tmp/scoped-application-263".as_ptr()) }, 0);
            client
                .resource_limit(
                    0,
                    w::RLIMIT_NOFILE,
                    Some(w::ResourceLimit { soft: 64, hard: 64 }),
                )
                .unwrap();
            let user = [1, 7].contains(&case);
            if user {
                assert_eq!(unsafe { seteuid(501) }, 0);
            }
            let scope = client.create_read_scope().unwrap();
            let (status, child) = launch_protocol::launch(
                service,
                posix,
                scope,
                &format!("/system/applications/{name}.app/entry.elf"),
                u8::from(user),
            );
            p::handle::close(scope.handle).unwrap();
            assert_eq!(status, expected, "case {case}");
            let mut result = -1;
            if expected == 0 {
                assert_ne!(child, 0);
                assert_eq!(
                    unsafe { waitpid(child as i32, &mut result, 0) },
                    child as i32
                );
                assert_eq!(result, 42 << 8, "case {case}");
            } else {
                assert_eq!(child, 0);
                assert_eq!(unsafe { waitpid(-1, &mut result, 1) }, -1);
            }
            unsafe {
                _exit(0);
            }
        }
        let mut status = -1;
        assert_eq!(unsafe { waitpid(source, &mut status, 0) }, source);
        assert_eq!(status, 0, "source case {case}");
        p::io::stdout(format!("shared-package: case {case} PASS\n").as_bytes()).unwrap();
    }
    p::io::stdout(b"shared-package: PASS two applications, shared and cyclic package dependencies, euid0/501 TLS/thread/fork, key/ABI/provenance/missing/undeclared/tampered rejection and recovery\n").unwrap();
}
