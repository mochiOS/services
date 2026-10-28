//! Real App launch, package-authorized DSO inputs, and newlib fork/exec.
#[path = "native_scoped_application.rs"]
mod launch_protocol;
use mochi_user_platform as p;
use mochios_posix_client::{Client, SyscallEndpointTransport};

unsafe extern "C" {
    fn fork() -> i32;
    fn waitpid(child: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(code: i32) -> !;
    fn seteuid(uid: u16) -> i32;
    fn chmod(path: *const core::ffi::c_char, mode: u32) -> i32;
}

pub fn run(posix: u32) {
    let client = Client::new(SyscallEndpointTransport::new(posix));
    let service = u32::try_from(p::process::find_by_name("capability.service").unwrap()).unwrap();
    for kind in ["good", "bad"] {
        let directory = format!("/tmp/symbol-versions-265/{kind}");
        std::fs::create_dir_all(&directory).unwrap();
        for path in ["/tmp/symbol-versions-265", &directory] {
            let path = std::ffi::CString::new(path).unwrap();
            assert_eq!(unsafe { chmod(path.as_ptr(), 0o755) }, 0);
        }
        let bytes = std::fs::read(format!("/system/tests/symbol-versions-265/{kind}.so")).unwrap();
        let target = format!("{directory}/libversions.so");
        std::fs::write(&target, bytes).unwrap();
        let path = std::ffi::CString::new(target).unwrap();
        assert_eq!(unsafe { chmod(path.as_ptr(), 0o644) }, 0);
    }
    for (case, name, user, expected) in [
        (0, "Versioned", false, 0),
        (1, "Versioned", true, 0),
        (2, "VersionPreempt", false, 0),
        (3, "VersionMissing", false, 8),
        (4, "VersionLegacy", false, 0),
        (5, "Versioned", true, 0),
    ] {
        let source = unsafe { fork() };
        assert!(source >= 0);
        if source == 0 {
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
        p::io::stdout(format!("symbol-versions: case {case} PASS\n").as_bytes()).unwrap();
    }
    p::io::stdout(b"symbol-versions: PASS versioned code/data/TLS, native app and newlib fork/exec, euid0/501, root interposition, legacy lookup, missing ABI rejection and recovery\n").unwrap();
}
