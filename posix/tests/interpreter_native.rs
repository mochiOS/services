//! Real scoped capability ProcessCreate handoff to the selected PT_INTERP.
#![cfg(target_os = "mochios")]
use mochi_user_platform as p;
use mochios_posix_client::{Client, SyscallEndpointTransport};
#[path = "native_scoped_application.rs"]
mod application;
unsafe extern "C" {
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn seteuid(uid: u32) -> i32;
    fn _exit(status: i32) -> !;
}
pub fn run(posix: u32) {
    let service = u32::try_from(p::process::find_by_name("capability.service").unwrap()).unwrap();
    for case in [0u8, 1] {
        let child = unsafe { fork() };
        assert!(child >= 0);
        if child == 0 {
            if case == 1 {
                assert_eq!(unsafe { seteuid(501) }, 0);
            }
            let client = Client::new(SyscallEndpointTransport::new(posix));
            let scope = client.create_read_scope().unwrap();
            let (status, application) = application::launch(
                service,
                posix,
                scope,
                "/system/applications/InterpreterProbe.app/entry.elf",
                case,
            );
            p::handle::close(scope.handle).unwrap();
            assert_eq!(status, 0, "interpreter application launch case={case}");
            assert_ne!(application, 0);
            let mut status = -1;
            assert_eq!(
                unsafe { waitpid(application as i32, &mut status, 0) },
                application as i32
            );
            assert_eq!(status, 0);
            unsafe { _exit(0) };
        }
        let mut status = -1;
        assert_eq!(unsafe { waitpid(child, &mut status, 0) }, child);
        assert_eq!(status, 0, "interpreter requester case={case}");
    }
    p::io::stdout(b"interpreter-native: PASS capability ProcessCreate UID0/501\n").unwrap();
}
