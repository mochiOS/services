//! Diagnostic manager entry uses real authorization and POSIX child registration.
#![cfg(target_os = "mochios")]
use mochi_user_platform as p;
use mochios_posix_client::{Client, ObjectHandleAttachment as Object, SyscallEndpointTransport};
use mochios_posix_protocol as w;
#[cfg(mochios_broker_dynamic_probe_301)]
#[path = "native_scoped_application.rs"]
mod scoped;
const PATH: &str = "/system/bin/msh";
pub fn run(posix: u32) {
    let client = Client::new(SyscallEndpointTransport::new(posix));
    let service = p::process::find_by_name("capability.service").unwrap() as u32;
    #[cfg(mochios_broker_dynamic_probe_301)]
    {
        let scope = client.create_read_scope().unwrap();
        let (status, pid) = scoped::launch(service, posix, scope, PATH, 0);
        assert_eq!(status, 0);
        assert!(pid > 0);
        unsafe extern "C" {
            fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        }
        let mut status = -1;
        assert_eq!(unsafe { waitpid(pid as i32, &mut status, 0) }, pid as i32);
        assert_eq!(status, 0);
        p::handle::close(scope.handle).unwrap();
        println!(
            "broker-image-native: PASS transformed trusted root is admitted to its created native process"
        );
        return;
    }
    #[cfg(not(mochios_broker_dynamic_probe_301))]
    for uid in [0, 501] {
        let image = p::capability::prepare_execution_image(
            service,
            PATH,
            p::service::ExecutionClass::Unprivileged,
        )
        .unwrap();
        let args = [format!(
            "{}{}:{posix}:{}",
            mochios_posix_client::launch_arguments::INHERITED_HANDLE_PREFIX,
            w::CONTROL_HANDLE_KEY,
            mnu_abi::HANDLE_RIGHT_SEND
                | mnu_abi::HANDLE_RIGHT_DUPLICATE
                | mnu_abi::HANDLE_RIGHT_TRANSFER
        )];
        let metadata = mochios_posix_client::launch_arguments::encode_native_launch(
            PATH, "msh", &args, [0; 16],
        )
        .unwrap();
        let (handle, pid) = mochios_posix_client::process_creation::create_with_rollback(
            || p::process::create_stopped(image.handle(), &metadata),
            |handle| {
                client
                    .register_spawned_child(
                        Object {
                            handle,
                            rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
                        },
                        uid,
                        uid,
                        &[],
                    )
                    .map_err(|_| p::syscall::SysError::from_raw(p::syscall::EIO as i64))
            },
            |handle| p::process::handle_status(handle).map(|s| s.process_id),
            p::process::resume_handle,
            |handle| {
                let _ = p::process::terminate_handle(handle, 127);
            },
            |handle| {
                let _ = p::process::wait_handle(handle, mnu_abi::PROCESS_WAIT_INFINITE);
                let _ = p::handle::close(handle);
            },
        )
        .unwrap();
        let status = p::process::wait_handle(handle, mnu_abi::PROCESS_WAIT_INFINITE).unwrap();
        assert_eq!(status.process_id, pid);
        assert_eq!(status.exit_code, 0);
        p::handle::close(handle).unwrap();
        println!(
            "broker-image-native: PASS trusted code gate and same-domain replacement rejection euid={uid}"
        );
    }
}
