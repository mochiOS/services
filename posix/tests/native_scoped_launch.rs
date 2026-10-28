//! Authenticated scope/process attachments at the actual stopped-child boundary.
use mochi_user_platform as p;
use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment as Object, SyscallEndpointTransport,
};
use mochios_posix_protocol::{self as wire, read_scope};
use std::ffi::c_char;

unsafe extern "C" {
    fn fork() -> i32;
    fn waitpid(child: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(code: i32) -> !;
    fn seteuid(uid: u16) -> i32;
    fn setegid(gid: u16) -> i32;
    fn setgroups(count: i32, groups: *const u16) -> i32;
    fn chdir(path: *const c_char) -> i32;
    fn chmod(path: *const c_char, mode: u32) -> i32;
    fn umask(mask: u32) -> u32;
}
struct Reference(u32);
impl Drop for Reference {
    fn drop(&mut self) {
        p::handle::close(self.0).unwrap();
    }
}
fn process(handle: u32) -> Object<u32> {
    Object {
        handle,
        rights: p::handle::HANDLE_RIGHT_WAIT | p::handle::HANDLE_RIGHT_SIGNAL,
    }
}
fn observation(handle: u32) -> Object<u32> {
    Object {
        handle,
        rights: p::handle::HANDLE_RIGHT_WAIT,
    }
}
const PATH: &str = "/system/bin/scoped-launch-probe";

pub fn run(posix: u32) {
    let client = Client::new(SyscallEndpointTransport::new(posix));
    let endpoint = Reference(p::ipc::create_handle().unwrap());
    let identity = p::process::current_execution_identity().unwrap();
    let own_process = Reference(
        p::process::open_handle_for_process_id(
            identity.process_id,
            p::handle::HANDLE_RIGHT_WAIT | p::handle::HANDLE_RIGHT_TRANSFER,
        )
        .unwrap(),
    );
    let capability =
        u32::try_from(p::process::find_by_name("capability.service").unwrap()).unwrap();
    std::fs::create_dir_all("/tmp/scoped-launch-261/old").unwrap();
    std::fs::create_dir_all("/tmp/scoped-launch-261/new").unwrap();
    for path in [
        c"/tmp/scoped-launch-261",
        c"/tmp/scoped-launch-261/old",
        c"/tmp/scoped-launch-261/new",
    ] {
        assert_eq!(unsafe { chmod(path.as_ptr(), 0o755) }, 0);
    }
    for case in 0u8..3 {
        let source = unsafe { fork() };
        assert!(source >= 0);
        if source == 0 {
            assert_eq!(unsafe { setgroups(2, [20u16, 42].as_ptr()) }, 0);
            assert_eq!(unsafe { setegid(20) }, 0);
            unsafe {
                umask(0o027);
            }
            client
                .resource_limit(
                    0,
                    wire::RLIMIT_NOFILE,
                    Some(wire::ResourceLimit { soft: 64, hard: 64 }),
                )
                .unwrap();
            assert_eq!(unsafe { seteuid(501) }, 0);
            assert_eq!(unsafe { chdir(c"/tmp/scoped-launch-261/old".as_ptr()) }, 0);
            let scope = client.create_read_scope().unwrap();
            if case == 1 {
                assert_eq!(unsafe { chdir(c"/tmp/scoped-launch-261/new".as_ptr()) }, 0);
            }
            if case == 2 {
                assert_eq!(unsafe { seteuid(0) }, 0);
            }
            let mut handles = p::ipc::IpcObjectHandles::default();
            handles.count = 1;
            handles.handles[0] = p::ipc::IpcObjectHandle {
                handle: scope.handle,
                rights: read_scope::TOKEN_RIGHTS,
                reserved: 0,
            };
            let mut reply = [0; 8];
            let n = p::ipc::call_object_handles(endpoint.0, &[case], &mut reply, &mut handles)
                .unwrap() as u32 as usize;
            assert_eq!(n, reply.len());
            assert_eq!(handles.count, 0);
            let child = u64::from_le_bytes(reply);
            p::handle::close(scope.handle).unwrap();
            if case == 0 {
                assert!(child != 0);
                let mut status = -1;
                assert_eq!(
                    unsafe { waitpid(child as i32, &mut status, 0) },
                    child as i32
                );
                assert_eq!(status, 0);
            } else {
                assert_eq!(child, 0);
            }
            unsafe {
                _exit(0);
            }
        }
        let mut bytes = [0; 32];
        let mut received = p::ipc::IpcObjectHandles::default();
        let message =
            p::ipc::wait_object_handles(endpoint.0 as u64, &mut bytes, &mut received).unwrap();
        assert_eq!(message as u32, 1);
        assert_eq!(bytes[0], case);
        assert_eq!(received.count, 1);
        assert!(received.is_user_delivery());
        let object = received.handles[0];
        assert_eq!(object.rights, read_scope::TOKEN_RIGHTS);
        let token_owner = Reference(object.handle);
        let token = Object {
            handle: object.handle,
            rights: object.rights,
        };
        let requester = Reference(
            p::process::open_handle_for_endpoint(
                message >> 32,
                p::handle::HANDLE_RIGHT_WAIT | p::handle::HANDLE_RIGHT_TRANSFER,
            )
            .unwrap(),
        );
        assert_eq!(
            p::process::handle_status(requester.0).unwrap().process_id,
            source as u64
        );
        let info = client.read_scope_info(token).unwrap();
        assert_eq!(info.effective_uid, 501);
        let image = p::capability::prepare_execution_image(
            capability,
            PATH,
            p::service::ExecutionClass::Unprivileged,
        )
        .unwrap();
        let startup = mochios_posix_client::process_image::Process {
            identity: info.into(),
            ..Default::default()
        };
        let metadata = mochios_posix_client::launch_arguments::encode_native_launch_for_process(
            PATH,
            PATH,
            &[
                source.to_string(),
                format!(
                    "__MNU_EXEC_INHERIT_HANDLE={}:{}:{}",
                    wire::CONTROL_HANDLE_KEY,
                    posix,
                    p::handle::HANDLE_RIGHT_SEND
                        | p::handle::HANDLE_RIGHT_DUPLICATE
                        | p::handle::HANDLE_RIGHT_TRANSFER
                ),
            ],
            [0; 16],
            startup,
        )
        .unwrap();
        let child = Reference(p::process::create_stopped(image.handle(), &metadata).unwrap());
        let child_id = p::process::handle_status(child.0).unwrap().process_id;
        assert!(matches!(
            client.process_session_info(observation(child.0)),
            Err(ClientError::Remote(wire::STATUS_ESRCH))
        ));
        if case == 0 {
            assert_eq!(
                client.register_launched_child_in_scope(
                    token,
                    process(own_process.0),
                    process(child.0)
                ),
                Err(ClientError::Remote(wire::STATUS_EPERM))
            );
            assert!(matches!(
                client.process_session_info(observation(child.0)),
                Err(ClientError::Remote(wire::STATUS_ESRCH))
            ));
            client
                .register_launched_child_in_scope(token, process(requester.0), process(child.0))
                .unwrap();
            assert_eq!(
                client.process_session_info(observation(child.0)).unwrap(),
                info
            );
            p::process::resume_handle(child.0).unwrap();
            let status =
                p::process::wait_handle(child.0, p::syscall::HANDLE_WAIT_INFINITE).unwrap();
            assert_eq!(status.exit_code, 0, "child POSIX environment mismatch");
        } else {
            assert_eq!(
                client.register_launched_child_in_scope(
                    token,
                    process(requester.0),
                    process(child.0)
                ),
                Err(ClientError::Remote(wire::STATUS_EAGAIN))
            );
            assert!(matches!(
                client.process_session_info(observation(child.0)),
                Err(ClientError::Remote(wire::STATUS_ESRCH))
            ));
            p::process::terminate_handle(child.0, 127).unwrap();
            p::process::wait_handle(child.0, p::syscall::HANDLE_WAIT_INFINITE).unwrap();
        }
        p::ipc::reply(
            message >> 32,
            &if case == 0 { child_id } else { 0 }.to_le_bytes(),
        )
        .unwrap();
        let mut status = -1;
        assert_eq!(unsafe { waitpid(source, &mut status, 0) }, source);
        assert_eq!(status, 0);
        drop(token_owner);
    }
    std::fs::remove_dir("/tmp/scoped-launch-261/old").unwrap();
    std::fs::remove_dir("/tmp/scoped-launch-261/new").unwrap();
    std::fs::remove_dir("/tmp/scoped-launch-261").unwrap();
    p::io::stdout(b"scoped-launch: PASS fresh stopped child, requester parent/credentials/cwd/groups/umask/limits, foreign owner rejection, stale cwd/credentials rollback\n").unwrap();
}
