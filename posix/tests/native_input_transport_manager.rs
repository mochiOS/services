use mochi_user_platform as p;
use mochios_posix_client::{Client, ObjectHandleAttachment, SyscallEndpointTransport};
use mochios_posix_protocol as w;

pub fn run(raw_input: u32, posix: u32) {
    let address = p::process::find_by_name("input.service").unwrap();
    let mut reply = [0; 8];
    let mut handles = p::ipc::IpcObjectHandles::default();
    // The byte is not a mapped key: test authority without producing a UI event.
    let packet = [p::input::RAW_KIND_KEYBOARD, 0, 0, 0, 0, 0, 0, 0];
    let message =
        p::ipc::call_object_handles(raw_input, &packet, &mut reply, &mut handles).unwrap();
    assert_eq!(message as u32, 1);
    assert_eq!(reply[0], 0);
    assert_eq!(handles.count, 0);
    let mut invalid = p::input::RAW_ENDPOINT_REQUEST;
    invalid[4] += 1;
    let message = p::ipc::call_object_handles(
        address.try_into().unwrap(),
        &invalid,
        &mut reply,
        &mut handles,
    )
    .unwrap();
    assert_eq!(message as u32, 8);
    assert_eq!(u64::from_le_bytes(reply), 22);
    assert_eq!(handles.count, 0);
    println!("input-authority-native: PASS delegated SEND ingress and strict export version");

    let client = Client::new(SyscallEndpointTransport::new(posix));
    let capability = p::process::find_by_name("capability.service").unwrap() as u32;
    let path = "/system/bin/llvm-runtime-probe";
    for uid in [0, 501] {
        let image = p::capability::prepare_execution_image(
            capability,
            path,
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
            path,
            "input-authority-probe",
            &args,
            [0; 16],
        )
        .unwrap();
        let (handle, pid) = mochios_posix_client::process_creation::create_with_rollback(
            || p::process::create_stopped(image.handle(), &metadata),
            |handle| {
                client
                    .register_spawned_child(
                        ObjectHandleAttachment {
                            handle,
                            rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
                        },
                        uid,
                        uid,
                        &[],
                    )
                    .map_err(|_| p::syscall::SysError::from_raw(-5))
            },
            |handle| p::process::handle_status(handle).map(|s| s.process_id),
            p::process::resume_handle,
            |handle| {
                let _ = p::process::terminate_handle(handle, 127);
            },
            |handle| {
                let _ = p::process::wait_handle(handle, u64::MAX);
                let _ = p::handle::close(handle);
            },
        )
        .unwrap();
        let status = p::process::wait_handle(handle, u64::MAX).unwrap();
        assert_eq!(status.process_id, pid);
        assert_eq!(status.exit_code, 0);
        p::handle::close(handle).unwrap();
    }
}
