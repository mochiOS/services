use mochi_user_platform as p;
use mochios_posix_client::{Client, SyscallEndpointTransport};
fn note(text: &[u8]) {
    let _ = p::logger::write_status_fmt(format_args!("{}", String::from_utf8_lossy(text)));
}
fn main() {
    let _ = p::logger::init_from_env();
    std::panic::set_hook(Box::new(|info| {
        note(format!("EXE-LAUNCH PANIC {info}\n").as_bytes())
    }));
    note(b"EXE-LAUNCH BEGIN\n");
    let posix = p::handle::inherited(mochios_posix_protocol::CONTROL_HANDLE_KEY).unwrap();
    let client = Client::new(SyscallEndpointTransport::new(posix));
    let scope = client.create_read_scope().unwrap();
    let service = u32::try_from(p::process::find_by_name("capability.service").unwrap()).unwrap();
    let mut request = vec![0; 24];
    request[..4].copy_from_slice(&0x41505053u32.to_le_bytes());
    request.extend_from_slice(b"/system/applications/ExecRefTest.app/entry.elf\0");
    let mut handles = p::ipc::IpcObjectHandles::default();
    handles.count = 2;
    handles.handles[0].handle = posix;
    handles.handles[0].rights = p::handle::HANDLE_RIGHT_SEND
        | p::handle::HANDLE_RIGHT_DUPLICATE
        | p::handle::HANDLE_RIGHT_TRANSFER;
    handles.handles[1].handle = scope.handle;
    handles.handles[1].rights = mochios_posix_protocol::read_scope::ATTACH_RIGHTS;
    let mut reply = [0; 16];
    let response = p::ipc::call_object_handles(service, &request, &mut reply, &mut handles);
    p::handle::close(scope.handle).unwrap();
    let status = i64::from_le_bytes(reply[..8].try_into().unwrap());
    note(format!("EXE-LAUNCH response={response:?} status={status}\n").as_bytes());
    assert_eq!(status, 0);
    for _ in 0..2000 {
        if let Ok(result) = std::fs::read_to_string("/tmp/executable-api-results.log") {
            if result.contains("EXE-API PASS") || result.contains("EXE-API FAIL") {
                note(result.as_bytes());
                return;
            }
        }
        let _ = p::thread::sleep_milliseconds(20);
    }
    note(b"EXE-LAUNCH timeout\n");
}
