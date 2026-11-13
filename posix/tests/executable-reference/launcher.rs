mod launcher_config;
use launcher_config::Configuration;
use mochi_user_platform as p;
use mochios_posix_client::{Client, SyscallEndpointTransport};
use std::{
    io::{Read, Seek, SeekFrom},
    time::{Duration, Instant},
};
fn note(text: &[u8]) {
    let _ = p::logger::write_status_fmt(format_args!("{}", String::from_utf8_lossy(text)));
}
fn main() {
    let _ = p::logger::init_from_env();
    std::panic::set_hook(Box::new(|info| {
        note(format!("EXE-LAUNCH PANIC {info}\n").as_bytes())
    }));
    note(b"EXE-LAUNCH BEGIN\n");
    let configuration = match std::fs::read_to_string("/system/resources/native-test.conf") {
        Ok(text) => Configuration::parse(&text).expect("invalid native fixture settings"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Configuration::default(),
        Err(error) => panic!("cannot read native fixture settings: {error}"),
    };
    let posix = p::handle::inherited(mochios_posix_protocol::CONTROL_HANDLE_KEY).unwrap();
    let client = Client::new(SyscallEndpointTransport::new(posix));
    let scope = client.create_read_scope().unwrap();
    let service = u32::try_from(p::process::find_by_name("capability.service").unwrap()).unwrap();
    let mut request = vec![0; 24];
    request[..4].copy_from_slice(&0x41505053u32.to_le_bytes());
    request.extend_from_slice(configuration.application.as_bytes());
    request.push(0);
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
    let deadline = Instant::now() + Duration::from_secs(configuration.timeout_seconds);
    let mut reader = None;
    let mut result = String::new();
    while Instant::now() < deadline {
        if reader.is_none() {
            match std::fs::File::open(&configuration.result) {
                Ok(file) => reader = Some(file),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("cannot read native fixture result: {error}"),
            }
        }
        if let Some(file) = &mut reader {
            file.seek(SeekFrom::Start(0)).expect("seek native result");
            result.clear();
            (&mut *file)
                .take(1024 * 1024 + 1)
                .read_to_string(&mut result)
                .expect("read native result");
            assert!(result.len() <= 1024 * 1024, "oversized native result");
            if let Some(passed) = configuration.completed(&result) {
                note(result.as_bytes());
                if !passed {
                    std::process::exit(1);
                }
                return;
            }
        }
        // Reopening a file every 20ms competes with the work under test.
        // Retain one reader and keep observer traffic bounded to two polls/s.
        let _ = p::thread::sleep_milliseconds(500);
    }
    note(b"EXE-LAUNCH timeout\n");
    std::process::exit(1);
}
