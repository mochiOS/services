//! Real cross-process attachment, credential and final-reference boundaries.
use mochi_user_platform as p;
use mochios_posix_client::{
    Client, ObjectHandleAttachment as Object, OpenAtBase, SyscallEndpointTransport,
};
use mochios_posix_protocol::{self as protocol, read_scope as wire};
#[cfg(mochios_shared_loader_260)]
#[path = "support/native_scoped_preparation.rs"]
mod scoped_preparation;

unsafe extern "C" {
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(status: i32) -> !;
    fn seteuid(uid: u32) -> i32;
    fn chdir(path: *const core::ffi::c_char) -> i32;
    fn chmod(path: *const core::ffi::c_char, mode: u32) -> i32;
}

pub fn run(posix: u32) {
    let client = Client::new(SyscallEndpointTransport::new(posix));
    std::fs::create_dir_all("/tmp/posix-read-scope-259/old").unwrap();
    std::fs::create_dir_all("/tmp/posix-read-scope-259/new").unwrap();
    std::fs::write("/tmp/posix-read-scope-259/old/public", b"old scope\n").unwrap();
    std::fs::write("/tmp/posix-read-scope-259/new/public", b"wrong cwd\n").unwrap();
    std::fs::write("/tmp/posix-read-scope-259/private", b"root secret\n").unwrap();
    for path in [
        c"/tmp/posix-read-scope-259",
        c"/tmp/posix-read-scope-259/old",
        c"/tmp/posix-read-scope-259/new",
    ] {
        assert_eq!(unsafe { chmod(path.as_ptr(), 0o755) }, 0);
    }
    assert_eq!(
        unsafe { chmod(c"/tmp/posix-read-scope-259/old/public".as_ptr(), 0o444) },
        0
    );
    assert_eq!(
        unsafe { chmod(c"/tmp/posix-read-scope-259/private".as_ptr(), 0o600) },
        0
    );
    let endpoint = p::ipc::create_handle().unwrap();
    let child = unsafe { fork() };
    assert!(child >= 0);
    if child == 0 {
        assert_eq!(unsafe { seteuid(501) }, 0);
        assert_eq!(
            unsafe { chdir(c"/tmp/posix-read-scope-259/old".as_ptr()) },
            0
        );
        let scope = client.create_read_scope().unwrap();
        assert_eq!(p::handle::rights(scope.handle).unwrap(), wire::TOKEN_RIGHTS);
        assert_eq!(
            unsafe { chdir(c"/tmp/posix-read-scope-259/new".as_ptr()) },
            0
        );
        let mut handles = p::ipc::IpcObjectHandles::default();
        handles.count = 1;
        handles.handles[0] = p::ipc::IpcObjectHandle {
            handle: scope.handle,
            rights: wire::TOKEN_RIGHTS,
            reserved: 0,
        };
        let mut reply = [0; 8];
        let n = p::ipc::call_object_handles(endpoint, b"scope", &mut reply, &mut handles).unwrap()
            as u32 as usize;
        assert_eq!(&reply[..n], b"accepted");
        assert_eq!(handles.count, 0);
        p::handle::close(scope.handle).unwrap();
        unsafe {
            _exit(0);
        }
    }
    let mut bytes = [0; 128];
    let mut handles = p::ipc::IpcObjectHandles::default();
    let incoming = p::ipc::wait_object_handles(endpoint as u64, &mut bytes, &mut handles).unwrap();
    assert_eq!(&bytes[..incoming as u32 as usize], b"scope");
    assert!(handles.is_user_delivery());
    assert_eq!(handles.count, 1);
    assert_eq!(
        p::ipc::endpoint_owner_process(incoming >> 32).unwrap(),
        child as u64
    );
    let attached = handles.handles[0];
    assert_eq!(attached.reserved, 0);
    assert_eq!(attached.rights, wire::TOKEN_RIGHTS);
    let scope = Object {
        handle: attached.handle,
        rights: attached.rights,
    };
    p::ipc::reply(incoming >> 32, b"accepted").unwrap();
    let mut status = -1;
    assert_eq!(unsafe { waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0);

    // The source is gone. Possession of the explicitly transferred native
    // object, rather than a live PID or receiver's UID, authorizes this read.
    let info = client.read_scope_info(scope).unwrap();
    assert_eq!((info.real_uid, info.effective_uid), (0, 501));
    assert_eq!(client.session_info().unwrap().effective_uid, 0);
    let public = client.read_scope_open(scope, false, b"public").unwrap();
    assert_eq!(public.rights, wire::FILE_RIGHTS);
    assert_eq!(p::handle::rights(public.handle).unwrap(), wire::FILE_RIGHTS);
    let n = p::handle::read_at(public.handle, &mut bytes, 0).unwrap();
    assert_eq!(&bytes[..n], b"old scope\n");
    for right in [
        p::handle::HANDLE_RIGHT_WRITE,
        p::handle::HANDLE_RIGHT_CONTROL,
    ] {
        assert!(p::handle::duplicate(public.handle, wire::FILE_RIGHTS | right).is_err());
        assert!(p::handle::duplicate(scope.handle, wire::TOKEN_RIGHTS | right).is_err());
    }
    assert!(
        client.read_scope_info(public).is_err(),
        "another provider cannot impersonate a scope"
    );
    assert!(
        p::handle::identify_provider_object(scope.handle).is_err(),
        "only the owning endpoint can identify"
    );
    p::handle::close(public.handle).unwrap();
    assert!(matches!(
        client.read_scope_open(scope, true, b"/tmp/posix-read-scope-259/private"),
        Err(mochios_posix_client::ClientError::Remote(-13))
    ));
    let private = client
        .open_at(
            OpenAtBase::ProcessRoot,
            protocol::OPEN_READ,
            0,
            b"/tmp/posix-read-scope-259/private",
        )
        .unwrap();
    let n = p::handle::read_at(private.handle, &mut bytes, 0).unwrap();
    assert_eq!(&bytes[..n], b"root secret\n");
    p::handle::close(private.handle).unwrap();

    #[cfg(mochios_shared_loader_260)]
    scoped_preparation::run(posix, scope);

    // A byte-identical final-release request from ordinary IPC has no native
    // delivery provenance and cannot retire even the first provider object.
    let mut request = [0; mnu_abi::provider::REQUEST_HEADER_LEN];
    let n = mnu_abi::provider::RequestHeader {
        opcode: mnu_abi::provider::OP_RELEASE,
        object_id: 1,
        argument: 0,
        basis: 0,
        length: 0,
        data_length: 0,
    }
    .encode(&[], &mut request)
    .unwrap();
    let mut no_handles = p::ipc::IpcObjectHandles::default();
    let n = p::ipc::call_object_handles(posix, &request[..n], &mut bytes, &mut no_handles).unwrap()
        as u32 as usize;
    assert_eq!(
        mnu_abi::provider::ResponseHeader::decode(&bytes[..n])
            .unwrap()
            .0
            .status,
        -1
    );
    assert_eq!(no_handles.count, 0);
    assert_eq!(client.read_scope_info(scope).unwrap(), info);
    p::handle::close(scope.handle).unwrap();

    // More than the per-source quota in succession proves the asynchronous
    // native final-reference messages release directory anchors and slots.
    for _ in 0..40 {
        let token = client.create_read_scope().unwrap();
        assert_eq!(client.read_scope_info(token).unwrap().effective_uid, 0);
        p::handle::close(token.handle).unwrap();
    }
    p::handle::close(endpoint).unwrap();
    for path in [
        "/tmp/posix-read-scope-259/old/public",
        "/tmp/posix-read-scope-259/new/public",
        "/tmp/posix-read-scope-259/private",
    ] {
        std::fs::remove_file(path).unwrap();
    }
    std::fs::remove_dir("/tmp/posix-read-scope-259/old").unwrap();
    std::fs::remove_dir("/tmp/posix-read-scope-259/new").unwrap();
    std::fs::remove_dir("/tmp/posix-read-scope-259").unwrap();
    p::io::stdout(b"read-scope: PASS delegated euid501, old cwd, source exit, attenuation, forged release, final-reference cleanup\n").unwrap();
}
