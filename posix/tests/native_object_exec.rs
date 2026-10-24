//! Real object-backed image authorization, inheritance and digest enforcement.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("object-exec: SKIP (requires mochiOS)");
}

#[cfg(target_os = "mochios")]
mod native {
    use mochi_user_platform as p;
    use mochi_user_syscall as syscall;
    use mochios_posix_client::{Client, OpenAtBase, StatAtBase};
    use mochios_posix_protocol as wire;
    use sha2::{Digest, Sha256};
    const KEY: &str = "opaque-object-exec-200";
    const MARKER: u64 = 0x4f424a4558454300;
    const CONTEXT: u64 = MARKER + 1;
    unsafe extern "C" {
        fn fork() -> i32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn _exit(code: i32) -> !;
        fn alarm(seconds: u32) -> u32;
    }
    fn cap(name: &str) -> u64 {
        p::capability::query(name.as_ptr() as u64, name.len() as u64).unwrap()
    }
    fn revoke() {
        let name = b"fs.read.all";
        syscall::call2(
            mnu_abi::SyscallNumber::CapDrop,
            name.as_ptr() as u64,
            name.len() as u64,
        )
        .unwrap();
        assert_eq!(cap("fs.read.all"), 0);
    }
    fn context_digest() -> u64 {
        let c = p::process::thread_security_context(0).unwrap();
        let mut h = Sha256::new();
        h.update(c.process_id.to_le_bytes());
        h.update(c.thread_id.to_le_bytes());
        h.update([c.provenance]);
        h.update(c.subject_key_id);
        h.update(c.package_id_len.to_le_bytes());
        h.update(c.package_id);
        h.update(c.developer_id_len.to_le_bytes());
        h.update(c.developer_id);
        u64::from_le_bytes(h.finalize()[..8].try_into().unwrap())
    }
    fn authorize(handle: u32) {
        let mut hash = Sha256::new();
        let mut offset = 0u64;
        let mut bytes = [0; mnu_abi::provider::MAX_DATA_LEN];
        loop {
            let count = p::handle::read_at(handle, &mut bytes, offset).unwrap();
            if count == 0 {
                break;
            }
            offset += count as u64;
            assert!(offset <= 64 * 1024 * 1024);
            hash.update(&bytes[..count]);
        }
        let digest: [u8; 32] = hash.finalize().into();
        authorize_digest(handle, &digest);
    }
    fn authorize_digest(handle: u32, digest: &[u8; 32]) {
        let endpoint =
            u32::try_from(p::process::find_by_name("capability.service").unwrap()).unwrap();
        let mut request = [0; 300];
        let length =
            p::capability::encode_authorize_exec_object_request(KEY, digest, &mut request).unwrap();
        let mut objects = p::ipc::IpcObjectHandles::default();
        objects.count = 1;
        objects.handles[0] = p::ipc::IpcObjectHandle {
            handle,
            reserved: 0,
            rights: mnu_abi::HANDLE_RIGHT_READ,
        };
        let mut reply = [0; 8];
        let message =
            p::ipc::call_object_handles(endpoint, &request[..length], &mut reply, &mut objects)
                .unwrap();
        assert_eq!(message as u32, 8);
        assert_eq!(objects.count, 0);
        assert_eq!(u64::from_le_bytes(reply), 0);
    }
    fn child(case: usize) {
        unsafe {
            alarm(60);
        }
        if case == 4 {
            // The calling thread owns this Provider and never serves it. Any
            // broker-side I/O would deadlock the global authorization loop.
            let endpoint = p::ipc::create_handle().unwrap();
            let object = p::handle::create_provider_object(
                endpoint,
                200,
                mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
            )
            .unwrap();
            authorize_digest(object, &[0; 32]);
            p::handle::close(object).unwrap();
            p::handle::close(endpoint).unwrap();
            unsafe {
                _exit(0);
            }
        }
        let client = Client::from_launch_context().unwrap();
        let path = "/tmp/object-exec-200";
        let _ = client.unlink_at(StatAtBase::ProcessRoot, 0, path);
        let original = client
            .open_at(
                OpenAtBase::ProcessRoot,
                wire::OPEN_READ,
                0,
                "/system/services/compositor.service",
            )
            .unwrap();
        let image = client
            .open_at(
                OpenAtBase::ProcessRoot,
                wire::OPEN_READ | wire::OPEN_WRITE | wire::OPEN_CREATE | wire::OPEN_EXCLUSIVE,
                0o700,
                path,
            )
            .unwrap();
        let mut offset = 0;
        let mut bytes = [0; mnu_abi::provider::MAX_DATA_LEN];
        loop {
            let count = p::handle::read_at(original.handle, &mut bytes, offset).unwrap();
            if count == 0 {
                break;
            }
            let mut done = 0;
            while done < count {
                let n =
                    p::handle::write_at(image.handle, &bytes[done..count], offset + done as u64)
                        .unwrap();
                assert!(n > 0);
                done += n;
            }
            offset += count as u64;
        }
        p::handle::close(original.handle).unwrap();
        client.fchmod(image, 0o700).unwrap();
        client.check_executable(image).unwrap();
        client.unlink_at(StatAtBase::ProcessRoot, 0, path).unwrap();
        assert_eq!(client.fstat(image).unwrap().link_count, 0);
        p::handle::set_context_value(MARKER, case as u64).unwrap();
        p::handle::set_context_value(CONTEXT, context_digest()).unwrap();
        if case == 3 {
            revoke();
        }
        authorize(image.handle);
        if case == 1 {
            assert_eq!(p::handle::write_at(image.handle, &[0], 0).unwrap(), 1);
        }
        if case == 2 {
            revoke();
        }
        let mut startup = vec![0; mnu_abi::process_image::MAX_IMAGE_BYTES];
        let length = mochios_posix_client::process_image::encode_initial_stack(
            &[b"object-exec"],
            &[],
            KEY.as_bytes(),
            [0; 16],
            &mut startup,
        )
        .unwrap();
        let error =
            syscall::image::replace_bounded(image.handle, KEY, &startup[..length], u64::MAX)
                .unwrap_err();
        assert!(
            case == 1 || case == 2,
            "replacement unexpectedly returned: {error:?}"
        );
        assert_eq!(
            error.raw(),
            mnu_abi::status::Error::AccessDenied.into_raw() as i64
        );
        // A failed digest or revoked permit is not reusable after fixing input.
        let error =
            syscall::image::replace_bounded(image.handle, KEY, &startup[..length], u64::MAX)
                .unwrap_err();
        assert_eq!(
            error.raw(),
            mnu_abi::status::Error::AccessDenied.into_raw() as i64
        );
        if case == 2 {
            assert_eq!(cap("fs.read.all"), 0);
        }
        p::handle::close(image.handle).unwrap();
        unsafe {
            _exit(0);
        }
    }
    pub fn run() {
        if let Ok(case) = p::handle::inherited_value(MARKER) {
            assert!(case == 0 || case == 3);
            assert_eq!(
                context_digest(),
                p::handle::inherited_value(CONTEXT).unwrap()
            );
            assert_eq!(cap("fs.read.all"), u64::from(case == 0));
            assert_eq!(cap("fs.write.all"), 1);
            assert_eq!(cap("process.spawn"), 1);
            p::io::stdout(b"object-exec: new image retained caller identity and current grants\n")
                .unwrap();
            unsafe {
                _exit(0);
            }
        }
        p::io::stdout(b"object-exec: starting native object image checks\n").unwrap();
        for (case, name) in [
            "unregistered unlinked ELF replaces image in the same security domain",
            "changed image bytes cannot use the digest-bound permit",
            "authority revoked after authorization cannot be restored",
            "retained FileHandle works after ambient read authority is dropped",
            "unresponsive caller-owned Provider cannot block the broker",
        ]
        .iter()
        .enumerate()
        {
            let pid = unsafe { fork() };
            assert!(pid >= 0);
            if pid == 0 {
                child(case);
            }
            let mut status = 0;
            assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid);
            assert_eq!(status, 0, "native object case {case}");
            p::io::stdout(format!("object-exec: PASS {name}\n").as_bytes()).unwrap();
        }
    }
}
#[cfg(target_os = "mochios")]
fn main() {
    native::run();
}
