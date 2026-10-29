//! Real image measurement across captured-space creation and native exec commit.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("process-image-info: SKIP (requires mochiOS)");
}

#[cfg(target_os = "mochios")]
mod native {
    use mochi_user_platform as p;
    use mochi_user_syscall as s;
    use mochios_posix_client::{Client, OpenAtBase, StatAtBase};
    use mochios_posix_protocol as w;
    use sha2::{Digest, Sha256};
    const REPORT: u64 = 0x494d414745323939;
    const RELEASE: u64 = REPORT + 1;
    const OBSERVER: u64 = REPORT + 2;
    const KEY: &str = "native-image-info-299";
    unsafe extern "C" {
        fn fork() -> i32;
        fn __errno() -> *mut i32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn _exit(status: i32) -> !;
        fn geteuid() -> u32;
        fn alarm(seconds: u32) -> u32;
    }
    fn send(handle: u32, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let n = p::handle::write(handle, bytes).unwrap();
            assert!(n > 0);
            bytes = &bytes[n..];
        }
    }
    fn receive(handle: u32, mut bytes: &mut [u8]) {
        while !bytes.is_empty() {
            let n = p::handle::read(handle, bytes).unwrap();
            assert!(n > 0);
            bytes = &mut bytes[n..];
        }
    }
    fn send_info(handle: u32, info: s::ProcessImageInfo) {
        let mut bytes = [0; 56];
        bytes[..8].copy_from_slice(&info.process_id.to_le_bytes());
        bytes[8..16].copy_from_slice(&info.image_revision.to_le_bytes());
        bytes[16..20].copy_from_slice(&info.digest_kind.to_le_bytes());
        bytes[20..24].copy_from_slice(&info.reserved.to_le_bytes());
        bytes[24..].copy_from_slice(&info.digest);
        send(handle, &bytes);
    }
    fn receive_info(handle: u32) -> s::ProcessImageInfo {
        let mut bytes = [0; 56];
        receive(handle, &mut bytes);
        s::ProcessImageInfo {
            process_id: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            image_revision: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            digest_kind: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            reserved: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
            digest: bytes[24..].try_into().unwrap(),
        }
    }
    fn stream() -> s::StreamPair {
        let mut pair = s::StreamPair::default();
        s::call1(
            s::SyscallNumber::StreamPairCreate,
            (&mut pair as *mut s::StreamPair) as u64,
        )
        .unwrap();
        pair
    }
    fn authorize(handle: u32, digest: &[u8; 32]) {
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
        let result =
            p::ipc::call_object_handles(endpoint, &request[..length], &mut reply, &mut objects)
                .unwrap();
        assert_eq!(result as u32, 8);
        assert_eq!(objects.count, 0);
        assert_eq!(u64::from_le_bytes(reply), 0);
    }
    fn child(initial: s::ProcessImageInfo, report: s::StreamPair, release: s::StreamPair) -> ! {
        p::handle::close(report.read).unwrap();
        p::handle::close(release.write).unwrap();
        let current = p::process::image_info(None).unwrap();
        assert_ne!(current.process_id, initial.process_id);
        assert_eq!(current.image_revision, 0);
        assert_eq!(current.digest, initial.digest);
        assert_eq!(current.digest_kind, initial.digest_kind);
        send_info(report.write, current);
        let endpoint = p::ipc::create().unwrap();
        let observer =
            p::process::open_handle_for_endpoint(endpoint, mnu_abi::HANDLE_RIGHT_WAIT).unwrap();
        p::handle::set_context_handle(OBSERVER, observer).unwrap();
        p::handle::set_context_handle(REPORT, report.write).unwrap();
        p::handle::set_context_handle(RELEASE, release.read).unwrap();
        // Already owned WAIT authority remains enough after ambient inspection
        // is dropped; neither self observation nor exec needs process lookup.
        let cap = b"process.inspect";
        s::call2(
            s::SyscallNumber::CapDrop,
            cap.as_ptr() as u64,
            cap.len() as u64,
        )
        .unwrap();
        assert_eq!(p::process::image_info(Some(observer)).unwrap(), current);
        let client = Client::from_launch_context().unwrap();
        let path = format!("/tmp/image-info-299-{}", current.process_id);
        let mut bytes = std::fs::read("/system/bin/llvm-runtime-probe").unwrap();
        bytes.extend_from_slice(b"measurement-299-trailer");
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        assert_ne!(digest, initial.digest);
        let image = client
            .open_at(
                OpenAtBase::ProcessRoot,
                w::OPEN_READ | w::OPEN_WRITE | w::OPEN_CREATE | w::OPEN_EXCLUSIVE,
                0o700,
                path.as_bytes(),
            )
            .unwrap();
        let mut offset = 0;
        while offset < bytes.len() {
            let end = bytes.len().min(offset + mnu_abi::provider::MAX_DATA_LEN);
            let n = p::handle::write_at(image.handle, &bytes[offset..end], offset as u64).unwrap();
            assert!(n > 0);
            offset += n;
        }
        client
            .unlink_at(StatAtBase::ProcessRoot, 0, path.as_bytes())
            .unwrap();
        let expected = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let mut startup = vec![0; mnu_abi::process_image::MAX_IMAGE_BYTES];
        let length = mochios_posix_client::process_image::encode_initial_stack(
            &[b"image-info", b"--replaced", expected.as_bytes()],
            &[],
            KEY.as_bytes(),
            [0; 16],
            &mut startup,
        )
        .unwrap();
        authorize(image.handle, &[0x19; 32]);
        assert_eq!(
            s::image::replace_bounded(image.handle, KEY, &startup[..length], u64::MAX)
                .unwrap_err()
                .native_error(),
            Some(s::NativeError::AccessDenied)
        );
        assert_eq!(
            p::process::image_info(None).unwrap(),
            current,
            "failed replacement must preserve digest and revision"
        );
        authorize(image.handle, &digest);
        let error =
            s::image::replace_bounded(image.handle, KEY, &startup[..length], u64::MAX).unwrap_err();
        panic!("native replacement returned {error:?}");
    }
    pub fn run() {
        unsafe {
            alarm(90);
        }
        let args = std::env::args().collect::<Vec<_>>();
        if args.get(1).map(String::as_str) == Some("--replaced") {
            let info = p::process::image_info(None).unwrap();
            assert_eq!(info.image_revision, 1);
            assert_eq!(info.digest_kind, mnu_abi::PROCESS_IMAGE_DIGEST_SHA256);
            let expected = (0..32)
                .map(|i| u8::from_str_radix(&args[2][i * 2..i * 2 + 2], 16).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(info.digest.as_slice(), expected);
            assert_eq!(
                p::process::image_info(Some(p::handle::inherited(OBSERVER).unwrap())).unwrap(),
                info
            );
            send_info(p::handle::inherited(REPORT).unwrap(), info);
            let mut byte = [0];
            receive(p::handle::inherited(RELEASE).unwrap(), &mut byte);
            assert_eq!(byte, [0x37]);
            unsafe { _exit(0) }
        }
        let info = p::process::image_info(None).unwrap();
        assert_eq!(
            info.process_id,
            p::process::current_execution_identity().unwrap().process_id
        );
        assert_eq!(info.digest_kind, mnu_abi::PROCESS_IMAGE_DIGEST_SHA256);
        let endpoint = p::ipc::create().unwrap();
        let observer = p::process::open_handle_for_endpoint(
            endpoint,
            mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_DUPLICATE,
        )
        .unwrap();
        assert_eq!(p::process::image_info(Some(observer)).unwrap(), info);
        let wrong_kind = p::ipc::create_handle().unwrap();
        assert_eq!(
            p::process::image_info(Some(wrong_kind))
                .unwrap_err()
                .native_error(),
            Some(s::NativeError::InvalidArgument)
        );
        p::handle::close(wrong_kind).unwrap();
        let denied = p::handle::duplicate(observer, 0).unwrap();
        assert_eq!(
            p::process::image_info(Some(denied))
                .unwrap_err()
                .native_error(),
            Some(s::NativeError::AccessDenied)
        );
        let invalid = s::call3(s::SyscallNumber::ProcessImageRead, 0, 0, 56).unwrap_err();
        assert_eq!(invalid.native_error(), Some(s::NativeError::InvalidAddress));
        // Observation-only Handles deliberately cannot be delegated by fork.
        // Finish those checks before creating the captured address space.
        p::handle::close(observer).unwrap();
        p::handle::close(denied).unwrap();
        let report = stream();
        let release = stream();
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork errno={}", unsafe { *__errno() });
        if pid == 0 {
            child(info, report, release);
        }
        p::handle::close(report.write).unwrap();
        p::handle::close(release.read).unwrap();
        let child_info = receive_info(report.read);
        assert_eq!(child_info.process_id, pid as u64);
        assert_eq!(child_info.digest, info.digest);
        let child_observer =
            p::process::open_handle_for_process_id(pid as u64, mnu_abi::HANDLE_RIGHT_WAIT).unwrap();
        let replaced = receive_info(report.read);
        assert_eq!(replaced.process_id, child_info.process_id);
        assert_eq!(replaced.image_revision, 1);
        assert_ne!(replaced.digest, child_info.digest);
        assert_eq!(
            p::process::image_info(Some(child_observer)).unwrap(),
            replaced
        );
        send(release.write, &[0x37]);
        let mut status = -1;
        assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0);
        assert_eq!(
            p::process::image_info(Some(child_observer))
                .unwrap_err()
                .native_error(),
            Some(s::NativeError::NotFound)
        );
        assert_eq!(
            p::process::handle_status(child_observer).unwrap().state,
            mnu_abi::PROCESS_STATE_EXITED
        );
        for handle in [child_observer, report.read, release.write] {
            p::handle::close(handle).unwrap();
        }
        println!(
            "process-image-info: PASS digest/revision/fork/failed-exec/commit/WAIT/exit euid={}",
            unsafe { geteuid() }
        );
    }
}
#[cfg(target_os = "mochios")]
fn main() {
    native::run();
}
