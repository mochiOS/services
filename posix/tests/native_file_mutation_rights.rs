#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("native-file-mutation-rights: SKIP (requires mochiOS)");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform::handle;
    use mochios_posix_client::{
        Client, ClientError, ObjectHandleAttachment as Attachment, ObjectHandles, OpenAtBase,
    };
    use mochios_posix_protocol as wire;
    use std::os::fd::AsRawFd;

    struct Lease(Attachment<u32>);
    impl Drop for Lease {
        fn drop(&mut self) {
            handle::close(self.0.handle).unwrap();
        }
    }
    fn reduced(source: Attachment<u32>, rights: u64) -> Lease {
        Lease(Attachment {
            handle: handle::duplicate(source.handle, rights).unwrap(),
            rights,
        })
    }
    unsafe extern "C" {
        fn ftruncate(fd: i32, length: i64) -> i32;
    }

    let client = Client::from_launch_context().unwrap();
    let path = "/tmp/native-file-mutation-rights";
    let _ = std::fs::remove_file(path);
    let file = Lease(
        client
            .open_at(
                OpenAtBase::ProcessRoot,
                wire::OPEN_READ | wire::OPEN_WRITE | wire::OPEN_CREATE | wire::OPEN_EXCLUSIVE,
                0o600,
                path,
            )
            .unwrap(),
    );
    let readonly = Lease(
        client
            .open_at(OpenAtBase::ProcessRoot, wire::OPEN_READ, 0, path)
            .unwrap(),
    );
    assert_eq!(handle::write(file.0.handle, b"abcdefgh").unwrap(), 8);
    let original = client.fstat(file.0).unwrap();
    assert_eq!(original.size, 8);

    let read = mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER;
    let narrowed = reduced(file.0, read);
    // Force actual IPC, bypassing the convenience client's preflight check.
    // Neither requested mode nor a claimed writable original OFD is authority.
    for (opcode, payload) in [
        (wire::OP_FTRUNCATE, 1u64.to_le_bytes().to_vec()),
        (wire::OP_FCHMOD, 0o777u32.to_le_bytes().to_vec()),
        (wire::OP_FCHOWN, [0u8; 8].to_vec()),
    ] {
        let mut attached = ObjectHandles::new();
        attached.push(narrowed.0).unwrap();
        assert!(matches!(
            client.request_with_handles(opcode, 0, &payload, &mut [], &mut attached),
            Err(ClientError::Remote(-13))
        ));
        assert!(attached.is_empty());
        let after = client.fstat(file.0).unwrap();
        assert_eq!(
            (after.size, after.mode, after.uid, after.gid),
            (original.size, original.mode, original.uid, original.gid)
        );
    }
    assert!(matches!(
        client.ftruncate(readonly.0, 1),
        Err(ClientError::Remote(-13))
    ));
    let data = reduced(
        file.0,
        mnu_abi::HANDLE_RIGHT_WRITE | mnu_abi::HANDLE_RIGHT_TRANSFER,
    );
    let metadata = reduced(
        file.0,
        mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_TRANSFER,
    );
    assert!(matches!(
        client.fchmod(data.0, 0o777),
        Err(ClientError::Remote(-13))
    ));
    assert!(matches!(
        client.ftruncate(metadata.0, 1),
        Err(ClientError::Remote(-13))
    ));
    client.fchmod(metadata.0, 0o600).unwrap();
    client.ftruncate(data.0, 6).unwrap();
    assert_eq!(client.fstat(file.0).unwrap().size, 6);
    client.fchmod(readonly.0, 0o640).unwrap();
    client.fchown(readonly.0, u32::MAX, u32::MAX).unwrap();
    assert_eq!(client.fstat(file.0).unwrap().mode & 0o7777, 0o640);

    let c_readonly = std::fs::File::open(path).unwrap();
    assert_eq!(unsafe { ftruncate(c_readonly.as_raw_fd(), 0) }, -1);
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(22));
    assert_eq!(client.fstat(file.0).unwrap().size, 6);
    std::fs::remove_file(path).unwrap();
    client.ftruncate(file.0, 4).unwrap();
    client.fchmod(readonly.0, 0o600).unwrap();
    assert_eq!(client.fstat(file.0).unwrap().size, 4);
    println!(
        "native-file-mutation-rights: PASS attenuated IPC denial without mutation, writable truncate, readonly metadata controls, C readonly errno and unlinked handles"
    );
}
