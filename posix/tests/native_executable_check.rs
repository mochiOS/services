//! Retained-image execute checks over real POSIX/filesystem IPC and ext4.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("executable-check: SKIP (requires mochiOS)");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform as platform;
    use mochios_posix_client::{Client, ClientError, OpenAtBase, StatAtBase};
    use mochios_posix_protocol as wire;
    unsafe extern "C" {
        fn alarm(seconds: u32) -> u32;
    }
    unsafe {
        alarm(60);
    }
    let client = Client::from_launch_context().unwrap();
    let root = StatAtBase::ProcessRoot;
    let old = "/tmp/executable-check-199";
    let renamed = "/tmp/executable-check-199-renamed";
    let _ = client.unlink_at(root, 0, old);
    let _ = client.unlink_at(root, 0, renamed);
    let file = client
        .open_at(
            OpenAtBase::ProcessRoot,
            wire::OPEN_READ | wire::OPEN_WRITE | wire::OPEN_CREATE | wire::OPEN_EXCLUSIVE,
            0o600,
            old,
        )
        .unwrap();
    assert_eq!(
        platform::handle::write(file.handle, b"retained inode").unwrap(),
        14
    );
    let cursor = platform::handle::seek(file.handle, 0, mnu_abi::HANDLE_SEEK_CURRENT).unwrap();
    client.fchmod(file, 0o600).unwrap();
    assert!(matches!(
        client.check_executable(file),
        Err(ClientError::Remote(-13))
    ));
    client.fchmod(file, 0o700).unwrap();
    client.check_executable(file).unwrap();
    assert_eq!(
        platform::handle::seek(file.handle, 0, mnu_abi::HANDLE_SEEK_CURRENT).unwrap(),
        cursor
    );
    platform::io::stdout(b"executable-check: PASS live chmod and unchanged cursor\n").unwrap();

    client.rename_at(root, old, root, renamed).unwrap();
    let replacement = client
        .open_at(
            OpenAtBase::ProcessRoot,
            wire::OPEN_READ | wire::OPEN_WRITE | wire::OPEN_CREATE | wire::OPEN_EXCLUSIVE,
            0o600,
            old,
        )
        .unwrap();
    client.fchmod(replacement, 0o600).unwrap();
    assert_ne!(
        client.fstat(file).unwrap().inode,
        client.fstat(replacement).unwrap().inode
    );
    client.check_executable(file).unwrap();
    assert!(matches!(
        client.check_executable(replacement),
        Err(ClientError::Remote(-13))
    ));
    platform::io::stdout(
        b"executable-check: PASS rename and pathname replacement preserve object selection\n",
    )
    .unwrap();

    client.unlink_at(root, 0, renamed).unwrap();
    assert_eq!(client.fstat(file).unwrap().link_count, 0);
    client.fchmod(file, 0o600).unwrap();
    assert!(matches!(
        client.check_executable(file),
        Err(ClientError::Remote(-13))
    ));
    client.fchmod(file, 0o100).unwrap();
    client.check_executable(file).unwrap();
    let mut bytes = [0; 14];
    assert_eq!(
        platform::handle::read_at(file.handle, &mut bytes, 0).unwrap(),
        14
    );
    assert_eq!(&bytes, b"retained inode");
    platform::io::stdout(
        b"executable-check: PASS unlinked inode retains live permissions and readable data\n",
    )
    .unwrap();

    for (path, options) in [
        ("/tmp", wire::OPEN_READ | wire::OPEN_DIRECTORY),
        ("/dev/null", wire::OPEN_READ),
    ] {
        let nonfile = client
            .open_at(OpenAtBase::ProcessRoot, options, 0, path)
            .unwrap();
        assert!(matches!(
            client.check_executable(nonfile),
            Err(ClientError::Remote(-13))
        ));
        platform::handle::close(nonfile.handle).unwrap();
    }
    let mut reduced = file;
    reduced.rights = mnu_abi::HANDLE_RIGHT_TRANSFER;
    assert!(matches!(
        client.check_executable(reduced),
        Err(ClientError::Remote(-13))
    ));
    for handle in [file.handle, replacement.handle] {
        platform::handle::close(handle).unwrap();
    }
    client.unlink_at(root, 0, old).unwrap();
    platform::io::stdout(
        b"executable-check: PASS directory/device and missing READ authority rejected\n",
    )
    .unwrap();
}
