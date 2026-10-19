//! Isolated Input-role client probe. Exercises the real POSIX service and
//! filesystem RPCs; does not publish Input readiness or claim a desktop boot.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("posix-times: SKIP (requires isolated mochiOS Input-role fixture)");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform::{self as platform, handle};
    use mochios_posix_client::{
        Client, ClientError, ObjectHandleAttachment, ObjectHandles, OpenAtBase, StatAtBase,
    };
    use mochios_posix_protocol::{
        self as wire,
        file_time::{Change, Update},
    };

    platform::io::stdout(b"posix-times: starting real client/service/provider checks\n").unwrap();
    let client = Client::from_launch_context().unwrap();
    client.register_session().unwrap();
    assert_eq!(client.session_info().unwrap().effective_uid, 0);
    let path = b"/tmp/native-posix-times";
    let file = client
        .open_at(
            OpenAtBase::ProcessRoot,
            wire::OPEN_READ | wire::OPEN_WRITE | wire::OPEN_CREATE | wire::OPEN_EXCLUSIVE,
            0o600,
            path,
        )
        .unwrap();
    let directory = client
        .open_at(
            OpenAtBase::ProcessRoot,
            wire::OPEN_READ | wire::OPEN_DIRECTORY,
            0,
            b"/tmp",
        )
        .unwrap();
    client.fchown(file, 1001, 77).unwrap();
    client.set_groups(&[77]).unwrap();
    client.set_effective_gid(77).unwrap();
    client.set_effective_uid(1001).unwrap();
    let explicit = Update {
        access: Change::Set {
            seconds: -1,
            nanoseconds: 123_456_789,
        },
        modification: Change::Set {
            seconds: 2_147_483_648,
            nanoseconds: 987_654_321,
        },
    };
    client
        .utimens_at(StatAtBase::ProcessRoot, path, explicit, 0)
        .unwrap();
    let original = client.fstat(file).unwrap();
    assert_eq!(
        (
            original.access_time_seconds,
            original.access_time_nanoseconds
        ),
        (-1, 123_456_789)
    );
    assert_eq!(
        (
            original.modification_time_seconds,
            original.modification_time_nanoseconds
        ),
        (2_147_483_648, 987_654_321)
    );
    client.chdir_at(StatAtBase::ProcessRoot, b"/tmp").unwrap();
    client
        .utimens_at(
            StatAtBase::ProcessCwd,
            b"native-posix-times",
            Update::now(),
            0,
        )
        .unwrap();
    let current = client.fstat(file).unwrap();
    assert_eq!(
        (current.access_time_seconds, current.access_time_nanoseconds),
        (
            current.modification_time_seconds,
            current.modification_time_nanoseconds
        )
    );
    assert_eq!(
        (current.access_time_seconds, current.access_time_nanoseconds),
        (current.change_time_seconds, current.change_time_nanoseconds)
    );
    client
        .utimens_at(
            StatAtBase::Directory(directory),
            b"native-posix-times",
            explicit,
            0,
        )
        .unwrap();
    let before = client.fstat(file).unwrap();
    client.set_effective_uid(0).unwrap();
    client.set_effective_uid(2002).unwrap();
    assert!(matches!(
        client.futimens(file, explicit),
        Err(ClientError::Remote(-1))
    ));
    assert!(matches!(
        client.futimens(file, Update::now()),
        Err(ClientError::Remote(-13))
    ));
    let omit = Update {
        access: Change::Omit,
        modification: Change::Omit,
    };
    client.futimens(file, omit).unwrap();
    assert_eq!(client.fstat(file).unwrap(), before);
    client.set_effective_uid(0).unwrap();
    client.set_effective_uid(1001).unwrap();
    let mixed = Update {
        access: Change::Omit,
        modification: Change::Now,
    };
    client.futimens(file, mixed).unwrap();
    let after = client.fstat(file).unwrap();
    assert_eq!(
        (after.access_time_seconds, after.access_time_nanoseconds),
        (-1, 123_456_789)
    );
    assert_ne!(after.modification_time_seconds, 2_147_483_648);
    let limited_rights = mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER;
    let limited = handle::duplicate(file.handle, limited_rights).unwrap();
    let limited = ObjectHandleAttachment {
        handle: limited,
        rights: limited_rights,
    };
    assert!(matches!(
        client.futimens(limited, explicit),
        Err(ClientError::Remote(-13))
    ));
    // Bypass client preflight to verify the service independently checks rights.
    let mut payload = [0; wire::file_time::UPDATE_LEN];
    wire::file_time::encode(explicit, &mut payload).unwrap();
    let mut objects = ObjectHandles::new();
    objects.push(limited).unwrap();
    assert!(matches!(
        client.request_with_handles(wire::OP_FUTIMENS, 0, &payload, &mut [], &mut objects),
        Err(ClientError::Remote(-13))
    ));
    assert!(objects.is_empty());
    handle::close(limited.handle).unwrap();
    client
        .symlink_at(
            b"native-posix-times",
            StatAtBase::ProcessRoot,
            b"/tmp/native-posix-times-link",
        )
        .unwrap();
    client
        .utimens_at(
            StatAtBase::ProcessRoot,
            b"/tmp/native-posix-times-link",
            explicit,
            wire::STAT_NOFOLLOW,
        )
        .unwrap();
    let link = client
        .stat_at(
            StatAtBase::ProcessRoot,
            wire::STAT_NOFOLLOW,
            b"/tmp/native-posix-times-link",
        )
        .unwrap();
    assert_eq!(
        (
            link.modification_time_seconds,
            link.modification_time_nanoseconds
        ),
        (2_147_483_648, 987_654_321)
    );
    assert_eq!(client.fstat(file).unwrap(), after);
    client
        .unlink_at(StatAtBase::ProcessRoot, 0, b"/tmp/native-posix-times-link")
        .unwrap();
    client.unlink_at(StatAtBase::ProcessRoot, 0, path).unwrap();
    client.futimens(file, explicit).unwrap();
    assert_eq!(
        client.fstat(file).unwrap().modification_time_seconds,
        2_147_483_648
    );
    client.reset_effective_ids().unwrap();
    handle::close(file.handle).unwrap();
    handle::close(directory.handle).unwrap();
    platform::io::stdout(b"posix-times: PASS real client, stored credentials, root/cwd/directory anchors, NOW/OMIT, symlink times, attenuated Handle and unlink lifetime\n").unwrap();
}
