use mochios_filesystem_protocol as filesystem;
use mochios_posix_protocol as wire;
use posix_service::{AuthenticatedProcess, PeerIdentity, PosixService};

#[test]
fn image_open_is_admitted_read_only_with_authenticated_effective_credentials() {
    let mut service = PosixService::<u32>::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 42,
                process_id: 17,
            },
            501,
            77,
            &[88],
        )
        .unwrap();
    // Authenticated session state wins over the stale identity fields.
    let peer = PeerIdentity {
        process_id: 17,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut payload = [0; wire::OPEN_AT_HEADER_LEN + 32];
    for extra in [
        0,
        wire::OPEN_WRITE,
        wire::OPEN_CREATE,
        wire::OPEN_EXCLUSIVE,
        wire::OPEN_TRUNCATE,
        wire::OPEN_APPEND,
        wire::OPEN_DIRECTORY,
        wire::OPEN_CURSOR_RECORDS,
    ] {
        let length = wire::encode_open_at(
            wire::OpenAtRequest {
                base: wire::OpenBase::ProcessCwd,
                options: wire::OPEN_READ | wire::OPEN_EXECUTE | extra,
                mode: 0,
                path: b"program",
            },
            &mut payload,
        )
        .unwrap();
        let result = service.prepare_open_at(peer, &payload[..length], 0);
        if extra != 0 {
            assert_eq!(result, Err(-22));
            continue;
        }
        let prepared = result.unwrap();
        assert_eq!((prepared.effective_uid, prepared.effective_gid), (501, 77));
        assert_eq!(prepared.supplementary_groups, [88]);
        for attached in [false, true] {
            let flags = prepared.filesystem_flags(attached);
            assert_eq!(
                flags,
                filesystem::OPEN_AT_READ
                    | filesystem::OPEN_AT_EXECUTE
                    | filesystem::OPEN_AT_ROOT_ATTACHED
                    | if attached {
                        filesystem::OPEN_AT_BASE_ATTACHED
                    } else {
                        0
                    }
            );
        }
    }
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let replace = runtime
        .split("fn replace_process_image(")
        .nth(1)
        .unwrap()
        .split("fn execve_with_launch_context(")
        .next()
        .unwrap();
    assert!(replace.contains("posix_protocol::OPEN_READ | posix_protocol::OPEN_EXECUTE"));
    let adapter = include_str!("../src/main.rs");
    let open = adapter
        .split("    fn open_request(")
        .nth(1)
        .unwrap()
        .split("    fn truncate_handle_request(")
        .next()
        .unwrap();
    assert!(open.contains("request.filesystem_flags(paths.base.is_some())"));
}
