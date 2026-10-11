use mnu_abi::ExecutionIdentity;
use posix_service::pty::{authorize_sync_request, EACCES, EINVAL};

fn request() -> [u8; 20] {
    let mut bytes = [0; 20];
    bytes[..4].copy_from_slice(b"PTYS");
    bytes[4..12].copy_from_slice(&2u64.to_le_bytes());
    bytes[12..20].copy_from_slice(&3u64.to_le_bytes());
    bytes
}

#[test]
fn readiness_sync_accepts_only_authenticated_service_threads() {
    let own = Some(ExecutionIdentity {
        process_id: 7,
        thread_id: 13,
    });
    let pair = authorize_sync_request(&request(), own, 7, 0).unwrap();
    assert_eq!(pair.master_object_id, 2);
    assert_eq!(pair.slave_object_id, 3);
    for identity in [
        None,
        Some(ExecutionIdentity {
            process_id: 8,
            thread_id: 13,
        }),
        Some(ExecutionIdentity {
            process_id: 7,
            thread_id: 0,
        }),
    ] {
        assert_eq!(
            authorize_sync_request(&request(), identity, 7, 0),
            Err(EACCES)
        );
    }
    assert_eq!(authorize_sync_request(&request(), own, 0, 0), Err(EACCES));
}

#[test]
fn forged_objects_and_malformed_internal_messages_cannot_supply_identity() {
    let own = Some(ExecutionIdentity {
        process_id: 7,
        thread_id: 13,
    });
    assert_eq!(authorize_sync_request(&request(), own, 7, 1), Err(EINVAL));
    assert_eq!(
        authorize_sync_request(&request()[..19], own, 7, 0),
        Err(EINVAL)
    );
    let mut forged = request();
    forged[..4].copy_from_slice(b"NOPE");
    assert_eq!(authorize_sync_request(&forged, own, 7, 0), Err(EINVAL));
    forged = request();
    forged[4..12].copy_from_slice(&7u64.to_le_bytes());
    assert_eq!(authorize_sync_request(&forged, None, 7, 0), Err(EACCES));
    assert_eq!(authorize_sync_request(&[], None, 7, 0), Err(EACCES));
}

#[test]
fn runtime_uses_endpoint_identity_before_readiness_mutation() {
    let source = include_str!("../src/main.rs");
    let route = source.split("starts_with(&PTY_SYNC_MAGIC)").nth(1).unwrap();
    assert!(
        route.find("endpoint_execution_identity(sender)").unwrap()
            < route.find("handle_pty_sync_request(").unwrap()
    );
    let handler = source.split("fn handle_pty_sync_request(").nth(1).unwrap();
    assert!(
        handler.find("authorize_sync_request(").unwrap() < handler.find("ptys.lock()").unwrap()
    );
}
