use mnu_abi::process_create::HandleGrant;
use mochios_posix_client::inheritance::clear_transient_context;

#[test]
fn fork_labels_are_removed_without_closing_handles_and_only_explicit_control_key_survives() {
    let key = mochios_posix_protocol::CONTROL_HANDLE_KEY;
    let grants = [
        HandleGrant {
            key: 91,
            source: 91,
            target: 91,
            rights: 0,
        },
        HandleGrant {
            key,
            source: 8,
            target: 8,
            rights: 0,
        },
        HandleGrant {
            key: 12,
            source: 12,
            target: 12,
            rights: 0,
        },
    ];
    let mut removed = Vec::new();
    assert_eq!(
        clear_transient_context(&grants, key, |key| {
            removed.push(key);
            Ok::<_, ()>(())
        }),
        Ok(())
    );
    assert_eq!(removed, [91, 12]);
    removed.clear();
    assert_eq!(
        clear_transient_context(&grants, key, |key| {
            removed.push(key);
            Err::<(), _>(5)
        }),
        Err(5)
    );
    assert_eq!(removed, [91]);
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let clone = runtime
        .split("fn clone_registered_process()")
        .nth(1)
        .unwrap();
    let child = clone.split("if image == 0 {").nth(2).unwrap();
    assert!(
        child.find("clear_transient_context(").unwrap()
            < child.find("fds.clear_reservations()").unwrap()
    );
    let resumed = clone.split("if image == 0 {").nth(1).unwrap();
    assert!(resumed.find("capture.disarm_child()").unwrap() < resumed.find("drop(guard)").unwrap());
    assert!(
        !clone
            .split("fn create_spawn_status_stream")
            .next()
            .unwrap()
            .contains("HandleTableRead")
    );
}
