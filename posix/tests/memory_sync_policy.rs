use mochios_posix_client::memory::{sync_policy, SyncPolicy, MS_ASYNC, MS_INVALIDATE, MS_SYNC};

#[test]
fn sync_policy_preserves_each_valid_posix_mode() {
    for asynchronous in [false, true] {
        for invalidate in [false, true] {
            let flags = if asynchronous { MS_ASYNC } else { MS_SYNC }
                | if invalidate { MS_INVALIDATE } else { 0 };
            assert_eq!(
                sync_policy(flags),
                Some(SyncPolicy {
                    asynchronous,
                    invalidate
                })
            );
        }
    }
}

#[test]
fn sync_policy_rejects_missing_conflicting_and_unknown_modes() {
    for flags in [0, MS_INVALIDATE, MS_ASYNC | MS_SYNC, -1, MS_SYNC | 8] {
        assert_eq!(sync_policy(flags), None);
    }
}
