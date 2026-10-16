use mochios_posix_client::fd::{Entry, FD_CLOEXEC, FdError, FdTable, HandleOps};

fn entry(handle: u32, descriptor_flags: u32) -> Entry<u32> {
    Entry {
        handle,
        rights: 3,
        descriptor_flags,
    }
}
struct NeverClose;
impl HandleOps<u32> for NeverClose {
    type Error = ();
    fn clone_handle(&mut self, _: u32, _: u64) -> Result<u32, ()> {
        panic!("reserved slot must be rejected before retaining a Handle")
    }
    fn close_handle(&mut self, _: u32) {
        panic!("reservation never owns a Handle")
    }
}

#[test]
fn pair_reserves_two_lowest_free_slots_and_publishes_descriptor_local_flags() {
    let mut table = FdTable::new();
    table.install_at(1, entry(10, 0), &mut NeverClose).unwrap();
    let pair = table.reserve_pair_from(0, 4).unwrap();
    assert_eq!([pair[0].descriptor(), pair[1].descriptor()], [0, 2]);
    assert_eq!(table.get(0), None);
    assert_eq!(table.get(2), None);
    assert_eq!(
        table.install_at(0, entry(11, 0), &mut NeverClose),
        Err(FdError::BusyDescriptor)
    );
    assert_eq!(
        table.duplicate_to(1, 2, &mut NeverClose),
        Err(FdError::BusyDescriptor)
    );
    assert_eq!(table.install_from(0, 4, entry(12, 0)), Ok(3));
    assert_eq!(
        table.commit_pair([&pair[0], &pair[1]], [entry(20, FD_CLOEXEC), entry(21, 0)]),
        Ok([0, 2])
    );
    assert_eq!(table.get(0), Some(entry(20, FD_CLOEXEC)));
    assert_eq!(table.get(2), Some(entry(21, 0)));
    assert!(!table.cancel_reservation(&pair[0]));
    assert!(!table.cancel_reservation(&pair[1]));
    assert_eq!(
        table.commit_pair([&pair[0], &pair[1]], [entry(22, 0), entry(23, 0)]),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(table.get(0), Some(entry(20, FD_CLOEXEC)));
}

#[test]
fn one_free_slot_and_invalid_ranges_never_leave_partial_reservations() {
    let mut table = FdTable::new();
    table.install_at(0, entry(10, 0), &mut NeverClose).unwrap();
    assert!(table.reserve_pair_from(0, 2).is_err());
    assert_eq!(table.install_from(0, 2, entry(11, 0)), Ok(1));
    for (minimum, limit) in [(-1, 4), (4, 4), (5, 4), (0, 257), (0, -1)] {
        assert!(table.reserve_pair_from(minimum, limit).is_err());
    }
    assert_eq!(table.install_from(0, 3, entry(12, 0)), Ok(2));
}

#[test]
fn stale_second_token_cannot_publish_first_or_cancel_a_new_reservation() {
    let mut table = FdTable::new();
    let pair = table.reserve_pair_from(0, 2).unwrap();
    assert!(table.cancel_reservation(&pair[1]));
    let replacement = table.reserve_from(0, 2).unwrap();
    assert_eq!(
        table.commit_pair([&pair[0], &pair[1]], [entry(10, 0), entry(11, 0)]),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(table.get(0), None);
    assert_eq!(table.get(1), None);
    assert_eq!(
        table.install_from(0, 2, entry(12, 0)),
        Err(FdError::InvalidDescriptor)
    );
    assert!(!table.cancel_reservation(&pair[1]));
    assert_eq!(table.commit_reservation(&replacement, entry(13, 0)), Ok(1));
    assert!(table.cancel_reservation(&pair[0]));
    assert_eq!(table.install_from(0, 2, entry(14, 0)), Ok(0));
}

#[test]
fn duplicate_token_and_fork_reservation_reset_never_publish_half_a_pair() {
    let mut table = FdTable::<u32>::new();
    let pair = table.reserve_pair_from(0, 2).unwrap();
    assert_eq!(
        table.commit_pair([&pair[0], &pair[0]], [entry(10, 0), entry(11, 0)]),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(table.get(0), None);
    assert_eq!(table.get(1), None);
    let mut child = table.clone();
    assert_eq!(child.install_from(0, 2, entry(12, 0)), Ok(0));
    assert_eq!(child.install_from(0, 2, entry(13, 0)), Ok(1));
    assert_eq!(
        table.commit_pair([&pair[0], &pair[1]], [entry(14, 0), entry(15, 0)]),
        Ok([0, 1])
    );
    let mut table = FdTable::<u32>::new();
    let pair = table.reserve_pair_from(0, 2).unwrap();
    table.clear_reservations();
    assert_eq!(
        table.commit_pair([&pair[0], &pair[1]], [entry(16, 0), entry(17, 0)]),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(table.install_from(0, 2, entry(18, 0)), Ok(0));
    assert_eq!(table.install_from(0, 2, entry(19, 0)), Ok(1));
}
