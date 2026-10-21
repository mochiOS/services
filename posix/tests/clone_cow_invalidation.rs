#[test]
fn source_write_access_is_invalidated_before_destination_can_fail() {
    let source = include_str!("../../../core/src/mem/paging.rs");
    let clone = &source[source.find("pub fn clone_user_page_table(").unwrap()..];
    let private = &clone[clone
        .find("ForkPagePolicy::Private | ForkPagePolicy::PrivateWritable")
        .unwrap()..];
    let update = private
        .find("pte.set_addr(pte.addr(), shared_flags)")
        .unwrap();
    let revoke = private
        .find("flush_page_if_active(src_table_phys, vaddr)")
        .unwrap();
    let share = private
        .find("share_page(dst_l4, vaddr, pte.addr().as_u64(), shared_flags, phys_off)?")
        .unwrap();
    assert!(update < revoke && revoke < share);
    // Native address-space capture now quiesces siblings and synchronizes
    // remote TLBs rather than embedding a single-threaded POSIX restriction.
    // The behavioral lock/cleanup paths are exercised by clone_mapping_lock;
    // these checks do not claim to execute physical multi-CPU invalidation.
    let process = include_str!("../../../core/src/syscall/process.rs");
    let clone = process
        .split("pub fn clone_address_space() -> u64 {")
        .nth(1)
        .unwrap()
        .split("/// Suspends every thread")
        .next()
        .unwrap();
    let quiesce = clone.find("quiesce_image_siblings(pid, owner)").unwrap();
    let capture = clone.find("CloneSource::capture(process)").unwrap();
    let copy = clone.find("source.clone_image()").unwrap();
    let synchronize = clone.find("tlb_shootdown::invalidate_all()").unwrap();
    let publish = clone.find(".object_handles_mut()").unwrap();
    assert!(quiesce < capture && capture < copy);
    assert!(copy < synchronize && synchronize < publish);
}
