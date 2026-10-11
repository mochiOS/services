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
    // Other CPUs cannot be ignored when lifting the existing single-thread
    // restriction. This test does not claim a remote TLB shootdown mechanism.
    let process = include_str!("../../../core/src/syscall/process.rs");
    assert!(process.contains("if live_threads != 1"));
}
