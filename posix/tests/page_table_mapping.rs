#[test]
fn segment_population_does_not_alias_a_shared_kernel_scratch_mapping() {
    // Structural regression guard, not a substitute for the native concurrent
    // population test in heap_mapping.c: host tests cannot execute page tables.
    let paging = include_str!("../../../core/src/mem/paging.rs");
    let start = paging.find("pub fn map_and_copy_segment_to(").unwrap();
    let rest = &paging[start..];
    let end = rest.find("pub fn protect_user_range_in_table(").unwrap();
    let population = &rest[..end];
    assert!(population.contains("let l4_virt = table_phys\n        .checked_add(phys_off)"));
    assert!(population.contains("ensure_user_page_table_hierarchy(l4_virt, page_addr, phys_off)"));
    assert!(!population.contains("temp_kern_virt"));
    assert!(!population.contains("TempMapGuard"));
    assert!(!population.contains("PAGE_TABLE.lock()"));
}
