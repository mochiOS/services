#[path = "../../../core/src/mem/cow_access.rs"]
mod cow_access;
use cow_access::*;

const WRITABLE: u64 = 1 << 1;
const PRESENT: u64 = 1;
const USER: u64 = 1 << 2;
const NX: u64 = 1 << 63;

#[test]
fn read_only_cow_storage_never_authorizes_a_write_fault() {
    let flags = PRESENT | USER | NX | COPY_ON_WRITE;
    assert!(may_resolve(flags));
    let restricted = with_write_access(flags, false);
    assert_eq!(restricted, flags | WRITE_DISABLED);
    assert!(!may_resolve(restricted));
    assert!(!may_resolve(restricted & !PRESENT & !NX));
    assert!(may_resolve(with_write_access(restricted, true)));
    assert!(!may_resolve(flags | WRITABLE));
    assert!(!may_resolve(PRESENT | USER | NX));
    assert!(!may_resolve(flags & !USER));
    assert!(!may_resolve(flags & !PRESENT));
}

#[test]
fn cloning_preserves_denial_and_can_later_isolate_read_only_or_none_pages() {
    for flags in [
        PRESENT | USER,
        USER | NX,
        PRESENT | USER | NX | COPY_ON_WRITE | WRITE_DISABLED,
    ] {
        let cloned = clone_private(flags, false);
        assert!(!may_resolve(cloned));
        assert_ne!(cloned & COPY_ON_WRITE, 0);
        assert!(may_resolve(with_write_access(cloned, true) | PRESENT));
        assert_eq!(cloned & (PRESENT | NX), flags & (PRESENT | NX));
    }
    for flags in [PRESENT | USER | WRITABLE, PRESENT | USER | COPY_ON_WRITE] {
        assert!(may_resolve(clone_private(flags, false)));
    }
    assert!(may_resolve(clone_private(PRESENT | USER, true)));
}

#[test]
fn live_cow_fault_and_usercopy_keep_root_locked_and_revalidate_identity() {
    let process = include_str!("../../../core/src/syscall/process.rs");
    let fault = process
        .split("pub(crate) fn resolve_user_copy_on_write(")
        .nth(1)
        .unwrap()
        .split("pub fn handle_user_memory_fault(")
        .next()
        .unwrap();
    assert!(fault.contains("with_process_mut"));
    assert!(fault.contains("process.page_table() != Some(table)"));
    let usercopy = include_str!("../../../core/src/syscall/mod.rs");
    let copy = usercopy
        .split("fn copy_into_current_root(")
        .nth(1)
        .unwrap()
        .split("pub fn copy_to_user_native(")
        .next()
        .unwrap();
    assert!(copy.contains("with_process_mut"));
    assert!(copy.contains("process.page_table() != Some(table)"));
    assert!(
        include_str!("../../../core/src/interrupt/idt.rs")
            .contains("process::resolve_user_copy_on_write")
    );
}
