#[test]
fn public_page_alias_abi_and_deferred_sender_root_capture_are_retired() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    let ipc = include_str!("../../../core/src/syscall/ipc.rs");
    let platform = include_str!("../../../user/crates/platform/src/lib.rs");
    assert!(!abi.contains("IpcSendPages"));
    assert!(!abi.contains("AllocSharedPages"));
    assert!(!abi.contains("UnmapPages"));
    assert!(!dispatch.contains("IpcSendPages"));
    assert!(!ipc.contains("pub fn send_pages("));
    assert!(!ipc.contains("send_virtual_pages_from_kernel"));
    assert!(!ipc.contains("source_page_table"));
    assert!(!ipc.contains("source_base"));
    assert!(
        !include_str!("../../../core/src/syscall/process.rs").contains("fn alloc_shared_pages(")
    );
    assert!(
        !include_str!("../../../core/src/syscall/process.rs").contains("fn rollback_shared_pages(")
    );
    assert!(!platform.contains("pub fn send_pages("));
    assert!(!platform.contains("pub fn send_page_count("));
    assert!(!platform.contains("pub fn alloc_shared_pages("));
    assert!(!platform.contains("pub fn alloc_shared_page_count("));
    assert!(!include_str!("../../../core/examples/user/src/lib.rs").contains("ipc_send_pages"));
}

#[test]
fn graphics_receivers_require_an_owned_mapping_instead_of_a_raw_address_packet() {
    let display = include_str!("../../display/src/service.rs");
    let guard = include_str!("../../display/src/shared_buffer.rs");
    let compositor = include_str!("../../compositor/src/server.rs");
    let surface = include_str!("../../compositor/src/surface.rs");
    assert!(!display.contains("shared_buffer_notification"));
    assert!(!guard.contains("fn legacy("));
    assert!(!guard.contains("Option<MemoryMapping>"));
    assert!(
        !compositor.contains(
            "handle_shared_buffer(&mut state.surfaces, client, mapped_addr, total, None)"
        )
    );
    assert!(
        surface.contains("mapping.as_ref().is_none_or(|view| view.view() != (mapped_addr, total))")
    );
}
