#[test]
fn retired_kernel_file_backend_has_no_vnode_or_posix_open_description() {
    let objects = include_str!("../../../core/src/task/fd_table.rs");
    let filesystem = include_str!("../../../core/src/syscall/fs.rs");
    let vfs = include_str!("../../../core/src/vfs/mod.rs");
    let pager = include_str!("../../../core/src/mem/vm_object.rs");
    for source in [objects, filesystem, vfs, pager] {
        for removed in [
            "Vnode",
            "InodeId",
            "O_APPEND",
            "open_flags",
            "file_size_rootfs_first",
            "read_file_range_rootfs_first",
            "seek_file_handle",
        ] {
            assert!(
                !source.contains(removed),
                "retired file backend {removed} returned to mnu"
            );
        }
    }
    for removed in ["pub data:", "pub pos:", "pub vnode:", "fd_remote"] {
        assert!(!objects.contains(removed));
    }
    assert!(objects.contains("pub io_options: u64"));
    assert!(
        objects.contains("close_pipe_endpoint_from_kernel(self.pipe_id")
            || objects.contains("close_pipe_endpoint_from_kernel(pipe_id")
    );
}

#[test]
fn native_mapping_and_file_io_keep_the_provider_path_and_boot_loader_authority() {
    let process = include_str!("../../../core/src/syscall/process.rs");
    let start = process.find("let file_backing = if anonymous").unwrap();
    let end = start
        + process[start..]
            .find("let result = crate::task::with_process_mut(pid")
            .unwrap();
    let mapping = &process[start..end];
    assert!(!mapping.contains("KernelObject::File("));
    assert!(mapping.contains("KernelObject::Provider(provider)"));
    assert!(mapping.contains("KernelObject::VmObject(object)"));
    assert!(mapping.contains("object_with_rights(backing_handle, rights)"));
    assert!(mapping.contains("provider_memory_object(&provider)"));
    let handles = include_str!("../../../core/src/syscall/handle.rs");
    assert!(handles.contains("provider_read(&provider, buffer, length)"));
    assert!(handles.contains("provider_write(&provider, buffer, length)"));
    assert!(handles.contains("provider_seek(&provider, offset as i64, basis)"));
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    assert!(exec.contains("ensure_fs_path_executable_for_process(path, pid)"));
    assert!(exec.contains("crate::init::fs::read_initfs(path)"));
    assert!(exec.contains("crate::cext::fs::read_all(path)"));
}
