#[test]
fn linux_service_file_transfers_use_the_userspace_posix_layer() {
    let host = include_str!("../../linux/src/host.rs");
    let portal = include_str!("../../linux/src/portal.rs");
    assert!(!host.contains("platform::file::"));
    assert!(!portal.contains("platform::file::"));
    assert!(host.contains("File::open(path)"));
    assert!(host.contains("SeekFrom::Start(source_offset)"));
    let compact: String = host
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    assert!(compact.contains("posix_read(file.as_raw_fd(),buffer_addressas*mutu8"));
    assert!(portal.contains("fs::read_dir(&directory)"));
    // Do not manufacture an exclusive Rust reference to the agent's alias.
    assert!(!host.contains("from_raw_parts_mut"));
}
