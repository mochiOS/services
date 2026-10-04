use mochios_filesystem_protocol as filesystem;
use mochios_posix_client::directory::{DirectoryDecodeError, DirectoryEntries};

#[test]
fn directory_chunks_decode_without_posix_fd_numbers() {
    let mut bytes = [0u8; 128];
    let first = filesystem::encode_dir_entry(
        41,
        filesystem::NODE_TYPE_DIRECTORY,
        b"Documents",
        &mut bytes,
    )
    .unwrap();
    let second = filesystem::encode_dir_entry(
        42,
        filesystem::NODE_TYPE_REGULAR,
        b"notes.txt",
        &mut bytes[first..],
    )
    .unwrap();
    let entries = DirectoryEntries::new(&bytes[..first + second])
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries[0].object_id, 41);
    assert_eq!(entries[0].kind, filesystem::NODE_TYPE_DIRECTORY);
    assert_eq!(entries[0].name, "Documents");
    assert_eq!(entries[1].object_id, 42);
    assert_eq!(entries[1].kind, filesystem::NODE_TYPE_REGULAR);
    assert_eq!(entries[1].name, "notes.txt");
}

#[test]
fn malformed_directory_chunk_stops_at_the_first_bad_record() {
    let mut entries = DirectoryEntries::new(&[0; filesystem::DIRENT_HEADER_LEN]);
    assert!(matches!(
        entries.next(),
        Some(Err(DirectoryDecodeError::Protocol(_)))
    ));
    assert_eq!(entries.next(), None);
}
