use filesystem_service::null_device::NullDescription;
use mochios_filesystem_protocol as protocol;

#[test]
fn null_reads_return_eof_without_modifying_caller_storage() {
    let null = NullDescription::new(true, false, 0).unwrap();
    let mut output = [0x5a; 4096];
    assert_eq!(null.read_into(&mut output), Ok(0));
    assert_eq!(null.read_at(&mut output, u64::MAX), Ok(0));
    assert_eq!(output, [0x5a; 4096]);
    assert_eq!(null.read_into(&mut []), Ok(0));
}

#[test]
fn null_writes_discard_data_and_never_change_size_or_position() {
    let null = NullDescription::new(false, true, protocol::OPEN_STATUS_APPEND).unwrap();
    assert_eq!(null.write(b"discarded"), Ok(9));
    assert_eq!(null.write_at(b"discarded", u64::MAX), Ok(9));
    assert_eq!(null.write(&[]), Ok(0));
    for basis in 0..=2 {
        for offset in [i64::MIN, 0, i64::MAX] {
            assert_eq!(null.seek(offset, basis), Ok(0));
        }
    }
    assert_eq!(null.seek(0, 3), Err(22));
    assert_eq!(null.status(4, 2).size, 0);
    assert_eq!(null.memory_object(), Err(95));
}

#[test]
fn access_rights_cannot_be_expanded_using_mutable_status_flags() {
    assert!(NullDescription::new(false, false, 0).is_err());
    assert!(NullDescription::new(true, true, u32::MAX).is_err());
    let mut reader = NullDescription::new(true, false, 0).unwrap();
    let writer = NullDescription::new(false, true, 0).unwrap();
    assert_eq!(reader.write(b"x"), Err(13));
    assert_eq!(writer.read_into(&mut [0]), Err(13));
    reader.set_flags(protocol::OPEN_STATUS_NONBLOCK).unwrap();
    assert_eq!(reader.write(b"x"), Err(13));
    assert_eq!(reader.set_flags(u32::MAX), Err(22));
    assert_eq!(reader.flags(), protocol::OPEN_STATUS_NONBLOCK);
}

#[test]
fn forwarded_descriptions_share_flags_but_separate_opens_do_not() {
    let shared = std::sync::Arc::new(std::sync::Mutex::new(
        NullDescription::new(true, true, 0).unwrap(),
    ));
    let duplicate = shared.clone();
    let separate = NullDescription::new(true, true, 0).unwrap();
    duplicate
        .lock()
        .unwrap()
        .set_flags(protocol::OPEN_STATUS_NONBLOCK)
        .unwrap();
    assert_eq!(
        shared.lock().unwrap().flags(),
        protocol::OPEN_STATUS_NONBLOCK
    );
    assert_eq!(separate.flags(), 0);
}

#[test]
fn null_metadata_is_a_character_device_not_a_regular_file() {
    let null = NullDescription::new(true, true, 0).unwrap();
    let status = null.status(4, 2);
    assert_eq!((status.device, status.node_id), (4, 2));
    assert_eq!(status.kind, protocol::NODE_TYPE_SPECIAL);
    assert_eq!(status.mode, 0o020666);
    assert_eq!(status.special_device, 259);
    assert_eq!((status.size, status.blocks), (0, 0));
    let mut payload = [0; protocol::NODE_STATUS_LEN];
    protocol::encode_node_status(status, &mut payload).unwrap();
    assert_eq!(protocol::decode_node_status(&payload).unwrap(), status);
}
