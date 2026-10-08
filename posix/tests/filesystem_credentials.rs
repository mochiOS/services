use mochios_filesystem_protocol as protocol;

#[test]
fn credential_envelope_round_trips_groups_and_opaque_payload() {
    let mut encoded = [0u8; protocol::CREDENTIALS_MAX_LEN + 16];
    let length = protocol::encode_credentials_payload(
        501,
        20,
        &[7, 42, 900],
        b"opaque/path",
        &mut encoded,
    )
    .unwrap();
    let (credentials, payload) = protocol::decode_credentials_payload(&encoded[..length]).unwrap();
    assert_eq!(credentials.effective_uid, 501);
    assert_eq!(credentials.effective_gid, 20);
    assert_eq!(credentials.supplementary_groups(), &[7, 42, 900]);
    assert_eq!(payload, b"opaque/path");
}

#[test]
fn credential_envelope_is_bounded_and_rejects_truncation() {
    let mut encoded = [0u8; protocol::CREDENTIALS_MAX_LEN];
    let groups = [3u32; protocol::MAX_SUPPLEMENTARY_GROUPS];
    let length =
        protocol::encode_credentials_payload(0, 0, &groups, &[], &mut encoded).unwrap();
    assert_eq!(length, protocol::CREDENTIALS_MAX_LEN);
    assert_eq!(
        protocol::decode_credentials_payload(&encoded[..length - 1]),
        Err(protocol::ProtocolError::InvalidLength)
    );
    assert_eq!(
        protocol::encode_credentials_payload(
            0,
            0,
            &[1; protocol::MAX_SUPPLEMENTARY_GROUPS + 1],
            &[],
            &mut encoded,
        ),
        Err(protocol::ProtocolError::InvalidLength)
    );
    encoded[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        protocol::decode_credentials_payload(&encoded),
        Err(protocol::ProtocolError::InvalidLength)
    );
}

#[test]
fn credential_envelope_supports_an_empty_group_set() {
    let mut encoded = [0u8; protocol::CREDENTIALS_HEADER_LEN + 1];
    let length =
        protocol::encode_credentials_payload(12, 34, &[], b"x", &mut encoded).unwrap();
    let (credentials, payload) = protocol::decode_credentials_payload(&encoded[..length]).unwrap();
    assert!(credentials.supplementary_groups().is_empty());
    assert_eq!(payload, b"x");
}
