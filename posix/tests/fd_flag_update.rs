//! Shared-memory provider still uses this userspace mask/value codec.
use mochios_posix_protocol::{self as wire, OPEN_APPEND, OPEN_NONBLOCK, ProtocolError};

#[test]
fn masked_flag_codec_rejects_partial_unknown_and_out_of_mask_values() {
    for (mask, flags) in [
        (0, 0),
        (OPEN_NONBLOCK, 0),
        (OPEN_NONBLOCK, OPEN_NONBLOCK),
        (OPEN_APPEND | OPEN_NONBLOCK, OPEN_APPEND),
    ] {
        let mut bytes = [0; wire::FILE_FLAGS_UPDATE_PAYLOAD_LEN];
        wire::encode_file_flags_update(mask, flags, &mut bytes).unwrap();
        assert_eq!(wire::decode_file_flags_update(&bytes), Ok((mask, flags)));
        for length in 0..bytes.len() {
            assert!(wire::decode_file_flags_update(&bytes[..length]).is_err());
        }
        assert!(wire::decode_file_flags_update(&[bytes.as_slice(), &[0]].concat()).is_err());
    }
    for (mask, flags) in [
        (0, OPEN_NONBLOCK),
        (OPEN_NONBLOCK, OPEN_APPEND),
        (u32::MAX, 0),
    ] {
        let mut bytes = [0; 8];
        assert_eq!(
            wire::encode_file_flags_update(mask, flags, &mut bytes),
            Err(ProtocolError::InvalidLength)
        );
        bytes[..4].copy_from_slice(&mask.to_le_bytes());
        bytes[4..].copy_from_slice(&flags.to_le_bytes());
        assert!(wire::decode_file_flags_update(&bytes).is_err());
    }
}
