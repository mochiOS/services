use mochios_capability_protocol::*;

#[test]
fn captured_image_keys_are_opaque_bounded_and_versioned() {
    for key in [
        "fexecve".to_string(),
        "opaque:未登録".to_string(),
        "x".repeat(255),
    ] {
        let mut bytes = [0u8; 263];
        let n = encode_authorize_captured_image_request(&key, &mut bytes).unwrap();
        assert_eq!(n, 8 + key.len());
        assert_eq!(
            decode_authorize_captured_image_request(&bytes[..n]),
            Ok(key.as_str())
        );
        assert!(encode_authorize_captured_image_request(&key, &mut bytes[..n - 1]).is_err());
        for end in 0..8 {
            assert!(decode_authorize_captured_image_request(&bytes[..end]).is_err());
        }
        bytes[4] = 99;
        assert_eq!(
            decode_authorize_captured_image_request(&bytes[..n]),
            Err(ProtocolError::UnsupportedVersion)
        );
        bytes[4] = PROTOCOL_VERSION as u8;
        bytes[0] ^= 1;
        assert_eq!(
            decode_authorize_captured_image_request(&bytes[..n]),
            Err(ProtocolError::UnknownOpcode)
        );
    }
    for key in ["".to_string(), "x".repeat(256), "key\0override".to_string()] {
        assert!(encode_authorize_captured_image_request(&key, &mut [0u8; 512]).is_err());
    }
    let mut bytes = [0u8; 16];
    let n = encode_authorize_captured_image_request("x", &mut bytes).unwrap();
    bytes[8] = 0xff;
    assert_eq!(
        decode_authorize_captured_image_request(&bytes[..n]),
        Err(ProtocolError::InvalidUtf8)
    );
}
