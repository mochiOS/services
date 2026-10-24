use mochios_capability_protocol as wire;

#[test]
fn object_request_is_versioned_bounded_and_keeps_an_opaque_identity() {
    for key in ["opaque:key", "relative", "/unlinked/image", "実行:object"] {
        let mut output = [0xaa; 300];
        let len =
            wire::encode_authorize_exec_object_request(key, &[0x5a; 32], &mut output).unwrap();
        assert_eq!(len, 40 + key.len());
        assert_eq!(
            &output[..4],
            &wire::AUTHORIZE_EXEC_OBJECT_OPCODE.to_le_bytes()
        );
        assert_eq!(&output[4..8], &wire::PROTOCOL_VERSION.to_le_bytes());
        assert_eq!(
            wire::decode_authorize_exec_object_request(&output[..len]),
            Ok(([0x5a; 32], key))
        );
        assert!(output[len..].iter().all(|b| *b == 0xaa));
        for capacity in 0..len {
            let mut small = vec![0xaa; capacity];
            assert!(
                wire::encode_authorize_exec_object_request(key, &[0x5a; 32], &mut small).is_err()
            );
            assert!(small.iter().all(|b| *b == 0xaa));
        }
    }
    let max = "x".repeat(wire::MAX_EXECUTABLE_IDENTITY_LEN);
    let mut output = [0; 300];
    let len = wire::encode_authorize_exec_object_request(&max, &[0x5a; 32], &mut output).unwrap();
    assert_eq!(
        wire::decode_authorize_exec_object_request(&output[..len]),
        Ok(([0x5a; 32], max.as_str()))
    );
    for bad in [
        "".to_string(),
        "embedded\0nul".to_string(),
        format!("{max}x"),
    ] {
        assert!(
            wire::encode_authorize_exec_object_request(&bad, &[0x5a; 32], &mut output).is_err()
        );
    }
}

#[test]
fn object_request_rejects_unknown_versions_wrong_operations_and_malformed_keys() {
    let mut output = [0; 300];
    let len = wire::encode_authorize_exec_object_request("key", &[0x5a; 32], &mut output).unwrap();
    for offset in [0, 4, 40] {
        let mut bad = output[..len].to_vec();
        bad[offset] = if offset == 40 { 0xff } else { bad[offset] ^ 1 };
        assert!(wire::decode_authorize_exec_object_request(&bad).is_err());
    }
    let mut nul = output[..len].to_vec();
    nul[40] = 0;
    assert!(wire::decode_authorize_exec_object_request(&nul).is_err());
    for length in 0..=40 {
        assert!(wire::decode_authorize_exec_object_request(&output[..length]).is_err());
    }
    assert_ne!(
        wire::AUTHORIZE_EXEC_OBJECT_OPCODE,
        wire::AUTHORIZE_EXEC_OPCODE
    );
    assert_ne!(
        wire::AUTHORIZE_EXEC_OBJECT_OPCODE,
        wire::PREPARE_EXECUTION_IMAGE_OPCODE
    );
}
