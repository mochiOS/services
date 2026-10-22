use mochios_filesystem_protocol::{ProtocolError, device_registration as wire};
fn request(name: &[u8]) -> wire::Request<'_> {
    wire::Request {
        mode: 0o6750,
        uid: u32::MAX,
        gid: 20,
        special_device: 0xfedc_ba98_7654_3210,
        name,
    }
}
#[test]
fn wire_preserves_byte_names_full_width_metadata_and_exact_framing() {
    for name in [b"device".as_slice(), &[0xff, 0x80, 0x01], &[b'x'; 255]] {
        let mut output = vec![0xaa; wire::HEADER_LEN + name.len() + 1];
        let length = wire::encode(request(name), &mut output).unwrap();
        assert_eq!(length, wire::HEADER_LEN + name.len());
        assert_eq!(wire::decode(&output[..length]), Ok(request(name)));
        assert_eq!(output[length], 0xaa);
        assert!(wire::decode(&output).is_err());
        assert!(wire::decode(&output[..length - 1]).is_err());
    }
}
#[test]
fn malformed_names_reserved_version_and_truncated_modes_do_not_encode_or_decode() {
    for name in [b"".as_slice(), b".", b"..", b"a/b", b"a\0b", &[b'x'; 256]] {
        let mut output = [0xaa; 512];
        assert!(wire::encode(request(name), &mut output).is_err());
        assert_eq!(output, [0xaa; 512]);
    }
    let mut output = vec![0; wire::HEADER_LEN + 1];
    wire::encode(request(b"x"), &mut output).unwrap();
    for at in [0, 2, 3, 26, 31] {
        let mut invalid = output.clone();
        invalid[at] ^= 0x80;
        assert!(wire::decode(&invalid).is_err());
    }
    let mut invalid = output.clone();
    invalid[4..8].copy_from_slice(&0o100600u32.to_le_bytes());
    assert!(wire::decode(&invalid).is_err());
    let mut invalid = output.clone();
    invalid[4..8].copy_from_slice(&0x10000u32.to_le_bytes());
    assert!(wire::decode(&invalid).is_err());
    let mut invalid = output.clone();
    invalid[24..26].copy_from_slice(&2u16.to_le_bytes());
    assert!(wire::decode(&invalid).is_err());
    for length in 0..wire::HEADER_LEN {
        assert!(wire::decode(&output[..length]).is_err());
    }
    let mut short = [0xaa; 1];
    assert_eq!(
        wire::encode(request(b"x"), &mut short),
        Err(ProtocolError::BufferTooSmall)
    );
    assert_eq!(short, [0xaa; 1]);
}
