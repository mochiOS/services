use mochios_posix_client::static_tls::{
    Template,
    image::{self, Error},
};

fn templates() -> [Option<Template>; 3] {
    let root = Template {
        source: 0x400003,
        file_size: 7,
        memory_size: 19,
        alignment: 16,
        residue: 3,
    };
    [
        Some(root),
        None,
        Some(Template {
            source: 0x800005,
            alignment: 8192,
            residue: 5,
            ..root
        }),
    ]
}
fn payload() -> Vec<u8> {
    let templates = templates();
    let mut bytes = vec![0; image::encoded_length(templates.len()).unwrap()];
    assert_eq!(image::encode(&templates, &mut bytes), Ok(bytes.len()));
    bytes
}
fn decode(
    bytes: &[u8],
    maximum: usize,
    output: &mut [Option<Template>],
) -> Result<usize, Error<i32>> {
    image::decode(0x1000, maximum, output, |address, output| {
        let offset = address.checked_sub(0x1000).ok_or(14)?;
        output.copy_from_slice(bytes.get(offset..offset + output.len()).ok_or(14)?);
        Ok(())
    })
}
fn put(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn round_trip_preserves_child_addresses_absent_modules_and_zero_only_templates() {
    let bytes = payload();
    let mut result = [None; 4];
    assert_eq!(decode(&bytes, bytes.len(), &mut result), Ok(3));
    assert_eq!(&result[..3], &templates());
    let empty = Template {
        source: 0,
        file_size: 0,
        memory_size: 73,
        alignment: 64,
        residue: 3,
    };
    let mut bytes = vec![0; image::encoded_length(1).unwrap()];
    image::encode(&[Some(empty)], &mut bytes).unwrap();
    assert_eq!(decode(&bytes, bytes.len(), &mut result), Ok(1));
    assert_eq!(result[0], Some(empty));
}

#[test]
fn malformed_formats_templates_and_aggregate_overflow_fail_before_allocation() {
    let good = payload();
    let mut output = [None; 3];
    for (offset, value) in [
        (0, 0),
        (8, 3u64 << 32 | 2),
        (8, 1),
        (16, 33),
        (24, 1),
        (32 + 8, 20),
        (32 + 24, 3),
        (32 + 32, 16),
        (32, u64::MAX - 3),
    ] {
        let mut bytes = good.clone();
        put(&mut bytes, offset, value);
        assert_eq!(
            decode(&bytes, bytes.len(), &mut output),
            Err(Error::Invalid),
            "offset={offset}"
        );
    }
    // Each module is individually representable, but their aggregate is not.
    let mut bytes = good.clone();
    put(&mut bytes, 32 + 16, (usize::MAX / 2) as u64);
    put(
        &mut bytes,
        32 + 2 * image::MODULE_BYTES + 16,
        (usize::MAX / 2) as u64,
    );
    assert_eq!(
        decode(&bytes, bytes.len(), &mut output),
        Err(Error::Invalid)
    );
    assert_eq!(
        decode(&good, good.len() - 1, &mut output),
        Err(Error::TooLarge)
    );
    assert_eq!(
        decode(&good, good.len(), &mut output[..2]),
        Err(Error::TooLarge)
    );
    assert_eq!(image::encoded_length(0), None);
    assert_eq!(image::encoded_length(usize::MAX), None);
    assert_eq!(
        image::encode(&templates(), &mut [0; 3]),
        Err(Error::TooLarge)
    );
}

#[test]
fn faultable_reads_and_mapping_extents_are_bounded() {
    let bytes = payload();
    let mut output = [None; 3];
    for end in [0, 31, 32, bytes.len() - 1] {
        assert_eq!(
            decode(&bytes[..end], bytes.len(), &mut output),
            Err(Error::Read(14))
        );
    }
    for base in [0, 1, usize::MAX & !7] {
        assert_eq!(
            image::decode::<i32>(base, bytes.len(), &mut output, |_, _| panic!(
                "invalid base"
            )),
            Err(Error::Invalid)
        );
    }
    // Valid header but the complete extent would wrap before a descriptor read.
    assert_eq!(
        image::decode::<i32>(usize::MAX - 63, bytes.len(), &mut output, |_, header| {
            header.copy_from_slice(&bytes[..32]);
            Ok(())
        }),
        Err(Error::Invalid)
    );
}
