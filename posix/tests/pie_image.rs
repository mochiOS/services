use mochios_posix_client::pie::{Error, Pie};
fn w16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn w64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
fn r64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn segment(
    b: &mut [u8],
    n: usize,
    kind: u32,
    flags: u32,
    off: u64,
    address: u64,
    file: u64,
    memory: u64,
) {
    let p = 64 + n * 56;
    w32(b, p, kind);
    w32(b, p + 4, flags);
    w64(b, p + 8, off);
    w64(b, p + 16, address);
    w64(b, p + 32, file);
    w64(b, p + 40, memory);
    w64(b, p + 48, 0x1000);
}
fn image() -> Vec<u8> {
    let mut b = vec![0u8; 0x1100];
    b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    w16(&mut b, 16, 3);
    w16(&mut b, 18, 62);
    w32(&mut b, 20, 1);
    w64(&mut b, 24, 0x180);
    w64(&mut b, 32, 64);
    w16(&mut b, 52, 64);
    w16(&mut b, 54, 56);
    w16(&mut b, 56, 3);
    segment(&mut b, 0, 1, 5, 0, 0, 0x200, 0x200);
    segment(&mut b, 1, 1, 6, 0x1000, 0x1000, 0x100, 0x3000);
    segment(&mut b, 2, 2, 6, 0x1000, 0x1000, 64, 64);
    for (n, (tag, value)) in [(7, 0x1040), (8, 24), (9, 24), (0, 0)]
        .into_iter()
        .enumerate()
    {
        w64(&mut b, 0x1000 + n * 16, tag);
        w64(&mut b, 0x1008 + n * 16, value);
    }
    w64(&mut b, 0x1040, 0x1200);
    w64(&mut b, 0x1048, 8);
    w64(&mut b, 0x1050, 0x180);
    b
}
#[test]
fn rebases_entry_and_relative_bss_target_without_materializing_the_rest_of_bss() {
    let b = image();
    let pie = Pie::parse(&b).unwrap();
    assert_eq!(pie.alignment(), 4096);
    let mut output = vec![0xcc; pie.output_length().unwrap()];
    let bias = 0x20000000;
    assert_eq!(pie.write(bias, &mut output).unwrap(), output.len());
    assert_eq!(&output[16..18], &2u16.to_le_bytes());
    assert_eq!(r64(&output, 24), bias + 0x180);
    assert_eq!(r64(&output, 32), 64);
    let executable = pie.executable(bias).unwrap();
    assert_eq!(executable.program_headers, bias + 64);
    assert_eq!(executable.program_header_count, 3);
    assert_ne!(executable.program_headers, r64(&output, 120 + 16));
    // The first LOAD owns the relocated program headers independently of source layout.
    assert_eq!(r64(&output, 64 + 16), bias - 4096);
    assert_eq!(r64(&output, 120 + 16), bias - 4096 + 64);
    let data = 64 + 3 * 56;
    let off = r64(&output, data + 8) as usize;
    assert_eq!(r64(&output, data + 32), 0x208);
    assert_eq!(r64(&output, data + 40), 0x3000);
    assert_eq!(r64(&output, off + 0x200), bias + 0x180);
    assert!(output[off + 0x100..off + 0x200].iter().all(|x| *x == 0));
    assert!(output.len() < 0x4000);
    assert_eq!(b, image());
}
#[test]
fn rejects_interpreters_dependencies_symbol_relocations_and_overlapping_fixups() {
    for kind in [3] {
        let mut b = image();
        w32(&mut b, 64 + 2 * 56, kind);
        assert!(matches!(Pie::parse(&b), Err(Error::Unsupported)));
    }
    let mut b = image();
    w64(&mut b, 0x1000, 1);
    assert!(matches!(Pie::parse(&b), Err(Error::Unsupported)));
    for info in [1, 6, 7, 37, 0x100000008] {
        let mut b = image();
        w64(&mut b, 0x1048, info);
        assert!(matches!(Pie::parse(&b), Err(Error::Unsupported)));
    }
    for target in [0x1200, 0x1201, 0x11ff] {
        let mut b = image();
        w64(&mut b, 0x1018, 48);
        w64(&mut b, 0x1058, target);
        w64(&mut b, 0x1060, 8);
        w64(&mut b, 0x1068, 0x180);
        assert!(matches!(Pie::parse(&b), Err(Error::Invalid)));
    }
}
#[test]
fn validates_every_extent_permissions_alignment_and_output_boundary() {
    let b = image();
    for end in 0..b.len() {
        assert!(Pie::parse(&b[..end]).is_err(), "prefix={end}");
    }
    for (offset, value) in [
        (64 + 8, u64::MAX),
        (64 + 16, u64::MAX),
        (64 + 32, 0x201),
        (64 + 40, 1),
        (64 + 48, 3),
        (0x1008, u64::MAX),
        (0x1018, 25),
        (0x1040, 0x3ffc),
    ] {
        let mut b = image();
        w64(&mut b, offset, value);
        assert!(Pie::parse(&b).is_err(), "offset={offset}");
    }
    for flags in [3, 7, 8] {
        let mut b = image();
        w32(&mut b, 68, flags);
        assert!(Pie::parse(&b).is_err());
    }
    let pie = Pie::parse(&b).unwrap();
    let mut out = vec![0; pie.output_length().unwrap()];
    assert_eq!(
        pie.write(0x20000000, &mut out[..1]),
        Err(Error::BufferTooSmall)
    );
    for bias in [0, 1, 0x0000800000000000, u64::MAX & !4095] {
        assert!(pie.write(bias, &mut out).is_err());
    }
}
#[test]
fn retains_unwind_metadata_and_program_headers_in_the_new_image() {
    let mut b = image();
    w16(&mut b, 56, 4);
    segment(&mut b, 3, 0x6474e550, 4, 0x190, 0x190, 0x30, 0x30);
    let pie = Pie::parse(&b).unwrap();
    let mut out = vec![0; pie.output_length().unwrap()];
    pie.write(0x20000000, &mut out).unwrap();
    let unwind = 64 + 4 * 56;
    assert_eq!(r64(&out, unwind + 16), 0x20000190);
    assert_eq!(r64(&out, unwind + 8), 0x1190);
    w64(&mut b, 64 + 3 * 56 + 8, 0x180);
    assert!(matches!(Pie::parse(&b), Err(Error::Invalid)));
}

#[test]
fn relative_values_use_elf64_modular_arithmetic_not_address_range_arithmetic() {
    let bias = 0x20000000u64;
    for addend in [-8i64, -0x40000000, i64::MAX] {
        let mut bytes = image();
        w64(&mut bytes, 0x1050, addend as u64);
        let pie = Pie::parse(&bytes).unwrap();
        let mut output = vec![0; pie.output_length().unwrap()];
        pie.write(bias, &mut output).unwrap();
        let offset = r64(&output, 64 + 3 * 56 + 8) as usize + 0x200;
        assert_eq!(r64(&output, offset), bias.wrapping_add(addend as u64));
    }
}

fn tls_image() -> Vec<u8> {
    let mut bytes = image();
    w16(&mut bytes, 56, 4);
    segment(&mut bytes, 3, 7, 4, 0x1080, 0x1080, 8, 0x5000);
    w64(&mut bytes, 64 + 3 * 56 + 48, 64);
    bytes[0x1080..0x1088].copy_from_slice(b"template");
    bytes
}

#[test]
fn preserves_original_tls_headers_and_supplies_the_bias_for_the_loaded_template() {
    let bytes = tls_image();
    let pie = Pie::parse(&bytes).unwrap();
    let bias = 0x20000000;
    let executable = pie.executable(bias).unwrap();
    assert_eq!(executable.load_bias, bias);
    assert_eq!(executable.interpreter_base, 0);
    let mut output = vec![0; pie.output_length().unwrap()];
    pie.write(bias, &mut output).unwrap();
    let read = |address: usize, buffer: &mut [u8]| -> Result<(), i32> {
        let count = u16::from_le_bytes(output[56..58].try_into().unwrap()) as usize;
        for index in 0..count {
            let header = 64 + index * 56;
            let kind = u32::from_le_bytes(output[header..header + 4].try_into().unwrap());
            let base = r64(&output, header + 16) as usize;
            let length = r64(&output, header + 32) as usize;
            if kind == 1
                && address >= base
                && address
                    .checked_add(buffer.len())
                    .is_some_and(|end| end <= base + length)
            {
                let offset = r64(&output, header + 8) as usize + address - base;
                buffer.copy_from_slice(&output[offset..offset + buffer.len()]);
                return Ok(());
            }
        }
        Err(14)
    };
    let template = mochios_posix_client::static_tls::template(
        executable.program_headers as usize,
        56,
        executable.program_header_count as usize,
        executable.load_bias as usize,
        read,
    )
    .unwrap()
    .unwrap();
    assert_eq!(template.source, bias as usize + 0x1080);
    assert_eq!(template.file_size, 8);
    assert_eq!(template.memory_size, 0x5000);
    let mut data = [0; 8];
    read(template.source, &mut data).unwrap();
    assert_eq!(&data, b"template");
}

#[test]
fn validates_tls_including_zero_fill_duplicate_headers_and_symbol_relocations() {
    let bytes = tls_image();
    for (field, value) in [(8, 0x1081), (32, 0x101), (40, 7), (48, 3)] {
        let mut invalid = bytes.clone();
        w64(&mut invalid, 64 + 3 * 56 + field, value);
        assert!(
            matches!(Pie::parse(&invalid), Err(Error::Invalid)),
            "field={field}"
        );
    }
    let mut duplicate = bytes.clone();
    w16(&mut duplicate, 56, 5);
    segment(&mut duplicate, 4, 7, 4, 0x1080, 0x1080, 8, 8);
    assert!(matches!(Pie::parse(&duplicate), Err(Error::Invalid)));
    for info in [16, 17, 18, 36] {
        let mut unsupported = bytes.clone();
        w64(&mut unsupported, 0x1048, info);
        assert!(matches!(Pie::parse(&unsupported), Err(Error::Unsupported)));
    }
    let mut zero = bytes;
    segment(&mut zero, 3, 7, 4, 0, 0x8000, 0, 4096);
    let pie = Pie::parse(&zero).unwrap();
    let mut output = vec![0; pie.output_length().unwrap()];
    pie.write(0x20000000, &mut output).unwrap();
}
