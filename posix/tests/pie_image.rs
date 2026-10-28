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
fn rejects_interpreters_dependencies_unresolvable_relocations_and_overlapping_fixups() {
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

fn relr_image(words: &[u64], rela: Option<u64>) -> Vec<u8> {
    let mut bytes = image();
    // Keep both tables outside the dynamic array and inside its backing LOAD.
    let mut tags = vec![(36, 0x10a0), (35, words.len() as u64 * 8), (37, 8)];
    if let Some(target) = rela {
        tags.extend([(7, 0x1080), (8, 24), (9, 24)]);
        w64(&mut bytes, 0x1080, target);
        w64(&mut bytes, 0x1088, 8);
        w64(&mut bytes, 0x1090, 0x180);
    }
    tags.push((0, 0));
    segment(
        &mut bytes,
        2,
        2,
        6,
        0x1000,
        0x1000,
        tags.len() as u64 * 16,
        tags.len() as u64 * 16,
    );
    for (index, (tag, value)) in tags.into_iter().enumerate() {
        w64(&mut bytes, 0x1000 + index * 16, tag);
        w64(&mut bytes, 0x1008 + index * 16, value);
    }
    for (index, word) in words.iter().enumerate() {
        w64(&mut bytes, 0x10a0 + index * 8, *word);
    }
    bytes
}

fn loaded_word(output: &[u8], address: u64) -> u64 {
    let count = u16::from_le_bytes(output[56..58].try_into().unwrap()) as usize;
    for index in 0..count {
        let header = 64 + index * 56;
        let base = r64(output, header + 16);
        if output[header] == 1 && address >= base && address + 8 <= base + r64(output, header + 32)
        {
            return r64(output, (r64(output, header + 8) + address - base) as usize);
        }
    }
    panic!("not file-backed: {address:x}");
}

#[test]
fn relr_bitmaps_advance_over_empty_words_and_materialize_only_needed_bss() {
    let mut bytes = relr_image(&[0x10e0, 0b1011, 3, 1, 1 | (1 << 63)], Some(0x1200));
    w64(&mut bytes, 0x10e0, 0x180);
    w64(&mut bytes, 0x10e8, (-0x40000000i64) as u64);
    w64(&mut bytes, 0x10f8, u64::MAX);
    let source = bytes.clone();
    let pie = Pie::parse(&bytes).unwrap();
    let bias = 0x20000000u64;
    let mut output = vec![0; pie.output_length().unwrap()];
    pie.write(bias, &mut output).unwrap();
    for (target, addend) in [
        (0x10e0, 0x180),
        (0x10e8, (-0x40000000i64) as u64),
        (0x10f8, u64::MAX),
        (0x12e0, 0),
        (0x18c0, 0),
        (0x1200, 0x180),
    ] {
        assert_eq!(
            loaded_word(&output, bias + target),
            bias.wrapping_add(addend),
            "target={target:x}"
        );
    }
    // Unselected words stay unchanged and the rest of the BSS stays demand-zero.
    assert_eq!(loaded_word(&output, bias + 0x10f0), 0);
    assert_eq!(loaded_word(&output, bias + 0x12e8), 0);
    assert_eq!(r64(&output, 64 + 3 * 56 + 32), 0x8c8);
    assert_eq!(r64(&output, 64 + 3 * 56 + 40), 0x3000);
    assert_eq!(bytes, source);
}

#[test]
fn relr_implicit_addends_can_straddle_file_and_zero_fill() {
    let mut bytes = relr_image(&[0x10fc], None);
    bytes[0x10fc..].copy_from_slice(&0x12345678u32.to_le_bytes());
    let pie = Pie::parse(&bytes).unwrap();
    let mut output = vec![0; pie.output_length().unwrap()];
    pie.write(0x20000000, &mut output).unwrap();
    assert_eq!(loaded_word(&output, 0x200010fc), 0x32345678);
}

#[test]
fn relr_rejects_missing_duplicate_malformed_and_unbacked_tables() {
    for offset in [0x1000, 0x1010, 0x1020] {
        let mut bytes = relr_image(&[0x10e0], None);
        w64(&mut bytes, offset, 0x60000000); // Remove each required tag.
        assert!(matches!(Pie::parse(&bytes), Err(Error::Invalid)));
    }
    for tag in [35, 36, 37] {
        let mut bytes = relr_image(&[0x10e0], None);
        w64(&mut bytes, 0x1030, tag);
        w64(&mut bytes, 64 + 2 * 56 + 32, 80);
        assert!(matches!(Pie::parse(&bytes), Err(Error::Invalid)));
    }
    for (offset, value) in [
        (0x1008, 0x3ff8),
        (0x1018, 9),
        (0x1028, 16),
        (0x1008, u64::MAX),
    ] {
        let mut bytes = relr_image(&[0x10e0], None);
        w64(&mut bytes, offset, value);
        assert!(Pie::parse(&bytes).is_err());
    }
    assert!(Pie::parse(&relr_image(&[], None)).is_ok());
}

#[test]
fn relr_rejects_bitmap_without_base_overflow_outside_load_and_overlapping_writes() {
    for words in [
        vec![1],
        vec![3],
        vec![0x3ffc],
        vec![0x10e0, 0x10e0],
        vec![0x10e0, 0x10e2],
        vec![0x10e0, 3, 0x10e8],
        vec![0x3ff8, 3],
        vec![u64::MAX - 1],
    ] {
        assert!(
            Pie::parse(&relr_image(&words, None)).is_err(),
            "words={words:x?}"
        );
    }
    for target in [0x10e0, 0x10df, 0x10e7, 0x12e0] {
        assert!(matches!(
            Pie::parse(&relr_image(&[0x10e0, 3, 3], Some(target))),
            Err(Error::Invalid)
        ));
    }
    // Unsorted but disjoint direct entries are legal.
    assert!(Pie::parse(&relr_image(&[0x1200, 0x10e0], None)).is_ok());
}

#[test]
fn dense_relr_bitmaps_keep_unreferenced_bss_out_of_the_prepared_file() {
    let mut bytes = relr_image(&[0x8000], None);
    bytes.resize(0x2000, 0);
    segment(&mut bytes, 1, 1, 6, 0x1000, 0x1000, 0x1000, 0x30000);
    w64(&mut bytes, 0x1008, 0x1100);
    w64(&mut bytes, 0x1018, 129 * 8);
    w64(&mut bytes, 0x1100, 0x8000);
    for index in 1..129 {
        w64(&mut bytes, 0x1100 + index * 8, u64::MAX);
    }
    let pie = Pie::parse(&bytes).unwrap();
    let mut output = vec![0; pie.output_length().unwrap()];
    pie.write(0x20000000, &mut output).unwrap();
    for index in 0..=128 * 63 {
        assert_eq!(loaded_word(&output, 0x20008000 + index * 8), 0x20000000);
    }
    assert_eq!(r64(&output, 64 + 3 * 56 + 40), 0x30000);
    assert!(output.len() < 0x20000);
}

fn symbol_image(kind: u32, gnu: bool, plt: bool) -> Vec<u8> {
    let mut bytes = image();
    bytes.resize(0x1500, 0);
    segment(&mut bytes, 1, 1, 6, 0x1000, 0x1000, 0x500, 0x3000);
    let tags = [
        (
            if gnu { 0x6ffffef5 } else { 4 },
            if gnu { 0x1160 } else { 0x10c0 },
        ),
        (5, 0x1140),
        (6, 0x1100),
        (10, 8),
        (11, 24),
        (if plt { 23 } else { 7 }, 0x10a0),
        (if plt { 2 } else { 8 }, 24),
        (if plt { 20 } else { 9 }, if plt { 7 } else { 24 }),
        (0, 0),
    ];
    segment(&mut bytes, 2, 2, 6, 0x1000, 0x1000, 144, 144);
    for (index, (tag, value)) in tags.into_iter().enumerate() {
        w64(&mut bytes, 0x1000 + index * 16, tag);
        w64(&mut bytes, 0x1008 + index * 16, value);
    }
    w64(&mut bytes, 0x10a0, 0x1300);
    w64(&mut bytes, 0x10a8, (1u64 << 32) | kind as u64);
    w64(&mut bytes, 0x10b0, 0x55);
    for (index, value) in [1, 2, 1, 0, 0].into_iter().enumerate() {
        w32(&mut bytes, 0x10c0 + index * 4, value);
    }
    w32(&mut bytes, 0x1118, 1);
    bytes[0x111c] = 0x11; // GLOBAL OBJECT
    w16(&mut bytes, 0x111e, 1);
    w64(&mut bytes, 0x1120, 0x1200);
    w64(&mut bytes, 0x1128, 8);
    bytes[0x1140..0x1148].copy_from_slice(b"\0symbol\0");
    for (index, value) in [1, 1, 1, 5, 0, 0, 1, 1].into_iter().enumerate() {
        w32(&mut bytes, 0x1160 + index * 4, value);
    }
    bytes
}

fn relocated_symbol(bytes: &[u8]) -> Result<u64, Error> {
    let pie = Pie::parse(bytes)?;
    let mut output = vec![0; pie.output_length()?];
    pie.write(0x20000000, &mut output)?;
    Ok(loaded_word(&output, 0x20001300))
}

#[test]
fn symbols_bind_defined_absolute_and_unresolved_weak_values_with_correct_addends() {
    for gnu in [false, true] {
        for (kind, plt) in [(1, false), (6, false), (7, true)] {
            let mut bytes = symbol_image(kind, gnu, plt);
            let addend = if kind == 1 { 0x55 } else { 0 };
            assert_eq!(relocated_symbol(&bytes), Ok(0x20001200 + addend));
            w16(&mut bytes, 0x111e, 0xfff1); // SHN_ABS must not receive bias.
            w64(&mut bytes, 0x1120, u64::MAX - 3);
            assert_eq!(
                relocated_symbol(&bytes),
                Ok((u64::MAX - 3).wrapping_add(addend))
            );
            w16(&mut bytes, 0x111e, 0); // Undefined weak binds zero, even if st_value is nonzero.
            bytes[0x111c] = 0x21;
            assert_eq!(relocated_symbol(&bytes), Ok(addend));
            bytes[0x111c] = 0x11;
            assert_eq!(relocated_symbol(&bytes), Err(Error::Unsupported));
            w64(&mut bytes, 0x10a8, kind as u64); // Symbol zero has absolute value zero.
            assert_eq!(relocated_symbol(&bytes), Ok(addend));
        }
    }
}

#[test]
fn symbols_reject_invalid_indices_names_extents_and_unsupported_resolution_rules() {
    for gnu in [false, true] {
        for (offset, value) in [
            (0x10a8, (2u64 << 32) | 1),
            (0x1120, 0x5000),
            (0x1128, u64::MAX),
        ] {
            let mut bytes = symbol_image(1, gnu, false);
            w64(&mut bytes, offset, value);
            assert!(relocated_symbol(&bytes).is_err());
        }
        let mut bytes = symbol_image(1, gnu, false);
        w32(&mut bytes, 0x1118, 8);
        assert_eq!(relocated_symbol(&bytes), Err(Error::Invalid));
        for info in [0x16, 0x1a, 0xa1] {
            // TLS, IFUNC, GNU_UNIQUE
            let mut bytes = symbol_image(1, gnu, false);
            bytes[0x111c] = info;
            assert_eq!(relocated_symbol(&bytes), Err(Error::Unsupported));
        }
        for section in [0xfff2, 0xffff] {
            let mut bytes = symbol_image(1, gnu, false);
            w16(&mut bytes, 0x111e, section);
            assert_eq!(relocated_symbol(&bytes), Err(Error::Unsupported));
        }
        let mut bytes = symbol_image(1, gnu, false);
        w64(&mut bytes, 0x1080, 0x6ffffff0); // DT_VERSYM cannot be ignored.
        w64(&mut bytes, 64 + 2 * 56 + 32, 160);
        assert_eq!(relocated_symbol(&bytes), Err(Error::Unsupported));
    }
}

#[test]
fn symbol_tables_use_bounded_hash_counts_and_complete_dynamic_metadata() {
    for (gnu, offset, value) in [
        (false, 0x10c0, 0),
        (false, 0x10c4, 0),
        (false, 0x10c8, 2),
        (false, 0x10d0, 2),
        (true, 0x1160, 0),
        (true, 0x1164, 0),
        (true, 0x1168, 0),
        (true, 0x1168, 3),
        (true, 0x1178, u32::MAX),
        (true, 0x117c, 0),
    ] {
        let mut bytes = symbol_image(1, gnu, false);
        w32(&mut bytes, offset, value);
        assert!(
            relocated_symbol(&bytes).is_err(),
            "gnu={gnu} offset={offset:x}"
        );
    }
    for offset in [0x1000, 0x1010, 0x1020, 0x1030, 0x1040] {
        let mut bytes = symbol_image(1, false, false);
        w64(&mut bytes, offset, 0x60000000);
        assert!(relocated_symbol(&bytes).is_err());
    }
    for (offset, value) in [(0x1018, 0x3fff), (0x1028, 0x3ff8), (0x1038, 0), (0x1048, 8)] {
        let mut bytes = symbol_image(1, false, false);
        w64(&mut bytes, offset, value);
        assert!(relocated_symbol(&bytes).is_err());
    }
    for offset in [0x1100, 0x1140, 0x1147] {
        let mut bytes = symbol_image(1, false, false);
        bytes[offset] = 1;
        assert_eq!(relocated_symbol(&bytes), Err(Error::Invalid));
    }
    // Both hash formats may coexist, but must agree on the symbol count.
    let mut bytes = symbol_image(1, false, false);
    w64(&mut bytes, 0x1080, 0x6ffffef5);
    w64(&mut bytes, 0x1088, 0x1160);
    w64(&mut bytes, 0x1090, 0);
    w64(&mut bytes, 64 + 2 * 56 + 32, 160);
    assert_eq!(relocated_symbol(&bytes), Ok(0x20001255));
    w32(&mut bytes, 0x1164, 2);
    w32(&mut bytes, 0x1178, 2);
    assert_eq!(relocated_symbol(&bytes), Err(Error::Invalid));
}

#[test]
fn eager_plt_validates_its_metadata_and_overlaps_with_other_relocations() {
    for (offset, value) in [
        (0x1050, 0x60000000),
        (0x1060, 0x60000000),
        (0x1070, 0x60000000),
        (0x1058, 0x3ff8),
        (0x1068, 25),
        (0x1078, 17),
    ] {
        let mut bytes = symbol_image(7, false, true);
        w64(&mut bytes, offset, value);
        assert!(relocated_symbol(&bytes).is_err());
    }
    let mut bytes = symbol_image(7, false, true);
    bytes.resize(0x1600, 0);
    segment(&mut bytes, 1, 1, 6, 0x1000, 0x1000, 0x600, 0x3000);
    // Give RELA a separate table, writing the same word as PLT.
    let tags = [(7, 0x1500), (8, 24), (9, 24), (0, 0)];
    for (i, (tag, value)) in tags.into_iter().enumerate() {
        w64(&mut bytes, 0x1480 + i * 16, tag);
        w64(&mut bytes, 0x1488 + i * 16, value);
    }
    // Extend the dynamic array into an unused part of the same LOAD.
    let dynamic = bytes[0x1000..0x1080].to_vec();
    bytes[0x1400..0x1480].copy_from_slice(&dynamic);
    segment(&mut bytes, 2, 2, 6, 0x1400, 0x1400, 192, 192);
    w64(&mut bytes, 0x1500, 0x1300);
    w64(&mut bytes, 0x1508, 8);
    assert_eq!(relocated_symbol(&bytes), Err(Error::Invalid));
}

fn with_needed(mut bytes: Vec<u8>, names: &[&[u8]]) -> Vec<u8> {
    bytes.resize(0x1800, 0);
    segment(&mut bytes, 1, 1, 6, 0x1000, 0x1000, 0x800, 0x3000);
    let dynamic = bytes[0x1000..0x1080].to_vec();
    bytes[0x1400..0x1480].copy_from_slice(&dynamic);
    // Relocate the string table so extra dependency names cannot alias hash data.
    bytes[0x1200..0x1208].copy_from_slice(b"\0symbol\0");
    w64(&mut bytes, 0x1418, 0x1200);
    let mut length = 8;
    for (index, name) in names.iter().enumerate() {
        w64(&mut bytes, 0x1480 + index * 16, 1);
        w64(&mut bytes, 0x1488 + index * 16, length as u64);
        bytes[0x1200 + length..0x1200 + length + name.len()].copy_from_slice(name);
        length += name.len() + 1;
    }
    w64(&mut bytes, 0x1438, length as u64);
    w64(&mut bytes, 0x1480 + names.len() * 16, 0);
    segment(
        &mut bytes,
        2,
        2,
        6,
        0x1400,
        0x1400,
        144 + names.len() as u64 * 16,
        144 + names.len() as u64 * 16,
    );
    bytes
}

#[test]
fn link_scope_derives_breadth_first_order_and_deduplicates_shared_cycles() {
    use mochios_posix_client::pie::link_scope::{Object, Scope};
    let mut root = with_needed(symbol_image(1, false, false), &[b"first", b"second"]);
    w16(&mut root, 0x111e, 0); // Strong reference supplied by another object.
    let mut first = with_needed(symbol_image(1, false, false), &[b"leaf"]);
    first[0x111c] = 0x21; // First definition wins even when weak at runtime.
    let second = with_needed(symbol_image(1, false, false), &[b"leaf"]);
    let leaf = with_needed(symbol_image(1, false, false), &[b"first"]);
    assert!(matches!(Pie::parse(&root), Err(Error::Unsupported)));
    let images: Vec<_> = [&root, &second, &leaf, &first]
        .into_iter()
        .map(|bytes| Pie::parse_object(bytes).unwrap())
        .collect();
    let objects: Vec<_> = [b"root".as_slice(), b"second", b"leaf", b"first"]
        .into_iter()
        .zip(&images)
        .enumerate()
        .map(|(index, (name, image))| Object {
            name,
            image,
            bias: 0x20000000 + index as u64 * 0x1000000,
        })
        .collect();
    let mut scratch = [0; 4];
    let scope = Scope::new(&objects, &mut scratch).unwrap();
    assert_eq!(scope.order(), &[0, 3, 1, 2]);
    let mut output = vec![0; images[0].output_length().unwrap()];
    scope.write(0, &mut output).unwrap();
    assert_eq!(loaded_word(&output, 0x20001300), 0x23001255);
    assert_eq!(
        images[0].write(0x20000000, &mut output),
        Err(Error::Unsupported)
    );
}

#[test]
fn link_scope_keeps_hidden_protected_local_and_symbolic_bindings_local() {
    use mochios_posix_client::pie::link_scope::{Object, Scope};
    for mode in [0, 1, 2, 3, 4, 5] {
        let root = with_needed(symbol_image(1, false, false), &[b"dep"]);
        let mut dep = symbol_image(1, false, false);
        if mode <= 3 {
            dep[0x111d] = mode;
        }
        if mode == 4 {
            w64(&mut dep, 0x1080, 16); // DT_SYMBOLIC
            w64(&mut dep, 64 + 2 * 56 + 32, 160);
        }
        if mode == 5 {
            dep[0x111c] = 1;
        } // STB_LOCAL
        let root = Pie::parse_object(&root).unwrap();
        let dep = Pie::parse_object(&dep).unwrap();
        let objects = [
            Object {
                name: b"root",
                image: &root,
                bias: 0x20000000,
            },
            Object {
                name: b"dep",
                image: &dep,
                bias: 0x30000000,
            },
        ];
        let mut scratch = [0; 2];
        let scope = Scope::new(&objects, &mut scratch).unwrap();
        let mut output = vec![0; dep.output_length().unwrap()];
        scope.write(1, &mut output).unwrap();
        assert_eq!(
            loaded_word(&output, 0x30001300),
            if mode == 0 { 0x20001255 } else { 0x30001255 }
        );
    }
}

#[test]
fn link_scope_rejects_missing_duplicate_unreachable_and_overlapping_objects() {
    use mochios_posix_client::pie::link_scope::{Object, Scope};
    let root = with_needed(symbol_image(1, false, false), &[b"dep"]);
    let root = Pie::parse_object(&root).unwrap();
    let dep = symbol_image(1, false, false);
    let dep = Pie::parse_object(&dep).unwrap();
    for (name, bias) in [
        (b"missing".as_slice(), 0x30000000),
        (b"root", 0x30000000),
        (b"dep", 0x20000000),
        (b"dep", 0x30000001),
        (b"dep", 0x800000000000),
        (b"dep", 0),
    ] {
        let objects = [
            Object {
                name: b"root",
                image: &root,
                bias: 0x20000000,
            },
            Object {
                name,
                image: &dep,
                bias,
            },
        ];
        assert!(Scope::new(&objects, &mut [0; 2]).is_err());
    }
    let objects = [Object {
        name: b"root",
        image: &root,
        bias: 0x20000000,
    }];
    assert!(Scope::new(&objects, &mut [0]).is_err());
    let objects = [
        Object {
            name: b"root",
            image: &dep,
            bias: 0x20000000,
        },
        Object {
            name: b"unused",
            image: &dep,
            bias: 0x30000000,
        },
    ];
    assert!(Scope::new(&objects, &mut [0; 2]).is_err());
    assert!(Scope::new(&objects, &mut [0]).is_err());
}

#[test]
fn link_scope_skips_nonexported_symbols_and_bounds_corrupt_hash_cycles() {
    use mochios_posix_client::pie::link_scope::{Object, Scope};
    let mut root = with_needed(symbol_image(1, false, false), &[b"hidden", b"visible"]);
    w16(&mut root, 0x111e, 0);
    let mut hidden = symbol_image(0, false, false); // No relocation references its hidden TLS symbol.
    hidden[0x111c] = 0x16;
    hidden[0x111d] = 2;
    let visible = symbol_image(1, false, false);
    let images: Vec<_> = [&root, &hidden, &visible]
        .into_iter()
        .map(|bytes| Pie::parse_object(bytes).unwrap())
        .collect();
    let objects: Vec<_> = [b"root".as_slice(), b"hidden", b"visible"]
        .into_iter()
        .zip(&images)
        .enumerate()
        .map(|(index, (name, image))| Object {
            name,
            image,
            bias: 0x20000000 + index as u64 * 0x1000000,
        })
        .collect();
    let mut scratch = [0; 3];
    let scope = Scope::new(&objects, &mut scratch).unwrap();
    let mut output = vec![0; images[0].output_length().unwrap()];
    scope.write(0, &mut output).unwrap();
    assert_eq!(loaded_word(&output, 0x20001300), 0x22001255);

    let mut root = with_needed(symbol_image(1, false, false), &[b"dep"]);
    w16(&mut root, 0x111e, 0);
    // The unresolved root's chain points to itself. Lookup must fail boundedly.
    w32(&mut root, 0x10d0, 1);
    let dep = symbol_image(1, false, false);
    let root = Pie::parse_object(&root).unwrap();
    let dep = Pie::parse_object(&dep).unwrap();
    let objects = [
        Object {
            name: b"root",
            image: &root,
            bias: 0x20000000,
        },
        Object {
            name: b"dep",
            image: &dep,
            bias: 0x30000000,
        },
    ];
    let mut scratch = [0; 2];
    let scope = Scope::new(&objects, &mut scratch).unwrap();
    let mut output = vec![0; root.output_length().unwrap()];
    assert_eq!(scope.write(0, &mut output), Err(Error::Invalid));
}

#[test]
fn link_scope_rejects_dependency_tls_until_a_module_layout_is_available() {
    use mochios_posix_client::pie::link_scope::{Object, Scope};
    let root = with_needed(symbol_image(1, false, false), &[b"dep"]);
    let root = Pie::parse_object(&root).unwrap();
    let dep = tls_image();
    let dep = Pie::parse_object(&dep).unwrap();
    let objects = [
        Object {
            name: b"root",
            image: &root,
            bias: 0x20000000,
        },
        Object {
            name: b"dep",
            image: &dep,
            bias: 0x30000000,
        },
    ];
    assert!(matches!(
        Scope::new(&objects, &mut [0; 2]),
        Err(Error::Unsupported)
    ));
}

#[test]
fn combined_scope_preserves_member_phdr_views_permissions_and_sparse_bss() {
    use mochios_posix_client::pie::link_scope::{Object, Scope};
    let root = with_needed(symbol_image(1, false, false), &[b"dep"]);
    let dep = symbol_image(1, false, false);
    let source_root = root.clone();
    let source_dep = dep.clone();
    let images = [
        Pie::parse_object(&root).unwrap(),
        Pie::parse_object(&dep).unwrap(),
    ];
    let objects = [
        Object {
            name: b"root",
            image: &images[0],
            bias: 0x20000000,
        },
        Object {
            name: b"dep",
            image: &images[1],
            bias: 0x30000000,
        },
    ];
    let mut order = [0; 2];
    let scope = Scope::new(&objects, &mut order).unwrap();
    let length = scope.bundle_length().unwrap();
    assert!(length < 0xc000);
    let mut output = vec![0xcc; length + 16];
    assert_eq!(
        scope.write_bundle(&mut output[..length - 1]),
        Err(Error::BufferTooSmall)
    );
    assert!(output.iter().all(|byte| *byte == 0xcc));
    assert_eq!(scope.write_bundle(&mut output).unwrap(), length);
    assert!(output[length..].iter().all(|byte| *byte == 0xcc));
    assert_eq!(r64(&output, 24), 0x20000180);
    let count = u16::from_le_bytes(output[56..58].try_into().unwrap()) as usize;
    assert_eq!(count, 8); // Global LOAD/PHDR + two member metadata/code/data LOADs.
    assert_eq!(r64(&output, 64 + 16), 0x1fffe000);
    assert_eq!(r64(&output, 120 + 16), 0x1fffe040);
    let mut ranges = Vec::new();
    for header in output[64..64 + count * 56].chunks_exact(56) {
        if header[0] != 1 {
            continue;
        }
        let address = r64(header, 16);
        let file = r64(header, 32);
        let memory = r64(header, 40);
        let flags = u32::from_le_bytes(header[4..8].try_into().unwrap());
        assert_ne!(flags & 3, 3);
        assert!(r64(header, 8) + file <= length as u64);
        if address == 0x20001000 || address == 0x30001000 {
            assert!(memory > file);
        }
        ranges.push((address, address + memory));
    }
    ranges.sort_unstable();
    assert!(ranges.windows(2).all(|pair| pair[0].1 <= pair[1].0));
    for (index, object) in objects.iter().enumerate() {
        let executable = images[index].executable(object.bias).unwrap();
        assert_eq!(
            loaded_word(&output, executable.program_headers),
            r64(if index == 0 { &root } else { &dep }, 64)
        );
        assert_eq!(loaded_word(&output, object.bias + 0x1300), 0x20001255);
    }
    assert_eq!(root, source_root);
    assert_eq!(dep, source_dep);
}

#[test]
fn combined_scope_requires_executable_root_and_room_for_global_metadata() {
    use mochios_posix_client::pie::link_scope::{Object, Scope};
    let mut bytes = symbol_image(1, false, false);
    for (entry, bias) in [(0x1300, 0x20000000), (0x180, 0x401000)] {
        w64(&mut bytes, 24, entry);
        let image = Pie::parse_object(&bytes).unwrap();
        let objects = [Object {
            name: b"root",
            image: &image,
            bias,
        }];
        let mut order = [0];
        let scope = Scope::new(&objects, &mut order).unwrap();
        assert_eq!(scope.bundle_length(), Err(Error::Invalid));
        assert_eq!(scope.write_bundle(&mut [0; 8192]), Err(Error::Invalid));
    }
}

#[test]
fn combined_scope_rejects_program_header_count_that_needs_extended_numbering() {
    use mochios_posix_client::pie::link_scope::{Object, Scope};
    let count = 65533usize;
    let mut bytes = vec![0; 64 + count * 56];
    bytes[..64].copy_from_slice(&image()[..64]);
    w16(&mut bytes, 56, count as u16);
    let length = bytes.len() as u64;
    segment(&mut bytes, 0, 1, 5, 0, 0, length, length);
    for index in 1..count {
        w32(&mut bytes, 64 + index * 56, 0x6474e550); // Retained, empty unwind headers.
    }
    let image = Pie::parse_object(&bytes).unwrap();
    let objects = [Object {
        name: b"root",
        image: &image,
        bias: 0x20000000,
    }];
    let mut order = [0];
    let scope = Scope::new(&objects, &mut order).unwrap();
    assert_eq!(scope.bundle_length(), Err(Error::Invalid));
}

#[test]
fn direct_scope_requires_supported_startup_and_conservative_placement() {
    for (tags, supported) in [
        (&[(12, 0x180)][..], false),
        (&[(13, 0x180)][..], false),
        (&[(25, 0x1500), (27, 8)][..], false),
        (&[(26, 0x1500), (28, 8)][..], false),
        (&[(32, 0x1500), (33, 8)][..], false),
        (&[(29, 0)][..], true),
        (&[(15, 0)][..], true),
        (&[(12, 0)][..], true),
        (&[(25, 0), (27, 0)][..], true),
    ] {
        let bytes = with_lifecycle(symbol_image(1, false, false), tags);
        let image = Pie::parse_object(&bytes).unwrap();
        assert_eq!(
            image.validate_direct_scope_startup().is_ok(),
            supported,
            "tags={tags:?}"
        );
    }
    let bytes = tls_image();
    let image = Pie::parse_object(&bytes).unwrap();
    let (bias, end) = image.placement(0x20000001).unwrap();
    assert_eq!(bias % image.alignment(), 0);
    assert!(bias >= 0x20001001 && end > bias);
    assert!(image.placement(u64::MAX).is_err());
}

fn with_lifecycle(mut bytes: Vec<u8>, tags: &[(u64, u64)]) -> Vec<u8> {
    let offset = r64(&bytes, 64 + 2 * 56 + 8) as usize;
    let length = r64(&bytes, 64 + 2 * 56 + 32) as usize;
    let original: Vec<_> = bytes[offset..offset + length]
        .chunks_exact(16)
        .take_while(|entry| r64(entry, 0) != 0)
        .flatten()
        .copied()
        .collect();
    bytes.resize(0x2000, 0);
    segment(&mut bytes, 1, 1, 6, 0x1000, 0x1000, 0x1000, 0x3000);
    bytes[0x1800..0x1800 + original.len()].copy_from_slice(&original);
    for (index, &(tag, value)) in tags.iter().enumerate() {
        let at = 0x1800 + original.len() + index * 16;
        w64(&mut bytes, at, tag);
        w64(&mut bytes, at + 8, value);
    }
    let length = (original.len() + (tags.len() + 1) * 16) as u64;
    segment(&mut bytes, 2, 2, 6, 0x1800, 0x1800, length, length);
    bytes
}

#[test]
fn lifecycle_metadata_rejects_duplicates_incomplete_pairs_and_invalid_load_ranges() {
    for tags in [
        vec![(12, 0), (12, 0)],
        vec![(13, 0), (13, 0)],
        vec![(12, 0x200)],
        vec![(13, 0x1500)],
        vec![(12, u64::MAX)],
        vec![(25, 0x1500)],
        vec![(27, 8)],
        vec![(26, 0x1500)],
        vec![(28, 8)],
        vec![(32, 0x1500)],
        vec![(33, 8)],
        vec![(25, 0x1501), (27, 8)],
        vec![(25, 0x1500), (27, 7)],
        vec![(25, 0x3ff8), (27, 16)],
        vec![(25, 0x8000), (27, 8)],
        vec![(25, u64::MAX - 7), (27, 8)],
    ] {
        let bytes = with_lifecycle(image(), &tags);
        assert!(Pie::parse_object(&bytes).is_err(), "{tags:?}");
    }
    for (address, size) in [(25, 27), (26, 28), (32, 33)] {
        for duplicate in [address, size] {
            let bytes = with_lifecycle(image(), &[(address, 0), (size, 0), (duplicate, 0)]);
            assert!(matches!(Pie::parse_object(&bytes), Err(Error::Invalid)));
        }
        let mut unreadable = with_lifecycle(image(), &[(address, 0x1500), (size, 8)]);
        w32(&mut unreadable, 64 + 56 + 4, 2);
        assert!(matches!(
            Pie::parse_object(&unreadable),
            Err(Error::Invalid)
        ));
    }
    // A table may be in zero-fill memory; its elements are examined only after
    // relocations have materialized their pointers in the prepared image.
    let bytes = with_lifecycle(image(), &[(25, 0x3000), (27, 8)]);
    assert!(Pie::parse_object(&bytes).is_ok());
}

#[test]
fn lifecycle_uses_dependency_postorder_instead_of_reversing_symbol_search() {
    use mochios_posix_client::pie::link_scope::{Object, Scope};
    for cycle in [false, true] {
        let bytes = [
            with_needed(symbol_image(1, false, false), &[b"first", b"second"]),
            with_needed(symbol_image(1, false, false), &[b"first", b"leaf"]),
            with_needed(
                symbol_image(1, false, false),
                if cycle { &[b"first"] } else { &[] },
            ),
            with_needed(symbol_image(1, false, false), &[b"leaf"]),
        ];
        let images: Vec<_> = bytes
            .iter()
            .map(|bytes| Pie::parse_object(bytes).unwrap())
            .collect();
        let objects: Vec<_> = [b"root".as_slice(), b"second", b"leaf", b"first"]
            .into_iter()
            .zip(&images)
            .enumerate()
            .map(|(index, (name, image))| Object {
                name,
                image,
                bias: 0x20000000 + index as u64 * 0x1000000,
            })
            .collect();
        let mut search = [0; 4];
        let scope = Scope::new(&objects, &mut search).unwrap();
        assert_eq!(scope.order(), [0, 3, 1, 2]);
        assert!(matches!(
            scope.lifecycle(&mut [0; 15]),
            Err(Error::BufferTooSmall)
        ));
        let mut scratch = [usize::MAX; 16];
        let plan = scope.lifecycle(&mut scratch).unwrap();
        assert_eq!(plan.order(), [2, 3, 1, 0]);
        let mut steps = Vec::new();
        plan.initializers(|step| steps.push(step)).unwrap();
        plan.finalizers(|step| steps.push(step)).unwrap();
        assert!(steps.is_empty());
        for object in &objects {
            assert!(plan.is_callable(object.bias + 0x180));
            assert!(!plan.is_callable(object.bias + 0x1300));
            assert!(!plan.is_callable(object.bias + 0x200));
        }
        assert!(!plan.is_callable(0) && !plan.is_callable(u64::MAX));
    }
}

#[test]
fn lifecycle_plans_root_preinit_init_before_arrays_and_reverse_fini_before_function() {
    use mochios_posix_client::pie::link_scope::{Object, Scope, Step};
    let tags = [
        (12, 0x180),
        (13, 0x190),
        (25, 0x1500),
        (27, 16),
        (26, 0x1510),
        (28, 24),
    ];
    let mut root_tags = tags.to_vec();
    root_tags.extend([(32, 0x1528), (33, 8)]);
    let bytes = [
        with_lifecycle(
            with_needed(symbol_image(1, false, false), &[b"dep"]),
            &root_tags,
        ),
        with_lifecycle(symbol_image(1, false, false), &tags),
    ];
    let images: Vec<_> = bytes
        .iter()
        .map(|bytes| Pie::parse_object(bytes).unwrap())
        .collect();
    let objects = [
        Object {
            name: b"root",
            image: &images[0],
            bias: 0x20000000,
        },
        Object {
            name: b"dep",
            image: &images[1],
            bias: 0x30000000,
        },
    ];
    let mut search = [0; 2];
    let scope = Scope::new(&objects, &mut search).unwrap();
    let mut scratch = [0; 8];
    let plan = scope.lifecycle(&mut scratch).unwrap();
    let mut steps = Vec::new();
    plan.initializers(|step| steps.push(step)).unwrap();
    assert_eq!(
        steps,
        [
            Step::Array {
                object: 0,
                address: 0x20001528,
                count: 1,
                reverse: false
            },
            Step::Function {
                object: 1,
                address: 0x30000180
            },
            Step::Array {
                object: 1,
                address: 0x30001500,
                count: 2,
                reverse: false
            },
            Step::Function {
                object: 0,
                address: 0x20000180
            },
            Step::Array {
                object: 0,
                address: 0x20001500,
                count: 2,
                reverse: false
            },
        ]
    );
    steps.clear();
    plan.finalizers(|step| steps.push(step)).unwrap();
    assert_eq!(
        steps,
        [
            Step::Array {
                object: 0,
                address: 0x20001510,
                count: 3,
                reverse: true
            },
            Step::Function {
                object: 0,
                address: 0x20000190
            },
            Step::Array {
                object: 1,
                address: 0x30001510,
                count: 3,
                reverse: true
            },
            Step::Function {
                object: 1,
                address: 0x30000190
            },
        ]
    );
    let invalid_dependency = with_lifecycle(symbol_image(1, false, false), &root_tags);
    let dependency = Pie::parse_object(&invalid_dependency).unwrap();
    let invalid_objects = [
        Object {
            name: b"root",
            image: &images[0],
            bias: 0x20000000,
        },
        Object {
            name: b"dep",
            image: &dependency,
            bias: 0x30000000,
        },
    ];
    let scope = Scope::new(&invalid_objects, &mut search).unwrap();
    assert!(matches!(
        scope.lifecycle(&mut scratch),
        Err(Error::Unsupported)
    ));
}

#[test]
fn search_metadata_validates_string_offsets_duplicates_and_runpath_presence() {
    let mut bytes = symbol_image(1, false, false);
    w64(&mut bytes, 0x1080, 15);
    w64(&mut bytes, 0x1088, 1); // "symbol"
    w64(&mut bytes, 0x1090, 29);
    w64(&mut bytes, 0x1098, 0); // An explicitly empty RUNPATH still shadows RPATH.
    // Move the relocation table so the extended dynamic array cannot alias it.
    let relocation = bytes[0x10a0..0x10b8].to_vec();
    bytes[0x1180..0x1198].copy_from_slice(&relocation);
    w64(&mut bytes, 0x1058, 0x1180);
    w64(&mut bytes, 0x10a0, 0);
    w64(&mut bytes, 64 + 2 * 56 + 32, 176);
    let image = Pie::parse_object(&bytes).unwrap();
    let paths = image.search_paths().unwrap();
    assert_eq!(paths.rpath, Some(b"symbol".as_slice()));
    assert_eq!(paths.runpath, Some(b"".as_slice()));
    w64(&mut bytes, 0x1090, 15);
    assert!(matches!(Pie::parse_object(&bytes), Err(Error::Invalid)));
    w64(&mut bytes, 0x1090, 29);
    w64(&mut bytes, 0x1098, 8);
    assert!(matches!(Pie::parse_object(&bytes), Err(Error::Invalid)));
}
