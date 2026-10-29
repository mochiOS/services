// Small raw images: mapped or unmapped source PHDRs, opaque dynamic records,
// executable entry, read/write data and sparse BSS. No parent-side relocations.
pub const PATH: &[u8] = b"/native/ld-test.so";
pub fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
pub fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
pub fn segment(
    bytes: &mut [u8],
    index: usize,
    kind: u32,
    flags: u32,
    offset: u64,
    address: u64,
    file: u64,
    memory: u64,
) {
    let at = 64 + index * 56;
    bytes[at..at + 4].copy_from_slice(&kind.to_le_bytes());
    bytes[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
    for (i, value) in [offset, address, 0, file, memory, 4096]
        .into_iter()
        .enumerate()
    {
        put64(bytes, at + 8 + i * 8, value);
    }
}
pub fn image(main: bool, fixed: bool, mapped: bool) -> Vec<u8> {
    let mut bytes = vec![0; 0x2100];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put16(&mut bytes, 16, if fixed { 2 } else { 3 });
    put16(&mut bytes, 18, 62);
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    let base = if fixed { 0x400000 } else { 0 };
    put64(&mut bytes, 24, base + 0x1100);
    put64(&mut bytes, 32, 64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    put16(&mut bytes, 56, if main { 5 } else { 4 });
    segment(
        &mut bytes,
        0,
        1,
        5,
        if mapped { 0 } else { 0x1000 },
        base + if mapped { 0 } else { 0x1000 },
        if mapped { 0x1200 } else { 0x200 },
        if mapped { 0x1200 } else { 0x200 },
    );
    segment(&mut bytes, 1, 1, 6, 0x2000, base + 0x3000, 0x100, 0x100000);
    // Dynamic content is deliberately opaque to this launcher (unknown tag).
    segment(&mut bytes, 2, 2, 6, 0x2000, base + 0x3000, 32, 32);
    put64(&mut bytes, 64 + 2 * 56 + 48, 8);
    put64(&mut bytes, 0x2000, 0x7000ffff);
    put64(&mut bytes, 0x2008, 0x123456789abcdef0);
    segment(&mut bytes, 3, 0x6474e551, 6, 0, 0, 0, 0);
    if main {
        segment(
            &mut bytes,
            4,
            3,
            4,
            0x1180,
            base + 0x1180,
            (PATH.len() + 1) as u64,
            (PATH.len() + 1) as u64,
        );
        put64(&mut bytes, 64 + 4 * 56 + 48, 1);
        bytes[0x1180..0x1180 + PATH.len()].copy_from_slice(PATH);
    }
    bytes[0x1100] = 0xc3;
    bytes
}
