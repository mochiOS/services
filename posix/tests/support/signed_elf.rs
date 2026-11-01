//! Minimal section-bearing ELF used by the production signature codec tests.
pub fn unsigned() -> Vec<u8> {
    let names = b"\0.shstrtab\0.text\0";
    let mut elf = vec![0; 0x100 + 3 * 64];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x80u64.to_le_bytes());
    elf[40..48].copy_from_slice(&0x100u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[58..60].copy_from_slice(&64u16.to_le_bytes());
    elf[60..62].copy_from_slice(&3u16.to_le_bytes());
    elf[62..64].copy_from_slice(&1u16.to_le_bytes());
    elf[0x80..0x84].copy_from_slice(&[0x90, 0x90, 0xc3, 0]);
    elf[0x90..0x90 + names.len()].copy_from_slice(names);
    for (index, name, kind, offset, size, align) in [
        (1, 1u32, 3u32, 0x90u64, names.len() as u64, 1u64),
        (2, 11u32, 1u32, 0x80u64, 4u64, 16u64),
    ] {
        let h = 0x100 + index * 64;
        elf[h..h + 4].copy_from_slice(&name.to_le_bytes());
        elf[h + 4..h + 8].copy_from_slice(&kind.to_le_bytes());
        elf[h + 24..h + 32].copy_from_slice(&offset.to_le_bytes());
        elf[h + 32..h + 40].copy_from_slice(&size.to_le_bytes());
        elf[h + 48..h + 56].copy_from_slice(&align.to_le_bytes());
    }
    elf
}
