#[path = "../../../user/crates/posix-client/src/static_tls.rs"]
mod tls;
use tls::{Error, Layout, Template};

fn header(kind: u32, offset: u64, address: u64, file: u64, memory: u64, align: u64) -> [u8; 56] {
    let mut bytes = [0; 56];
    bytes[..4].copy_from_slice(&kind.to_le_bytes());
    for (position, value) in [
        (8, offset),
        (16, address),
        (32, file),
        (40, memory),
        (48, align),
    ] {
        bytes[position..position + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn parse(headers: &[[u8; 56]]) -> Result<Option<Template>, Error<i32>> {
    tls::template(0x1000, 56, headers.len(), 0, |address, bytes| {
        let offset = address - 0x1000;
        bytes.copy_from_slice(&headers.get(offset / 56).ok_or(14)?[..]);
        Ok(())
    })
}

#[test]
fn reads_file_backed_template_and_does_not_require_tbss_in_load() {
    let result = parse(&[
        header(7, 0x1203, 0x401203, 7, 8192, 64),
        header(1, 0x1000, 0x401000, 0x400, 0x400, 4096),
    ])
    .unwrap()
    .unwrap();
    assert_eq!(
        result,
        Template {
            source: 0x401203,
            file_size: 7,
            memory_size: 8192,
            alignment: 64,
            residue: 3
        }
    );
}

#[test]
fn rejects_duplicate_tls_bad_alignment_and_unbacked_templates() {
    let load = header(1, 0x1000, 0x401000, 0x400, 0x400, 4096);
    let good = header(7, 0x1200, 0x401200, 16, 32, 16);
    assert_eq!(parse(&[load, good, good]), Err(Error::InvalidImage));
    for bad in [
        header(7, 0x1200, 0x401200, 33, 32, 16),
        header(7, 0x1200, 0x401200, 16, 32, 3),
        header(7, 0x1201, 0x401200, 16, 32, 16),
        header(7, 0x13ff, 0x4013ff, 2, 32, 16),
        header(7, u64::MAX, 0x401200, 16, 32, 16),
        header(7, 0x1200, u64::MAX, 16, 32, 16),
    ] {
        assert_eq!(parse(&[load, bad]), Err(Error::InvalidImage));
    }
}

#[test]
fn handles_no_tls_and_zero_initialized_only_tls() {
    assert_eq!(parse(&[header(1, 0, 0x400000, 4096, 4096, 4096)]), Ok(None));
    for align in [0, 1, 64] {
        let result = parse(&[header(7, 0, 0x800000, 0, 32, align)])
            .unwrap()
            .unwrap();
        assert_eq!(result.alignment, (align as usize).max(1));
        assert_eq!(result.file_size, 0);
    }
}

#[test]
fn preserves_reader_errors_bounds_and_extended_stride() {
    assert_eq!(
        tls::template(4096, 56, 1, 0, |_, _| Err(14)),
        Err(Error::Read(14))
    );
    for (address, stride, count) in [
        (0, 56, 1),
        (1, 55, 1),
        (1, 56, 0),
        (usize::MAX - 55, 56, 1),
        (1, 56, 65536),
        (1, 65536, 1),
    ] {
        assert_eq!(
            tls::template(address, stride, count, 0, |_, _| -> Result<(), i32> {
                panic!("invalid extent must not be read")
            }),
            Err(Error::InvalidImage)
        );
    }
    let table = [header(0, 0, 0, 0, 0, 0), header(7, 0, 0x403003, 0, 128, 64)];
    let mut calls = Vec::new();
    let result = tls::template(
        4096,
        128,
        2,
        0x200000,
        |address, bytes| -> Result<(), i32> {
            calls.push(address);
            bytes.copy_from_slice(&table[(address - 4096) / 128]);
            Ok(())
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(calls, [4096, 4224]);
    assert_eq!(result.source, 0x603003);
    assert_eq!(result.residue, 3);
}

#[test]
fn variant_two_layout_matches_linker_offsets_for_all_alignment_residues() {
    for alignment in [1usize, 2, 8, 16, 64, 4096, 8192] {
        for residue in 0..alignment {
            for memory_size in [0usize, 1, 7, 64, 4097] {
                let template = Template {
                    source: 0x400000 + residue,
                    file_size: 0,
                    memory_size,
                    alignment,
                    residue,
                };
                let layout = Layout::new(Some(template), 4096).unwrap();
                // Include non-page-aligned bases to exercise alignment slack.
                for base in [0x100000usize, 0x100003, 0x100fff] {
                    let placed = layout.place(base).unwrap();
                    assert!(placed.data >= base);
                    assert_eq!(placed.data % alignment, residue);
                    assert_eq!(placed.thread_pointer % alignment.max(8), 0);
                    assert!(placed.data + memory_size <= placed.thread_pointer);
                    assert!(placed.thread_pointer + 8 <= base + layout.mapping_size);
                    let lld_offset = -(memory_size as i64)
                        - ((0usize.wrapping_sub(residue).wrapping_sub(memory_size))
                            & (alignment - 1)) as i64;
                    assert_eq!(
                        placed.data as i64 - placed.thread_pointer as i64,
                        lld_offset
                    );
                }
            }
        }
    }
}

#[test]
fn empty_tcb_and_overflow_rejection() {
    let empty = Layout::new(None, 4096).unwrap();
    assert_eq!(empty.distance, 0);
    assert_eq!(empty.mapping_size, 4096);
    assert_eq!(empty.place(0x1000).unwrap().thread_pointer, 0x1000);
    assert_eq!(empty.place(usize::MAX - 4095), None);
    for (memory_size, alignment, residue) in [
        (usize::MAX, 8, 0),
        (1, 3, 0),
        (1, 8, 8),
        (usize::MAX - 7, 8, 0),
    ] {
        assert_eq!(
            Layout::new(
                Some(Template {
                    source: 0,
                    file_size: 0,
                    memory_size,
                    alignment,
                    residue
                }),
                4096
            ),
            None
        );
    }
    assert_eq!(Layout::new(None, 3), None);
}
