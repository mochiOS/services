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

#[test]
fn module_layout_preserves_root_offsets_and_separates_every_alignment_residue() {
    use tls::modules::Plan;
    let root = Template {
        source: 0x400003,
        file_size: 7,
        memory_size: 19,
        alignment: 16,
        residue: 3,
    };
    let root_distance = Layout::new(Some(root), 4096).unwrap().distance;
    for alignment in [1usize, 8, 64, 4096, 8192] {
        for residue in 0..alignment {
            let dependency = Template {
                source: 0x800000 + residue,
                file_size: 13,
                memory_size: 123,
                alignment,
                residue,
            };
            let templates = [Some(root), None, Some(dependency), Some(root)];
            let plan = Plan::new(&templates, 4096).unwrap();
            let modules: Vec<_> = plan.modules().collect();
            assert_eq!(
                modules.iter().map(|m| m.index).collect::<Vec<_>>(),
                [0, 2, 3]
            );
            assert_eq!(modules[0].distance, root_distance);
            for base in [0x100000usize, 0x100003, 0x100fff] {
                let layout = plan.layout();
                let tp = layout.place(base).unwrap().thread_pointer;
                let mut preceding = tp;
                for module in &modules {
                    let start = tp - module.distance;
                    assert_eq!(start % module.template.alignment, module.template.residue);
                    assert!(start >= base);
                    assert!(start + module.template.memory_size <= preceding);
                    preceding = start;
                }
                assert_eq!(tp % alignment.max(16), 0);
                assert!(tp + 8 <= base + layout.mapping_size);
            }
        }
    }
    assert_eq!(
        Plan::new(&[], 4096).unwrap().layout(),
        Layout::new(None, 4096).unwrap()
    );
}

#[test]
fn module_plan_rejects_bad_templates_cumulative_overflow_and_short_mappings() {
    use tls::modules::{InitializeError, Plan};
    let good = Template {
        source: 0x400000,
        file_size: 7,
        memory_size: 16,
        alignment: 16,
        residue: 0,
    };
    for bad in [
        Template {
            file_size: 17,
            ..good
        },
        Template {
            source: usize::MAX - 3,
            ..good
        },
        Template {
            alignment: 3,
            ..good
        },
        Template {
            residue: 16,
            ..good
        },
        Template {
            memory_size: usize::MAX,
            ..good
        },
    ] {
        assert!(Plan::new(&[Some(good), Some(bad)], 4096).is_none());
    }
    let huge = Template {
        memory_size: usize::MAX / 2,
        ..good
    };
    assert!(Plan::new(&[Some(huge), Some(huge), Some(good)], 4096).is_none());
    assert!(Plan::new(&[], 3).is_none());
    let templates = [Some(good)];
    let plan = Plan::new(&templates, 4096).unwrap();
    for (base, size) in [(0x1000, 4095), (usize::MAX - 4094, 4096)] {
        assert_eq!(
            plan.initialize_zeroed::<i32>(
                base,
                size,
                |_, _| panic!("invalid mapping must not be read"),
                |_, _| panic!("invalid mapping must not be written"),
            ),
            Err(InitializeError::InvalidMapping)
        );
    }
}

#[test]
fn real_linker_tls_symbols_address_initialized_and_zero_storage_in_all_modules() {
    use std::{collections::BTreeMap, path::PathBuf, process::Command};
    struct Temporary(PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let temporary = Temporary(std::env::temp_dir().join(format!(
        "mochios-tls-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&temporary.0).unwrap();
    let word = |bytes: &[u8], offset| {
        usize::try_from(u64::from_le_bytes(
            bytes[offset..offset + 8].try_into().unwrap(),
        ))
        .unwrap()
    };
    let mut templates = Vec::new();
    let mut sources = Vec::new();
    let mut symbols = Vec::new();
    for (index, alignment) in [16, 8192, 64].into_iter().enumerate() {
        let output = temporary.0.join(format!("module-{index}.so"));
        let compile = Command::new("x86_64-elf-gcc")
            .args(["-fPIC", "-nostdlib", "-shared", "-Wl,-z,noexecstack"])
            .arg(format!("-DVALUE={}", 31 + index))
            .arg(format!("-DALIGNMENT={alignment}"))
            .arg(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/tls_module_fixture.c"),
            )
            .arg("-o")
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let bytes = std::fs::read(&output).unwrap();
        let table = word(&bytes, 32);
        let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
        let mut template =
            tls::template(table, 56, count, 0, |address, buffer| -> Result<(), i32> {
                buffer.copy_from_slice(bytes.get(address..address + buffer.len()).ok_or(14)?);
                Ok(())
            })
            .unwrap()
            .unwrap();
        // Supply the actual captured bytes at the source address described by
        // PT_TLS. The producer normally maps these bytes through PT_LOAD.
        let header = bytes[table..table + count * 56]
            .chunks_exact(56)
            .find(|header| u32::from_le_bytes(header[..4].try_into().unwrap()) == 7)
            .unwrap();
        let offset = word(header, 8);
        let source = bytes[offset..offset + template.file_size].to_vec();
        template.source = source.as_ptr() as usize;
        sources.push(source);
        templates.push(Some(template));
        let nm = Command::new("x86_64-elf-nm").arg(&output).output().unwrap();
        assert!(nm.status.success());
        let names: BTreeMap<_, _> = String::from_utf8(nm.stdout)
            .unwrap()
            .lines()
            .filter_map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                (fields.len() == 3).then(|| {
                    (
                        fields[2].to_owned(),
                        usize::from_str_radix(fields[0], 16).unwrap(),
                    )
                })
            })
            .collect();
        symbols.push(names);
    }
    let plan = tls::modules::Plan::new(&templates, 4096).unwrap();
    let base = 0x100003;
    let mut mapping = vec![0; plan.layout().mapping_size];
    let tp = plan
        .initialize_zeroed::<i32>(
            base,
            mapping.len(),
            |address, buffer| {
                for source in &sources {
                    let start = source.as_ptr() as usize;
                    if address >= start && address + buffer.len() <= start + source.len() {
                        buffer.copy_from_slice(
                            &source[address - start..address - start + buffer.len()],
                        );
                        return Ok(());
                    }
                }
                Err(14)
            },
            |address, bytes| {
                mapping[address - base..address - base + bytes.len()].copy_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
    for module in plan.modules() {
        let start = tp - module.distance - base;
        let names = &symbols[module.index];
        let initialized = start + names["initialized"];
        let zeroed = start + names["zeroed"];
        assert_eq!(
            &mapping[initialized..initialized + 7],
            &[31 + module.index as u8, 2, 3, 4, 5, 6, 7]
        );
        assert!(mapping[zeroed..zeroed + 8195].iter().all(|&byte| byte == 0));
    }
}
