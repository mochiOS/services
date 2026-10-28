//! Real PIE imports outside an empty GNU hash, without section-table bounds.
use super::{
    Command, Error, Fixture, PathBuf, Pie, loaded_bytes, symbol, table, tag, w16, w32, w64, word,
};

fn fixture(hash: &str) -> Fixture {
    let mut fixture = Fixture::new(hash, true);
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/copy_root.c");
    // This cross compiler emits GOT imports for PIE. The host oracle uses
    // -fPIC to select the same access model while retaining its host startup.
    for (compiler, leaf, oracle) in [("x86_64-elf-gcc", "root", false), ("cc", "oracle", true)] {
        let mut command = Command::new(compiler);
        command.args([
            if oracle { "-fPIC" } else { "-fPIE" },
            "-pie",
            "-ffreestanding",
            "-fno-stack-protector",
            "-Wl,-z,noexecstack",
        ]);
        if oracle {
            command.arg("-DCOPY_ORACLE");
        } else {
            command.args(["-nostdlib", "-Wl,-e,_start,--no-dynamic-linker"]);
        }
        let result = command
            .arg(&source)
            .arg(format!("-Wl,--hash-style={hash}"))
            .arg(format!("-L{}", fixture.temporary.0.display()))
            .args(["-lcopy", "-Wl,-rpath,$ORIGIN"])
            .arg("-o")
            .arg(fixture.temporary.0.join(leaf))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    fixture.root = std::fs::read(fixture.temporary.0.join("root")).unwrap();
    fixture
}
fn assert_empty_gnu(bytes: &[u8]) {
    let start = table(bytes, 0x6ffffef5);
    let buckets = u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap()) as usize;
    let bloom = u32::from_le_bytes(bytes[start + 8..start + 12].try_into().unwrap()) as usize;
    let start = start + 16 + bloom * 8;
    assert!(
        bytes[start..start + buckets * 4]
            .iter()
            .all(|byte| *byte == 0)
    );
}
fn records(bytes: &[u8], address_tag: u64, size_tag: u64) -> std::ops::Range<usize> {
    let start = table(bytes, address_tag);
    start..start + word(bytes, tag(bytes, size_tag) + 8) as usize
}

#[test]
fn unexported_pie_imports_bind_with_gnu_sysv_and_both_hashes_without_sections() {
    for hash in ["gnu", "both", "sysv"] {
        let fixture = fixture(hash);
        fixture.oracle();
        let result = Command::new("x86_64-elf-readelf")
            .args(["-rW"])
            .arg(fixture.temporary.0.join("root"))
            .output()
            .unwrap();
        assert!(result.status.success());
        let text = String::from_utf8(result.stdout).unwrap();
        assert!(!text.contains("R_X86_64_COPY"));
        assert!(text.contains("R_X86_64_GLOB_DAT") && text.contains("R_X86_64_JUMP_SLOT"));
        if hash != "sysv" {
            assert_empty_gnu(&fixture.root);
        }
        for stripped in [false, true] {
            let mut root = fixture.root.clone();
            let mut library = fixture.library.clone();
            if stripped {
                for bytes in [&mut root, &mut library] {
                    bytes[40..48].fill(0);
                    bytes[58..64].fill(0);
                }
            }
            let output = fixture.prepare(&root, &library).unwrap();
            let path = fixture.temporary.0.join("bundle.elf");
            std::fs::write(&path, &output).unwrap();
            super::super::super::native_image::assert_captured_image(&path);
            assert_eq!(
                super::super::execute(&output),
                42,
                "hash={hash} stripped={stripped}"
            );
        }
    }
}

#[test]
fn either_relocation_table_can_supply_the_required_symbol_prefix() {
    let fixture = fixture("gnu");
    for size_tag in [8, 2] {
        let mut root = fixture.root.clone();
        let offset = tag(&root, size_tag) + 8;
        w64(&mut root, offset, 0);
        assert!(
            fixture.prepare(&root, &fixture.library).is_ok(),
            "size tag={size_tag}"
        );
    }
}

#[test]
fn no_op_relocations_do_not_address_symbol_records_even_with_large_indices() {
    let fixture = fixture("both");
    let hash = table(&fixture.root, 4);
    let count = u32::from_le_bytes(fixture.root[hash + 4..hash + 8].try_into().unwrap());
    for first in [1, count] {
        let mut root = fixture.root.clone();
        let sysv = tag(&root, 4);
        w64(&mut root, sysv, 0x6000_0000);
        let gnu = table(&root, 0x6ffffef5);
        w32(&mut root, gnu + 4, first);
        for range in [records(&root, 7, 8), records(&root, 23, 2)] {
            for offset in range.step_by(24) {
                w64(&mut root, offset + 8, 0xffff_ffff_0000_0000);
            }
        }
        assert!(
            fixture.prepare(&root, &fixture.library).is_ok(),
            "symoffset={first}"
        );
    }
}

#[test]
fn excessive_relocation_indices_are_rejected_before_symbol_or_version_reads() {
    for hash in ["gnu", "both", "sysv"] {
        let fixture = fixture(hash);
        for (address, size) in [(7, 8), (23, 2)] {
            let mut root = fixture.root.clone();
            let first = records(&root, address, size).start;
            let kind = word(&root, first + 8) as u32;
            w64(&mut root, first + 8, 0xffff_ffff_0000_0000 | kind as u64);
            assert!(matches!(
                Pie::parse_object(&root),
                Err(Error::Invalid | Error::Overflow)
            ));
        }
    }
}

#[test]
fn symbol_prefixes_and_empty_hash_offsets_must_fit_captured_load_bytes() {
    let fixture = fixture("gnu");
    let mut root = fixture.root.clone();
    let pointer = tag(&root, 6) + 8;
    let symbols = word(&root, pointer);
    let headers = word(&root, 32) as usize;
    let count = u16::from_le_bytes(root[56..58].try_into().unwrap()) as usize;
    let end = root[headers..headers + count * 56]
        .chunks_exact(56)
        .find_map(|header| {
            let start = word(header, 16);
            let end = start + word(header, 32);
            (header[0] == 1 && symbols >= start && symbols < end).then_some(end)
        })
        .unwrap();
    w64(&mut root, pointer, end - 1);
    assert!(Pie::parse_object(&root).is_err());
    let mut root = fixture.root.clone();
    let start = table(&root, 0x6ffffef5);
    w32(&mut root, start + 4, u32::MAX);
    assert!(Pie::parse_object(&root).is_err());
    let mut root = fixture.root.clone();
    let range = records(&root, 7, 8);
    let size_pointer = tag(&root, 8) + 8;
    w64(&mut root, size_pointer, (range.len() + 1) as u64);
    assert!(Pie::parse_object(&root).is_err());
    assert_ne!(symbols, 0);
}

#[test]
fn an_exact_sysv_count_cannot_be_extended_to_satisfy_invalid_import_indices() {
    let fixture = fixture("both");
    let mut root = fixture.root.clone();
    let hash = table(&root, 4);
    let buckets = u32::from_le_bytes(root[hash..hash + 4].try_into().unwrap()) as usize;
    w32(&mut root, hash + 4, 1);
    root[hash + 8..hash + 8 + (buckets + 1) * 4].fill(0);
    assert_empty_gnu(&root);
    assert!(matches!(Pie::parse_object(&root), Err(Error::Invalid)));
}

#[test]
fn empty_gnu_lookup_does_not_export_a_prefix_symbol_through_the_sysv_table() {
    let fixture = fixture("both");
    let mut root = fixture.root.clone();
    let entry = symbol(&root, b"provider_sum");
    let index = (entry - table(&root, 6)) / 24;
    w16(&mut root, entry + 6, 1);
    w64(&mut root, entry + 8, fixture.root_symbols()["_start"]);
    let version = table(&root, 0x6ffffff0) + index * 2;
    w16(&mut root, version, 1);
    let output = fixture.prepare(&root, &fixture.library).unwrap();
    let relocation = records(&root, 23, 2)
        .step_by(24)
        .find(|offset| (word(&root, *offset + 8) >> 32) as usize == index)
        .unwrap();
    let target = fixture.bias + word(&root, relocation);
    let expected = 0x60000000
        + super::super::super::symbols(&fixture.temporary.0.join("libcopy.so"))["provider_sum"];
    assert_eq!(
        u64::from_le_bytes(loaded_bytes(&output, target, 8).try_into().unwrap()),
        expected
    );
}
