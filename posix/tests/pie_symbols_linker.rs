//! Compare real linker-generated dynamic bindings with its symbol/relocation
//! tools. No section-table decoding or duplicate loader implementation here.
use mochios_posix_client::pie::Pie;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    process::Command,
};
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn loaded(bytes: &[u8], address: u64) -> u64 {
    let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    for header in bytes[64..64 + count * 56].chunks_exact(56) {
        let base = word(header, 16);
        if header[0] == 1 && address >= base && address + 8 <= base + word(header, 32) {
            return word(bytes, (word(header, 8) + address - base) as usize);
        }
    }
    panic!("not loaded: {address:x}");
}

#[test]
fn real_dynamic_bindings_match_linker_symbols_for_both_hash_formats_without_sections() {
    let temporary = Temporary(
        std::env::temp_dir().join(format!(
            "mochios-symbols-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )),
    );
    std::fs::create_dir(&temporary.0).unwrap();
    let binary = temporary.0.join("image");
    for hash in ["sysv", "gnu", "both"] {
        let compile = Command::new("x86_64-elf-gcc")
            .args([
                "-fPIC",
                "-ffreestanding",
                "-fno-stack-protector",
                "-nostdlib",
                "-Wl,-shared,-e,_start,-z,noexecstack",
            ])
            .arg(format!("-Wl,--hash-style={hash}"))
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/elf_symbol_fixture.c"))
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let nm = Command::new("x86_64-elf-nm").arg(&binary).output().unwrap();
        assert!(nm.status.success());
        let symbols: BTreeMap<_, _> = String::from_utf8(nm.stdout)
            .unwrap()
            .lines()
            .filter_map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                (fields.len() == 3).then(|| {
                    (
                        fields[2].to_owned(),
                        u64::from_str_radix(fields[0], 16).unwrap(),
                    )
                })
            })
            .collect();
        let relocations = Command::new("x86_64-elf-readelf")
            .arg("-rW")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(relocations.status.success());
        let relocations = String::from_utf8(relocations.stdout).unwrap();
        let bytes = std::fs::read(&binary).unwrap();
        for strip_sections in [false, true] {
            let mut source = bytes.clone();
            if strip_sections {
                source[40..48].fill(0);
                source[58..64].fill(0);
            }
            let pie = Pie::parse(&source).unwrap();
            let bias = 0x20000000u64;
            let mut output = vec![0; pie.output_length().unwrap()];
            pie.write(bias, &mut output).unwrap();
            let mut kinds = BTreeSet::new();
            for line in relocations.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() < 7 || !fields[2].starts_with("R_X86_64_") {
                    continue;
                }
                let target = u64::from_str_radix(fields[0], 16).unwrap();
                let name = fields[4];
                let symbol = match name {
                    "symbol_value" | "symbol_function" => bias + symbols[name],
                    "missing_data" | "missing_function" => 0,
                    other => panic!("unexpected reference {other}"),
                };
                let expected = match fields[2] {
                    "R_X86_64_64" => {
                        symbol.wrapping_add(u64::from_str_radix(fields[6], 16).unwrap())
                    }
                    "R_X86_64_GLOB_DAT" | "R_X86_64_JUMP_SLOT" => symbol,
                    other => panic!("unexpected relocation {other}"),
                };
                kinds.insert(fields[2]);
                assert_eq!(
                    loaded(&output, bias + target),
                    expected,
                    "hash={hash} symbol={name}"
                );
            }
            assert_eq!(
                kinds,
                BTreeSet::from(["R_X86_64_64", "R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT"])
            );
            for (name, expected) in [
                ("symbol_pointer", bias + symbols["symbol_value"]),
                ("function_pointer", bias + symbols["symbol_function"]),
                ("weak_pointer", 0),
                ("absolute_pointer", 0x1234),
            ] {
                assert_eq!(
                    loaded(&output, bias + symbols[name]),
                    expected,
                    "hash={hash} pointer={name}"
                );
            }
        }
    }
}
