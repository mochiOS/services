//! Compare real linker relocations and symbols with the prepared scope.
use mochios_posix_client::{
    pie::{
        Pie,
        link_scope::{Object, Scope},
    },
    static_tls::modules::Plan,
};
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
        let start = word(header, 16);
        if header[0] == 1 && address >= start && address + 8 <= start + word(header, 32) {
            return word(bytes, (word(header, 8) + address - start) as usize);
        }
    }
    panic!("no loaded word {address:x}")
}
#[test]
fn gd_ld_ie_tls_relocations_match_linker_symbols_with_preemption_and_without_sections() {
    let temporary = Temporary(std::env::temp_dir().join(format!(
            "mochios-tls-scope-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
    std::fs::create_dir(&temporary.0).unwrap();
    let binaries = [
        temporary.0.join("root"),
        temporary.0.join("libtls-gd.so"),
        temporary.0.join("libtls-ie.so"),
    ];
    for (dialect, hash) in ["gnu", "gnu2"].into_iter().flat_map(|dialect| {
        ["sysv", "gnu", "both"]
            .into_iter()
            .map(move |hash| (dialect, hash))
    }) {
        for index in [1usize, 2, 0] {
            let mut command = Command::new("x86_64-elf-gcc");
            command
                .args([
                    "-fPIC",
                    "-ffreestanding",
                    "-fno-stack-protector",
                    "-nostdlib",
                    "-Wl,-shared",
                    "-Wl,-z,noexecstack",
                ])
                .arg(format!("-Wl,--hash-style={hash}"))
                .arg(format!("-mtls-dialect={dialect}"))
                .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/elf_tls_fixture.c"));
            if dialect == "gnu2" {
                command.arg("-DTLS_DESCRIPTOR");
            }
            match index {
                1 => {
                    command.args([
                        "-DTLS_GENERAL",
                        "-ftls-model=global-dynamic",
                        "-Wl,-soname,libtls-gd.so",
                    ]);
                }
                2 => {
                    command.args([
                        "-DTLS_INITIAL",
                        "-ftls-model=initial-exec",
                        "-Wl,-soname,libtls-ie.so",
                    ]);
                }
                0 => {
                    command
                        .args(["-DTLS_ROOT", "-Wl,-e,_start"])
                        .arg(format!("-L{}", temporary.0.display()))
                        .args(["-l:libtls-gd.so", "-l:libtls-ie.so"]);
                }
                _ => unreachable!(),
            }
            let result = command.arg("-o").arg(&binaries[index]).output().unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        let symbols: Vec<BTreeMap<String, u64>> = binaries
            .iter()
            .map(|binary| {
                let output = Command::new("x86_64-elf-nm").arg(binary).output().unwrap();
                assert!(output.status.success());
                String::from_utf8(output.stdout)
                    .unwrap()
                    .lines()
                    .filter_map(|line| {
                        let f: Vec<_> = line.split_whitespace().collect();
                        (f.len() == 3)
                            .then(|| (f[2].to_owned(), u64::from_str_radix(f[0], 16).unwrap()))
                    })
                    .collect()
            })
            .collect();
        let relocations: Vec<String> = binaries
            .iter()
            .map(|binary| {
                let output = Command::new("x86_64-elf-readelf")
                    .arg("-rW")
                    .arg(binary)
                    .output()
                    .unwrap();
                assert!(output.status.success());
                String::from_utf8(output.stdout).unwrap()
            })
            .collect();
        for strip in [false, true] {
            let sources: Vec<Vec<u8>> = binaries
                .iter()
                .map(|binary| {
                    let mut bytes = std::fs::read(binary).unwrap();
                    if strip {
                        bytes[40..48].fill(0);
                        bytes[58..64].fill(0);
                    }
                    bytes
                })
                .collect();
            let images: Vec<_> = sources
                .iter()
                .map(|source| Pie::parse_object(source).unwrap())
                .collect();
            let names = [b"root".as_slice(), b"libtls-gd.so", b"libtls-ie.so"];
            let objects: Vec<_> = images
                .iter()
                .enumerate()
                .map(|(index, image)| Object {
                    name: names[index],
                    image,
                    bias: 0x20000000 + (index as u64) * 0x10000000,
                })
                .collect();
            let mut scratch = [0; 3];
            let scope = Scope::new(&objects, &mut scratch).unwrap();
            let templates: Vec<_> = objects
                .iter()
                .map(|object| object.image.tls_template(object.bias).unwrap())
                .collect();
            let plan = Plan::new(&templates, 4096).unwrap();
            let distances: BTreeMap<_, _> = plan
                .modules()
                .map(|module| (module.index, module.distance as u64))
                .collect();
            let mut output = vec![0; scope.bundle_length().unwrap()];
            scope.write_bundle(&mut output).unwrap();
            let mut kinds = BTreeSet::new();
            for (origin, relocations) in relocations.iter().enumerate() {
                for line in relocations.lines() {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    if fields.len() < 4 || !fields[2].starts_with("R_X86_64_") {
                        continue;
                    }
                    let kind = fields[2];
                    let target = u64::from_str_radix(fields[0], 16).unwrap() + objects[origin].bias;
                    let missing = fields.len() >= 7 && fields[4] == "tls_missing";
                    let (owner, symbol) = if missing {
                        (0, 0)
                    } else if fields.len() >= 7 {
                        let name = fields[4];
                        let owner = symbols
                            .iter()
                            .position(|table| table.contains_key(name))
                            .unwrap();
                        (owner, symbols[owner][name])
                    } else {
                        (origin, 0)
                    };
                    let mut addend = u64::from_str_radix(fields.last().unwrap(), 16).unwrap();
                    if fields.get(fields.len() - 2) == Some(&"-") {
                        addend = addend.wrapping_neg();
                    }
                    let expected = match kind {
                        "R_X86_64_TLSDESC" => {
                            let thunk = if missing {
                                "__mochios_tlsdesc_weak"
                            } else {
                                "__mochios_tlsdesc_static"
                            };
                            let argument = if missing {
                                addend
                            } else {
                                symbol.wrapping_add(addend).wrapping_sub(distances[&owner])
                            };
                            assert_eq!(loaded(&output, target + 8), argument);
                            symbols[0][thunk] + objects[0].bias
                        }
                        "R_X86_64_DTPMOD64" => (owner + 1) as u64,
                        "R_X86_64_DTPOFF64" => symbol.wrapping_add(addend),
                        "R_X86_64_TPOFF64" => {
                            symbol.wrapping_add(addend).wrapping_sub(distances[&owner])
                        }
                        "R_X86_64_JUMP_SLOT" | "R_X86_64_GLOB_DAT" => symbol + objects[owner].bias,
                        other => panic!("unexpected relocation {other}"),
                    };
                    kinds.insert(kind);
                    assert_eq!(
                        loaded(&output, target),
                        expected,
                        "hash={hash} stripped={strip} origin={origin}: {line}"
                    );
                }
            }
            assert!(kinds.contains("R_X86_64_TPOFF64"));
            if dialect == "gnu2" {
                assert!(kinds.contains("R_X86_64_TLSDESC"));
                let mut unmarked = sources[0].clone();
                for name in [
                    b"__mochios_tlsdesc_static".as_slice(),
                    b"__mochios_tlsdesc_weak",
                ] {
                    for offset in 0..=unmarked.len() - name.len() {
                        if &unmarked[offset..offset + name.len()] == name {
                            unmarked[offset] = b'X';
                        }
                    }
                }
                let root = Pie::parse_object(&unmarked).unwrap();
                let unmarked_objects = [
                    Object {
                        name: names[0],
                        image: &root,
                        bias: objects[0].bias,
                    },
                    Object {
                        name: names[1],
                        image: &images[1],
                        bias: objects[1].bias,
                    },
                    Object {
                        name: names[2],
                        image: &images[2],
                        bias: objects[2].bias,
                    },
                ];
                let mut scratch = [0; 3];
                let missing_runtime = Scope::new(&unmarked_objects, &mut scratch).unwrap();
                assert_eq!(
                    missing_runtime.write_bundle(&mut output),
                    Err(mochios_posix_client::pie::Error::Unsupported)
                );
            } else {
                assert!(kinds.contains("R_X86_64_DTPMOD64") && kinds.contains("R_X86_64_DTPOFF64"));
            }
        }
    }
}
