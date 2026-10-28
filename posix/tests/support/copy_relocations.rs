use super::{
    Error, Mappings, Object, PathBuf, Pie, Scope, Temporary, file_offset, table, tag, w16, w32,
    w64, word,
};
use std::process::Command;

struct Fixture {
    temporary: Temporary,
    root: Vec<u8>,
    library: Vec<u8>,
    bias: u64,
}
impl Fixture {
    fn new(hash: &str, pie: bool) -> Self {
        let temporary = Temporary(std::env::temp_dir().join(format!(
                "mochios-copy-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )));
        std::fs::create_dir(&temporary.0).unwrap();
        let support = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support");
        let library = temporary.0.join("libcopy.so");
        super::compile(
            &support.join("copy_library.c"),
            &library,
            hash,
            &[
                "-Wl,-soname,libcopy.so".to_owned(),
                format!(
                    "-Wl,--version-script={}",
                    support.join("copy_library.map").display()
                ),
            ],
        );
        let common = [
            format!("-L{}", temporary.0.display()),
            "-lcopy".to_owned(),
            "-Wl,-rpath,$ORIGIN".to_owned(),
            format!("-Wl,--hash-style={hash}"),
        ];
        for (compiler, leaf, oracle) in [
            (if pie { "cc" } else { "x86_64-elf-gcc" }, "root", false),
            ("cc", "oracle", true),
        ] {
            let mut command = Command::new(compiler);
            command.args([
                if pie { "-fPIE" } else { "-fno-pic" },
                if pie { "-pie" } else { "-no-pie" },
                "-fno-stack-protector",
                "-ffreestanding",
                "-Wl,-z,noexecstack",
            ]);
            if oracle {
                command.arg("-DCOPY_ORACLE");
            } else {
                command.args(["-nostdlib", "-Wl,-e,_start,--no-dynamic-linker"]);
            }
            let result = command
                .arg(support.join("copy_root.c"))
                .args(&common)
                .arg("-o")
                .arg(temporary.0.join(leaf))
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        Self {
            root: std::fs::read(temporary.0.join("root")).unwrap(),
            library: std::fs::read(library).unwrap(),
            temporary,
            bias: if pie { 0x50000000 } else { 0 },
        }
    }
    fn oracle(&self) {
        let result = Command::new(self.temporary.0.join("oracle"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "GNU oracle: {:?} {}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        );
    }
    fn prepare(&self, root: &[u8], library: &[u8]) -> Result<Vec<u8>, Error> {
        let root = Pie::parse_object(root)?;
        let library = Pie::parse_object(library)?;
        let objects = [
            Object {
                name: b"root",
                image: &root,
                bias: self.bias,
            },
            Object {
                name: b"libcopy.so",
                image: &library,
                bias: 0x60000000,
            },
        ];
        let mut order = [0; 2];
        let scope = Scope::new(&objects, &mut order)?;
        let mut output = vec![0; scope.bundle_length()?];
        scope.write_bundle(&mut output)?;
        Ok(output)
    }
    fn root_symbols(&self) -> std::collections::BTreeMap<String, u64> {
        super::super::symbols(&self.temporary.0.join("root"))
    }
}
fn symbol(bytes: &[u8], name: &[u8]) -> usize {
    let hash = table(bytes, 4);
    let count = u32::from_le_bytes(bytes[hash + 4..hash + 8].try_into().unwrap()) as usize;
    let entries = table(bytes, 6);
    let strings = table(bytes, 5);
    (0..count)
        .map(|index| entries + index * 24)
        .find(|&offset| {
            let start = strings
                + u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            bytes.get(start..start + name.len()) == Some(name)
                && bytes.get(start + name.len()) == Some(&0)
        })
        .expect("fixture symbol")
}
fn copy_record(bytes: &[u8], name: &[u8]) -> usize {
    let entry = symbol(bytes, name);
    let index = (entry - table(bytes, 6)) / 24;
    let start = table(bytes, 7);
    let size = word(bytes, tag(bytes, 8) + 8) as usize;
    (start..start + size)
        .step_by(24)
        .find(|offset| word(bytes, *offset + 8) == ((index as u64) << 32) | 5)
        .expect("COPY fixture")
}
fn loaded_bytes(bytes: &[u8], address: u64, length: usize) -> &[u8] {
    let offset = file_offset(bytes, address);
    &bytes[offset..offset + length]
}

#[test]
fn copies_variable_sized_versioned_data_after_provider_relocation_with_canonical_addresses() {
    for pie in [false, true] {
        for hash in ["sysv", "gnu", "both"] {
            let fixture = Fixture::new(hash, pie);
            fixture.oracle();
            let relocations = Command::new("x86_64-elf-readelf")
                .args(["-rW"])
                .arg(fixture.temporary.0.join("root"))
                .output()
                .unwrap();
            assert!(relocations.status.success());
            let text = String::from_utf8(relocations.stdout).unwrap();
            assert_eq!(text.matches("R_X86_64_COPY").count(), 6);
            assert!(text.contains("api_data@API_1") && text.contains("api_data@API_2"));
            for stripped in [false, true] {
                let mut root = fixture.root.clone();
                let mut library = fixture.library.clone();
                if stripped {
                    for bytes in [&mut root, &mut library] {
                        bytes[40..48].fill(0);
                        bytes[58..64].fill(0);
                    }
                }
                let bundle = fixture.prepare(&root, &library).unwrap();
                super::super::native_image::assert_captured_image(&{
                    let path = fixture.temporary.0.join("bundle.elf");
                    std::fs::write(&path, &bundle).unwrap();
                    path
                });
                assert_eq!(
                    super::execute(&bundle),
                    42,
                    "pie={pie} hash={hash} stripped={stripped}"
                );
            }
        }
    }
}

#[test]
fn independent_root_output_copies_the_same_relocated_initializers_as_the_bundle() {
    let fixture = Fixture::new("both", true);
    let root = Pie::parse_object(&fixture.root).unwrap();
    let library = Pie::parse_object(&fixture.library).unwrap();
    let objects = [
        Object {
            name: b"root",
            image: &root,
            bias: fixture.bias,
        },
        Object {
            name: b"libcopy.so",
            image: &library,
            bias: 0x60000000,
        },
    ];
    let mut order = [0; 2];
    let scope = Scope::new(&objects, &mut order).unwrap();
    let mut output = vec![0; root.output_length().unwrap()];
    scope.write(0, &mut output).unwrap();
    let bundle = fixture.prepare(&fixture.root, &fixture.library).unwrap();
    for (name, length) in [
        ("copy_box", 32),
        ("copy_self", 16),
        ("copy_zero", 8193),
        ("copy_partial", 7),
    ] {
        let address =
            fixture.bias + word(&fixture.root, symbol(&fixture.root, name.as_bytes()) + 8);
        assert_eq!(
            loaded_bytes(&output, address, length),
            loaded_bytes(&bundle, address, length),
            "{name}"
        );
    }
    let before = fixture.root_symbols();
    assert_eq!(
        super::super::loaded(&output, fixture.bias + before["copy_box@API_2"]),
        fixture.bias + before["api_data@API_1"]
    );
}

#[test]
fn source_size_changes_are_bounded_and_partial_pointer_fixups_are_copied_byte_exactly() {
    let fixture = Fixture::new("both", true);
    let target = fixture.bias + word(&fixture.root, symbol(&fixture.root, b"copy_partial") + 8);
    for length in [3, 11] {
        let mut library = fixture.library.clone();
        let entry = symbol(&library, b"copy_partial");
        w64(&mut library, entry + 16, length);
        let bundle = fixture.prepare(&fixture.root, &library).unwrap();
        assert_eq!(
            loaded_bytes(&bundle, target, 7),
            if length == 3 {
                b"abc\0\0\0\0"
            } else {
                b"abcdefg"
            }
        );
    }
    let mut root = fixture.root.clone();
    let entry = symbol(&root, b"copy_box");
    w64(&mut root, entry + 16, 5);
    let bundle = fixture.prepare(&root, &fixture.library).unwrap();
    let pointer = fixture.bias + fixture.root_symbols()["api_data@API_1"];
    let address = fixture.bias + word(&root, entry + 8);
    assert_eq!(
        loaded_bytes(&bundle, address, 5),
        &pointer.to_le_bytes()[..5]
    );
}

#[test]
fn malformed_copy_ranges_kinds_symbols_and_overlaps_are_rejected() {
    let fixture = Fixture::new("both", true);
    let entry = symbol(&fixture.root, b"copy_box");
    let relocation = copy_record(&fixture.root, b"copy_box");
    let mut changes = Vec::new();
    let mut bytes = fixture.root.clone();
    w64(&mut bytes, entry + 16, u64::MAX);
    changes.push(bytes);
    let mut bytes = fixture.root.clone();
    w64(&mut bytes, relocation, word(&fixture.root, relocation) + 1);
    changes.push(bytes);
    let mut bytes = fixture.root.clone();
    bytes[entry + 4] = 0x12;
    changes.push(bytes); // Function.
    let mut bytes = fixture.root.clone();
    bytes[entry + 4] = 0x16;
    changes.push(bytes); // TLS.
    let mut bytes = fixture.root.clone();
    bytes[entry + 4] = 0x01;
    changes.push(bytes); // Local.
    let mut bytes = fixture.root.clone();
    bytes[entry + 5] = 2;
    changes.push(bytes);
    let mut bytes = fixture.root.clone();
    w16(&mut bytes, entry + 6, 0);
    changes.push(bytes);
    let mut bytes = fixture.root.clone();
    w64(&mut bytes, relocation + 8, 5);
    changes.push(bytes);
    let mut bytes = fixture.root.clone();
    w64(&mut bytes, relocation + 8, 0);
    changes.push(bytes); // Import cannot silently become a definition.
    for bytes in changes {
        assert!(Pie::parse_object(&bytes).is_err());
    }
    // Make an in-LOAD destination overlap the next copy by exactly one byte.
    let mut root = fixture.root.clone();
    let start = table(&root, 7);
    let size = word(&root, tag(&root, 8) + 8) as usize;
    let mut copies: Vec<_> = (start..start + size)
        .step_by(24)
        .filter(|offset| word(&root, *offset + 8) as u32 == 5)
        .map(|offset| {
            (
                word(&root, offset),
                (word(&root, offset + 8) >> 32) as usize,
            )
        })
        .collect();
    copies.sort();
    let entry = table(&root, 6) + copies[0].1 * 24;
    w64(&mut root, entry + 16, copies[1].0 - copies[0].0 + 1);
    assert!(Pie::parse_object(&root).is_err());
    let mut root = fixture.root.clone();
    let address = word(&root, relocation);
    for index in 0..u16::from_le_bytes(root[56..58].try_into().unwrap()) as usize {
        let header = word(&root, 32) as usize + index * 56;
        if root[header] == 1
            && address >= word(&root, header + 16)
            && address < word(&root, header + 16) + word(&root, header + 40)
        {
            w32(&mut root, header + 4, 4);
        }
    }
    assert!(Pie::parse_object(&root).is_err());
}

#[test]
fn sources_must_be_external_data_definitions_and_only_the_root_can_contain_copy() {
    let fixture = Fixture::new("both", true);
    for action in 0..4 {
        let mut library = fixture.library.clone();
        let entry = symbol(&library, b"copy_box");
        match action {
            0 => w32(&mut library, entry, 0),
            1 => library[entry + 4] = 0x12,
            2 => library[entry + 5] = 3,
            _ => w64(&mut library, entry + 16, u64::MAX),
        }
        assert!(
            fixture.prepare(&fixture.root, &library).is_err(),
            "action={action}"
        );
    }
    assert!(Pie::parse(&fixture.root).is_err());
    let root = Pie::parse_object(&fixture.root).unwrap();
    let objects = [
        Object {
            name: b"root",
            image: &root,
            bias: fixture.bias,
        },
        Object {
            name: b"libcopy.so",
            image: &root,
            bias: 0x70000000,
        },
    ];
    assert!(Scope::new(&objects, &mut [0; 2]).is_err());
}

#[test]
fn undefined_weak_copy_keeps_destination_bytes_and_missing_strong_copy_fails_before_emission() {
    let fixture = Fixture::new("both", true);
    let mut library = fixture.library.clone();
    let entry = symbol(&library, b"copy_partial");
    w32(&mut library, entry, 0);
    assert!(fixture.prepare(&fixture.root, &library).is_err());
    library[entry + 4] = 0x21; // The provider's own reference must also be weak.
    let mut root = fixture.root.clone();
    let entry = symbol(&root, b"copy_partial");
    root[entry + 4] = 0x21;
    let bundle = fixture.prepare(&root, &library).unwrap();
    let address = fixture.bias + word(&root, entry + 8);
    assert_eq!(loaded_bytes(&bundle, address, 7), &[0; 7]);
}

#[test]
fn zero_sized_copies_and_ignored_addends_do_not_write_beyond_their_declared_ranges() {
    let fixture = Fixture::new("both", true);
    let mut root = fixture.root.clone();
    let relocation = copy_record(&root, b"copy_partial");
    w64(&mut root, relocation + 16, u64::MAX);
    let bundle = fixture.prepare(&root, &fixture.library).unwrap();
    assert_eq!(super::execute(&bundle), 42);
    let entry = symbol(&root, b"copy_partial");
    w64(&mut root, entry + 16, 0);
    assert!(fixture.prepare(&root, &fixture.library).is_ok());
}
