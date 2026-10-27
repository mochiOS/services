//! Compare real linker-generated dynamic bindings with its symbol/relocation
//! tools. No section-table decoding or duplicate loader implementation here.
#[path = "elf_image_native.rs"]
mod native_image;

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
    let temporary = Temporary(std::env::temp_dir().join(format!(
            "mochios-symbols-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn scoped_real_library_bindings_execute_with_root_preemption_and_eager_plt() {
    use mochios_posix_client::pie::link_scope::{Object, Scope};
    struct Mappings(Vec<(*mut libc::c_void, usize)>);
    impl Drop for Mappings {
        fn drop(&mut self) {
            for &(pointer, length) in self.0.iter().rev() {
                assert_eq!(unsafe { libc::munmap(pointer, length) }, 0);
            }
        }
    }
    impl Mappings {
        fn install(&mut self, image: &[u8]) {
            let count = u16::from_le_bytes(image[56..58].try_into().unwrap()) as usize;
            for header in image[64..64 + count * 56].chunks_exact(56) {
                if header[0] != 1 || word(header, 40) == 0 {
                    continue;
                }
                let address = word(header, 16) as usize;
                let base = address & !4095;
                let length = (address - base + word(header, 40) as usize + 4095) & !4095;
                let pointer = unsafe {
                    libc::mmap(
                        base as *mut _,
                        length,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                        -1,
                        0,
                    )
                };
                assert_ne!(
                    pointer,
                    libc::MAP_FAILED,
                    "{}",
                    std::io::Error::last_os_error()
                );
                self.0.push((pointer, length));
                assert_eq!(pointer as usize, base);
                let offset = word(header, 8) as usize;
                let file = word(header, 32) as usize;
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        image[offset..offset + file].as_ptr(),
                        address as *mut u8,
                        file,
                    );
                }
                let flags = u32::from_le_bytes(header[4..8].try_into().unwrap());
                let protection = if flags & 4 != 0 { libc::PROT_READ } else { 0 }
                    | if flags & 2 != 0 { libc::PROT_WRITE } else { 0 }
                    | if flags & 1 != 0 { libc::PROT_EXEC } else { 0 };
                assert_eq!(unsafe { libc::mprotect(pointer, length, protection) }, 0);
            }
        }
    }
    fn symbols(binary: &std::path::Path) -> BTreeMap<String, u64> {
        let nm = Command::new("x86_64-elf-nm").arg(binary).output().unwrap();
        assert!(nm.status.success());
        String::from_utf8(nm.stdout)
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
            .collect()
    }
    let temporary = Temporary(std::env::temp_dir().join(
        format!("mochios-scope-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()),
    ));
    std::fs::create_dir(&temporary.0).unwrap();
    let library = temporary.0.join("libscope.so");
    let root = temporary.0.join("root");
    for hash in ["sysv", "gnu", "both"] {
        for (source, output, extra) in [
            (
                "elf_scope_dependency.c",
                &library,
                vec!["-Wl,-soname,libscope.so".to_owned()],
            ),
            (
                "elf_scope_root.c",
                &root,
                vec![
                    "-Wl,-e,_start".to_owned(),
                    format!("-L{}", temporary.0.display()),
                    "-l:libscope.so".to_owned(),
                ],
            ),
        ] {
            let result = Command::new("x86_64-elf-gcc")
                .args([
                    "-fPIC",
                    "-ffreestanding",
                    "-fno-stack-protector",
                    "-nostdlib",
                    "-Wl,-shared,-z,noexecstack",
                ])
                .arg(format!("-Wl,--hash-style={hash}"))
                .arg(
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("tests")
                        .join(source),
                )
                .args(extra)
                .arg("-o")
                .arg(output)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        let root_symbols = symbols(&root);
        let library_symbols = symbols(&library);
        let root_bytes = std::fs::read(&root).unwrap();
        let library_bytes = std::fs::read(&library).unwrap();
        assert!(
            Pie::parse(&root_bytes).is_err(),
            "ordinary exec must not ignore DT_NEEDED"
        );
        let root_image = Pie::parse_object(&root_bytes).unwrap();
        let library_image = Pie::parse_object(&library_bytes).unwrap();
        let objects = [
            Object {
                name: b"root",
                image: &root_image,
                bias: 0x20000000,
            },
            Object {
                name: b"libscope.so",
                image: &library_image,
                bias: 0x30000000,
            },
        ];
        let mut order = [0; 2];
        let scope = Scope::new(&objects, &mut order).unwrap();
        let mut outputs = Vec::new();
        for (index, object) in objects.iter().enumerate() {
            let mut bytes = vec![0; object.image.output_length().unwrap()];
            scope.write(index, &mut bytes).unwrap();
            outputs.push(bytes);
        }
        for (image, name, expected) in [
            (
                0,
                "root_shared_pointer",
                0x30000000 + library_symbols["shared_value"],
            ),
            (
                0,
                "root_function_pointer",
                0x30000000 + library_symbols["shared_function"],
            ),
            (0, "root_weak_pointer", 0),
            (
                1,
                "dependency_root_pointer",
                0x20000000 + root_symbols["root_override"],
            ),
            (
                1,
                "dependency_protected_pointer",
                0x30000000 + library_symbols["protected_value"],
            ),
        ] {
            let symbols = if image == 0 {
                &root_symbols
            } else {
                &library_symbols
            };
            assert_eq!(
                loaded(&outputs[image], objects[image].bias + symbols[name]),
                expected,
                "hash={hash} symbol={name}"
            );
        }
        let mut bundle = vec![0xcc; scope.bundle_length().unwrap()];
        assert_eq!(scope.write_bundle(&mut bundle).unwrap(), bundle.len());
        assert_eq!(word(&bundle, 24), 0x20000000 + root_symbols["_start"]);
        let bundle_path = temporary.0.join("bundle.elf");
        std::fs::write(&bundle_path, &bundle).unwrap();
        native_image::assert_captured_image(&bundle_path);
        let mut mappings = Mappings(Vec::new());
        mappings.install(&bundle);
        // Execute only these locally compiled, syscall-free fixture functions.
        // Host mappings test relocation/code behavior, not mochiOS ProcessCreate.
        let shared: extern "C" fn(i32) -> i32 = unsafe {
            std::mem::transmute((0x30000000 + library_symbols["shared_function"]) as usize)
        };
        let entry: extern "C" fn() =
            unsafe { std::mem::transmute((0x20000000 + root_symbols["_start"]) as usize) };
        assert_eq!(shared(2), 91);
        entry();
        assert_eq!(
            unsafe {
                std::ptr::read_volatile((0x20000000 + root_symbols["root_override"]) as *const i32)
            },
            120
        );
        assert_eq!(shared(2), 170);
    }
}
