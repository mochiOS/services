//! Real GNU linker output and independent ELF-table reads verify SIZE32/64.
//! These fixtures contain no native syscalls; all files are private to a test.
use mochios_posix_client::pie::{
    Error, Pie,
    link_scope::{Object, Scope},
};
use std::{path::PathBuf, process::Command};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "support/pie_mappings.rs"]
mod host_mappings;
struct Fixture {
    directory: PathBuf,
    bytes: Vec<Vec<u8>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
fn run(command: &mut Command) -> String {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{:?}: status={} stdout={} stderr={}",
        command,
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
impl Fixture {
    fn new(hash: &str, preempt: bool) -> Self {
        Self::build(hash, preempt, false)
    }
    fn build(hash: &str, preempt: bool, weak_defined: bool) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "mochios-size-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let mut fixture = Self {
            directory,
            bytes: Vec::new(),
        };
        let directory = &fixture.directory;
        let source =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/elf_symbol_sizes.S");
        for (name, define) in [
            ("libprovider.so", "PROVIDER"),
            ("libconsumer.so", "CONSUMER"),
            ("root.so", "ROOT"),
        ] {
            let mut c = Command::new("x86_64-elf-gcc");
            c.args(["-fPIC", "-nostdlib", "-Wl,-shared", "-Wl,-z,noexecstack"])
                .arg(format!("-Wl,--hash-style={hash}"))
                .arg(format!("-D{define}"))
                .arg(&source)
                .arg(format!("-L{}", directory.display()));
            if name == "libconsumer.so" {
                c.args([
                    "-Wl,-soname,libconsumer.so",
                    "-Wl,--no-as-needed",
                    "-l:libprovider.so",
                ]);
            } else if name == "root.so" {
                if weak_defined {
                    c.arg("-DWEAK_DEFINED");
                }
                c.args([
                    "-Wl,-e,_start",
                    "-Wl,--no-as-needed",
                    "-l:libconsumer.so",
                    "-l:libprovider.so",
                ]);
                if preempt {
                    c.arg("-DPREEMPT");
                }
            } else {
                c.arg("-Wl,-soname,libprovider.so");
            }
            run(c.arg("-o").arg(directory.join(name)));
        }
        let bytes = ["root.so", "libconsumer.so", "libprovider.so"]
            .iter()
            .map(|name| std::fs::read(directory.join(name)).unwrap())
            .collect();
        fixture.bytes = bytes;
        fixture
    }
    fn symbols(&self) -> std::collections::BTreeMap<String, u64> {
        run(Command::new("x86_64-elf-nm").arg(self.directory.join("libconsumer.so")))
            .lines()
            .filter_map(|line| {
                let f: Vec<_> = line.split_whitespace().collect();
                (f.len() == 3).then(|| (f[2].into(), u64::from_str_radix(f[0], 16).unwrap()))
            })
            .collect()
    }
}
fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn put(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn file_offset(bytes: &[u8], address: u64, length: u64) -> usize {
    let base = word(bytes, 32) as usize;
    let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    for h in bytes[base..base + count * 56].chunks_exact(56) {
        let start = word(h, 16);
        if h[0] == 1 && address >= start && address + length <= start + word(h, 32) {
            return (word(h, 8) + address - start) as usize;
        }
    }
    panic!("no file bytes at {address:x} length {length}")
}
fn relocated(bytes: &[u8], address: u64, length: usize) -> u64 {
    let start = file_offset(bytes, address, length as u64);
    let mut value = [0; 8];
    value[..length].copy_from_slice(&bytes[start..start + length]);
    u64::from_le_bytes(value)
}
fn rela(bytes: &[u8], kind: u32) -> usize {
    let base = word(bytes, 32) as usize;
    let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    let h = bytes[base..base + count * 56]
        .chunks_exact(56)
        .find(|h| h[0] == 2)
        .unwrap();
    let dynamic = word(h, 8) as usize;
    let length = word(h, 32) as usize;
    let mut table = 0;
    let mut size = 0;
    for d in bytes[dynamic..dynamic + length].chunks_exact(16) {
        match word(d, 0) {
            7 => table = word(d, 8),
            8 => size = word(d, 8),
            0 => break,
            _ => {}
        }
    }
    let offset = file_offset(bytes, table, size);
    (offset..offset + size as usize)
        .step_by(24)
        .find(|p| word(bytes, *p + 8) as u32 == kind)
        .unwrap()
}
fn prepare(bytes: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
    let images: Vec<_> = bytes
        .iter()
        .map(|b| Pie::parse_object(b))
        .collect::<Result<_, _>>()?;
    let names = [b"root.so".as_slice(), b"libconsumer.so", b"libprovider.so"];
    let objects: Vec<_> = images
        .iter()
        .enumerate()
        .map(|(i, image)| Object {
            name: names[i],
            image,
            bias: 0x20000000 + (i as u64) * 0x10000000,
        })
        .collect();
    let mut scratch = [0; 3];
    let scope = Scope::new(&objects, &mut scratch)?;
    let mut out = vec![0; scope.bundle_length()?];
    scope.write_bundle(&mut out)?;
    Ok(out)
}

#[test]
fn real_size_relocations_follow_scope_preemption_and_preserve_adjacent_bytes() {
    for hash in ["sysv", "gnu", "both"] {
        for preempt in [false, true] {
            let f = Fixture::new(hash, preempt);
            let symbols = f.symbols();
            let relocations = run(Command::new("x86_64-elf-readelf")
                .arg("-rW")
                .arg(f.directory.join("libconsumer.so")));
            assert!(
                relocations.contains("R_X86_64_SIZE32") && relocations.contains("R_X86_64_SIZE64"),
                "{relocations}"
            );
            for strip in [false, true] {
                let mut bytes = f.bytes.clone();
                if strip {
                    for b in &mut bytes {
                        b[40..48].fill(0);
                        b[58..64].fill(0);
                    }
                }
                let out = prepare(&bytes).unwrap();
                let size = if preempt { 41u64 } else { 23 };
                let bias = 0x30000000;
                for (name, n, expected) in [
                    ("size64", 8, size + 7),
                    ("size32", 4, size - 3),
                    ("canary", 4, 0xdeadbeef),
                    ("weak_size", 8, 5),
                    ("absolute_size", 8, 94),
                    ("tls_size", 8, 22),
                    ("wrap_size", 8, size.wrapping_sub(60)),
                ] {
                    assert_eq!(
                        relocated(&out, bias + symbols[name], n),
                        expected,
                        "{hash}, preempt={preempt}, sections={}, {name}",
                        !strip
                    );
                }
                #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                {
                    let mut mapping = host_mappings::Mappings::default();
                    mapping.install(&out);
                    // Only code compiled from this fixture is executed. No TLS
                    // register is changed; measure reads relocated size64.
                    let function: unsafe extern "C" fn() -> u64 =
                        unsafe { core::mem::transmute((bias + symbols["measure"]) as usize) };
                    assert_eq!(unsafe { function() }, size + 7);
                }
            }
        }
    }
}

#[test]
fn gnu_loader_independently_selects_the_same_provider_size() {
    for preempt in [false, true] {
        // GNU's SIZE handler dereferences a null symbol for an unresolved weak
        // import on the host used here. Compare defined bindings independently;
        // the other fixture covers the unresolved-weak size of zero.
        let f = Fixture::build("both", preempt, true);
        let source = f.directory.join("driver.c");
        std::fs::write(&source,"#include <dlfcn.h>\n#include <stdio.h>\nint main(int n,char **v){void*h=dlopen(v[1],RTLD_NOW);if(!h){puts(dlerror());return 1;}unsigned long(*f)(void)=dlsym(h,\"measure\");printf(\"%lu\\n\",f());return 0;}\n").unwrap();
        run(Command::new("cc")
            .arg(&source)
            .arg("-ldl")
            .arg("-o")
            .arg(f.directory.join("driver")));
        let result = run(Command::new(f.directory.join("driver"))
            .env("LD_LIBRARY_PATH", &f.directory)
            .arg(f.directory.join("root.so")));
        let expected = if preempt { 48 } else { 30 };
        assert_eq!(result.trim(), expected.to_string());
        let out = prepare(&f.bytes).unwrap();
        assert_eq!(
            relocated(&out, 0x30000000 + f.symbols()["size64"], 8),
            expected
        );
    }
}

#[test]
fn size32_overflow_and_underflow_are_reported_without_truncation() {
    let f = Fixture::new("both", false);
    let offset = rela(&f.bytes[1], 32);
    for (addend, expected) in [
        (u32::MAX as u64 - 23, Ok(u32::MAX as u64)),
        (u32::MAX as u64 - 22, Err(Error::Overflow)),
        (0u64.wrapping_sub(23), Ok(0)),
        (0u64.wrapping_sub(24), Err(Error::Overflow)),
    ] {
        let mut b = f.bytes.clone();
        put(&mut b[1], offset + 16, addend);
        match expected {
            Ok(value) => {
                let out = prepare(&b).unwrap();
                assert_eq!(
                    relocated(&out, 0x30000000 + f.symbols()["size32"], 4),
                    value
                );
            }
            Err(e) => assert_eq!(prepare(&b), Err(e)),
        }
    }
}

#[test]
fn size32_at_four_byte_bss_boundary_is_valid_but_size64_cannot_overrun_it() {
    let f = Fixture::new("both", false);
    let mut bytes = f.bytes.clone();
    let offset = rela(&bytes[1], 32);
    let ph = word(&bytes[1], 32) as usize;
    let count = u16::from_le_bytes(bytes[1][56..58].try_into().unwrap()) as usize;
    let header = (ph..ph + count * 56)
        .step_by(56)
        .find(|h| bytes[1][*h] == 1 && bytes[1][*h + 4] & 2 != 0)
        .unwrap();
    let end = word(&bytes[1], header + 16) + word(&bytes[1], header + 40) + 4096;
    let target = end - 4;
    let start = word(&bytes[1], header + 16);
    put(&mut bytes[1], header + 40, end - start);
    put(&mut bytes[1], offset, target);
    let out = prepare(&bytes).unwrap();
    assert_eq!(relocated(&out, 0x30000000 + target, 4), 20);
    let info = word(&bytes[1], offset + 8);
    put(&mut bytes[1], offset + 8, (info & !0xffffffff) | 33);
    assert!(matches!(Pie::parse_object(&bytes[1]), Err(Error::Invalid)));
}

#[test]
fn standalone_image_uses_symbol_size_without_bias_and_strong_imports_still_fail() {
    let f = Fixture::new("gnu", false);
    let mut c = Command::new("x86_64-elf-gcc");
    c.args([
        "-fPIC",
        "-nostdlib",
        "-Wl,-shared",
        "-Wl,-e,_start",
        "-DSTANDALONE",
        "-Wl,--hash-style=gnu",
    ])
    .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/elf_symbol_sizes.S"))
    .arg("-o")
    .arg(f.directory.join("single.so"));
    run(&mut c);
    let source = std::fs::read(f.directory.join("single.so")).unwrap();
    let image = Pie::parse(&source).unwrap();
    let mut out = vec![0; image.output_length().unwrap()];
    image.write(0x20000000, &mut out).unwrap();
    let data = run(Command::new("x86_64-elf-nm").arg(f.directory.join("single.so")));
    for (name, size, expected) in [("size64", 8, 30), ("size32", 4, 20), ("weak_size", 8, 5)] {
        let row = data
            .lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>())
            .find(|r| r.len() == 3 && r[2] == name)
            .unwrap();
        let address = u64::from_str_radix(row[0], 16).unwrap();
        assert_eq!(relocated(&out, 0x20000000 + address, size), expected);
    }
    assert!(matches!(Pie::parse(&f.bytes[1]), Err(Error::Unsupported)));
}
