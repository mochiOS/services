//! Real syscall-free ELF resolvers, called only after installing the test's
//! locally compiled fixture with its final mapping permissions.
use mochios_posix_client::{
    indirect_image::{Access, Captured, Fixup, Region, State},
    pie::{
        Error, Pie,
        link_scope::{Object, Scope},
    },
};
use std::{collections::BTreeMap, path::PathBuf, process::Command};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "support/pie_mappings.rs"]
mod host_mappings;
const BASES: [u64; 3] = [0x2000_0000, 0x3000_0000, 0x4000_0000];
const PLAN: u64 = 0x600_0000;

fn run(command: &mut Command) -> String {
    let out = command.output().unwrap();
    assert!(
        out.status.success(),
        "{command:?}: {}\n{}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
struct Fixture {
    directory: PathBuf,
    bytes: Vec<Vec<u8>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
impl Fixture {
    fn new(hash: &str, mode: &str, versioned: bool) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "mochios-ifunc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let mut f = Self {
            directory,
            bytes: Vec::new(),
        };
        let support = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support");
        let map = f.directory.join("versions.map");
        std::fs::write(&map, "IFUNC_1 { global: choose; choose_plt; seed; };\n").unwrap();
        for (name, define, deps) in [
            ("libprovider.so", "PROVIDER", &[][..]),
            ("libmiddle.so", "MIDDLE", &["libprovider.so"][..]),
            ("root.so", "ROOT", &["libmiddle.so", "libprovider.so"][..]),
        ] {
            let mut c = Command::new("x86_64-elf-gcc");
            c.args([
                "-fPIC",
                "-nostdlib",
                "-Wl,-shared",
                "-Wl,-z,noexecstack",
                "-Wl,--no-as-needed",
            ])
            .arg(format!("-Wl,--hash-style={hash}"))
            .arg(format!("-D{define}"))
            .arg(support.join("elf_ifunc.S"))
            .arg(format!("-L{}", f.directory.display()));
            if name == "root.so" {
                c.arg("-Wl,-e,_start");
                if !mode.is_empty() {
                    c.arg(format!("-D{mode}"));
                }
            } else {
                c.arg(format!("-Wl,-soname,{name}"));
            }
            if versioned && name == "libprovider.so" {
                c.arg(format!("-Wl,--version-script={}", map.display()));
            }
            for name in deps {
                c.arg(format!("-l:{name}"));
            }
            run(c.arg("-o").arg(f.directory.join(name)));
        }
        f.bytes = ["root.so", "libmiddle.so", "libprovider.so"]
            .map(|n| std::fs::read(f.directory.join(n)).unwrap())
            .into();
        run(Command::new("cc")
            .arg(support.join("elf_ifunc_gnu.c"))
            .arg("-ldl")
            .arg("-o")
            .arg(f.directory.join("gnu-reference")));
        f
    }
    fn symbols(&self, object: usize) -> BTreeMap<String, u64> {
        let name = ["root.so", "libmiddle.so", "libprovider.so"][object];
        run(Command::new("x86_64-elf-nm").arg(self.directory.join(name)))
            .lines()
            .filter_map(|s| {
                let p: Vec<_> = s.split_whitespace().collect();
                (p.len() == 3).then(|| (p[2].to_owned(), u64::from_str_radix(p[0], 16).unwrap()))
            })
            .collect()
    }
    fn gnu(&self, expected: u64) {
        let result = run(Command::new(self.directory.join("gnu-reference"))
            .env("LD_LIBRARY_PATH", &self.directory)
            .arg(self.directory.join("root.so")));
        assert_eq!(result, format!("{} {expected} 2 0\n", expected * 2 + 7));
    }
}
fn word(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn put(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn headers(b: &[u8]) -> impl Iterator<Item = usize> + '_ {
    let start = word(b, 32) as usize;
    let n = u16::from_le_bytes(b[56..58].try_into().unwrap()) as usize;
    (start..start + n * 56).step_by(56)
}
fn file_offset(b: &[u8], address: u64, length: u64) -> usize {
    for h in headers(b) {
        let start = word(b, h + 16);
        if b[h] == 1 && address >= start && address + length <= start + word(b, h + 32) {
            return (word(b, h + 8) + address - start) as usize;
        }
    }
    panic!("no file bytes at {address:x}")
}
fn dynamic(b: &[u8]) -> BTreeMap<u64, u64> {
    let h = headers(b).find(|h| b[*h] == 2).unwrap();
    let at = word(b, h + 8) as usize;
    b[at..at + word(b, h + 32) as usize]
        .chunks_exact(16)
        .take_while(|p| word(p, 0) != 0)
        .map(|p| (word(p, 0), word(p, 8)))
        .collect()
}
fn relocations(b: &[u8]) -> Vec<usize> {
    let d = dynamic(b);
    [(7, 8), (23, 2)]
        .into_iter()
        .flat_map(|(t, s)| match (d.get(&t), d.get(&s)) {
            (Some(&table), Some(&size)) => {
                let at = file_offset(b, table, size);
                (at..at + size as usize).step_by(24).collect::<Vec<_>>()
            }
            _ => Vec::new(),
        })
        .collect()
}
fn symbol(b: &[u8], name: &str) -> usize {
    let d = dynamic(b);
    let at = file_offset(b, d[&6], 24);
    let strings = file_offset(b, d[&5], d[&10]);
    let hash = file_offset(b, d[&4], 8);
    let count = u32::from_le_bytes(b[hash + 4..hash + 8].try_into().unwrap()) as usize;
    (at..at + count * 24)
        .step_by(24)
        .find(|p| {
            let index = u32::from_le_bytes(b[*p..*p + 4].try_into().unwrap()) as usize;
            b[strings + index..].split(|b| *b == 0).next() == Some(name.as_bytes())
        })
        .unwrap()
}
struct Prepared {
    bundle: Vec<u8>,
    plan: Vec<u8>,
    regions: usize,
    fixups: usize,
}
fn prepare(bytes: &[Vec<u8>]) -> Result<Prepared, Error> {
    let images = bytes
        .iter()
        .map(|b| Pie::parse_object(b))
        .collect::<Result<Vec<_>, _>>()?;
    let names = [b"root.so".as_slice(), b"libmiddle.so", b"libprovider.so"];
    let objects: Vec<_> = images
        .iter()
        .enumerate()
        .map(|(i, image)| Object {
            name: names[i],
            image,
            bias: if image.is_fixed() { 0 } else { BASES[i] },
        })
        .collect();
    let mut order = [0; 3];
    let scope = Scope::new(&objects, &mut order)?;
    let (r, f) = scope.deferred_counts()?;
    let mut regions = vec![Region::EMPTY; r];
    let mut fixups = vec![Fixup::EMPTY; f];
    let mut order = vec![0; scope.lifecycle_scratch_len()?];
    let mut deferred = scope.deferred(&mut regions, &mut fixups, &mut order)?;
    let mut result = Prepared {
        bundle: vec![0xcc; scope.bundle_length()?],
        plan: vec![0xcc; deferred.encoded_length()?],
        regions: r,
        fixups: f,
    };
    assert_eq!(deferred.encode(&mut result.plan)?, result.plan.len());
    assert_eq!(
        deferred.write_bundle(&mut result.bundle)?,
        result.bundle.len()
    );
    // Legacy paths must never silently publish unresolved resolver records.
    assert_eq!(
        scope.write_bundle(&mut vec![0; result.bundle.len()]),
        Err(Error::Unsupported)
    );
    Ok(result)
}
fn records(p: &Prepared) -> impl Iterator<Item = (u64, u64, u64)> + '_ {
    p.plan[40 + p.regions * 24..]
        .chunks_exact(32)
        .map(|r| (word(r, 0), word(r, 8), word(r, 16)))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn execute(p: &Prepared, fixture: &Fixture, expected: u64, addend: u64) {
    let root = fixture.symbols(0);
    let middle = fixture.symbols(1);
    let provider = fixture.symbols(2);
    let mut mappings = host_mappings::Mappings::default();
    mappings.install(&p.bundle);
    let load = |address| {
        file_offset(&p.bundle, address, 8);
        // SAFETY: the fixture's live mapping owns this checked extent.
        unsafe { std::ptr::read_unaligned(address as *const u64) }
    };
    assert_eq!(load(BASES[2] + provider["provider_calls"]), 0);
    assert_eq!(load(BASES[1] + middle["local_calls"]), 0);
    let mut regions = vec![Region::EMPTY; p.regions];
    let mut fixups = vec![Fixup::EMPTY; p.fixups];
    let captured = Captured::capture(
        PLAN,
        p.plan.len(),
        &mut regions,
        &mut fixups,
        |address, out| -> Result<(), i32> {
            let at = (address - PLAN) as usize;
            out.copy_from_slice(p.plan.get(at..at + out.len()).ok_or(14)?);
            Ok(())
        },
    )
    .unwrap();
    let state = State::new();
    state
        .apply(
            &captured,
            |address| -> Result<u64, i32> {
                assert!(regions.iter().any(|r| r.access == Access::Executable
                    && address >= r.address
                    && address < r.address + r.length));
                // SAFETY: only the test's syscall-free, locally compiled resolvers are
                // present in these installed executable mappings.
                let function: unsafe extern "C" fn() -> u64 =
                    unsafe { std::mem::transmute(address as usize) };
                Ok(unsafe { function() })
            },
            |address, value| {
                assert!(regions.iter().any(|r| r.access == Access::Writable
                    && address >= r.address
                    && address + 8 <= r.address + r.length));
                file_offset(&p.bundle, address, 8);
                // SAFETY: the test owns the live writable eight-byte fixture extent.
                unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), address as *mut u8, 8) };
                Ok(())
            },
        )
        .unwrap();
    state
        .apply::<i32>(
            &captured,
            |_| panic!("second resolver call"),
            |_, _| panic!("second write"),
        )
        .unwrap();
    assert_eq!(load(BASES[1] + middle["local_calls"]), 2);
    assert_eq!(load(BASES[1] + middle["seen_during_resolve"]), expected);
    assert_eq!(load(BASES[1] + middle["zero_slot"]), 0);
    let implementation = if expected == 73 {
        BASES[2] + provider["provider_impl"]
    } else if let Some(&address) = root.get("override_impl") {
        BASES[0] + address
    } else {
        BASES[0] + root["choose"]
    };
    assert_eq!(
        load(BASES[1] + middle["public_slot"]),
        implementation.wrapping_add(addend)
    );
    assert_eq!(
        load(BASES[2] + provider["provider_calls"]) != 0,
        expected == 73
    );
    // SAFETY: the root's checked executable entry is a scalar fixture function.
    let entry: unsafe extern "C" fn() -> u64 =
        unsafe { std::mem::transmute((BASES[0] + root["_start"]) as usize) };
    assert_eq!(unsafe { entry() }, expected * 2 + 7);
}

#[test]
fn real_resolvers_follow_selected_definitions_hashes_versions_and_stripped_sections() {
    for hash in ["sysv", "gnu", "both"] {
        for mode in ["", "OVERRIDE_ORDINARY", "OVERRIDE_IFUNC"] {
            let f = Fixture::new(hash, mode, true);
            let expected = if mode.is_empty() { 73 } else { 99 };
            f.gnu(expected);
            for stripped in [false, true] {
                let mut bytes = f.bytes.clone();
                if stripped {
                    for b in &mut bytes {
                        b[40..48].fill(0);
                        b[58..64].fill(0);
                    }
                }
                let p = prepare(&bytes).unwrap();
                assert!(p.fixups >= 3);
                #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                execute(&p, &f, expected, 0);
            }
        }
    }
}

#[test]
fn absolute_ifunc_resolvers_use_the_absolute_address_once_and_validate_it() {
    let f = Fixture::new("both", "", false);
    let mut bytes = f.bytes.clone();
    for name in ["choose", "choose_plt"] {
        let at = symbol(&bytes[2], name);
        let value = word(&bytes[2], at + 8);
        bytes[2][at + 6..at + 8].copy_from_slice(&0xfff1u16.to_le_bytes());
        put(&mut bytes[2], at + 8, BASES[2] + value);
    }
    let p = prepare(&bytes).unwrap();
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    execute(&p, &f, 73, 0);
    let at = symbol(&bytes[2], "choose");
    for bad in [0, BASES[2] + f.symbols(2)["seed"], u64::MAX] {
        let mut bad_bytes = bytes.clone();
        put(&mut bad_bytes[2], at + 8, bad);
        assert!(matches!(prepare(&bad_bytes), Err(Error::Invalid)));
    }
}

#[test]
fn absolute_addends_follow_resolution_but_got_and_plt_addends_are_ignored() {
    let f = Fixture::new("both", "", false);
    for addend in [5, u64::MAX] {
        let mut bytes = f.bytes.clone();
        for at in relocations(&bytes[1]) {
            let kind = word(&bytes[1], at + 8) as u32;
            if matches!(kind, 1 | 6 | 7) {
                put(&mut bytes[1], at + 16, addend);
            }
        }
        let p = prepare(&bytes).unwrap();
        let slot = BASES[1] + f.symbols(1)["public_slot"];
        assert_eq!(records(&p).find(|r| r.0 == slot).unwrap().2, addend);
        assert!(records(&p).filter(|r| r.0 != slot).all(|r| r.2 == 0));
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        execute(&p, &f, 73, addend);
    }
}

#[test]
fn unsorted_irelative_runs_after_the_objects_symbolic_ifunc_writes() {
    let f = Fixture::new("both", "", false);
    let mut bytes = f.bytes.clone();
    let all = relocations(&bytes[1]);
    let first = all[0];
    let relative = *all
        .iter()
        .find(|at| word(&bytes[1], **at + 8) as u32 == 37)
        .unwrap();
    let a = bytes[1][first..first + 24].to_vec();
    let b = bytes[1][relative..relative + 24].to_vec();
    bytes[1][first..first + 24].copy_from_slice(&b);
    bytes[1][relative..relative + 24].copy_from_slice(&a);
    let p = prepare(&bytes).unwrap();
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    execute(&p, &f, 73, 0);
}

#[test]
fn non_executable_resolvers_readonly_targets_bad_symbols_and_partial_writes_are_rejected() {
    let f = Fixture::new("both", "", false);
    let source = &f.bytes[1];
    let relative = *relocations(source)
        .iter()
        .find(|at| word(source, **at + 8) as u32 == 37)
        .unwrap();
    for (at, value) in [
        (relative + 16, f.symbols(1)["public_slot"]),
        (relative + 8, (1u64 << 32) | 37),
        (relative, f.symbols(1)["call_got"]),
    ] {
        let mut bytes = f.bytes.clone();
        put(&mut bytes[1], at, value);
        assert!(prepare(&bytes).is_err(), "at={at} value={value}");
    }
    let data = headers(source)
        .find(|h| source[*h] == 1 && source[*h + 4] & 2 != 0)
        .unwrap();
    let mut bytes = f.bytes.clone();
    put(
        &mut bytes[1],
        relative,
        word(source, data + 16) + word(source, data + 40) - 4,
    );
    assert!(matches!(Pie::parse_object(&bytes[1]), Err(Error::Invalid)));
    let at = symbol(&f.bytes[2], "choose");
    let mut bytes = f.bytes.clone();
    put(&mut bytes[2], at + 8, f.symbols(2)["seed"]);
    assert!(matches!(prepare(&bytes), Err(Error::Invalid)));
}

#[test]
fn size_relocations_of_ifuncs_use_symbol_size_without_deferring_a_call() {
    for (mode, expected_object) in [("", 2), ("OVERRIDE_IFUNC", 0)] {
        let f = Fixture::new("both", mode, false);
        let slot = f.symbols(1)["public_slot"];
        let mut bytes = f.bytes.clone();
        let at = relocations(&bytes[1])
            .into_iter()
            .find(|at| word(&bytes[1], *at) == slot)
            .unwrap();
        let info = word(&bytes[1], at + 8);
        put(&mut bytes[1], at + 8, (info & !0xffff_ffff) | 33);
        put(&mut bytes[1], at + 16, 9);
        let selected = symbol(&bytes[expected_object], "choose");
        let size = word(&bytes[expected_object], selected + 16);
        let p = prepare(&bytes).unwrap();
        assert!(!records(&p).any(|r| r.0 == BASES[1] + slot));
        let at = file_offset(&p.bundle, BASES[1] + slot, 8);
        assert_eq!(word(&p.bundle, at), size + 9);
    }
}

#[test]
fn missing_weak_ifunc_is_zero_and_missing_strong_ifunc_is_an_error() {
    let f = Fixture::new("both", "", false);
    let mut bytes = f.bytes.clone();
    let export = symbol(&bytes[2], "choose");
    bytes[2][export + 5] = 2; // Hidden provider cannot satisfy external lookup.
    let reference = symbol(&bytes[1], "choose");
    bytes[1][reference + 4] = 0x2a; // Weak, STT_GNU_IFUNC, undefined.
    let p = prepare(&bytes).unwrap();
    let slot = BASES[1] + f.symbols(1)["public_slot"];
    assert!(!records(&p).any(|r| r.0 == slot));
    assert_eq!(word(&p.bundle, file_offset(&p.bundle, slot, 8)), 0);
    // Do not execute: the fixture's local resolver deliberately calls choose,
    // whereas this variant tests only the unresolved-weak binding rule.
    bytes[1][reference + 4] = 0x1a;
    assert!(matches!(prepare(&bytes), Err(Error::Unsupported)));
}

#[test]
fn planning_checks_all_scratch_capacities_before_emitting_any_bundle() {
    let f = Fixture::new("both", "", false);
    let images: Vec<_> = f
        .bytes
        .iter()
        .map(|b| Pie::parse_object(b).unwrap())
        .collect();
    let names = [b"root.so".as_slice(), b"libmiddle.so", b"libprovider.so"];
    let objects: Vec<_> = images
        .iter()
        .enumerate()
        .map(|(i, image)| Object {
            name: names[i],
            image,
            bias: BASES[i],
        })
        .collect();
    let mut order = [0; 3];
    let scope = Scope::new(&objects, &mut order).unwrap();
    let (r, f) = scope.deferred_counts().unwrap();
    let n = scope.lifecycle_scratch_len().unwrap();
    for (r, f, n) in [(r - 1, f, n), (r, f - 1, n), (r, f, n - 1)] {
        assert!(matches!(
            scope.deferred(
                &mut vec![Region::EMPTY; r],
                &mut vec![Fixup::EMPTY; f],
                &mut vec![0; n]
            ),
            Err(Error::BufferTooSmall)
        ));
    }
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn copied_data_observes_provider_ifuncs_before_root_resolvers_like_gnu_loader() {
    let mut f = Fixture::new("both", "", false);
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/elf_ifunc_copy.S");
    let root = f.directory.join("copy-root");
    run(Command::new("x86_64-elf-gcc")
        .args([
            "-fno-pic",
            "-no-pie",
            "-nostdlib",
            "-Wl,-e,_start,--no-dynamic-linker,--export-dynamic",
            "-Wl,-z,noexecstack,--no-as-needed",
        ])
        .arg(&source)
        .arg(format!("-L{}", f.directory.display()))
        .args(["-l:libmiddle.so", "-l:libprovider.so"])
        .arg("-o")
        .arg(&root));
    f.bytes[0] = std::fs::read(&root).unwrap();
    assert!(
        relocations(&f.bytes[0])
            .iter()
            .any(|p| word(&f.bytes[0], *p + 8) as u32 == 5)
    );
    let prepared = prepare(&f.bytes).unwrap();
    assert_eq!(word(&prepared.plan, 8) as u32, 2);
    assert!(records(&prepared).any(|(_, source, length)| source >= BASES[1] && length == 8));
    let mut regions = vec![Region::EMPTY; prepared.regions];
    let mut fixups = vec![Fixup::EMPTY; prepared.fixups];
    let captured = Captured::capture(
        PLAN,
        prepared.plan.len(),
        &mut regions,
        &mut fixups,
        |a, out| {
            let at = (a - PLAN) as usize;
            out.copy_from_slice(&prepared.plan[at..at + out.len()]);
            Ok::<(), i32>(())
        },
    )
    .unwrap();
    let mut mappings = host_mappings::Mappings::default();
    mappings.install(&prepared.bundle);
    State::new()
        .apply_with_copies(
            &captured,
            |a, out| {
                file_offset(&prepared.bundle, a, out.len() as u64);
                // SAFETY: the test owns the checked live fixture extent.
                unsafe {
                    std::ptr::copy_nonoverlapping(a as *const u8, out.as_mut_ptr(), out.len())
                };
                Ok(())
            },
            |a| -> Result<u64, i32> {
                // SAFETY: capture checked the resolver against this fixture's RX LOADs.
                let f: unsafe extern "C" fn() -> u64 = unsafe { std::mem::transmute(a as usize) };
                Ok(unsafe { f() })
            },
            |a, out| {
                file_offset(&prepared.bundle, a, out.len() as u64);
                // SAFETY: capture checked a writable extent in this owned fixture.
                unsafe { std::ptr::copy_nonoverlapping(out.as_ptr(), a as *mut u8, out.len()) };
                Ok(())
            },
        )
        .unwrap();
    let symbols = run(Command::new("x86_64-elf-nm").arg(&root));
    let root_slot = symbols
        .lines()
        .find_map(|s| {
            let p: Vec<_> = s.split_whitespace().collect();
            (p.len() == 3 && p[2] == "root_slot").then(|| u64::from_str_radix(p[0], 16).unwrap())
        })
        .unwrap();
    let expected = BASES[2] + f.symbols(2)["provider_impl"];
    file_offset(&prepared.bundle, root_slot, 8);
    assert_eq!(
        unsafe { std::ptr::read_unaligned(root_slot as *const u64) },
        expected
    );
    let entry = word(&prepared.bundle, 24);
    let function: unsafe extern "C" fn() -> u64 = unsafe { std::mem::transmute(entry as usize) };
    assert_eq!(unsafe { function() }, expected);
    // A separate process runs the same assembly and DSOs with GNU's actual
    // loader. Its syscall-only _start checks COPY and root resolver ordering.
    let reference = f.directory.join("gnu-copy-reference");
    run(Command::new("x86_64-elf-gcc")
        .args([
            "-fno-pic",
            "-no-pie",
            "-nostdlib",
            "-DGNU_REFERENCE",
            "-Wl,-e,_start,--export-dynamic,-z,noexecstack,--no-as-needed",
            "-Wl,--dynamic-linker,/lib64/ld-linux-x86-64.so.2",
        ])
        .arg(&source)
        .arg(format!("-L{}", f.directory.display()))
        .args(["-l:libmiddle.so", "-l:libprovider.so"])
        .arg("-o")
        .arg(&reference));
    run(Command::new(reference).env("LD_LIBRARY_PATH", &f.directory));
}
