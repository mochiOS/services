use super::{Mappings, Temporary, word};
use mochios_posix_client::pie::{
    Error, Pie,
    link_scope::{Object, Scope},
};
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
};

static EXECUTION: Mutex<()> = Mutex::new(());
const VERSYM: u64 = 0x6ffffff0;
const VERDEF: u64 = 0x6ffffffc;
const VERDEFNUM: u64 = 0x6ffffffd;
const VERNEED: u64 = 0x6ffffffe;
const VERNEEDNUM: u64 = 0x6fffffff;

struct Fixture {
    temporary: Temporary,
    root: Vec<u8>,
    library: Vec<u8>,
}
fn compile(source: &Path, output: &Path, hash: &str, arguments: &[String]) {
    let result = Command::new("x86_64-elf-gcc")
        .args([
            "-fPIC",
            "-ffreestanding",
            "-fno-stack-protector",
            "-nostdlib",
            "-Wl,-shared,-z,noexecstack",
            "-ftls-model=initial-exec",
        ])
        .arg(format!("-Wl,--hash-style={hash}"))
        .arg(source)
        .args(arguments)
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
impl Fixture {
    fn new(hash: &str, mode: &str) -> Self {
        let temporary = Temporary(std::env::temp_dir().join(
            format!(
            "mochios-versions-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()),
        ));
        std::fs::create_dir(&temporary.0).unwrap();
        let support = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support");
        let library = temporary.0.join("libversions.so");
        let mut arguments = vec![
            "-Wl,-soname,libversions.so".to_owned(),
            format!(
                "-Wl,--version-script={}",
                support.join("versioned_library.map").display()
            ),
        ];
        if mode == "tls" {
            arguments.push("-DVERSIONED_TLS".to_owned());
        }
        compile(
            &support.join("versioned_library.c"),
            &library,
            hash,
            &arguments,
        );
        let search = if mode == "unversioned" {
            let directory = temporary.0.join("unversioned");
            std::fs::create_dir(&directory).unwrap();
            let source = directory.join("library.c");
            std::fs::write(
                &source,
                "int api_data=7; int api_call(int n){return n+7;}\n",
            )
            .unwrap();
            compile(
                &source,
                &directory.join("libversions.so"),
                hash,
                &["-Wl,-soname,libversions.so".to_owned()],
            );
            directory
        } else {
            temporary.0.clone()
        };
        let root = temporary.0.join("root.so");
        let mut arguments = vec![
            "-Wl,-e,_start".to_owned(),
            "-Wl,-rpath,$ORIGIN".to_owned(),
            format!("-L{}", search.display()),
            "-Wl,--no-as-needed".to_owned(),
            "-lversions".to_owned(),
        ];
        match mode {
            "unversioned" => arguments.push("-DUNVERSIONED_REFERENCE".to_owned()),
            "preempt" => arguments.push("-DROOT_PREEMPTION".to_owned()),
            "tls" => arguments.push("-DVERSIONED_TLS".to_owned()),
            _ => {}
        }
        compile(&support.join("versioned_root.c"), &root, hash, &arguments);
        Self {
            root: std::fs::read(root).unwrap(),
            library: std::fs::read(library).unwrap(),
            temporary,
        }
    }
    fn oracle(&self) -> i32 {
        // GNU ld.so independently resolves the same locally compiled fixtures.
        // Run separately so host link-map state cannot affect another test.
        let result = Command::new("python3")
            .args([
                "-c",
                "import ctypes,sys; print(ctypes.CDLL(sys.argv[1])._start())",
            ])
            .arg(self.temporary.0.join("root.so"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }
}
fn prepare_named(root: &[u8], library: &[u8], name: &[u8]) -> Result<Vec<u8>, Error> {
    let root = Pie::parse_object(root)?;
    let library = Pie::parse_object(library)?;
    let objects = [
        Object {
            name: b"root",
            image: &root,
            bias: 0x50000000,
        },
        Object {
            name,
            image: &library,
            bias: 0x60000000,
        },
    ];
    let mut order = [0; 2];
    let scope = Scope::new(&objects, &mut order)?;
    let mut bundle = vec![0; scope.bundle_length()?];
    scope.write_bundle(&mut bundle)?;
    Ok(bundle)
}
fn prepare(root: &[u8], library: &[u8]) -> Result<Vec<u8>, Error> {
    prepare_named(root, library, b"libversions.so")
}
fn execute(bundle: &[u8]) -> i32 {
    let _guard = EXECUTION.lock().unwrap();
    let mut mappings = Mappings::default();
    mappings.install(bundle);
    let entry: extern "C" fn() -> i32 = unsafe { std::mem::transmute(word(bundle, 24) as usize) };
    entry()
}
fn file_offset(bytes: &[u8], address: u64) -> usize {
    let start = word(bytes, 32) as usize;
    let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    for header in bytes[start..start + count * 56].chunks_exact(56) {
        if header[0] == 1
            && address >= word(header, 16)
            && address < word(header, 16) + word(header, 32)
        {
            return (word(header, 8) + address - word(header, 16)) as usize;
        }
    }
    panic!("fixture address {address:x} not file-backed")
}
fn tag(bytes: &[u8], key: u64) -> usize {
    let start = word(bytes, 32) as usize;
    let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    for header in bytes[start..start + count * 56].chunks_exact(56) {
        if header[0] == 2 {
            for offset in (word(header, 8) as usize..(word(header, 8) + word(header, 32)) as usize)
                .step_by(16)
            {
                if word(bytes, offset) == key {
                    return offset;
                }
            }
        }
    }
    panic!("missing fixture tag {key:x}")
}
fn table(bytes: &[u8], key: u64) -> usize {
    file_offset(bytes, word(bytes, tag(bytes, key) + 8))
}
fn w16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn w32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn w64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn exact_versions_bind_old_and_new_code_and_data_with_both_hashes_without_sections() {
    for hash in ["sysv", "gnu", "both"] {
        let fixture = Fixture::new(hash, "normal");
        assert_eq!(fixture.oracle(), 75);
        for stripped in [false, true] {
            let mut root = fixture.root.clone();
            let mut library = fixture.library.clone();
            if stripped {
                for bytes in [&mut root, &mut library] {
                    bytes[40..48].fill(0);
                    bytes[58..64].fill(0);
                }
            }
            assert_eq!(
                execute(&prepare(&root, &library).unwrap()),
                75,
                "{hash} {stripped}"
            );
        }
    }
}

#[test]
fn legacy_unversioned_lookup_and_root_interposition_match_gnu_loader() {
    for mode in ["unversioned", "preempt"] {
        let fixture = Fixture::new("both", mode);
        let expected = fixture.oracle();
        assert_eq!(expected, if mode == "unversioned" { 15 } else { 1201 });
        assert_eq!(
            execute(&prepare(&fixture.root, &fixture.library).unwrap()),
            expected,
            "{mode}"
        );
    }
}

#[test]
fn needed_versions_are_checked_before_output_even_without_a_symbol_reference() {
    let fixture = Fixture::new("both", "normal");
    let need = table(&fixture.root, VERNEED);
    let auxiliary =
        need + u32::from_le_bytes(fixture.root[need + 8..need + 12].try_into().unwrap()) as usize;
    let mut root = fixture.root.clone();
    // Keep the node internally valid while requiring a nonexistent ABI name.
    let strings = table(&root, 5);
    let name = u32::from_le_bytes(root[auxiliary + 8..auxiliary + 12].try_into().unwrap()) as usize;
    root[strings + name..strings + name + 5].copy_from_slice(b"BAD_1");
    let digest = b"BAD_1".iter().fold(0u32, |hash, byte| {
        let value = hash.wrapping_shl(4).wrapping_add(*byte as u32);
        (value ^ ((value & 0xf0000000) >> 24)) & 0x0fffffff
    });
    w32(&mut root, auxiliary, digest);
    assert!(Pie::parse_object(&root).is_ok());
    assert!(matches!(
        prepare(&root, &fixture.library),
        Err(Error::Unsupported)
    ));
    // Weak ABI nodes do not require availability, but a strong unresolved
    // symbol still cannot be silently bound to the wrong version.
    w16(&mut root, auxiliary + 4, 2);
    let pie = Pie::parse_object(&root).unwrap();
    let library = Pie::parse_object(&fixture.library).unwrap();
    let objects = [
        Object {
            name: b"root",
            image: &pie,
            bias: 0x50000000,
        },
        Object {
            name: b"libversions.so",
            image: &library,
            bias: 0x60000000,
        },
    ];
    assert!(Scope::new(&objects, &mut [0; 2]).is_ok());
    assert!(prepare(&root, &fixture.library).is_err());
    // Remove every symbol's reference to this node. The non-weak ABI
    // requirement must still be checked, independently of relocations.
    let id = u16::from_le_bytes(root[auxiliary + 6..auxiliary + 8].try_into().unwrap()) & 0x7fff;
    let versions = table(&root, VERSYM);
    let hash = table(&root, 4);
    let count = u32::from_le_bytes(root[hash + 4..hash + 8].try_into().unwrap()) as usize;
    for index in 0..count {
        let offset = versions + index * 2;
        if u16::from_le_bytes(root[offset..offset + 2].try_into().unwrap()) & 0x7fff == id {
            w16(&mut root, offset, 1);
        }
    }
    w16(&mut root, auxiliary + 4, 0);
    assert!(matches!(
        prepare(&root, &fixture.library),
        Err(Error::Unsupported)
    ));
    w16(&mut root, auxiliary + 4, 2);
    std::fs::write(fixture.temporary.0.join("root.so"), &root).unwrap();
    let expected = fixture.oracle();
    assert_eq!(expected, 31); // Both unversioned references now select API_1.
    assert_eq!(
        execute(&prepare(&root, &fixture.library).unwrap()),
        expected
    );
}

#[test]
fn version_requirement_provider_can_be_matched_by_its_soname() {
    let fixture = Fixture::new("gnu", "normal");
    let mut root = fixture.root.clone();
    let need = table(&root, VERNEED);
    let aux = need + u32::from_le_bytes(root[need + 8..need + 12].try_into().unwrap()) as usize;
    let name = u32::from_le_bytes(root[aux + 8..aux + 12].try_into().unwrap()) as u64;
    let needed = tag(&root, 1);
    w64(&mut root, needed + 8, name);
    let strings = table(&root, 5);
    let name = &root[strings + name as usize..strings + name as usize + 5];
    assert_eq!(
        execute(&prepare_named(&root, &fixture.library, name).unwrap()),
        75
    );
}

#[test]
fn repeated_sonames_select_the_first_provider_in_dependency_order_not_input_order() {
    let fixture = Fixture::new("both", "normal");
    let mut root = fixture.root.clone();
    let need = table(&root, VERNEED);
    let aux = need + u32::from_le_bytes(root[need + 8..need + 12].try_into().unwrap()) as usize;
    let name = u32::from_le_bytes(root[aux + 8..aux + 12].try_into().unwrap()) as u64;
    let strings = table(&root, 5);
    let alias = root[strings + name as usize..strings + name as usize + 5].to_vec();
    let extra = tag(&root, 15); // Replace fixture RPATH with a second DT_NEEDED.
    w64(&mut root, extra, 1);
    w64(&mut root, extra + 8, name);
    let mut shadow = fixture.library.clone();
    let mut definition = table(&shadow, VERDEF);
    loop {
        let aux = definition
            + u32::from_le_bytes(shadow[definition + 12..definition + 16].try_into().unwrap())
                as usize;
        let string = u32::from_le_bytes(shadow[aux..aux + 4].try_into().unwrap()) as usize;
        let strings = table(&shadow, 5);
        if &shadow[strings + string..strings + string + 5] == b"API_2" {
            shadow[strings + string + 4] = b'3';
            let hash =
                u32::from_le_bytes(shadow[definition + 8..definition + 12].try_into().unwrap());
            w32(&mut shadow, definition + 8, hash + 1);
            break;
        }
        let next = u32::from_le_bytes(shadow[definition + 16..definition + 20].try_into().unwrap())
            as usize;
        assert_ne!(next, 0, "fixture must define API_2");
        definition += next;
    }
    let root = Pie::parse_object(&root).unwrap();
    let shadow = Pie::parse_object(&shadow).unwrap();
    let provider = Pie::parse_object(&fixture.library).unwrap();
    let objects = [
        Object {
            name: b"root",
            image: &root,
            bias: 0x50000000,
        },
        Object {
            name: &alias,
            image: &shadow,
            bias: 0x70000000,
        },
        Object {
            name: b"libversions.so",
            image: &provider,
            bias: 0x60000000,
        },
    ];
    let mut order = [0; 3];
    let scope = Scope::new(&objects, &mut order).unwrap();
    assert_eq!(scope.order(), &[0, 2, 1]);
    let mut bundle = vec![0; scope.bundle_length().unwrap()];
    scope.write_bundle(&mut bundle).unwrap();
    assert_eq!(execute(&bundle), 75);
}

#[test]
fn versioned_initial_exec_tls_uses_the_selected_definition_not_the_default_alias() {
    for hash in ["sysv", "gnu", "both"] {
        let fixture = Fixture::new(hash, "tls");
        let root = Pie::parse_object(&fixture.root).unwrap();
        let library = Pie::parse_object(&fixture.library).unwrap();
        let objects = [
            Object {
                name: b"root",
                image: &root,
                bias: 0x50000000,
            },
            Object {
                name: b"libversions.so",
                image: &library,
                bias: 0x60000000,
            },
        ];
        let mut order = [0; 2];
        let scope = Scope::new(&objects, &mut order).unwrap();
        let mut output = vec![0; root.output_length().unwrap()];
        scope.write(0, &mut output).unwrap();
        let result = Command::new("x86_64-elf-readelf")
            .args(["-rW"])
            .arg(fixture.temporary.0.join("root.so"))
            .output()
            .unwrap();
        assert!(result.status.success());
        let template = library.tls_template(0).unwrap().unwrap();
        let templates = [None, Some(template)];
        let plan = mochios_posix_client::static_tls::modules::Plan::new(&templates, 4096).unwrap();
        let distance = plan
            .modules()
            .find(|module| module.index == 1)
            .unwrap()
            .distance as u64;
        let nm = super::symbols(&fixture.temporary.0.join("libversions.so"));
        let mut found = 0;
        for line in String::from_utf8(result.stdout).unwrap().lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() > 5 && fields[2] == "R_X86_64_TPOFF64" {
                let name = fields[4];
                let target = u64::from_str_radix(fields[0], 16).unwrap();
                assert!(name.starts_with("api_tls@API_"));
                let key = if name.ends_with('1') {
                    "api_tls@API_1"
                } else {
                    "api_tls@@API_2"
                };
                assert_eq!(
                    super::loaded(&output, 0x50000000 + target),
                    nm[key].wrapping_sub(distance)
                );
                found += 1;
            }
        }
        assert_eq!(found, 2);
    }
}

#[test]
fn malformed_version_tags_records_auxiliary_chains_and_indices_are_rejected() {
    let fixture = Fixture::new("both", "normal");
    for original in [&fixture.root, &fixture.library] {
        let definition = std::ptr::eq(original, &fixture.library);
        let key = if definition { VERDEF } else { VERNEED };
        let start = table(original, key);
        let aux = start
            + u32::from_le_bytes(
                original[start + if definition { 12 } else { 8 }
                    ..start + if definition { 16 } else { 12 }]
                    .try_into()
                    .unwrap(),
            ) as usize;
        let mut mutations = Vec::new();
        let mut changed = original.clone();
        w64(&mut changed, tag(original, VERSYM), 0x60000000);
        mutations.push(changed);
        let mut changed = original.clone();
        w64(&mut changed, tag(original, key) + 8, u64::MAX);
        mutations.push(changed);
        let mut changed = original.clone();
        w64(
            &mut changed,
            tag(original, if definition { VERDEFNUM } else { VERNEEDNUM }) + 8,
            0,
        );
        mutations.push(changed);
        let mut changed = original.clone();
        w16(&mut changed, start, 2);
        mutations.push(changed);
        let mut changed = original.clone();
        w16(&mut changed, start + if definition { 6 } else { 2 }, 0);
        mutations.push(changed);
        let mut changed = original.clone();
        w32(&mut changed, start + if definition { 12 } else { 8 }, 4);
        mutations.push(changed);
        let mut changed = original.clone();
        w32(
            &mut changed,
            start + if definition { 16 } else { 12 },
            u32::MAX - 3,
        );
        mutations.push(changed);
        let mut changed = original.clone();
        w32(
            &mut changed,
            aux + if definition { 4 } else { 12 },
            u32::MAX,
        );
        mutations.push(changed);
        let mut changed = original.clone();
        w32(&mut changed, aux + if definition { 0 } else { 8 }, u32::MAX);
        mutations.push(changed);
        let mut changed = original.clone();
        changed[start + if definition { 8 } else { aux - start }] ^= 1;
        mutations.push(changed);
        let mut changed = original.clone();
        w16(&mut changed, table(original, VERSYM), 1);
        mutations.push(changed);
        let mut changed = original.clone();
        w16(&mut changed, table(original, VERSYM) + 2, 0x7fff);
        mutations.push(changed);
        for (case, bytes) in mutations.into_iter().enumerate() {
            assert!(
                Pie::parse_object(&bytes).is_err(),
                "definitions={definition} mutation={case}"
            );
        }
    }
}
