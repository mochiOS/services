use mochios_posix_client::pie::{
    Error, Pie,
    link_scope::{
        Object, Scope,
        lookup::{Search, Value, Version},
    },
};
use std::{collections::BTreeMap, path::PathBuf, process::Command};
struct Fixture {
    directory: PathBuf,
    versions: Vec<u8>,
    special: Vec<u8>,
    root: Vec<u8>,
    dependency: Vec<u8>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
fn run(command: &mut Command) -> String {
    let out = command.output().unwrap();
    assert!(
        out.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
impl Fixture {
    fn new(hash: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "mochios-export-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let tests = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
        std::fs::write(
            directory.join("special.c"),
            r#"
__thread int thread_data=13;
int public_data=9;
__attribute__((visibility("hidden"))) int hidden_data=11;
__attribute__((visibility("protected"))) int protected_data=17;
static int implementation(void){return 73;}
static void *select_function(void) __attribute__((used));
static void *select_function(void){return implementation;}
static void *select_null(void) __attribute__((used));
static void *select_null(void){return 0;}
__asm__(".global selected\n.type selected,@gnu_indirect_function\n.set selected,select_function\n");
__asm__(".global null_selected\n.type null_selected,@gnu_indirect_function\n.set null_selected,select_null\n");
__asm__(".global absolute_zero\n.set absolute_zero,0\n");
"#,
        )
        .unwrap();
        for (source, output, extra) in [
            (
                tests.join("support/versioned_library.c"),
                "versions.so",
                vec![
                    format!(
                        "-Wl,--version-script={}",
                        tests.join("support/versioned_library.map").display()
                    ),
                    "-DVERSIONED_TLS".into(),
                ],
            ),
            (directory.join("special.c"), "special.so", vec![]),
            (
                tests.join("elf_scope_dependency.c"),
                "libscope.so",
                vec!["-Wl,-soname,libscope.so".into()],
            ),
            (
                tests.join("elf_scope_root.c"),
                "root.so",
                vec![
                    format!("-L{}", directory.display()),
                    "-l:libscope.so".into(),
                    "-Wl,-e,_start".into(),
                ],
            ),
        ] {
            run(Command::new("x86_64-elf-gcc")
                .args([
                    "-fPIC",
                    "-ffreestanding",
                    "-fno-stack-protector",
                    "-nostdlib",
                    "-Wl,-shared,-z,noexecstack",
                ])
                .arg(format!("-Wl,--hash-style={hash}"))
                .arg(source)
                .args(extra)
                .arg("-o")
                .arg(directory.join(output)));
        }
        let versions = std::fs::read(directory.join("versions.so")).unwrap();
        let special = std::fs::read(directory.join("special.so")).unwrap();
        let root = std::fs::read(directory.join("root.so")).unwrap();
        let dependency = std::fs::read(directory.join("libscope.so")).unwrap();
        Self {
            directory,
            versions,
            special,
            root,
            dependency,
        }
    }
    fn symbols(&self, file: &str) -> BTreeMap<String, u64> {
        run(Command::new("x86_64-elf-nm").arg(self.directory.join(file)))
            .lines()
            .filter_map(|l| {
                let p: Vec<_> = l.split_whitespace().collect();
                (p.len() == 3).then(|| (p[2].into(), u64::from_str_radix(p[0], 16).unwrap()))
            })
            .collect()
    }
    fn oracle(&self) {
        let source =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/symbol_lookup_gnu.c");
        run(Command::new("cc")
            .arg(source)
            .args(["-ldl", "-pthread", "-o"])
            .arg(self.directory.join("oracle")));
        assert_eq!(
            run(Command::new(self.directory.join("oracle"))
                .arg(self.directory.join("versions.so"))
                .arg(self.directory.join("special.so"))),
            "exports: default/old/new/TLS/IFUNC/zero/missing PASS\n"
        );
    }
}
fn strip_sections(bytes: &mut [u8]) {
    bytes[40..48].fill(0);
    bytes[58..64].fill(0);
}
fn address(search: &Search<'_, '_>, name: &[u8], version: Version<'_>) -> u64 {
    let export = search.find(name, version).unwrap().unwrap();
    let Value::Address(address) = export.value else {
        panic!("expected direct address")
    };
    address
}
#[test]
fn default_exports_choose_the_public_version_while_exact_queries_can_select_hidden_versions() {
    for hash in ["sysv", "gnu", "both"] {
        let f = Fixture::new(hash);
        f.oracle();
        let symbols = f.symbols("versions.so");
        for stripped in [false, true] {
            let mut bytes = f.versions.clone();
            if stripped {
                strip_sections(&mut bytes);
            }
            let image = Pie::parse_object(&bytes).unwrap();
            let objects = [Object {
                name: b"versions.so",
                image: &image,
                bias: 0x32000000,
            }];
            let search = Search::new(&objects, &[0]).unwrap();
            assert_eq!(
                address(&search, b"api_data", Version::Default),
                0x32000000 + symbols["new_data"]
            );
            assert_eq!(
                address(&search, b"api_data", Version::Named(b"API_1")),
                0x32000000 + symbols["old_data"]
            );
            assert_eq!(
                address(&search, b"api_data", Version::Named(b"API_2")),
                0x32000000 + symbols["new_data"]
            );
            assert_eq!(
                address(&search, b"api_call", Version::Default),
                0x32000000 + symbols["new_call"]
            );
            assert_eq!(
                search.find(b"api_data", Version::Named(b"MISSING")),
                Ok(None)
            );
            assert_eq!(
                search.find(b"old_data", Version::Default),
                Ok(None),
                "version-script local records never export"
            );
            assert!(matches!(
                search
                    .find(b"api_tls", Version::Default)
                    .unwrap()
                    .unwrap()
                    .value,
                Value::Tls { .. }
            ));
        }
    }
}
#[test]
fn family_and_next_searches_never_escape_the_selected_visible_order() {
    let f = Fixture::new("both");
    let root = Pie::parse_object(&f.root).unwrap();
    let dep = Pie::parse_object(&f.dependency).unwrap();
    let objects = [
        Object {
            name: b"root.so",
            image: &root,
            bias: 0x32000000,
        },
        Object {
            name: b"libscope.so",
            image: &dep,
            bias: 0x33000000,
        },
        Object {
            name: b"unrelated.so",
            image: &dep,
            bias: 0x34000000,
        },
    ];
    let mut order = [0; 3];
    let family = Search::family(&objects, 0, &mut order).unwrap();
    assert_eq!(family.order(), [0, 1]);
    assert_eq!(
        family
            .find(b"root_override", Version::Default)
            .unwrap()
            .unwrap()
            .object,
        0
    );
    assert_eq!(
        family
            .after(0, b"root_override", Version::Default)
            .unwrap()
            .unwrap()
            .object,
        1
    );
    assert_eq!(
        family.after(1, b"root_override", Version::Default),
        Ok(None)
    );
    assert!(matches!(
        family.after(2, b"root_override", Version::Default),
        Err(Error::Invalid)
    ));
    let global = Search::new(&objects, &[2, 0, 1]).unwrap();
    assert_eq!(
        global
            .find(b"root_override", Version::Default)
            .unwrap()
            .unwrap()
            .object,
        2
    );
    let mut local_order = [0; 3];
    let local = Search::family(&objects, 1, &mut local_order).unwrap();
    assert_eq!(local.order(), [1]);
    assert_eq!(
        local
            .find(b"root_override", Version::Default)
            .unwrap()
            .unwrap()
            .object,
        1
    );
    let mut scratch = [0; 2];
    let scope = Scope::new(&objects[..2], &mut scratch).unwrap();
    assert_eq!(
        scope
            .exports()
            .find(b"root_override", Version::Default)
            .unwrap()
            .unwrap()
            .object,
        0
    );
    assert_eq!(family.find(b"optional_value", Version::Default), Ok(None));
}
#[test]
fn tls_ifunc_absolute_zero_and_callback_errors_stay_distinct_from_missing_symbols() {
    let f = Fixture::new("gnu");
    let image = Pie::parse_object(&f.special).unwrap();
    let objects = [Object {
        name: b"special.so",
        image: &image,
        bias: 0x32000000,
    }];
    let search = Search::new(&objects, &[0]).unwrap();
    let symbols = f.symbols("special.so");
    let tls = search
        .find(b"thread_data", Version::Default)
        .unwrap()
        .unwrap();
    assert_eq!(
        tls.value,
        Value::Tls {
            offset: symbols["thread_data"]
        }
    );
    for thread in [0x50000000u64, 0x60000000] {
        assert_eq!(
            tls.resolve::<i32>(
                |object, offset| {
                    assert_eq!(object, 0);
                    Ok(thread + offset)
                },
                |_, _| panic!()
            ),
            Ok(thread + symbols["thread_data"])
        );
    }
    assert_eq!(tls.resolve(|_, _| Err(37), |_, _| Ok(0)), Err(37));
    for name in [b"selected".as_slice(), b"null_selected"] {
        let export = search.find(name, Version::Default).unwrap().unwrap();
        assert!(matches!(export.value, Value::Ifunc { .. }));
        assert_eq!(
            export.resolve::<i32>(
                |_, _| panic!(),
                |object, resolver| {
                    assert_eq!(object, 0);
                    assert!(resolver >= 0x32000000);
                    Ok(0)
                }
            ),
            Ok(0)
        );
        assert_eq!(export.resolve(|_, _| Ok(0), |_, _| Err(41)), Err(41));
    }
    let zero = search
        .find(b"absolute_zero", Version::Default)
        .unwrap()
        .unwrap();
    assert_eq!(zero.value, Value::Address(0));
    assert_eq!(zero.resolve::<i32>(|_, _| panic!(), |_, _| panic!()), Ok(0));
    assert_eq!(search.find(b"missing", Version::Default), Ok(None));
    assert_eq!(search.find(b"hidden_data", Version::Default), Ok(None));
    assert!(
        search
            .find(b"protected_data", Version::Default)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        address(&search, b"public_data", Version::Named(b"ANY")),
        0x32000000 + symbols["public_data"],
        "unversioned interposition remains available for explicit versions"
    );
}
#[test]
fn malformed_queries_scopes_and_dependency_families_are_rejected_before_lookup() {
    let f = Fixture::new("sysv");
    let root = Pie::parse_object(&f.root).unwrap();
    let dep = Pie::parse_object(&f.dependency).unwrap();
    let objects = [
        Object {
            name: b"root.so",
            image: &root,
            bias: 0x32000000,
        },
        Object {
            name: b"libscope.so",
            image: &dep,
            bias: 0x33000000,
        },
    ];
    for order in [&[2][..], &[0, 0], &[1, 0, 1]] {
        assert!(matches!(Search::new(&objects, order), Err(Error::Invalid)));
    }
    let search = Search::new(&objects, &[0, 1]).unwrap();
    assert_eq!(
        search.find(b"root\0override", Version::Default),
        Err(Error::Invalid)
    );
    assert_eq!(
        search.find(b"root_override", Version::Named(b"X\0Y")),
        Err(Error::Invalid)
    );
    assert_eq!(search.find(b"", Version::Default), Ok(None));
    let mut short = [0; 1];
    assert!(matches!(
        Search::family(&objects, 0, &mut short),
        Err(Error::BufferTooSmall)
    ));
    let mut scratch = [0; 2];
    assert!(matches!(
        Search::family(&objects, 2, &mut scratch),
        Err(Error::Invalid)
    ));
    assert!(matches!(
        Search::family(&objects[..1], 0, &mut scratch),
        Err(Error::Unsupported)
    ));
    let duplicate = [
        Object {
            name: b"root.so",
            image: &root,
            bias: 0x32000000,
        },
        Object {
            name: b"libscope.so",
            image: &dep,
            bias: 0x33000000,
        },
        Object {
            name: b"libscope.so",
            image: &dep,
            bias: 0x34000000,
        },
    ];
    let mut order = [0; 3];
    assert!(matches!(
        Search::family(&duplicate, 0, &mut order),
        Err(Error::Invalid)
    ));
    let bad = [Object {
        name: b"bad",
        image: &dep,
        bias: 1,
    }];
    assert!(matches!(Search::new(&bad, &[0]), Err(Error::Invalid)));
}
