use mochios_posix_client::elf_launch::{self, Error, Image, Launch};
#[path = "support/interpreter_fixture.rs"]
mod fixture;
use fixture::*;
fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn mapped(bytes: &[u8], address: u64, length: usize) -> &[u8] {
    for h in bytes[64..64 + u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize * 56]
        .chunks_exact(56)
    {
        if h[..4] == 1u32.to_le_bytes()
            && address >= word(h, 16)
            && address + length as u64 <= word(h, 16) + word(h, 32)
        {
            let at = (word(h, 8) + address - word(h, 16)) as usize;
            return &bytes[at..at + length];
        }
    }
    panic!("unmapped address {address:#x}")
}
#[test]
fn preserves_source_loads_headers_and_uninterpreted_dynamic_data() {
    for fixed in [false, true] {
        for headers_mapped in [false, true] {
            let root = image(true, fixed, headers_mapped);
            let loader = image(false, false, true);
            let launch = Launch::new(
                Image::parse(&root).unwrap(),
                Image::parse(&loader).unwrap(),
                [11; 16],
            )
            .unwrap();
            let info = launch.executable();
            let mut output = vec![0xcc; launch.length() + 17];
            assert_eq!(launch.write(&mut output), Ok(launch.length()));
            assert_eq!(&output[launch.length()..], &[0xcc; 17]);
            assert_eq!(word(&output, 24), info.interpreter_base + 0x1100);
            assert_ne!(word(&output, 24), info.entry);
            assert_eq!(info.load_bias == 0, fixed);
            assert_eq!(
                info.entry,
                info.load_bias + if fixed { 0x401100 } else { 0x1100 }
            );
            assert_eq!(
                mapped(&output, info.program_headers, 5 * 56),
                &root[64..64 + 5 * 56]
            );
            assert_eq!(info.program_header_count, 5);
            assert_eq!(info.program_header_size, 56);
            let base = if fixed { 0x400000 } else { 0 };
            let start = if headers_mapped { 0 } else { 0x1000 };
            assert_eq!(
                mapped(
                    &output,
                    info.load_bias + base + start,
                    0x1200 - start as usize
                ),
                &root[start as usize..0x1200]
            );
            assert_eq!(
                mapped(&output, info.load_bias + base + 0x3000, 0x100),
                &root[0x2000..0x2100]
            );
            assert_eq!(
                mapped(&output, info.interpreter_base, 0x1200),
                &loader[..0x1200]
            );
            assert!(launch.length() < 0x20000, "sparse BSS must stay sparse");
            assert!(Image::parse(&output[..launch.length()]).is_ok());
            assert_eq!(elf_launch::interpreter(&output), Ok(None));
        }
    }
}
#[test]
fn requires_exact_terminated_single_interpreter_and_rejects_recursive_loader() {
    let root = image(true, false, true);
    assert_eq!(elf_launch::interpreter(&root), Ok(Some(PATH)));
    let mut other = image(false, false, true);
    assert_eq!(elf_launch::interpreter(&other), Ok(None));
    assert!(
        Launch::new(
            Image::parse(&root).unwrap(),
            Image::parse(&root).unwrap(),
            [0; 16]
        )
        .is_err()
    );
    assert!(
        Launch::new(
            Image::parse(&other).unwrap(),
            Image::parse(&other).unwrap(),
            [0; 16]
        )
        .is_err()
    );
    for (at, value) in [(0x1180, 0), (0x1180 + PATH.len(), 1)] {
        let mut broken = root.clone();
        broken[at] = value;
        assert!(Image::parse(&broken).is_err());
    }
    let mut duplicate = root.clone();
    let h = duplicate[64 + 4 * 56..64 + 5 * 56].to_vec();
    duplicate[64 + 2 * 56..64 + 3 * 56].copy_from_slice(&h);
    assert!(Image::parse(&duplicate).is_err());
    // Exact bytes remain available to scoped open; no UTF-8 or search rewrite.
    other = root.clone();
    other[0x1180] = 0xff;
    assert_eq!(
        Image::parse(&other)
            .unwrap()
            .interpreter()
            .unwrap()
            .unwrap()[0],
        0xff
    );
}
#[test]
fn rejects_invalid_mapping_boundaries_permissions_headers_and_collisions() {
    let root = image(true, true, true);
    let fixed_loader = image(false, true, true);
    assert!(
        Launch::new(
            Image::parse(&root).unwrap(),
            Image::parse(&fixed_loader).unwrap(),
            [0; 16]
        )
        .is_err()
    );
    for (at, value) in [
        (24, 0x403000),
        (32, u64::MAX),
        (64 + 32, u64::MAX),
        (64 + 40, 1),
        (64 + 48, 3),
        (64 + 56 + 16, 0x400100),
        (64 + 56 + 40, u64::MAX),
    ] {
        let mut b = root.clone();
        put64(&mut b, at, value);
        assert!(Image::parse(&b).is_err(), "accepted invalid field {at}");
    }
    for (at, value) in [(64 + 4, 7u32), (64 + 3 * 56 + 4, 7)] {
        let mut b = root.clone();
        b[at..at + 4].copy_from_slice(&value.to_le_bytes());
        assert!(Image::parse(&b).is_err());
    }
    for count in [0, 65535] {
        let mut b = root.clone();
        put16(&mut b, 56, count);
        assert!(Image::parse(&b).is_err());
    }
    for n in [0, 6, 63, 64, 200, 0x1100] {
        assert!(Image::parse(&root[..n]).is_err());
    }
    let mut b = root.clone();
    segment(&mut b, 2, 6, 4, 64, 0x400041, 5 * 56, 5 * 56);
    assert!(Image::parse(&b).is_err());
}
#[test]
fn planning_validates_placement_alignment_and_short_output_before_mutation() {
    let mut root = image(true, false, true);
    let loader = image(false, false, true);
    put64(&mut root, 64 + 48, 0x200000);
    let launch = Launch::new(
        Image::parse(&root).unwrap(),
        Image::parse(&loader).unwrap(),
        [0xff; 16],
    )
    .unwrap();
    assert_eq!(launch.executable().load_bias % 0x200000, 0);
    let mut short = vec![0xa5; launch.length() - 1];
    assert_eq!(launch.write(&mut short), Err(Error::ShortOutput));
    assert!(short.iter().all(|&b| b == 0xa5));
    let mut output = vec![0; launch.length()];
    launch.write(&mut output).unwrap();
    let mut second = output.clone();
    launch.write(&mut second).unwrap();
    assert_eq!(output, second);
}

#[test]
fn actual_gnu_dynamic_main_and_interpreter_keep_every_load_byte_unrelocated() {
    use std::{path::PathBuf, process::Command};
    struct Temporary(PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let temporary =
        Temporary(std::env::temp_dir().join(format!("mochios-interpreter-{}", std::process::id())));
    std::fs::create_dir(&temporary.0).unwrap();
    let tests = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let library = temporary.0.join("libscope.so");
    let root = temporary.0.join("root");
    let interpreter = temporary.0.join("ld.native.so");
    for (source, output, flags) in [
        (
            tests.join("elf_scope_dependency.c"),
            library.clone(),
            vec!["-Wl,-shared,-soname,libscope.so".to_owned()],
        ),
        (
            tests.join("elf_scope_root.c"),
            root.clone(),
            vec![
                "-Wl,-pie,-e,_start,--dynamic-linker,/native/ld-test.so".to_owned(),
                format!("-L{}", temporary.0.display()),
                "-l:libscope.so".to_owned(),
            ],
        ),
        (
            tests.join("support/native_interpreter.S"),
            interpreter.clone(),
            vec!["-Wl,-shared,-e,_start".to_owned()],
        ),
    ] {
        let result = Command::new("x86_64-elf-gcc")
            .args([
                "-fPIC",
                "-ffreestanding",
                "-fno-stack-protector",
                "-nostdlib",
                "-Wl,-z,noexecstack",
            ])
            .arg(source)
            .args(flags)
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
    let root = std::fs::read(root).unwrap();
    let loader = std::fs::read(interpreter).unwrap();
    assert_eq!(elf_launch::interpreter(&root), Ok(Some(PATH)));
    // The existing direct-entry linker rejects PT_INTERP; this route never
    // parses its DT_NEEDED/PLT or resolves the library in the parent.
    assert!(mochios_posix_client::pie::Pie::parse_object(&root).is_err());
    let launch = Launch::new(
        Image::parse(&root).unwrap(),
        Image::parse(&loader).unwrap(),
        [19; 16],
    )
    .unwrap();
    let info = launch.executable();
    let mut output = vec![0; launch.length()];
    launch.write(&mut output).unwrap();
    for (bytes, bias) in [(&root, info.load_bias), (&loader, info.interpreter_base)] {
        let phoff = word(bytes, 32) as usize;
        let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
        for h in bytes[phoff..phoff + count * 56].chunks_exact(56) {
            if h[..4] != 1u32.to_le_bytes() {
                continue;
            }
            let at = word(h, 8) as usize;
            let n = word(h, 32) as usize;
            assert_eq!(mapped(&output, bias + word(h, 16), n), &bytes[at..at + n]);
        }
    }
    assert_ne!(word(&output, 24), info.entry);
}
