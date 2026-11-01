//! Normal clang/ld/msign with embedded declarations and unchanged SDK inputs.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("native-embedded-manifest: requires mochiOS");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochios_elf_signature::verify_image;
    use mochios_file_publication::PrivateDirectory;
    use std::{fs, path::Path, process::Command};

    unsafe { libc::alarm(900) };
    let directory = PrivateDirectory::new_in(Path::new("/tmp"), "manifest326").unwrap();
    let command = |program: &str| {
        let mut command = Command::new(program);
        command.current_dir(directory.path());
        for variable in [
            "MOCHIOS_SDK",
            "MOCHIOS_LLD",
            "MOCHIOS_MSIGN",
            "LIBRARY_PATH",
            "CCC_OVERRIDE_OPTIONS",
        ] {
            command.env_remove(variable);
        }
        command
    };
    let declaration = "[package]\nid = \"org.example.main\"\nname = \"main\"\nversion = \"1\"\n[[binary]]\npath = \"main\"\nrequires = [\"net.connect\"]\n";
    let manifest = directory.path().join("manifest.toml");
    let executable = directory.path().join("main");
    fs::write(
        directory.path().join("main.c"),
        "#include <stdio.h>\nint main(void) { puts(\"manifest326\"); return 37; }\n",
    )
    .unwrap();
    fs::write(&manifest, declaration).unwrap();
    let compile = || {
        command("clang")
            .args(["main.c", "-Wl,--manifest,manifest.toml", "-o", "main"])
            .output()
            .unwrap()
    };
    let built = compile();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let signed = fs::read(&executable).unwrap();
    assert_eq!(
        verify_image(&signed, None, &Default::default())
            .unwrap()
            .manifest(),
        Some(declaration)
    );
    assert!(
        command("msign")
            .args(["elf", "verify", "main"])
            .output()
            .unwrap()
            .status
            .success()
    );
    println!("embedded-manifest-326: PASS normal clang/ld/msign and exact embedded declarations");

    fs::remove_file(&manifest).unwrap();
    let executed = command("./main").output().unwrap();
    assert_eq!(executed.status.code(), Some(37));
    assert_eq!(executed.stdout, b"manifest326\n");
    println!("embedded-manifest-326: PASS ./main after removing the manifest input");

    for invalid in [
        "broken = [".to_owned(),
        declaration.replace("requires = [\"net.connect\"]", "requires = \"net.connect\""),
    ] {
        fs::write(&manifest, invalid).unwrap();
        let rejected = compile();
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("invalid manifest.toml"));
        assert_eq!(fs::read(&executable).unwrap(), signed);
    }
    println!(
        "manifest-schema-327: PASS malformed syntax and declaration types preserve the old signed ELF"
    );

    let mut tampered = signed;
    let matches: Vec<_> = tampered
        .windows(declaration.len())
        .enumerate()
        .filter_map(|(i, bytes)| (bytes == declaration.as_bytes()).then_some(i))
        .collect();
    assert_eq!(matches.len(), 1);
    tampered[matches[0]] ^= 1;
    fs::write(&executable, tampered).unwrap();
    assert!(
        !command("msign")
            .args(["elf", "verify", "main"])
            .output()
            .unwrap()
            .status
            .success()
    );
    println!("embedded-manifest-326: PASS declaration mutation fails signature verification");
    unsafe { libc::alarm(0) };
    drop(directory);
    println!("embedded-manifest-326: PASS cleanup");
}
