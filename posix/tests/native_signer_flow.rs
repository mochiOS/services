//! Real guest C compiler, linker driver and existing msign; no host-tool fallback.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("native-signer-flow: requires mochiOS");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochios_file_publication::PrivateDirectory;
    use std::os::unix::process::CommandExt;
    use std::{
        ffi::CString,
        fs,
        io::Write,
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt, symlink},
        },
        path::Path,
        process::{Command, Output},
    };
    const ROOT: &str = "/system/tests/posix/signer314";
    fn execute(tool: &str, arguments: &[&std::ffi::OsStr]) -> Output {
        let output = Command::new(format!("{ROOT}/bin/{tool}"))
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{tool}: {:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }
    unsafe {
        libc::alarm(900);
    }
    if std::env::args().any(|argument| argument == "--current-exe-child") {
        unsafe {
            std::env::set_var("MOCHI_EXECUTABLE_PATH", "/fake/env-path");
        }
        std::env::set_current_dir("/").unwrap();
        assert_eq!(
            std::env::current_exe().unwrap(),
            Path::new("/system/bin/native-signer314")
        );
        println!(
            "native-signer-314: PASS relative executable name ignores argv/env and later chdir"
        );
        return;
    }
    let directory = PrivateDirectory::new_in(Path::new("/tmp"), "native-signer314").unwrap();
    let alias = directory
        .path()
        .join(std::ffi::OsStr::from_bytes(b"probe-\xff"));
    symlink("/system/bin/native-signer314", &alias).unwrap();
    let result = Command::new(std::ffi::OsStr::from_bytes(b"./probe-\xff"))
        .arg0("fake argv0")
        .arg("--current-exe-child")
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    print!("{}", String::from_utf8_lossy(&result.stdout));
    let mut held = directory.create_file("held").unwrap();
    held.write_all(b"owned descriptor").unwrap();
    held.set_permissions(fs::metadata("/system/bin/msh").unwrap().permissions())
        .unwrap();
    held.set_permissions(fs::Permissions::from_mode(0)).unwrap();
    let published = directory.path().join("published");
    directory.publish("held", &held, &published).unwrap();
    assert_eq!(
        fs::metadata(&published).unwrap().permissions().mode() & 0o777,
        0
    );
    held.set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    assert_eq!(fs::read(&published).unwrap(), b"owned descriptor");
    println!(
        "native-signer-314: PASS stat mode reuse and publication through the owned descriptor"
    );
    let source = directory.path().join("main.c");
    let object = directory.path().join("main.o");
    let application = directory.path().join("main");
    let target = directory.path().join("target");
    let link = directory.path().join("link");
    fs::write(&target, b"target").unwrap();
    symlink("target", &link).unwrap();
    let before = fs::metadata(&target).unwrap();
    let name = CString::new(link.as_os_str().as_bytes()).unwrap();
    let times = [
        libc::timeval {
            tv_sec: -1,
            tv_usec: 123_456,
        },
        libc::timeval {
            tv_sec: 2_147_483_648,
            tv_usec: 999_999,
        },
    ];
    assert_eq!(
        unsafe { libc::lutimes(name.as_ptr(), times.as_ptr()) },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
    let changed = fs::symlink_metadata(&link).unwrap();
    assert!(changed.file_type().is_symlink());
    assert_eq!((changed.atime(), changed.atime_nsec()), (-1, 123_456_000));
    assert_eq!(
        (changed.mtime(), changed.mtime_nsec()),
        (2_147_483_648, 999_999_000)
    );
    let after = fs::metadata(&target).unwrap();
    assert_eq!(
        (before.mtime(), before.mtime_nsec()),
        (after.mtime(), after.mtime_nsec())
    );
    println!("native-signer-314: PASS lutimes updates only the link");
    fs::write(
        &source,
        "extern int puts(const char *); int main(void) { puts(\"guest-build314\"); return 37; }\n",
    )
    .unwrap();
    execute(
        "clang",
        &[
            "--target=x86_64-unknown-none-elf".as_ref(),
            "-fno-pie".as_ref(),
            "-mno-red-zone".as_ref(),
            "-c".as_ref(),
            source.as_os_str(),
            "-o".as_ref(),
            object.as_os_str(),
        ],
    );
    let sdk = format!("{ROOT}/sdk");
    let lld = format!("{ROOT}/bin/ld.lld");
    let msign = format!("{ROOT}/bin/msign");
    let mut arguments: Vec<&std::ffi::OsStr> = vec![
        "--mochios-sdk".as_ref(),
        sdk.as_ref(),
        "--mochios-lld".as_ref(),
        lld.as_ref(),
        "--mochios-msign".as_ref(),
        msign.as_ref(),
        object.as_os_str(),
        "-o".as_ref(),
        application.as_os_str(),
    ];
    execute("ld", &arguments);
    execute(
        "msign",
        &["elf".as_ref(), "verify".as_ref(), application.as_os_str()],
    );
    let output = Command::new(&application).output().unwrap();
    assert_eq!(output.status.code(), Some(37));
    assert_eq!(output.stdout, b"guest-build314\n");
    println!("native-signer-314: PASS guest clang -> ld.lld -> msign -> generated ELF execution");
    let mut bytes = fs::read(&application).unwrap();
    bytes[9] ^= 1;
    fs::write(&application, bytes).unwrap();
    assert!(
        !Command::new(&msign)
            .args(["elf", "verify"])
            .arg(&application)
            .output()
            .unwrap()
            .status
            .success()
    );
    println!("native-signer-314: PASS tampered ELF signature rejected");
    let private = directory.path().join("developer.key");
    let public = directory.path().join("developer.pub");
    execute(
        "msign",
        &[
            "key".as_ref(),
            "generate".as_ref(),
            "--private-key".as_ref(),
            private.as_os_str(),
            "--public-key".as_ref(),
            public.as_os_str(),
        ],
    );
    assert_eq!(
        fs::metadata(&private).unwrap().permissions().mode() & 0o077,
        0
    );
    arguments.extend([
        "--sign-key".as_ref(),
        private.as_os_str(),
        "--public-key".as_ref(),
        public.as_os_str(),
    ]);
    execute("ld", &arguments);
    execute(
        "msign",
        &[
            "elf".as_ref(),
            "verify".as_ref(),
            application.as_os_str(),
            "--public-key".as_ref(),
            public.as_os_str(),
        ],
    );
    println!("native-signer-314: PASS native random-backed key generation and keyed signing");
    let help = execute("msign", &["certificate".as_ref(), "--help".as_ref()]);
    assert!(!String::from_utf8_lossy(&help.stdout).contains("obtain"));
    unsafe {
        libc::alarm(0);
    }
    drop(directory);
    println!("native-signer-314: PASS cleanup");
}
