//! Run in a desktop session. Each decision must be made through the actual
//! protected window; the test never supplies input serials or approves itself.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("native-graphical-consent: requires mochiOS and physical decisions");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform as p;
    use mochios_file_publication::PrivateDirectory;
    use std::{
        fs,
        path::{Path, PathBuf},
        process::Command,
        time::{Duration, Instant},
    };
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let existing = match args.as_slice() {
        [] => None,
        [option, path] if option == "--image" && Path::new(path).is_absolute() => {
            Some(PathBuf::from(path))
        }
        _ => panic!("usage: native-graphical-consent [--image ABSOLUTE_ELF]"),
    };
    unsafe {
        libc::alarm(900);
    }
    let has_network = || p::capability::query(b"net.connect".as_ptr() as u64, 11).unwrap() == 1;
    assert!(!has_network());
    let broker = p::process::find_by_name("capability.service").unwrap();
    let mut reply = [0; 8];
    let result = p::ipc::call(
        broker,
        &p::capability::consent::frontend::encode_wait(
            p::capability::consent::frontend::Kind::Graphical,
        ),
        &mut reply,
    )
    .unwrap();
    assert_eq!(result as u32, 8);
    assert_eq!(
        u64::from_le_bytes(reply),
        13,
        "unmeasured renderer accepted"
    );
    println!("graphical-consent364: PASS untrusted presenter rejected");
    let directory = PrivateDirectory::new_in(Path::new("/tmp"), "gui-consent364").unwrap();
    let source = r#"
#include <stdio.h>
#include <string.h>
static unsigned long query(const char *name) {
    unsigned long number = @QUERY@, a0 = (unsigned long)name, a1 = strlen(name), a2 = 0;
    __asm__ volatile("syscall" : "+a"(number), "+D"(a0), "+S"(a1), "+d"(a2)
        : : "rcx", "r11", "r8", "r9", "r10", "memory", "cc");
    return number;
}
int main(void) {
    if (query("net.connect") != 1) return 91;
    if (query("capabilities.manage") != 0 || query("fs.write.all") != 0) return 92;
    puts("graphical-consent364: exact net.connect grant");
    return 37;
}
"#
    .replace(
        "@QUERY@",
        &(mnu_abi::SyscallNumber::CapQuery as u64).to_string(),
    );
    if existing.is_none() {
        fs::write(directory.path().join("main.c"), source).unwrap();
        fs::write(directory.path().join("manifest.toml"),
        "[package]\nid='local.consent364'\nname='Consent Test'\nversion='1'\n[[binary]]\npath='main'\nrequires=['net.connect']\n"
    ).unwrap();
        let compiled = Command::new("clang")
            .current_dir(directory.path())
            .args(["main.c", "-o", "main", "-Wl,--manifest,manifest.toml"])
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "clang: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        println!("graphical-consent364: PASS clang/link/automatic signing");
    }
    let program = existing.as_deref().unwrap_or_else(|| Path::new("./main"));
    for (instruction, allowed) in [
        ("Allow Once", true),
        ("Deny", false),
        ("Escape dismissal", false),
        ("Allow Once again", true),
    ] {
        println!("graphical-consent364: choose {instruction}");
        let deadline = Instant::now() + Duration::from_secs(20);
        let result = loop {
            let result = Command::new(program).current_dir(directory.path()).status();
            if result
                .as_ref()
                .err()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
            break result;
        };
        if allowed {
            let executed = result.unwrap();
            assert_eq!(executed.code(), Some(37), "target capability checks failed");
        } else {
            assert_eq!(
                result.unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
        assert!(!has_network(), "requester authority widened");
        println!("graphical-consent364: PASS {instruction}");
    }
    drop(directory);
    unsafe {
        libc::alarm(0);
    }
    println!("graphical-consent364: PASS fresh consent, isolated grants, cleanup");
}
