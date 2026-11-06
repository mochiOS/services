//! Desktop integration: approve Always once, then run without further input.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("native-remembered-consent requires mochiOS");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform as p;
    use std::{
        path::PathBuf,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (path, remembered, deny_stdin_first) = match args.as_slice() {
        [flag, path] if flag == "--image" => (PathBuf::from(path), false, false),
        [flag, path, mode] if flag == "--image" && mode == "--expect-remembered" => {
            (PathBuf::from(path), true, false)
        }
        [flag, path, mode] if flag == "--image" && mode == "--deny-stdin-first" => {
            (PathBuf::from(path), false, true)
        }
        _ => panic!(
            "usage: native-remembered-consent --image ELF [--expect-remembered | --deny-stdin-first]"
        ),
    };
    assert!(path.is_absolute());
    let has_network = || p::capability::query(b"net.connect".as_ptr() as u64, 11).unwrap() == 1;
    assert!(!has_network());
    unsafe {
        libc::alarm(180);
    }
    if deny_stdin_first {
        use std::{fs::File, io::Write, os::fd::FromRawFd};
        let mut descriptors = [-1; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        let reader = unsafe { File::from_raw_fd(descriptors[0]) };
        let mut writer = unsafe { File::from_raw_fd(descriptors[1]) };
        writer.write_all(b"y\na\n").unwrap();
        drop(writer);
        println!("text-consent: stdin already contains y and a; wait, then choose n");
        let result = Command::new(&path).stdin(Stdio::from(reader)).status();
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(!has_network(), "requester authority widened");
        println!("text-consent: PASS piped y/a did not approve; physical n denied");
    }
    let execute = || {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let result = Command::new(&path).status();
            if result
                .as_ref()
                .err()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
            assert_eq!(
                result.unwrap().code(),
                Some(37),
                "exact target grant checks failed"
            );
            assert!(!has_network(), "requester authority widened");
            break;
        }
    };
    if !remembered {
        println!("remembered-consent377: choose Always Allow ONCE");
        execute();
        println!("remembered-consent377: PASS Always; no more input required");
    }
    for number in 1..=2 {
        execute();
        println!("remembered-consent377: PASS remembered execution {number}");
    }
    unsafe {
        libc::alarm(0);
    }
    println!("remembered-consent377: PASS exact child grant, unchanged parent, durable consent");
}
