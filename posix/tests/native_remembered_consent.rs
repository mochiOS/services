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
        process::Command,
        time::{Duration, Instant},
    };
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (path, remembered) = match args.as_slice() {
        [flag, path] if flag == "--image" => (PathBuf::from(path), false),
        [flag, path, mode] if flag == "--image" && mode == "--expect-remembered" => {
            (PathBuf::from(path), true)
        }
        _ => panic!("usage: native-remembered-consent --image ELF [--expect-remembered]"),
    };
    assert!(path.is_absolute());
    let has_network = || p::capability::query(b"net.connect".as_ptr() as u64, 11).unwrap() == 1;
    assert!(!has_network());
    unsafe {
        libc::alarm(180);
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
