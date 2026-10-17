//! Isolated Input-role probe: uses the real std/newlib/Handle path, no IME parser.
use std::fs::{self, File};
use std::io::{self, Read};
use std::time::Instant;

const PATH: &str = "/system/libraries/ime/ja.mime";

fn hash(mut value: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        value = value.wrapping_mul(31).wrapping_add(u64::from(*byte));
    }
    value
}

pub(crate) fn run() -> io::Result<()> {
    eprintln!("rust-dictionary-read: metadata");
    let expected = fs::metadata(PATH)?.len();
    assert!(expected != 0, "dictionary fixture must not be empty");
    eprintln!("rust-dictionary-read: size={expected}");
    let start = Instant::now();
    let bytes = fs::read(PATH)?;
    eprintln!(
        "rust-dictionary-read: whole={} elapsed_ms={}",
        bytes.len(),
        start.elapsed().as_millis()
    );
    assert_eq!(bytes.len() as u64, expected);
    let whole_hash = hash(0, &bytes);
    drop(bytes);

    let mut file = File::open(PATH)?;
    let mut buffer = [0; 65536];
    let mut count = 0u64;
    let mut streamed_hash = 0;
    let start = Instant::now();
    loop {
        let read = match file.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if read == 0 {
            break;
        }
        count += read as u64;
        streamed_hash = hash(streamed_hash, &buffer[..read]);
    }
    assert_eq!(count, expected);
    assert_eq!(streamed_hash, whole_hash);
    eprintln!(
        "rust-dictionary-read: PASS bytes={count} streamed_ms={}",
        start.elapsed().as_millis()
    );
    Ok(())
}

#[cfg(target_os = "mochios")]
fn main() {
    if let Err(error) = run() {
        eprintln!("rust-dictionary-read: FAIL {error:?}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("rust-dictionary-read: SKIP (requires mochiOS)");
}
