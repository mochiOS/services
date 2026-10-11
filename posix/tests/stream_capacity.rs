use std::process::Command;

#[test]
fn production_stream_readiness_waits_for_the_requested_capacity() {
    let source = include_str!("../../../core/src/syscall/fs.rs");
    let state = source
        .split("struct PipeState {")
        .nth(1)
        .unwrap()
        .split("\nstatic PIPE_TABLE:")
        .next()
        .unwrap();
    let probe = format!(
        r#"
mod mnu_abi {{ pub use ::mnu_abi::*; }}
mod task {{ pub type ThreadId = u64; }}
const PIPE_BUFFER_CAP: usize = 1024;
struct PipeState {{{state}
fn main() {{
 let mut queue = PipeState {{ data: vec![0; 1023], readers: 1, writers: 1, waiters: vec![] }};
 assert_ne!(queue.signals(true) & mnu_abi::HANDLE_SIGNAL_WRITABLE, 0);
 assert_eq!(queue.signals_with_capacity(true, 512) & mnu_abi::HANDLE_SIGNAL_WRITABLE, 0);
 queue.data.truncate(513);
 assert_eq!(queue.signals_with_capacity(true, 512) & mnu_abi::HANDLE_SIGNAL_WRITABLE, 0);
 queue.data.truncate(512);
 assert_ne!(queue.signals_with_capacity(true, 512) & mnu_abi::HANDLE_SIGNAL_WRITABLE, 0);
 queue.readers = 0;
 assert_ne!(queue.signals_with_capacity(true, 1024) & mnu_abi::HANDLE_SIGNAL_PEER_CLOSED, 0);
 assert_eq!(queue.signals_with_capacity(true, 1) & mnu_abi::HANDLE_SIGNAL_WRITABLE, 0);
 assert_ne!(queue.signals(false) & mnu_abi::HANDLE_SIGNAL_READABLE, 0);
}}
"#
    );
    let dir = std::env::temp_dir().join(format!("mochios-stream-capacity-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    // Compile the production state machine with only its ABI/type dependencies stubbed.
    let probe = probe.replace("pub use ::mnu_abi::*;", "pub const HANDLE_SIGNAL_WRITABLE:u64=4; pub const HANDLE_SIGNAL_READABLE:u64=2; pub const HANDLE_SIGNAL_PEER_CLOSED:u64=8;");
    std::fs::write(dir.join("probe.rs"), probe).unwrap();
    let output = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings"])
        .arg(dir.join("probe.rs"))
        .arg("-o")
        .arg(dir.join("probe"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Command::new(dir.join("probe")).status().unwrap().success());
}

#[test]
fn capacity_conditions_keep_wait_rights_and_reject_wrong_resource_kinds() {
    assert_eq!(std::mem::size_of::<mnu_abi::HandleWaitItem>(), 24);
    assert_eq!(
        std::mem::offset_of!(mnu_abi::HandleWaitItem, minimum_write_bytes),
        4
    );
    let source = include_str!("../../../core/src/syscall/handle.rs");
    let wait = source
        .split("fn wait_item_signal(")
        .nth(1)
        .unwrap()
        .split("fn copy_wait_items_to_user(")
        .next()
        .unwrap();
    assert!(
        wait.find("HandleRights::WAIT").unwrap()
            < wait.find("item.minimum_write_bytes != 0").unwrap()
    );
    assert!(wait.contains("stream_signals_for_capacity"));
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(runtime.contains("u32::try_from(remaining).map_err(|_| EOVERFLOW)?"));
    assert!(runtime.contains(
        "wait_for_handle_capacity(entry, interests, control, caught, minimum_write_bytes)"
    ));
}
