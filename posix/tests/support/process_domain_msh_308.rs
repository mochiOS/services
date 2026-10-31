//! Test-only request from the actual measured msh, after Terminal launch.
use mochi_user_platform as p;
pub fn run() {
    let broker = p::process::find_by_name("capability.service").unwrap();
    let mut reply = [0; 8];
    let message = p::ipc::call(broker, b"DM08", &mut reply).unwrap();
    assert_eq!(message >> 32, broker);
    assert_eq!(message as u32, 8);
    assert_eq!(
        u64::from_le_bytes(reply),
        0,
        "msh must inherit the actual desktop launch domain"
    );
    let text = b"process-domain-308: PASS measured msh belongs to the real desktop domain through Terminal; no grant\n";
    p::syscall::call2(
        p::syscall::SyscallNumber::DebugWrite,
        text.as_ptr() as u64,
        text.len() as u64,
    )
    .unwrap();
}
