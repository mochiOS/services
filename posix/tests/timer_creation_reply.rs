#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn actual_native_reply_encodes_one_complete_id_and_reports_enqueue_failure() {
    let protocol = include_str!("../../../user/crates/posix-protocol/src/lib.rs");
    let main = include_str!("../src/main.rs");
    let mut program = String::from(
        "#![allow(dead_code)]\nextern crate self as mochios_posix_protocol;\nextern crate self as mochi_user_platform;\n",
    );
    probe::constants(
        &mut program,
        protocol,
        &[
            "MAGIC",
            "VERSION",
            "HEADER_LEN",
            "MAX_MESSAGE_LEN",
            "OP_STATUS",
        ],
    );
    program.push_str("#[derive(Default)]\n");
    program.push_str(probe::between(
        protocol,
        "pub struct Header {",
        "pub fn decode(",
    ));
    program.push_str(probe::between(protocol, "fn put_u16(", "fn get_u16("));
    program.push_str(
        r#"
use std::cell::{Cell,RefCell};
thread_local!{
 static FAIL:Cell<bool>=const{Cell::new(false)};
 static FRAMES:RefCell<Vec<Vec<u8>>>=const{RefCell::new(Vec::new())};
}
pub mod ipc {
 pub fn reply(sender:u64,bytes:&[u8])->Result<(),()>{
  assert_eq!(sender,17);
  crate::FRAMES.with_borrow_mut(|frames|frames.push(bytes.to_vec()));
  if crate::FAIL.get(){Err(())}else{Ok(())}
 }
}
"#,
    );
    program.push_str(probe::between(
        main,
        "fn reply_timer_created(",
        "#[cfg(target_os = \"mochios\")]\nfn reply_signal_wait(",
    ));
    program.push_str(
        r#"
fn main(){
 for id in [1,u64::MAX] {
  for fails in [true,false] {
   FAIL.set(fails);FRAMES.with_borrow_mut(|frames|frames.clear());
   assert_eq!(reply_timer_created(17,0x1234_5678_8765_4321,id),!fails);
   FRAMES.with_borrow(|frames|{
    assert_eq!(frames.len(),1);let bytes=&frames[0];assert_eq!(bytes.len(),40);
    assert_eq!(&bytes[..4],b"POSX");assert_eq!(&bytes[4..6],&VERSION.to_le_bytes());
    assert_eq!(&bytes[6..8],&OP_STATUS.to_le_bytes());
    assert_eq!(&bytes[8..16],&0x1234_5678_8765_4321_u64.to_le_bytes());
    assert_eq!(bytes[16..20],[0;4]);assert_eq!(bytes[20..24],8u32.to_le_bytes());
    assert_eq!(bytes[24..32],[0;8]);assert_eq!(bytes[32..],id.to_le_bytes());
   });
  }
 }
}
"#,
    );
    probe::run(&program);
    let branch = probe::between(
        main,
        "if matches!(header.opcode, protocol::OP_TIMER_CREATE | protocol::OP_TIMER_CREATE_PROCESS_CPU) =>",
        "protocol::OP_TIMER_DELETE",
    );
    assert!(branch.contains("service.create_process_timer_with_reply("));
    assert!(branch.contains("|id| reply_timer_created(sender, header.request_id, id)"));
    assert!(branch.contains("Ok(_) => None"));
}

#[test]
fn native_one_way_probe_tracks_current_wire_and_handle_abi() {
    use mnu_abi::{status::Error, SyscallNumber};
    use mochios_posix_protocol::{self as protocol, process_timer as wire};
    let source = include_str!("native_timer_creation_reply.c");
    for (name, value) in [
        ("CONTEXT_GET", SyscallNumber::LaunchHandleGet as u64),
        ("SEND", SyscallNumber::IpcSendObjectHandles as u64),
        ("TIMER_CREATE", protocol::OP_TIMER_CREATE as u64),
        ("MONOTONIC", wire::Clock::Monotonic as u64),
    ] {
        assert!(source.contains(&format!("{name} = {value}")));
    }
    assert_eq!(protocol::MAGIC, *b"POSX");
    assert_eq!(protocol::VERSION, 1);
    assert_eq!(protocol::HEADER_LEN + wire::CREATE_LEN, 56);
    assert_eq!(size_of::<mnu_abi::IpcObjectHandles>(), 72);
    assert!(source.contains(&format!(
        "#define NOT_READY INT64_C({})",
        Error::NotReady.into_raw() as i64
    )));
    assert_eq!(posix_service::process_timer::MAX_TIMERS_PER_PROCESS, 128);
}
