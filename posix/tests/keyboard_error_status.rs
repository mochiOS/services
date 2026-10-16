#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn keyboard_queue_pressure_does_not_invalidate_input_endpoint() {
    let source = include_str!("../../../drivers/ps2/i8042-driver/src/lib.rs");
    let mut program = probe::program();
    program.push_str(
        r#"
use std::{cell::RefCell,collections::VecDeque};
#[derive(Default)]
struct State { replies:VecDeque<Result<u64,SysError>>, packets:Vec<Vec<u8>>, yields:usize }
thread_local!{static STATE:RefCell<State>=RefCell::new(State::default());}
mod platform {
    pub mod input {
"#,
    );
    probe::constants(
        &mut program,
        include_str!("../../../user/crates/platform/src/lib.rs"),
        &["RAW_KIND_KEYBOARD"],
    );
    program.push_str(r#"
    }
    pub mod ipc {
        pub fn send(endpoint:u64,bytes:&[u8])->Result<u64,crate::SysError>{
            assert_eq!(endpoint,41);
            crate::STATE.with_borrow_mut(|s|{s.packets.push(bytes.to_vec());s.replies.pop_front().expect("extra send")})
        }
    }
    pub mod thread {pub fn yield_now(){crate::STATE.with_borrow_mut(|s|s.yields+=1);}}
}
"#);
    program.push_str(probe::between(
        source,
        "fn send_keyboard_byte(",
        "\nfn ascii_to_set1(",
    ));
    program.push_str(r#"
fn main(){
    STATE.set(State{replies:vec![Err(SysError::from(NativeError::NotReady.into_raw())),Err(SysError::from(NativeError::NotReady.into_raw())),Ok(1)].into(),..State::default()});
    let mut endpoint=41;send_keyboard_byte(&mut endpoint,0x1e);assert_eq!(endpoint,41);
    STATE.with_borrow(|s|{
        assert_eq!(s.yields,2);assert_eq!(s.packets.len(),3);assert!(s.replies.is_empty());
        assert!(s.packets.iter().all(|p|p==&[platform::input::RAW_KIND_KEYBOARD,0,0,0,0x1e,0,0,0]));
    });
    for status in [EAGAIN,EACCES,EPIPE,ENOENT,NativeError::ResourceUnavailable.into_raw(),NativeError::NotFound.into_raw()] {
        STATE.set(State{replies:vec![Err(SysError::from(status))].into(),..State::default()});
        let mut endpoint=41;send_keyboard_byte(&mut endpoint,0x9e);assert_eq!(endpoint,0);
        STATE.with_borrow(|s|{assert_eq!(s.yields,0);assert_eq!(s.packets.len(),1);assert!(s.replies.is_empty());});
    }
    STATE.set(State::default());let mut endpoint=0;send_keyboard_byte(&mut endpoint,0x1e);
    STATE.with_borrow(|s|assert!(s.packets.is_empty()));
}
"#);
    probe::run(&program);
}
