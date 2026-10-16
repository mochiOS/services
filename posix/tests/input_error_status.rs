#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn input_and_compositor_retry_only_queue_pressure_and_keep_delivery_bounds() {
    let input = include_str!("../../input/src/main.rs");
    let compositor = include_str!("../../compositor/src/input.rs");
    let protocol = include_str!("../../compositor/src/protocol.rs");
    let mut program = probe::program();
    program.push_str(r#"
use std::{cell::RefCell,collections::VecDeque};
#[derive(Default)]
struct State { replies: VecDeque<Result<u64,SysError>>, sends: Vec<(u64,Vec<u8>)>, yields: usize }
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}
mod platform {
    pub mod ipc {
        pub fn send(endpoint:u64,bytes:&[u8])->Result<u64,crate::SysError>{
            crate::STATE.with_borrow_mut(|s|{s.sends.push((endpoint,bytes.to_vec()));s.replies.pop_front().expect("unexpected extra send")})
        }
    }
    pub mod thread {pub fn yield_now(){crate::STATE.with_borrow_mut(|s|s.yields+=1);}}
}
fn setup(replies:Vec<Result<u64,SysError>>){STATE.set(State{replies:replies.into(),..State::default()});}
fn check(sends:usize,yields:usize){STATE.with_borrow(|s|{assert_eq!(s.sends.len(),sends);assert_eq!(s.yields,yields);assert!(s.replies.is_empty());});}
mod input {
    use super::*;
"#);
    probe::constants(
        &mut program,
        input,
        &["MAX_SUBSCRIBERS", "RELIABLE_SEND_RETRIES"],
    );
    program.push_str(probe::between(
        input,
        "fn send_event_reliably(",
        "\nfn sign_extend_mouse_delta(",
    ));
    program.push_str(r#"
    pub fn test(){
        let mut subscribers=[0;MAX_SUBSCRIBERS];subscribers[1]=41;subscribers[4]=42;
        setup(vec![Err(SysError::from(NativeError::NotReady.into_raw())),Ok(1),Ok(1)]);
        send_event_reliably(&subscribers,b"key");check(3,1);
        STATE.with_borrow(|s|assert_eq!(s.sends,vec![(41,b"key".to_vec()),(41,b"key".to_vec()),(42,b"key".to_vec())]));
        for status in [EAGAIN,EACCES,EPIPE,NativeError::ResourceUnavailable.into_raw(),NativeError::NotFound.into_raw()] {
            setup(vec![Err(SysError::from(status)),Ok(1)]);
            send_event_reliably(&subscribers,b"key");check(2,0);
        }
        let mut replies=vec![Err(SysError::from(NativeError::NotReady.into_raw()));RELIABLE_SEND_RETRIES];replies.push(Ok(1));
        setup(replies);send_event_reliably(&subscribers,b"key");check(RELIABLE_SEND_RETRIES+1,RELIABLE_SEND_RETRIES);
        setup(vec![]);send_event_reliably(&[0;MAX_SUBSCRIBERS],b"key");check(0,0);
    }
}
mod compositor {
    use super::*;
"#);
    probe::constants(&mut program, compositor, &["RELIABLE_SEND_RETRIES"]);
    probe::constants(
        &mut program,
        protocol,
        &[
            "EVENT_KEY",
            "EVENT_POINTER_BUTTON",
            "EVENT_POINTER_SCROLL",
            "EVENT_APPEARANCE_CHANGED",
            "EVENT_FOCUS_GAINED",
            "EVENT_FOCUS_LOST",
            "EVENT_POINTER_MOTION",
        ],
    );
    program.push_str(probe::between(
        protocol,
        "pub(crate) fn put_u32(",
        "\npub(crate) fn errno_status(",
    ));
    program.push_str(probe::between(protocol, "pub(crate) fn put_i32(", "\n}"));
    program.push_str("\n}\n");
    program.push_str(probe::between(
        compositor,
        "pub(crate) fn send_event(",
        "\nfn send_decoration_button_event(",
    ));
    program.push_str(r#"
    pub fn test(){
        for kind in [EVENT_KEY,EVENT_POINTER_BUTTON,EVENT_POINTER_SCROLL,EVENT_APPEARANCE_CHANGED,EVENT_FOCUS_GAINED,EVENT_FOCUS_LOST] {
            setup(vec![Err(SysError::from(NativeError::NotReady.into_raw())),Ok(1)]);
            send_event(41,57,kind,-2,3,4);check(2,1);
            STATE.with_borrow(|s|{
                assert_eq!(s.sends[0],s.sends[1]);assert_eq!(s.sends[0].0,41);
                assert_eq!(s.sends[0].1,encode_surface_event(57,kind,-2,3,4));
            });
            for status in [EAGAIN,EACCES,EPIPE,NativeError::ResourceUnavailable.into_raw(),NativeError::NotFound.into_raw()] {
                setup(vec![Err(SysError::from(status))]);send_event(41,57,kind,-2,3,4);check(1,0);
            }
            setup(vec![Err(SysError::from(NativeError::NotReady.into_raw()));RELIABLE_SEND_RETRIES]);
            send_event(41,57,kind,-2,3,4);check(RELIABLE_SEND_RETRIES,RELIABLE_SEND_RETRIES);
        }
        setup(vec![Err(SysError::from(NativeError::NotReady.into_raw()))]);send_event(41,57,EVENT_POINTER_MOTION,0,0,0);check(1,0);
        setup(vec![]);send_event(0,57,EVENT_KEY,0,0,0);check(0,0);
    }
}
fn main(){input::test();compositor::test();}
"#);
    probe::run(&program);
}
