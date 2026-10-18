#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn real_network_authorization_preserves_userspace_eperm_and_sender_checks() {
    let mut program = String::from("#![allow(dead_code)]\nmod mochios_posix_protocol {\n");
    probe::constants(
        &mut program,
        include_str!("../../../user/crates/posix-protocol/src/lib.rs"),
        &["STATUS_EPERM"],
    );
    program.push_str(
        r#"
}
use std::cell::Cell;
thread_local! {static SENDER:Cell<Option<u64>>=const{Cell::new(Some(42))};}
#[derive(Clone,Copy)]struct Identity{uid:u32}
#[derive(Clone,Copy)]struct ActiveSession{id:u64,linux_pid:Option<u64>,identity:Identity}
struct RequestNetworkRequest<'a>{session_id:u64,user:&'a str}
struct User{name:&'static str}
fn user_for_uid(uid:u32)->Option<User>{(uid==1000).then_some(User{name:"alice"})}
fn sender_process(endpoint:u64)->Option<u64>{assert_eq!(endpoint,77);SENDER.get()}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../service-manager/src/portal.rs"),
        "fn authorize_network(",
        "fn prompt_network(",
    ));
    program.push_str(r#"
fn main(){
    let session=ActiveSession{id:9,linux_pid:Some(42),identity:Identity{uid:1000}};
    let request=RequestNetworkRequest{session_id:9,user:"alice"};
    let denied=Err((-1i64) as u64);
    assert_eq!(authorize_network(77,session,&request),Ok(()));
    assert_eq!(authorize_network(77,ActiveSession{linux_pid:None,..session},&request),denied);
    assert_eq!(authorize_network(77,session,&RequestNetworkRequest{session_id:8,..request}),denied);
    for sender in [None,Some(41),Some(0)]{
        SENDER.set(sender);
        assert_eq!(authorize_network(77,session,&request),denied);
    }
    SENDER.set(Some(42));
    assert_eq!(authorize_network(77,ActiveSession{identity:Identity{uid:0},..session},&request),denied);
    assert_eq!(authorize_network(77,session,&RequestNetworkRequest{user:"root",..request}),denied);
    assert_eq!(authorize_network(77,session,&request),Ok(()));
}
"#);
    probe::run(&program);
}
