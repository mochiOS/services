//! Execute the actual C adapter; service state and Handle transport are tested
//! separately by protocol.rs and terminal_reply_ownership.rs.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn tcgetsid_retains_the_terminal_lease_and_checks_pid_t_range() {
    let mut program = String::from(
        r#"
#![allow(dead_code,non_camel_case_types)]
use std::cell::Cell;
type c_int=i32;
const EOVERFLOW:c_int=75;
thread_local! {
    static LIVE:Cell<bool>=const {Cell::new(false)};
    static ERRNO:Cell<i32>=const {Cell::new(0)};
    static CALLS:Cell<usize>=const {Cell::new(0)};
    static FD_ERROR:Cell<Option<i32>>=const {Cell::new(None)};
    static CONNECT_ERROR:Cell<Option<i32>>=const {Cell::new(None)};
    static REPLY:Cell<Result<u64,i32>>=const {Cell::new(Ok(141))};
}
struct Lease;
impl Drop for Lease {fn drop(&mut self){assert!(LIVE.replace(false));}}
fn terminal_attachment(fd:i32)->Result<(Lease,u32),i32>{
    assert_eq!(fd,7);
    if let Some(error)=FD_ERROR.get(){return Err(error)}
    assert!(!LIVE.replace(true));Ok((Lease,29))
}
mod io_resources {
    pub fn with<T,R>(acquire:impl FnOnce()->Result<T,i32>,body:impl FnOnce(&mut T)->Result<R,i32>)->Result<R,i32>{
        let mut resource=acquire()?;body(&mut resource)
    }
}
struct Client;
fn posix_client()->Result<Client,i32>{
    assert!(LIVE.get());CONNECT_ERROR.get().map_or(Ok(Client),Err)
}
impl Client {fn terminal_session_id(&self,terminal:u32)->Result<u64,i32>{
    assert!(LIVE.get());assert_eq!(terminal,29);CALLS.set(CALLS.get()+1);REPLY.get()
}}
fn map_posix_client_error(error:i32)->i32{error}
fn result_with_errno(result:Result<i32,i32>,failure:i32)->i32{
    assert!(!LIVE.get());result.unwrap_or_else(|error|{ERRNO.set(error);failure})
}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../user/crates/newlib-runtime/src/lib.rs"),
        "pub extern \"C\" fn tcgetsid(",
        "\n#[unsafe(no_mangle)]\npub extern \"C\" fn tcsetpgrp(",
    ));
    program.push_str(
        r#"
fn main(){
    assert_eq!(tcgetsid(7),141);assert_eq!(CALLS.get(),1);
    for reply in [Ok(i32::MAX as u64),Ok(i32::MAX as u64+1),Ok(u64::MAX),Err(25),Err(13),Err(5)]{
        REPLY.set(reply);ERRNO.set(0);CALLS.set(0);
        let (result,errno)=match reply {Ok(value)if value<=i32::MAX as u64=>(value as i32,0),Ok(_)=>(-1,EOVERFLOW),Err(e)=>(-1,e)};
        assert_eq!(tcgetsid(7),result);assert_eq!(ERRNO.get(),errno);assert_eq!(CALLS.get(),1);
    }
    for error in [9,25] {
        FD_ERROR.set(Some(error));CALLS.set(0);ERRNO.set(0);
        assert_eq!(tcgetsid(7),-1);assert_eq!(ERRNO.get(),error);assert_eq!(CALLS.get(),0);
    }
    FD_ERROR.set(None);CONNECT_ERROR.set(Some(5));CALLS.set(0);ERRNO.set(0);
    assert_eq!(tcgetsid(7),-1);assert_eq!(ERRNO.get(),5);assert_eq!(CALLS.get(),0);assert!(!LIVE.get());
}
"#,
    );
    probe::run(&program);
}
