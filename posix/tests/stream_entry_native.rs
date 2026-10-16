#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn stream_entry_validates_native_options_and_preserves_object_authority_errors() {
    let mut program = probe::program().replace("mod mnu_abi {pub mod status {",
        "mod mnu_abi {pub const STREAM_READ_OPTIONS_ALL:u64=2;pub const STREAM_WRITE_OPTIONS_ALL:u64=3;pub mod status {");
    program.push_str(
        r#"
use mnu_abi::status::Error;
use std::cell::Cell;
#[derive(Debug,PartialEq,Eq)]struct HandleRights(u64);
impl HandleRights{const READ:Self=Self(1);const WRITE:Self=Self(2);}
enum KernelObject{File(u64),Other}
thread_local!{
    static REQUIRED:Cell<u64>=const{Cell::new(1)};
    static FAILURE:Cell<Option<Error>>=const{Cell::new(None)};
    static LOOKUPS:Cell<usize>=const{Cell::new(0)};
    static IO:Cell<usize>=const{Cell::new(0)};
    static RESULT:Cell<u64>=const{Cell::new(7)};
}
fn object_native(raw:u64,rights:HandleRights)->Result<KernelObject,Error>{
    assert_eq!(rights.0,REQUIRED.get());LOOKUPS.set(LOOKUPS.get()+1);
    if let Some(error)=FAILURE.get(){return Err(error);}
    Ok(if raw==1{KernelObject::File(9)}else{KernelObject::Other})
}
mod syscall{pub mod fs{
    fn transfer(file:&u64,buffer:u64,length:u64,options:u64)->u64{
        assert_eq!((*file,buffer,length),(9,0x1000,7));assert!(options<=3);
        crate::IO.set(crate::IO.get()+1);crate::RESULT.get()
    }
    pub fn read_stream_handle(file:&u64,buffer:u64,length:u64,options:u64)->u64{
        assert_eq!(crate::REQUIRED.get(),1);transfer(file,buffer,length,options)
    }
    pub fn write_stream_handle(file:&u64,buffer:u64,length:u64,options:u64)->u64{
        assert_eq!(crate::REQUIRED.get(),2);transfer(file,buffer,length,options)
    }
}}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub fn stream_read(",
        "pub fn seek(",
    ));
    program.push_str(r#"
fn main(){
    for (operation,rights,options) in [
        (stream_read as fn(u64,u64,u64,u64)->u64,1,2),
        (stream_write as fn(u64,u64,u64,u64)->u64,2,3),
    ] {
        REQUIRED.set(rights);LOOKUPS.set(0);IO.set(0);
        assert_eq!(operation(1,0x1000,7,4),Error::InvalidArgument.into_raw());
        assert_eq!(LOOKUPS.get(),0);assert_eq!(IO.get(),0);
        for error in [Error::InvalidArgument,Error::AccessDenied,Error::NotReady,Error::ResourceUnavailable] {
            FAILURE.set(Some(error));
            assert_eq!(operation(1,0x1000,7,options),error.into_raw());
            assert_eq!(IO.get(),0);
        }
        FAILURE.set(None);
        assert_eq!(operation(2,0x1000,7,options),Error::InvalidArgument.into_raw());
        assert_eq!(IO.get(),0);
        for result in [0,3,7,Error::InvalidAddress.into_raw(),Error::NotReady.into_raw(),
            Error::PeerClosed.into_raw(),Error::BackingFailure.into_raw()] {
            RESULT.set(result);
            assert_eq!(operation(1,0x1000,7,options),result);
        }
    }
}
"#);
    probe::run(&program);
}
