#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn display_info_limit_and_commit_preserve_native_failure_categories() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        "#![allow(dead_code)]\nextern crate self as mnu_abi;\n#[path={:?}]mod status;\n",
        root.join("core/crates/abi/src/status.rs"),
    );
    program.push_str(
        r#"
use status::Error;
use std::cell::{Cell,RefCell};
const SUCCESS:u64=0;const FIRMWARE_PRESENT_MAX:usize=65536;const PLATFORM_PRESENT_MAX:usize=1048576;
thread_local!{
    static AUTH:Cell<bool>=const{Cell::new(true)};
    static MEDIATED:Cell<bool>=const{Cell::new(true)};
    static VGA:Cell<bool>=const{Cell::new(false)};
    static BACKEND:Cell<Option<platform::PlatformError>>=const{Cell::new(None)};
    static COPY_ERROR:Cell<Option<Error>>=const{Cell::new(None)};
    static LIMIT:Cell<usize>=const{Cell::new(4096)};
    static CALLS:Cell<u32>=const{Cell::new(0)};
    static OUTPUT:RefCell<Vec<u8>>=const{RefCell::new(Vec::new())};
}
mod capability{pub enum Capability{DisplayRead}}
mod syscall{pub mod security{
    pub fn caller_has_any_capability(_: &[crate::capability::Capability])->bool{crate::AUTH.get()}
}}
mod hypervisor_guest{pub fn is_active()->bool{crate::MEDIATED.get()}}
mod hypervisor{
"#,
    );
    probe::constants(
        &mut program,
        include_str!("../../../core/crates/abi/src/hypervisor.rs"),
        &[
            "FRAMEBUFFER_FORMAT_MEDIATED",
            "FRAMEBUFFER_FORMAT_SHARED_SURFACE",
        ],
    );
    program.push_str(r#"
}
mod util{pub mod vga{
    pub struct Info{pub addr:u64,pub size:usize,pub width:usize,pub height:usize,pub stride:usize}
    pub fn get_info()->Option<Info>{crate::VGA.get().then_some(Info{addr:0x123000,size:4096,width:4,height:8,stride:4})}
}}
mod platform{
    #[derive(Clone,Copy)]
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/platform.rs"),
        "pub enum PlatformError {",
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct DisplayInfo",
    ));
    program.push_str(r#"
    pub struct Info{pub surface_address:u64,pub surface_size:u64,pub shared_surface:bool,pub width:u32,pub height:u32,pub stride:u32}
    pub fn display_info()->Result<Info,PlatformError>{
        match crate::BACKEND.get(){Some(error)=>Err(error),None=>Ok(Info{
            surface_address:0x456000,surface_size:8192,shared_surface:true,width:4,height:8,stride:4
        })}
    }
    pub fn display_transfer_limit()->Result<usize,PlatformError>{
        crate::BACKEND.get().map_or(Ok(crate::LIMIT.get()),Err)
    }
    pub fn commit_display(x:u32,y:u32,width:u32,height:u32)->Result<(),PlatformError>{
        assert_eq!((x,y,width,height),(1,2,3,4));crate::CALLS.set(crate::CALLS.get()+1);
        crate::BACKEND.get().map_or(Ok(()),Err)
    }
}
fn copy_to_user_native(pointer:u64,bytes:&[u8])->Result<(),Error>{
    assert_eq!((pointer,bytes.len()),(4096,32));
    if let Some(error)=COPY_ERROR.get(){return Err(error);}
    OUTPUT.with_borrow_mut(|out|{out.clear();out.extend_from_slice(bytes)});Ok(())
}
#[repr(C)]
"#);
    let syscall = include_str!("../../../core/src/syscall/mod.rs");
    program.push_str(probe::between(
        syscall,
        "struct UserFramebufferInfo {",
        "pub fn present_framebuffer(",
    ));
    program.push_str(probe::between(
        syscall,
        "pub fn framebuffer_transfer_limit(",
        "pub fn map_framebuffer(",
    ));
    program.push_str(r#"
fn main(){
    let position=1|(2u64<<32);let size=3|(4u64<<32);
    for (platform,native) in [(platform::PlatformError::Unsupported,Error::Unsupported),
        (platform::PlatformError::Unavailable,Error::NotReady),
        (platform::PlatformError::InvalidRequest,Error::InvalidArgument),
        (platform::PlatformError::Transport,Error::BackingFailure)]{
        BACKEND.set(Some(platform));
        assert_eq!(get_framebuffer_info(4096),native.into_raw());
        assert_eq!(framebuffer_transfer_limit(),native.into_raw());
        assert_eq!(commit_framebuffer(position,size),native.into_raw());
    }
    BACKEND.set(None);assert_eq!(get_framebuffer_info(4096),0);
    OUTPUT.with_borrow(|out|{
        assert_eq!(u64::from_le_bytes(out[..8].try_into().unwrap()),0x456000);
        assert_eq!(u64::from_le_bytes(out[8..16].try_into().unwrap()),8192);
        assert_eq!(u32::from_le_bytes(out[28..].try_into().unwrap()),1|hypervisor::FRAMEBUFFER_FORMAT_SHARED_SURFACE);
    });
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::NotReady,Error::BackingFailure]{
        COPY_ERROR.set(Some(error));assert_eq!(get_framebuffer_info(4096),error.into_raw());
    }
    COPY_ERROR.set(None);MEDIATED.set(false);
    assert_eq!(get_framebuffer_info(4096),Error::NotReady.into_raw());MEDIATED.set(true);
    VGA.set(true);BACKEND.set(Some(platform::PlatformError::Transport));
    assert_eq!(get_framebuffer_info(4096),0);
    OUTPUT.with_borrow(|out|assert_eq!(u64::from_le_bytes(out[..8].try_into().unwrap()),0));
    assert_eq!(framebuffer_transfer_limit(),FIRMWARE_PRESENT_MAX as u64);
    VGA.set(false);BACKEND.set(None);
    for limit in [0,PLATFORM_PRESENT_MAX+1]{LIMIT.set(limit);assert_eq!(framebuffer_transfer_limit(),Error::BackingFailure.into_raw());}
    LIMIT.set(4096);assert_eq!(framebuffer_transfer_limit(),4096);
    assert_eq!(commit_framebuffer(position,size),0);
    let before=CALLS.get();
    assert_eq!(commit_framebuffer(position,0),Error::InvalidArgument.into_raw());assert_eq!(CALLS.get(),before);
    AUTH.set(false);assert_eq!(framebuffer_transfer_limit(),Error::AccessDenied.into_raw());
    assert_eq!(commit_framebuffer(position,size),Error::AccessDenied.into_raw());assert_eq!(CALLS.get(),before);
}
"#);
    probe::run(&program);
}
