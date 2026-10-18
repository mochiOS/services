#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn platform_and_display_unsupported_paths_use_native_errors_not_enosys() {
    let mut program = probe::program();
    probe::constants(
        &mut program,
        include_str!("../../display/src/present.rs"),
        &["SIZE_LIMIT"],
    );
    program.push_str(
        r#"
extern crate self as mochi_user_platform;
#[macro_export] macro_rules! logln {($($arg:tt)*)=>{{}}}
mod syscall {
    pub use crate::mochi_user_syscall::*;
    pub type SysResult<T> = Result<T, SysError>;
}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../user/crates/platform/src/lib.rs"),
        "pub mod env {",
        "pub mod package;",
    ));
    program.push_str(probe::between(
        include_str!("../../display/src/protocol.rs"),
        "pub(crate) fn errno_status(",
        "#[cfg(test)]",
    ));
    program.push_str(
        r#"
use std::cell::Cell;
thread_local! {static COMMITS:Cell<usize>=const{Cell::new(0)};}
const GPU_SCENE_COMMIT_X:u32=0x564b4753;
const GPU_SCENE_COMMIT_WIDTH:u32=0x47505531;
mod platform {
    pub mod time {pub fn monotonic_milliseconds()->Result<u64,()> {Ok(0)}}
    pub mod memory {
        pub fn commit_framebuffer(_:u32,bytes:u32,_:u32,_:u32)->Result<(),crate::SysError> {
            assert_eq!(bytes,3);crate::COMMITS.set(crate::COMMITS.get()+1);Ok(())
        }
    }
}
mod mochios_viewkit_gpu_protocol {pub mod compositor {
    #[derive(Clone,Copy)] pub struct Timing {pub control_ms:u32}
    pub const HEADER_LEN:usize=16;
    pub fn frame_timing(_: &[u8])->Option<Timing>{None}
    pub fn set_frame_timing(_: &mut[u8],_:Timing)->Result<(),()>{Ok(())}
}}
struct FramebufferBackend {
    shared_surface:bool,pixels:*mut u8,mapped_size:u64,last_control_ms:u32,
}
impl FramebufferBackend {
"#,
    );
    program.push_str(probe::between(
        include_str!("../../display/src/framebuffer_backend.rs"),
        "    pub(crate) fn present_gpu_scene(&mut self, bytes:",
        "    pub(crate) fn present(&mut self, frame:",
    ));
    program.push_str(
        r#"
}
struct PanelFrame<'a>(&'a [u8]);
#[derive(Debug)]struct GpuError;
impl GpuError {fn errno(self)->u64{NativeError::AccessDenied.into_raw()}}
struct Gpu;
impl Gpu {fn present_gpu_panel(&mut self,_:&PanelFrame<'_>)->Result<(),GpuError>{Err(GpuError)}}
enum DisplayBackend {Framebuffer(FramebufferBackend),VirtioGpu(Gpu)}
impl DisplayBackend {
"#,
    );
    program.push_str(probe::between(
        include_str!("../../display/src/backend.rs"),
        "    pub(crate) fn present_gpu_panel(",
        "    pub(crate) fn present_gpu_scene(",
    ));
    program.push_str(r#"
}
fn main() {
    let unsupported=NativeError::Unsupported.into_raw();
    let reply_status=errno_status(unsupported);
    assert_eq!(SysError::from_raw(-i64::from(reply_status)).native_error(),Some(NativeError::Unsupported));
    let error=env::args().unwrap_err();
    assert_eq!(error.native_error(),Some(NativeError::Unsupported));
    assert_eq!(error.errno(),None);
    let mut pixels=[0xa5;8];
    let mut framebuffer=FramebufferBackend{shared_surface:false,pixels:pixels.as_mut_ptr(),mapped_size:8,last_control_ms:0};
    assert_eq!(framebuffer.present_gpu_scene(&[1,2,3]),Err(unsupported));
    assert_eq!(pixels,[0xa5;8]);assert_eq!(COMMITS.get(),0);
    framebuffer.shared_surface=true;framebuffer.pixels=std::ptr::null_mut();
    assert_eq!(framebuffer.present_gpu_scene(&[1,2,3]),Err(unsupported));
    framebuffer.pixels=pixels.as_mut_ptr();
    assert_eq!(framebuffer.present_gpu_scene(&[]),Err(unsupported));
    assert_eq!(COMMITS.get(),0);
    framebuffer.mapped_size=2;
    assert_eq!(framebuffer.present_gpu_scene(&[1,2,3]),Err(NativeError::LimitExceeded.into_raw()));
    assert_eq!(pixels,[0xa5;8]);assert_eq!(COMMITS.get(),0);
    framebuffer.mapped_size=8;
    assert_eq!(framebuffer.present_gpu_scene(&[1,2,3]),Ok(()));
    assert_eq!(pixels,[1,2,3,0xa5,0xa5,0xa5,0xa5,0xa5]);assert_eq!(COMMITS.get(),1);
    let mut backend=DisplayBackend::Framebuffer(framebuffer);
    assert_eq!(backend.present_gpu_panel(&PanelFrame(&[])),Err(unsupported));
    let mut backend=DisplayBackend::VirtioGpu(Gpu);
    assert_eq!(backend.present_gpu_panel(&PanelFrame(&[])),Err(NativeError::AccessDenied.into_raw()));
}
"#);
    probe::run(&program);
}
