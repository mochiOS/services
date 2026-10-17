#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn owned_display_snapshots_allow_reentrant_faults_and_reuse_storage_without_locked_allocations() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code)]
extern crate alloc;
extern crate self as mnu_abi;
#[path={status:?}]mod status;
use status::Error;
use std::cell::Cell;
use std::sync::atomic::{{AtomicBool,AtomicUsize,Ordering}};
static HELD:AtomicUsize=AtomicUsize::new(0);
static FAIL:AtomicBool=AtomicBool::new(false);
static LOCKED_ALLOC:AtomicUsize=AtomicUsize::new(0);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator{{
    unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{{
        if HELD.load(Ordering::Relaxed)!=0{{LOCKED_ALLOC.fetch_add(1,Ordering::Relaxed);}}
        if FAIL.swap(false,Ordering::Relaxed){{return std::ptr::null_mut();}}
        unsafe{{std::alloc::System.alloc(l)}}
    }}
    unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){{
        if HELD.load(Ordering::Relaxed)!=0{{LOCKED_ALLOC.fetch_add(1,Ordering::Relaxed);}}
        unsafe{{std::alloc::System.dealloc(p,l)}}
    }}
}}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
mod interrupt{{pub mod spinlock{{
    pub struct SpinLock<T>(std::sync::Mutex<T>);
    pub struct Guard<'a,T>(std::sync::MutexGuard<'a,T>);
    impl<T> SpinLock<T>{{
        pub const fn new(value:T)->Self{{Self(std::sync::Mutex::new(value))}}
        pub fn lock(&self)->Guard<'_,T>{{
            let guard=self.0.try_lock().expect("recursive display lock");
            crate::HELD.fetch_add(1,crate::Ordering::Relaxed);Guard(guard)
        }}
    }}
    impl<T> std::ops::Deref for Guard<'_,T>{{type Target=T;fn deref(&self)->&T{{&self.0}}}}
    impl<T> std::ops::DerefMut for Guard<'_,T>{{fn deref_mut(&mut self)->&mut T{{&mut self.0}}}}
    impl<T> Drop for Guard<'_,T>{{fn drop(&mut self){{crate::HELD.fetch_sub(1,crate::Ordering::Relaxed);}}}}
}}}}
#[path={pool:?}]mod owned_buffer;
const SUCCESS:u64=0;const PLATFORM_PRESENT_MAX:usize=64;const FIRMWARE_PRESENT_MAX:usize=16;
static PRESENT_BUFFERS:owned_buffer::Pool=owned_buffer::Pool::new(PLATFORM_PRESENT_MAX);
static FIRMWARE_PRESENT_BUFFER:interrupt::spinlock::SpinLock<[u8;FIRMWARE_PRESENT_MAX]>=interrupt::spinlock::SpinLock::new([0;FIRMWARE_PRESENT_MAX]);
thread_local!{{
    static AUTH:Cell<bool>=const{{Cell::new(true)}};
    static FIRMWARE:Cell<bool>=const{{Cell::new(false)}};
    static LIMIT:Cell<usize>=const{{Cell::new(64)}};
    static COPY_ERROR:Cell<Option<Error>>=const{{Cell::new(None)}};
    static BACKEND_ERROR:Cell<bool>=const{{Cell::new(false)}};
    static REENTER_COPY:Cell<bool>=const{{Cell::new(false)}};
    static REENTER_BACKEND:Cell<bool>=const{{Cell::new(false)}};
    static COPIES:Cell<usize>=const{{Cell::new(0)}};
    static PRESENTS:Cell<usize>=const{{Cell::new(0)}};
    static LAST:Cell<u8>=const{{Cell::new(0)}};
}}
mod capability{{pub enum Capability{{DisplayRead}}}}
mod syscall{{pub mod security{{
    pub fn caller_has_any_capability(_: &[crate::capability::Capability])->bool{{crate::AUTH.get()}}
}}}}
mod hypervisor{{pub enum HypercallNumber{{FirmwareFramebufferPresent}}pub const HYPERCALL_SUCCESS:u64=0;}}
mod util{{pub mod vga{{pub fn get_info()->Option<()>{{crate::FIRMWARE.get().then_some(())}}}}}}
mod hypervisor_guest{{
    pub fn is_active()->bool{{crate::FIRMWARE.get()}}
    pub fn invoke(_:crate::hypervisor::HypercallNumber,_:u64,_:u64,pointer:u64)->u64{{
        assert_eq!(crate::HELD.load(crate::Ordering::Relaxed),1);
        crate::LAST.set(unsafe{{*(pointer as *const u8)}});crate::PRESENTS.set(crate::PRESENTS.get()+1);
        u64::from(crate::BACKEND_ERROR.get())
    }}
}}
mod platform{{
    #[derive(Clone,Copy)]
"#,
        status = root.join("core/crates/abi/src/status.rs"),
        pool = root.join("core/src/syscall/owned_buffer.rs")
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/platform.rs"),
        "pub enum PlatformError {",
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct DisplayInfo",
    ));
    program.push_str(
        r#"
    pub fn display_transfer_limit()->Result<usize,PlatformError>{
        assert_eq!(crate::HELD.load(crate::Ordering::Relaxed),0);Ok(crate::LIMIT.get())
    }
    pub fn present_display(_:u32,_:u32,_:u32,_:u32,bytes:&[u8])->Result<(),PlatformError>{
        assert_eq!(crate::HELD.load(crate::Ordering::Relaxed),0);
        if crate::REENTER_BACKEND.replace(false){
            assert_eq!(crate::present_framebuffer(0,1|(1u64<<32),8192,4),0);
            assert_eq!(bytes,[0x11;4]);
        }
        crate::LAST.set(bytes[0]);crate::PRESENTS.set(crate::PRESENTS.get()+1);
        if crate::BACKEND_ERROR.get(){Err(PlatformError::Transport)}else{Ok(())}
    }
}
fn copy_from_user_native(pointer:u64,bytes:&mut[u8])->Result<(),Error>{
    assert_eq!(HELD.load(Ordering::Relaxed),0);COPIES.set(COPIES.get()+1);
    bytes.fill(if pointer==8192{0x22}else{0x11});
    if REENTER_COPY.replace(false){
        assert_eq!(present_framebuffer(0,1|(1u64<<32),8192,4),0);
        assert_eq!(bytes,[0x11;4]);
    }
    if let Some(error)=COPY_ERROR.get(){Err(error)}else{Ok(())}
}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/mod.rs"),
        "pub fn present_framebuffer(",
        "pub fn framebuffer_transfer_limit(",
    ));
    program.push_str(r#"
fn main(){
    let pool=owned_buffer::Pool::new(32);
    assert!(matches!(pool.acquire(33),Err(Error::LimitExceeded)));
    FAIL.store(true,Ordering::Relaxed);assert!(matches!(pool.acquire(8),Err(Error::ResourceUnavailable)));
    let mut first=pool.acquire(8).unwrap();first.bytes_mut().fill(1);
    let mut second=pool.acquire(16).unwrap();second.bytes_mut().fill(2);
    assert_eq!(first.bytes(),[1;8]);assert_eq!(second.bytes(),[2;16]);
    drop(first);drop(second);
    FAIL.store(true,Ordering::Relaxed);
    let reused=pool.acquire(16).unwrap();assert_eq!(reused.bytes(),[0;16]);drop(reused);
    assert!(FAIL.swap(false,Ordering::Relaxed));
    FAIL.store(true,Ordering::Relaxed);assert!(matches!(pool.acquire(32),Err(Error::ResourceUnavailable)));
    FAIL.store(true,Ordering::Relaxed);let reused=pool.acquire(16).unwrap();drop(reused);
    assert!(FAIL.swap(false,Ordering::Relaxed));
    let size=1|(1u64<<32);
    for firmware in [false,true]{
        FIRMWARE.set(firmware);COPIES.set(0);PRESENTS.set(0);
        REENTER_COPY.set(true);assert_eq!(present_framebuffer(0,size,4096,4),0);
        assert_eq!((COPIES.get(),PRESENTS.get(),LAST.get()),(2,2,0x11));
        for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::NotReady,Error::BackingFailure]{
            COPY_ERROR.set(Some(error));let before=PRESENTS.get();
            assert_eq!(present_framebuffer(0,size,4096,4),error.into_raw());assert_eq!(PRESENTS.get(),before);
        }
        COPY_ERROR.set(None);BACKEND_ERROR.set(true);
        assert_eq!(present_framebuffer(0,size,4096,4),Error::BackingFailure.into_raw());BACKEND_ERROR.set(false);
    }
    FIRMWARE.set(false);REENTER_BACKEND.set(true);
    assert_eq!(present_framebuffer(0,size,4096,4),0);assert_eq!(LAST.get(),0x11);
    let before=COPIES.get();AUTH.set(false);
    assert_eq!(present_framebuffer(0,size,4096,4),Error::AccessDenied.into_raw());AUTH.set(true);
    assert_eq!(present_framebuffer(0,size,0,4),Error::InvalidAddress.into_raw());
    assert_eq!(present_framebuffer(0,size,4096,3),Error::InvalidArgument.into_raw());
    assert_eq!(present_framebuffer(0,0,4096,0),Error::InvalidArgument.into_raw());
    assert_eq!(present_framebuffer(0,5|(4u64<<32),4096,80),Error::LimitExceeded.into_raw());
    assert_eq!(COPIES.get(),before);assert_eq!(HELD.load(Ordering::Relaxed),0);
    assert_eq!(LOCKED_ALLOC.load(Ordering::Relaxed),0);
}
"#);
    probe::run(&program);
}
