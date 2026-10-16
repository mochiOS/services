#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn actual_stream_writer_handles_peer_closure_and_allocation_failure_without_mutation() {
    let source = include_str!("../../../core/src/syscall/fs.rs");
    let mut program = probe::program();
    probe::constants(
        &mut program,
        include_str!("../../../core/crates/abi/src/lib.rs"),
        &["HANDLE_OPTION_NONBLOCKING"],
    );
    program.push_str(probe::between(
        source,
        "const MAX_IO_BYTES:",
        "#[derive(Clone, Copy, Debug",
    ));
    program.push_str("use alloc::vec::Vec;\n");
    program.push_str(probe::between(
        source,
        "struct PipeState {",
        "impl PipeState {",
    ));
    program.push_str(
        r#"
use std::sync::Mutex;
use std::cell::Cell;
thread_local!{static FAIL_AFTER:Cell<Option<usize>>=const{Cell::new(None)};}
struct FaultAllocator;
unsafe impl std::alloc::GlobalAlloc for FaultAllocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        let fail=FAIL_AFTER.with(|state|match state.get(){
            Some(0)=>{state.set(None);true}
            Some(count)=>{state.set(Some(count-1));false}
            None=>false,
        });
        if fail{std::ptr::null_mut()}else{unsafe{std::alloc::System.alloc(layout)}}
    }
    unsafe fn dealloc(&self,pointer:*mut u8,layout:std::alloc::Layout){
        unsafe{std::alloc::System.dealloc(pointer,layout)}
    }
}
#[global_allocator] static ALLOCATOR:FaultAllocator=FaultAllocator;
static WOKEN:Mutex<Vec<u64>>=Mutex::new(Vec::new());
struct FileHandle{stream:usize}
impl FileHandle{fn stream_endpoint(&self)->Option<(usize,bool)>{Some((self.stream,false))}}
mod interrupt {pub mod spinlock {
    pub struct SpinLock<T>(std::sync::Mutex<T>);
    impl<T> SpinLock<T>{
        pub const fn new(value:T)->Self{Self(std::sync::Mutex::new(value))}
        pub fn lock(&self)->std::sync::MutexGuard<'_,T>{self.0.lock().unwrap()}
    }
}}
mod task {
    pub type ThreadId=u64;
    pub fn current_thread_id()->Option<u64>{Some(7)}
    pub fn wake_registered_waiter(tid:u64){crate::WOKEN.lock().unwrap().push(tid);}
    pub fn sleep_thread_unless_woken(_:u64){panic!("closed peer must not wait")}
    pub fn yield_now(){panic!("closed peer must not yield")}
}
mod performance {pub fn record_vfs_temporary_buffer(_:usize){}}
mod syscall {
    pub fn copy_to_user(_:u64,_:&[u8])->Result<(),u64>{panic!("empty reader must not copy")}
    pub fn copy_from_user(pointer:u64,bytes:&mut [u8])->Result<(),u64>{
        assert_ne!(pointer,0);
        unsafe{std::ptr::copy_nonoverlapping(pointer as *const u8,bytes.as_mut_ptr(),bytes.len());}
        Ok(())
    }
}
mod upcall {pub fn current_has_deliverable_upcall()->bool{false}}
"#,
    );
    program.push_str(probe::between(
        source,
        "static PIPE_TABLE:",
        "pub(crate) fn alloc_stream_state(",
    ));
    program.push_str(probe::between(
        source,
        "pub fn close_pipe_endpoint_from_kernel(",
        "pub(crate) fn stream_signals(",
    ));
    program.push_str(probe::between(
        source,
        "pub(crate) fn register_stream_waiter(",
        "pub(crate) fn remove_stream_waiter(",
    ));
    program.push_str(probe::between(
        source,
        "pub(crate) fn remove_stream_waiter(",
        "pub(crate) fn file_handle_options(",
    ));
    program.push_str("mod io {use crate::*;\n");
    program.push_str(
        &probe::between(source, "fn read_pipe(", "pub(crate) fn write_file_handle(")
            .replace("fn read_pipe(", "pub fn read_pipe(")
            .replace(
                "mnu_abi::HANDLE_OPTION_NONBLOCKING",
                "HANDLE_OPTION_NONBLOCKING",
            ),
    );
    program.push_str(
        &probe::between(source, "fn write_pipe(", "#[cfg(test)]")
            .replace("fn write_pipe(", "pub fn write_pipe(")
            .replace(
                "mnu_abi::HANDLE_OPTION_NONBLOCKING",
                "HANDLE_OPTION_NONBLOCKING",
            ),
    );
    program.push_str(
        r#"
}
fn main(){
    PIPE_TABLE.lock()[0]=Some(PipeState{data:b"old".to_vec(),readers:1,writers:1,waiters:vec![9]});
    close_pipe_endpoint_from_kernel(0,false);
    assert_eq!(*WOKEN.lock().unwrap(),vec![9]);
    let input=b"new";
    for options in [0,HANDLE_OPTION_NONBLOCKING] {
        for complete in [false,true] {
            assert_eq!(io::write_pipe(0,options,input.as_ptr() as u64,3,complete),
                mnu_abi::status::Error::PeerClosed.into_raw());
            let table=PIPE_TABLE.lock();let pipe=table[0].as_ref().unwrap();
            assert_eq!(pipe.data,b"old");assert_eq!((pipe.readers,pipe.writers),(0,1));
            assert!(pipe.waiters.is_empty());assert_eq!(*WOKEN.lock().unwrap(),vec![9]);
        }
    }
    assert_eq!(io::write_pipe(0,0,0,0,true),0);
    close_pipe_endpoint_from_kernel(0,true);
    assert!(PIPE_TABLE.lock()[0].is_none());
    PIPE_TABLE.lock()[1]=Some(PipeState{data:Vec::new(),readers:1,writers:1,waiters:vec![8]});
    assert_eq!(io::write_pipe(1,0,input.as_ptr() as u64,3,true),3);
    assert_eq!(PIPE_TABLE.lock()[1].as_ref().unwrap().data,b"new");
    assert_eq!(*WOKEN.lock().unwrap(),vec![9,8]);
    // Fail the temporary buffer and then backing growth independently.
    for allocation in [0,1] {
        PIPE_TABLE.lock()[2]=Some(PipeState{data:Vec::new(),readers:1,writers:1,waiters:vec![9]});
        FAIL_AFTER.set(Some(allocation));
        let result=io::write_pipe(2,0,input.as_ptr() as u64,3,true);
        assert_eq!(FAIL_AFTER.get(),None);
        assert_eq!(result,mnu_abi::status::Error::ResourceUnavailable.into_raw());
        let table=PIPE_TABLE.lock();let pipe=table[2].as_ref().unwrap();
        assert!(pipe.data.is_empty());assert_eq!(pipe.waiters,vec![9]);
        assert_eq!((pipe.readers,pipe.writers),(1,1));
        assert_eq!(*WOKEN.lock().unwrap(),vec![9,8]);
    }
    // Writer admission cannot register a partial waiter on allocation failure.
    PIPE_TABLE.lock()[2]=Some(PipeState{data:vec![1;PIPE_BUFFER_CAP],readers:1,writers:1,waiters:Vec::new()});
    FAIL_AFTER.set(Some(1));
    let result=io::write_pipe(2,0,input.as_ptr() as u64,3,true);
    assert_eq!(FAIL_AFTER.get(),None);
    assert_eq!(result,mnu_abi::status::Error::ResourceUnavailable.into_raw());
    assert!(PIPE_TABLE.lock()[2].as_ref().unwrap().waiters.is_empty());
    assert_eq!(PIPE_TABLE.lock()[2].as_ref().unwrap().data,vec![1;PIPE_BUFFER_CAP]);
    // The empty-reader path and external readiness registration use the same
    // fallible waiter admission, without consuming data or sleeping on failure.
    PIPE_TABLE.lock()[2]=Some(PipeState{data:Vec::new(),readers:1,writers:1,waiters:Vec::new()});
    FAIL_AFTER.set(Some(0));
    let result=io::read_pipe(2,0,1,3);
    assert_eq!(FAIL_AFTER.get(),None);
    assert_eq!(result,mnu_abi::status::Error::ResourceUnavailable.into_raw());
    assert!(PIPE_TABLE.lock()[2].as_ref().unwrap().waiters.is_empty());
    FAIL_AFTER.set(Some(0));
    let result=register_stream_waiter(&FileHandle{stream:2},7);
    assert_eq!(FAIL_AFTER.get(),None);
    assert_eq!(result,Err(mnu_abi::status::Error::ResourceUnavailable.into_raw()));
    assert!(PIPE_TABLE.lock()[2].as_ref().unwrap().waiters.is_empty());
    assert_eq!(register_stream_waiter(&FileHandle{stream:2},7),Ok(2));
    // Re-registering an existing waiter needs no additional storage.
    FAIL_AFTER.set(Some(0));
    let result=register_stream_waiter(&FileHandle{stream:2},7);
    let pending=FAIL_AFTER.replace(None);
    assert_eq!(pending,Some(0));assert_eq!(result,Ok(2));
    assert_eq!(PIPE_TABLE.lock()[2].as_ref().unwrap().waiters,vec![7]);
}
"#,
    );
    probe::run(&program);
}

#[test]
fn posix_conversion_generates_sigpipe_before_partial_progress_hides_peer_closure() {
    let mut program = probe::program();
    program.push_str("const STATUS_EIO:i32=-5;const STATUS_EAGAIN:i32=-11;\nmod wire_status{use crate::mnu_abi;\n");
    program.push_str(
        &include_str!("../../../user/crates/posix-protocol/src/status.rs").replace("//!", "//"),
    );
    program.push_str("}\nmod newlib_errno{use crate::wire_status as mochios_posix_protocol;\n");
    program.push_str(
        &include_str!("../../../user/crates/posix-client/src/newlib_errno.rs")
            .replace("//!", "//")
            .replace(
                "mochios_posix_protocol::status::",
                "mochios_posix_protocol::",
            ),
    );
    program.push_str("}\nmod stream{\n");
    program.push_str(include_str!(
        "../../../user/crates/posix-client/src/stream.rs"
    ));
    program.push_str(
        r#"
}
use newlib_errno::{EPIPE,EIO};
use std::cell::Cell;
thread_local!{static SIGNALS:Cell<usize>=const{Cell::new(0)};}
mod posix_protocol{pub const SIGNAL_PIPE:u32=13;}
fn generate_thread_signal(signal:u32)->Result<(),i32>{
    assert_eq!(signal,13);SIGNALS.set(SIGNALS.get()+1);Ok(())
}
fn observe(result:Result<u64,i32>)->Result<usize,i32>{
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../user/crates/newlib-runtime/src/lib.rs"),
        "                    if matches!(result, Err(EPIPE))",
        "                },\n            )",
    ));
    program.push_str(
        r#"
}
fn main(){
    let raw=mnu_abi::status::Error::PeerClosed.into_raw();
    assert_eq!(raw as i64,-262134);
    assert_eq!(wire_status::normalize_failure(raw as i64),-32);
    let error=newlib_errno::from_status(raw as i64);assert_eq!(error,EPIPE);
    assert_eq!(observe(Err(error)),Err(EPIPE));assert_eq!(SIGNALS.get(),1);
    SIGNALS.set(0);
    assert_eq!(stream::write(90000,false,|offset,_,_|{
        observe(if offset==0{Ok(65536)}else{Err(error)})
    }),Ok(65536));
    assert_eq!(SIGNALS.get(),1);
    SIGNALS.set(0);
    assert_eq!(observe(Err(newlib_errno::EAGAIN)),Err(newlib_errno::EAGAIN));
    assert_eq!(observe(Ok(3)),Ok(3));assert_eq!(SIGNALS.get(),0);
}
"#,
    );
    probe::run(&program);
}
