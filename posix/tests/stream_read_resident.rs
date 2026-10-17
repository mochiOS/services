#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn stream_faults_outside_locks_and_commits_only_resident_copy() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code)]
extern crate self as mnu_abi;
#[path={status:?}]mod status;
use status::Error;
use std::cell::{{Cell,RefCell}};
pub const HANDLE_OPTION_NONBLOCKING:u64=1;
thread_local!{{
    static PROC:Cell<bool>=const{{Cell::new(false)}};
    static PIPE:Cell<bool>=const{{Cell::new(false)}};
    static ROOT:Cell<u64>=const{{Cell::new(100)}};
    static WRITABLE:Cell<bool>=const{{Cell::new(false)}};
    static MODE:Cell<u8>=const{{Cell::new(0)}};
    static FAULTS:Cell<u32>=const{{Cell::new(0)}};
    static COPIES:Cell<u32>=const{{Cell::new(0)}};
    static WAKES:Cell<u32>=const{{Cell::new(0)}};
    static OUTPUT:RefCell<Vec<u8>>=const{{RefCell::new(Vec::new())}};
}}
fn unlocked(){{assert!(!PROC.get());assert!(!PIPE.get());}}
mod task{{
    pub type ThreadId=u64;
    pub fn current_thread_id()->Option<u64>{{Some(7)}}
    pub struct Process;
    impl Process{{
        pub fn page_table(&self)->Option<u64>{{Some(crate::ROOT.get())}}
        pub fn memory_regions(&self)->&[()]{{&[]}}
    }}
    pub fn with_process_mut<T>(pid:u64,f:impl FnOnce(&mut Process)->T)->Option<T>{{
        assert_eq!(pid,1);assert!(!crate::PIPE.get());assert!(!crate::PROC.replace(true));
        let result=f(&mut Process);crate::PROC.set(false);Some(result)
    }}
    pub fn sleep_thread_unless_woken(_:u64){{crate::unlocked();crate::syscall::fs::seed(b"later",0);}}
    pub fn yield_now(){{crate::unlocked();}}
}}
mod mem{{
    pub mod mapping_admission{{
        pub fn check_native(_:&[()],_:u64,_:u64)->Result<(),crate::Error>{{
            assert!(crate::PROC.get());assert!(!crate::PIPE.get());
            if crate::MODE.get()==7{{Err(crate::Error::NotReady)}}else{{Ok(())}}
        }}
    }}
    pub mod paging{{
        pub fn is_user_range_writable_in_table(_:u64,_:u64,_:u64)->bool{{crate::WRITABLE.get()}}
        pub fn copy_to_user_in_table(table:u64,address:u64,bytes:&[u8])->Result<(),crate::Error>{{
            assert!(crate::PROC.get());assert!(crate::PIPE.get());assert!(crate::WRITABLE.get());
            assert_eq!((table,address),(100,4096));crate::COPIES.set(crate::COPIES.get()+1);
            if crate::MODE.get()==6{{return Err(crate::Error::BackingFailure);}}
            crate::OUTPUT.with_borrow_mut(|out|out.extend_from_slice(bytes));Ok(())
        }}
    }}
}}
mod syscall{{
    use super::*;
    #[path={output:?}]mod user_output;
    pub(crate) use user_output::with_user_output_native;
    pub fn current_user_page_table()->Option<u64>{{Some(ROOT.get())}}
    pub mod security{{pub fn current_process_id()->Option<u64>{{Some(1)}}}}
    pub mod usercopy_error{{pub fn resident(error:crate::Error)->crate::Error{{error}}}}
    pub fn fault_in_user_range(table:u64,address:u64,length:u64,write:bool)->Result<(),Error>{{
        unlocked();assert_eq!((table,address,write),(100,4096,true));assert!(length<=5);
        FAULTS.set(FAULTS.get()+1);
        // A provider may itself acquire PIPE while preparing the destination.
        match MODE.get(){{
            1=>return Err(Error::ResourceUnavailable),2=>{{WRITABLE.set(false);return Ok(());}}
            3=>ROOT.set(200),4=>fs::seed(b"XYZ",1),5=>fs::seed(b"",0),_=>{{}}
        }}
        WRITABLE.set(true);Ok(())
    }}
    pub mod upcall{{pub fn current_has_deliverable_upcall()->bool{{crate::MODE.get()==8}}}}
    pub mod fs{{
        use super::*;
        const MAX_IO_BYTES:usize=128*1024*1024;
        struct PipeState{{data:Vec<u8>,writers:usize,waiters:Vec<u64>}}
        struct Lock(std::sync::Mutex<[Option<PipeState>;1]>);
        struct Guard<'a>(std::sync::MutexGuard<'a,[Option<PipeState>;1]>);
        impl Lock{{fn lock(&self)->Guard<'_>{{
            assert!(!PIPE.replace(true));Guard(self.0.try_lock().expect("recursive stream lock"))
        }}}}
        impl std::ops::Deref for Guard<'_>{{type Target=[Option<PipeState>;1];fn deref(&self)->&Self::Target{{&self.0}}}}
        impl std::ops::DerefMut for Guard<'_>{{fn deref_mut(&mut self)->&mut Self::Target{{&mut self.0}}}}
        impl Drop for Guard<'_>{{fn drop(&mut self){{PIPE.set(false);}}}}
        static PIPE_TABLE:Lock=Lock(std::sync::Mutex::new([None]));
        pub fn seed(bytes:&[u8],writers:usize){{unlocked();PIPE_TABLE.lock()[0]=Some(PipeState{{data:bytes.to_vec(),writers,waiters:vec![9]}});}}
        pub fn remaining()->Vec<u8>{{PIPE_TABLE.lock()[0].as_ref().unwrap().data.clone()}}
        fn wake_stream_waiters(waiters:Vec<u64>){{unlocked();WAKES.set(WAKES.get()+waiters.len()as u32);}}
        fn remove_stream_waiter(_:usize,current:u64){{PIPE_TABLE.lock()[0].as_mut().unwrap().waiters.retain(|w|*w!=current);}}
"#,
        status = root.join("core/crates/abi/src/status.rs"),
        output = root.join("core/src/syscall/user_output.rs")
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/fs.rs"),
        "fn read_pipe(",
        "pub(crate) fn write_file_handle(",
    ));
    program.push_str(
        r#"
        pub fn read(options:u64,length:u64)->u64{read_pipe(0,options,4096,length)}
    }
}
fn reset(mode:u8){unlocked();ROOT.set(100);WRITABLE.set(false);MODE.set(mode);
    FAULTS.set(0);COPIES.set(0);WAKES.set(0);OUTPUT.with_borrow_mut(Vec::clear);
    syscall::fs::seed(b"abc",1);
}
fn main(){
    reset(0);
    assert_eq!(syscall::with_user_output_native(4096,0,|_|Ok(())),Err(Error::InvalidArgument));
    assert_eq!(FAULTS.get(),0);
    assert_eq!(syscall::with_user_output_native(u64::MAX,1,|_|Ok(())),Err(Error::InvalidAddress));
    assert_eq!(FAULTS.get(),0);
    assert_eq!(syscall::with_user_output_native(4096,1,|copy|copy(b"ab")),Err(Error::InvalidArgument));
    assert_eq!(COPIES.get(),0);assert_eq!(syscall::fs::remaining(),b"abc");
    for (mode,error) in [(1,Error::ResourceUnavailable),(2,Error::NotReady),
        (3,Error::InvalidAddress),(6,Error::BackingFailure),(7,Error::NotReady)]{
        reset(mode);assert_eq!(syscall::fs::read(0,5),error.into_raw());
        assert_eq!(syscall::fs::remaining(),b"abc");assert_eq!(WAKES.get(),0);unlocked();
    }
    reset(0);assert_eq!(syscall::fs::read(0,2),2);assert_eq!(syscall::fs::remaining(),b"c");
    OUTPUT.with_borrow(|out|assert_eq!(out,b"ab"));assert_eq!(WAKES.get(),1);
    reset(4);assert_eq!(syscall::fs::read(0,5),3);
    OUTPUT.with_borrow(|out|assert_eq!(out,b"XYZ"));assert!(syscall::fs::remaining().is_empty());
    reset(5);assert_eq!(syscall::fs::read(0,5),0);assert_eq!(COPIES.get(),0);
    reset(0);syscall::fs::seed(b"",1);
    assert_eq!(syscall::fs::read(HANDLE_OPTION_NONBLOCKING,5),Error::NotReady.into_raw());
    assert_eq!(FAULTS.get(),0);
    assert_eq!(syscall::fs::read(0,5),5);OUTPUT.with_borrow(|out|assert_eq!(out,b"later"));
    reset(8);syscall::fs::seed(b"",1);
    assert_eq!(syscall::fs::read(0,5),Error::NotReady.into_raw());assert_eq!(FAULTS.get(),0);
    reset(0);syscall::fs::seed(b"",0);assert_eq!(syscall::fs::read(0,5),0);
    assert_eq!(FAULTS.get(),0);unlocked();
}
"#,
    );
    probe::run(&program);
}
