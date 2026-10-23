use std::io::Write;
use std::process::{Command, Stdio};

struct TemporaryDirectory(std::path::PathBuf);
impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn actual_vector_apis_release_their_buffer_before_cancelling_and_preserve_progress() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut program = format!(
        r#"
use std::ffi::{{c_char,c_void}};
use std::ptr;
extern crate self as mochios_posix_client;
extern crate self as mnu_abi;
#[derive(Debug,PartialEq)]pub enum SyscallNumber{{MemoryCopy}}
pub mod memory_copy{{pub const MAX_BYTES:usize=4096;}}
mod posix_protocol{{pub const MAX_PATH_LEN:usize=4096;}}
use std::sync::atomic::{{AtomicU32, AtomicU64, Ordering}};
type c_int = i32;
const EFAULT: i32 = 14;
const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;
const EIO: i32 = 5;
const EINTR: i32 = 4;
const EAGAIN: i32 = 11;
const ENOENT:i32=2;
const ENAMETOOLONG:i32=91;
const PAGE_SIZE:usize=4096;
#[repr(C)] struct IoVec {{ iov_base: *const c_void, iov_len: usize }}
#[repr(C)] struct IoVecMut {{ iov_base: *mut c_void, iov_len: usize }}
#[derive(Clone, Copy, PartialEq)] enum FdKind {{ ObjectStreamRead, ObjectStreamWrite, ObjectSocket, File }}
#[derive(Clone, Copy)] struct FdObject {{ kind: FdKind }}
#[derive(Clone, Copy)] struct FdEntry {{ handle: FdObject }}
struct Lease(FdEntry);
impl std::ops::Deref for Lease {{ type Target = FdEntry; fn deref(&self)->&FdEntry {{ &self.0 }} }}
impl Drop for Lease {{ fn drop(&mut self) {{
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    assert_eq!(PINS.fetch_sub(1, Ordering::Relaxed), 1);
}} }}
static PINS: AtomicU32 = AtomicU32::new(0);
struct ThreadControl {{ native: AtomicU32, active_signal_scope_id: AtomicU64, callback_resources: callback_resources::Chain }}
static CONTROL: ThreadControl = ThreadControl {{ native: AtomicU32::new(0), active_signal_scope_id: AtomicU64::new(0), callback_resources: callback_resources::Chain::new() }};
fn register_current_thread()->Option<(u32, &'static ThreadControl)> {{Some((1,&CONTROL))}}
fn defer_native_delivery()->Option<upcall_guard::Guard<'static>> {{upcall_guard::Guard::enter(&CONTROL.native)}}
unsafe extern "C" {{
    fn mochios_test_io_escape(operation: extern "C" fn(u32), mode: u32)->i32;
    fn mochios_test_io_jump()->!;
    fn mmap(address:*mut c_void,length:usize,protection:i32,flags:i32,fd:i32,offset:isize)->*mut c_void;
    fn mprotect(address:*mut c_void,length:usize,protection:i32)->i32;
    fn munmap(address:*mut c_void,length:usize)->i32;
}}
static PENDING: AtomicU32 = AtomicU32::new(0);
static CHECKS: AtomicU32 = AtomicU32::new(0);
static CASE: AtomicU32 = AtomicU32::new(0);
static VECTORS: AtomicU64 = AtomicU64::new(0);
static DECOY: AtomicU64 = AtomicU64::new(0);
static MUTATIONS: AtomicU32 = AtomicU32::new(0);
static IO_CALLS: AtomicU32 = AtomicU32::new(0);
static OUTPUT_PAGE: AtomicU64 = AtomicU64::new(0);
static LAST_ERRNO: AtomicU32 = AtomicU32::new(0);
fn rewrite_caller_metadata() {{
    let vectors = VECTORS.load(Ordering::Relaxed) as *mut IoVecMut;
    unsafe {{ (*vectors).iov_base = DECOY.load(Ordering::Relaxed) as *mut c_void;
        (*vectors).iov_len = 7; (*vectors.add(1)).iov_len = 0; }}
    MUTATIONS.fetch_add(1,Ordering::Relaxed);
}}
static ALLOCATIONS: std::sync::Mutex<std::collections::BTreeMap<usize, usize>> = std::sync::Mutex::new(std::collections::BTreeMap::new());
unsafe fn malloc(length: usize) -> *mut c_void {{
    assert!(CONTROL.callback_resources.capture_for_fork().is_none());
    let case = CASE.load(Ordering::Relaxed);
    if case == 7 || (case == 20 && length == 7) || (case == 21 && length == 16) {{ return std::ptr::null_mut(); }}
    if case == 23 && length == 7 {{ rewrite_caller_metadata(); }}
    let layout = std::alloc::Layout::from_size_align(length, 16).unwrap();
    let pointer = unsafe {{ std::alloc::alloc(layout) }};
    ALLOCATIONS.lock().unwrap().insert(pointer as usize, length);
    pointer.cast()
}}
unsafe fn free(pointer: *mut c_void) {{
    assert!(CONTROL.callback_resources.capture_for_fork().is_none());
    let length = ALLOCATIONS.lock().unwrap().remove(&(pointer as usize)).unwrap();
    unsafe {{ std::alloc::dealloc(pointer.cast(), std::alloc::Layout::from_size_align(length, 16).unwrap()) }};
}}
fn pthread_testcancel() {{
    let checks = CHECKS.fetch_add(1, Ordering::AcqRel) + 1;
    if PENDING.load(Ordering::Acquire) != 0 {{
        assert!(ALLOCATIONS.lock().unwrap().is_empty(), "cancellation leaked the vector buffer");
        assert_eq!(PINS.load(Ordering::Relaxed), 0);
        assert_eq!(checks, if matches!(CASE.load(Ordering::Acquire), 2 | 12 | 16) {{ 1 }} else {{ 2 }});
        std::process::exit(73)
    }}
}}
fn set_errno(error: i32) {{ LAST_ERRNO.store(error as u32,Ordering::Relaxed); }}
fn result_with_errno(result: Result<isize, i32>, failed: isize) -> isize {{ match result {{Ok(value)=>value,Err(error)=>{{set_errno(error);failed}}}} }}
fn with_fd_entry(_: i32) -> Result<Lease, i32> {{
    assert!(CONTROL.callback_resources.capture_for_fork().is_none());
    if CASE.load(Ordering::Relaxed) == 8 {{return Err(9)}}
    let kind=match CASE.load(Ordering::Relaxed){{47|53=>FdKind::ObjectStreamWrite,48|54=>FdKind::ObjectStreamRead,49|50|55|56=>FdKind::ObjectSocket,_=>FdKind::File}};
    PINS.fetch_add(1,Ordering::Relaxed); Ok(Lease(FdEntry {{ handle: FdObject {{ kind }} }}))
}}
fn record_stdio_io(_: &Result<isize,i32>) {{}}
fn positioned_file_io(fd:i32, _: *mut c_void, length:usize, offset:i64, writing:bool)->Result<isize,i32> {{
    let case = CASE.load(Ordering::Relaxed);
    assert_eq!((fd, length, offset, writing), (3, 7, 11, case >= 16));
    io_resources::with(|| with_fd_entry(fd), |_| {{
        PENDING.store(1,Ordering::Release);
        match case % 4 {{1 => Err(EINTR), 2 => Ok(3), 3 => Ok(0), _ => panic!("pending entry reached native I/O")}}
    }})
}}
fn escape_if_requested() {{
    if matches!(CASE.load(Ordering::Relaxed), 3..=6 | 10 | 11 | 27 | 28) {{
        CONTROL.active_signal_scope_id.store(7, Ordering::Relaxed);
        {{ let _native = defer_native_delivery(); unsafe {{ CONTROL.callback_resources.abandon_from(0) }}; }}
        unsafe {{ mochios_test_io_jump() }}
    }}
}}
fn syscall_write(_: FdEntry, buffer: *const c_void, length: usize) -> Result<isize, i32> {{
    IO_CALLS.fetch_add(1,Ordering::Relaxed);
    if CASE.load(Ordering::Relaxed)>=47 {{
        observe_vector_fork();
        assert_eq!(unsafe{{std::slice::from_raw_parts(buffer.cast::<u8>(),length)}},b"abcDEFG");
        return Ok(7);
    }}
    if CASE.load(Ordering::Relaxed)>=33 {{
        assert_eq!(unsafe{{std::slice::from_raw_parts(buffer.cast::<u8>(),length)}},b"abcDEFG");
        return Ok(length as isize);
    }}
    assert_eq!(unsafe {{ std::slice::from_raw_parts(buffer.cast::<u8>(), length) }}, b"abcDEFG");
    assert_eq!(ALLOCATIONS.lock().unwrap().len(), match CASE.load(Ordering::Relaxed) {{5 => 0, 10 | 23 => 2, _ => 1}});
    if CASE.load(Ordering::Relaxed) == 23 {{return Ok(7)}}
    escape_if_requested();
    PENDING.store(1, Ordering::Release);
    if CASE.load(Ordering::Relaxed) == 9 {{return Ok(3)}}
    Err(EINTR)
}}
fn syscall_read(_: FdEntry, buffer: *mut c_void, length: usize) -> Result<isize, i32> {{
    IO_CALLS.fetch_add(1,Ordering::Relaxed);
    if CASE.load(Ordering::Relaxed)>=47 {{
        observe_vector_fork();assert_eq!(length,7);
        unsafe{{ptr::copy_nonoverlapping(b"abcDEFG".as_ptr(),buffer.cast::<u8>(),7)}};
        return Ok(7);
    }}
    if CASE.load(Ordering::Relaxed)>=33 {{
        assert_eq!(length,7);
        let case=CASE.load(Ordering::Relaxed);
        unsafe{{ptr::copy_nonoverlapping(b"abcDEFG".as_ptr(),buffer.cast::<u8>(),if case==45{{3}}else{{7}})}};
        if case==44{{assert_eq!(unsafe{{mprotect(OUTPUT_PAGE.load(Ordering::Relaxed) as *mut _,4096,0)}},0);}}
        return Ok(if case==45{{3}}else if case==46{{8}}else{{7}});
    }}
    if CASE.load(Ordering::Relaxed) == 26 {{ assert_eq!(length,0); return Ok(0); }}
    assert_eq!(length, 7);
    assert_eq!(ALLOCATIONS.lock().unwrap().len(), match CASE.load(Ordering::Relaxed) {{6 => 0, 11 | 22 => 2, _ => 1}});
    if CASE.load(Ordering::Relaxed) == 22 {{
        unsafe {{ptr::copy_nonoverlapping(b"abcDEFG".as_ptr(), buffer.cast::<u8>(),7)}};
        rewrite_caller_metadata(); return Ok(7);
    }}
    escape_if_requested();
    PENDING.store(1, Ordering::Release);
    Err(EINTR)
}}
#[path = "{root_dir}/user/crates/posix-client/src/io_vector.rs"] pub mod io_vector;
#[path = "{root_dir}/user/crates/posix-client/src/upcall_guard.rs"] pub mod upcall_guard;
#[path = "{root_dir}/user/crates/newlib-runtime/src/callback_resources.rs"] mod callback_resources;
#[path = "{root_dir}/user/crates/newlib-runtime/src/io_resources.rs"] mod io_resources;
#[path = "{root_dir}/user/crates/newlib-runtime/src/vector_metadata.rs"] mod vector_metadata;
#[path = "{root_dir}/user/crates/newlib-runtime/src/vector_memory.rs"] mod vector_memory;
#[path = "{root_dir}/user/crates/newlib-runtime/src/user_copy.rs"] mod user_copy;
#[path = "{root_dir}/services/posix/tests/support/user_copy_native.rs"] mod user_copy_native;
use user_copy_native::{{syscall,syscall_errno}};
use vector_metadata::VectorMetadata;
fn message_entry(_: FdEntry, _: u64, length: usize, flags: i32, sending: bool) -> Result<isize, i32> {{
    let case = CASE.load(Ordering::Relaxed);
    assert_eq!((length, flags, sending), (7, 0, case % 2 == 1));
    assert_eq!(PINS.load(Ordering::Relaxed), 1);
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    assert!(!CONTROL.callback_resources.is_empty());
    escape_if_requested();
    PENDING.store(1, Ordering::Release);
    if case >= 31 {{Ok(3)}} else {{Err(EINTR)}}
}}
"#,
        root_dir = root.canonicalize().unwrap().display()
    );
    for entry in [
        "fn vector_errno(",
        "fn capture_vector_metadata(",
        "struct VectorBuffer {",
        "impl VectorBuffer {",
        "impl Drop for VectorBuffer {",
        "fn finish_io_cancellation(",
        "pub extern \"C\" fn _read(",
        "pub extern \"C\" fn _write(",
        "pub extern \"C\" fn pread(",
        "pub extern \"C\" fn pwrite(",
        "pub unsafe extern \"C\" fn writev(",
        "pub unsafe extern \"C\" fn readv(",
    ] {
        let start = runtime.find(entry).unwrap();
        let end = start + runtime[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&runtime[start..end]);
    }
    let socket = include_str!("../../../user/crates/newlib-runtime/src/socket.rs");
    for entry in [
        "fn message_io(",
        "pub extern \"C\" fn send(",
        "pub extern \"C\" fn recv(",
    ] {
        let start = socket.find(entry).unwrap();
        let end = start + socket[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&socket[start..end]);
    }
    program.push_str(
        r#"
extern "C" fn operation(case: u32) {
    if case>=47 {
        let mut first=[0u8;3];let mut second=[0u8;4];
        let writing=case%2==1;
        let mut vectors=[const{IoVecMut{iov_base:ptr::null_mut(),iov_len:0}};9];
        vectors[0]=IoVecMut{iov_base:if writing{b"abc".as_ptr().cast_mut().cast()}else{first.as_mut_ptr().cast()},iov_len:3};
        vectors[1]=IoVecMut{iov_base:if writing{b"DEFG".as_ptr().cast_mut().cast()}else{second.as_mut_ptr().cast()},iov_len:4};
        let count=if case>=53{9}else{2};
        let result=unsafe{if writing{writev(3,vectors.as_ptr().cast(),count)}else{readv(3,vectors.as_ptr(),count)}};
        assert_eq!(result,7);assert_eq!(CHECKS.load(Ordering::Acquire),1);
        if !writing{assert_eq!(&first,b"abc");assert_eq!(&second,b"DEFG");}
        return;
    }
    if case>=33 {
        let page=unsafe{mmap(ptr::null_mut(),8192,3,0x22,-1,0)};
        assert_ne!(page as usize,usize::MAX);
        OUTPUT_PAGE.store(page as u64,Ordering::Relaxed);
        unsafe{ptr::copy_nonoverlapping(b"abcDEFG".as_ptr(),page.cast(),7)};
        let mut first=[0x55u8;8];let mut second=[0x66u8;8];
        let mut vectors=[IoVecMut{iov_base:first.as_mut_ptr().cast(),iov_len:3},
                         IoVecMut{iov_base:second.as_mut_ptr().cast(),iov_len:4}];
        let writing=matches!(case,33|35|39|43);
        if writing {
            vectors[0].iov_base=b"abc".as_ptr().cast_mut().cast();
            vectors[1].iov_base=b"DEFG".as_ptr().cast_mut().cast();
        }
        match case {
            35|36=>{vectors[0].iov_base=1usize as *mut _;vectors[0].iov_len=7;vectors[1].iov_len=0;},
            37|43|45=>vectors[1].iov_base=1usize as *mut _,
            38=>{vectors[0].iov_base=usize::MAX as *mut _;vectors[0].iov_len=0;vectors[1].iov_len=7;},
            39|40=>{vectors[0].iov_base=page;vectors[0].iov_len=7;vectors[1].iov_len=0;
                assert_eq!(unsafe{mprotect(page,4096,1)},0);},
            44=>vectors[1].iov_base=page,
            _=>{},
        }
        let mut count=2;
        let mut unaligned=[0u8;17];
        let pointer=match case {
            33=>1usize as *const IoVecMut,
            34=>usize::MAX as *const IoVecMut,
            41=>{
                let at=unsafe{page.cast::<u8>().add(4088)};
                unsafe{ptr::write_unaligned(at.cast::<usize>(),first.as_mut_ptr() as usize)};
                assert_eq!(unsafe{mprotect(page.cast::<u8>().add(4096).cast(),4096,0)},0);
                count=1;at.cast()
            },
            42=>{
                unsafe{ptr::write_unaligned(unaligned.as_mut_ptr().add(1).cast(),IoVecMut{iov_base:first.as_mut_ptr().cast(),iov_len:7})};
                count=1;unaligned.as_ptr().wrapping_add(1).cast()
            },
            _=>vectors.as_ptr(),
        };
        let result=unsafe{if writing{writev(3,pointer.cast(),count)}else{readv(3,pointer,count)}};
        let expected=match case{37|44|45=>3,38|39|42=>7,_=>-1};
        assert_eq!(result,expected);
        if expected<0{assert_eq!(LAST_ERRNO.load(Ordering::Relaxed),if case==46{EIO as u32}else{EFAULT as u32});}
        assert_eq!(IO_CALLS.load(Ordering::Relaxed),u32::from(!matches!(case,33|34|35|41|43)));
        assert_eq!(CHECKS.load(Ordering::Relaxed),if expected>0{1}else{2});
        if matches!(case,37|44|45){assert_eq!(&first[..3],b"abc");assert_eq!(&first[3..],&[0x55;5]);}
        if case==38{assert_eq!(&second[..7],b"abcDEFG");assert_eq!(second[7],0x66);}
        if case==42{assert_eq!(&first[..7],b"abcDEFG");assert_eq!(first[7],0x55);}
        if case==46{assert_eq!(first,[0x55;8]);assert_eq!(second,[0x66;8]);}
        assert_eq!(unsafe{munmap(page,8192)},0);
        return;
    }
    if case >= 27 {
        let mut bytes = [0u8; 7];
        let result = if case % 2 == 1 {send(3, bytes.as_ptr().cast(), 7, 0)}
                     else {recv(3, bytes.as_mut_ptr().cast(), 7, 0)};
        assert_eq!(result, 3);
        assert_eq!(CHECKS.load(Ordering::Relaxed), 1);
        return;
    }
    if case >= 22 {
        let mut first = [0u8;3]; let mut second = [0u8;4]; let mut decoy = [0u8;16];
        let mut vectors = [const {IoVecMut {iov_base:std::ptr::null_mut(),iov_len:0}};9];
        vectors[0] = IoVecMut {iov_base:if case == 23 {b"abc".as_ptr().cast_mut().cast()} else {first.as_mut_ptr().cast()},iov_len:3};
        vectors[1] = IoVecMut {iov_base:if case == 23 {b"DEFG".as_ptr().cast_mut().cast()} else {second.as_mut_ptr().cast()},iov_len:4};
        VECTORS.store(vectors.as_mut_ptr() as u64,Ordering::Relaxed);
        DECOY.store(decoy.as_mut_ptr() as u64,Ordering::Relaxed);
        if case == 24 {vectors[8].iov_len = 1;}
        let result = unsafe { match case {
            23 => writev(3,vectors.as_ptr().cast(),9),
            25 => readv(3,1usize as *const IoVecMut,1025),
            26 => readv(3,std::ptr::null(),0),
            _ => readv(3,vectors.as_ptr(),9),
        }};
        assert_eq!(result,match case {24 | 25 => -1,26 => 0,_ => 7});
        assert_eq!(IO_CALLS.load(Ordering::Relaxed),u32::from(!matches!(case,24 | 25)));
        if case == 24 || case == 25 { assert_eq!(LAST_ERRNO.load(Ordering::Relaxed),if case == 24 {14} else {22}); }
        if case == 22 {assert_eq!(&first,b"abc");assert_eq!(&second,b"DEFG");}
        assert_eq!(MUTATIONS.load(Ordering::Relaxed),u32::from(matches!(case,22 | 23)));
        assert_eq!(decoy,[0;16]);
        return;
    }
    if (12..20).contains(&case) {
        let mut bytes = [0u8;7];
        if case % 4 == 0 {PENDING.store(1,Ordering::Release);}
        let result = if case < 16 { pread(3,bytes.as_mut_ptr().cast(),7,11) }
                     else { pwrite(3,bytes.as_ptr().cast(),7,11) };
        assert_eq!(result,3); assert_eq!(CHECKS.load(Ordering::Relaxed),1);
        return;
    }
    if (7..=9).contains(&case) || case >= 20 {
        if case >= 20 {
            let mut vectors = [const {IoVec {iov_base: std::ptr::null(), iov_len:0}};9];
            vectors[0] = IoVec { iov_base:b"abcDEFG".as_ptr().cast(), iov_len:7 };
            assert_eq!(unsafe {writev(3,vectors.as_ptr(),9)}, -1);
            assert_eq!(CHECKS.load(Ordering::Relaxed),2);
            return;
        }
        let vectors = [IoVec { iov_base:b"abcDEFG".as_ptr().cast(), iov_len:7 }];
        let result = unsafe { writev(3, vectors.as_ptr(), 1) };
        assert_eq!(result, if case == 9 {3} else {-1});
        assert_eq!(CHECKS.load(Ordering::Relaxed), if case == 9 {1} else {2});
        return;
    }
    if case == 2 {
        PENDING.store(1, Ordering::Release);
        assert_eq!(finish_io_cancellation(17), 17);
        assert_eq!(CHECKS.load(Ordering::Acquire), 0);
        finish_io_cancellation(0);
    } else if matches!(case, 0 | 3 | 10) {
        let mut vectors = [const {IoVec {iov_base: std::ptr::null(), iov_len:0}};9];
        vectors[0] = IoVec { iov_base: b"abc".as_ptr().cast(), iov_len:3 };
        vectors[1] = IoVec { iov_base: b"DEFG".as_ptr().cast(), iov_len:4 };
        unsafe { writev(3, vectors.as_ptr(), if case == 10 {9} else {2}) };
    } else if matches!(case, 1 | 4 | 11) {
        let mut first = [0u8; 3]; let mut second = [0u8; 4];
        let mut vectors = [const {IoVecMut {iov_base: std::ptr::null_mut(), iov_len:0}};9];
        vectors[0] = IoVecMut { iov_base:first.as_mut_ptr().cast(), iov_len:3 };
        vectors[1] = IoVecMut { iov_base:second.as_mut_ptr().cast(), iov_len:4 };
        unsafe { readv(3, vectors.as_ptr(), if case == 11 {9} else {2}) };
    } else if case == 5 {
        _write(3, b"abcDEFG".as_ptr().cast(), 7);
    } else {
        let mut bytes = [0u8;7]; _read(3,bytes.as_mut_ptr().cast(),7);
    }
    panic!("cancellation point returned");
}
fn main() {
    let case: u32 = std::env::args().nth(1).unwrap().parse().unwrap();
    CASE.store(case, Ordering::Release);
    if matches!(case, 3..=6 | 10 | 11 | 27 | 28) {
        assert_eq!(unsafe { mochios_test_io_escape(operation, case) }, 73);
        assert_eq!(PINS.load(Ordering::Relaxed), 0);
        assert!(ALLOCATIONS.lock().unwrap().is_empty(), "nonlocal exit leaked allocation");
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    } else {
        operation(case);
        assert_eq!(PINS.load(Ordering::Relaxed), 0);
        assert!(ALLOCATIONS.lock().unwrap().is_empty());
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(PENDING.load(Ordering::Relaxed), u32::from(matches!(case, 9 | 14 | 18 | 31 | 32)));
    }
}

fn observe_vector_fork(){
    let case=CASE.load(Ordering::Acquire);
    assert_eq!(ALLOCATIONS.lock().unwrap().len(),if case>=53{2}else{1});
    assert_eq!(PINS.load(Ordering::Acquire),1);
    let capture=CONTROL.callback_resources.capture_for_fork();
    assert_eq!(capture.is_some(),(case-47)%6<4);
    drop(capture);
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-vector-cancel-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let _cleanup = TemporaryDirectory(directory.clone());
    let executable = directory.join("probe");
    let trampoline = directory.join("escape.o");
    let compiled_c = Command::new("cc")
        .args(["-Wall", "-Wextra", "-Werror", "-c"])
        .arg(root.join("services/posix/tests/runtime_io_escape.c"))
        .arg("-o")
        .arg(&trampoline)
        .output()
        .unwrap();
    assert!(
        compiled_c.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled_c.stderr)
    );
    let mut compiler = Command::new("rustc")
        .args([
            "--edition=2021",
            "-Awarnings",
            "-Cdebuginfo=0",
            "-Cstrip=symbols",
            "-",
        ])
        .arg(format!("-Clink-arg={}", trampoline.display()))
        .arg("-o")
        .arg(&executable)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let compiled = compiler.wait_with_output().unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    for case in 0..59 {
        let executed = Command::new(&executable)
            .arg(case.to_string())
            .output()
            .unwrap();
        assert_eq!(
            executed.status.code(),
            Some(
                if matches!(case, 0..=2 | 12 | 13 | 15 | 16 | 17 | 19 | 29 | 30) {
                    73
                } else {
                    0
                }
            ),
            "case {case}: {}",
            String::from_utf8_lossy(&executed.stderr)
        );
    }
}

#[test]
fn internal_io_returns_through_owned_resources_instead_of_exiting_under_a_stdio_lock() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for entry in ["fn _write(", "fn _read("] {
        let start = source.find(entry).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap();
        assert!(!source[start..end].contains("pthread_testcancel()"));
    }
    let stream = source
        .split("fn stream_io_since<")
        .nth(1)
        .unwrap()
        .split("fn io_cancellation_requested(")
        .next()
        .unwrap();
    assert!(
        stream.find("io_cancellation_requested(control)").unwrap()
            < stream.find("operation()").unwrap()
    );
    assert!(!stream.contains("pthread_testcancel()"));
    let wait = source
        .split("fn wait_for_handle_capacity(")
        .nth(1)
        .unwrap()
        .split("fn stream_io<")
        .next()
        .unwrap();
    assert!(wait.contains("wait_cancellable("));
    assert!(wait.contains("minimum_write_bytes,"));
    assert!(wait.contains("nonrestart_signal_generation.load"));
    assert!(!wait.contains("pthread_testcancel()"));
}
