#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

fn program() -> String {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = String::from(
        "#![allow(dead_code)]\nuse core::{ffi::{c_char,c_int,c_void},ptr};\nconst EINVAL:c_int=22; const EFAULT:c_int=14; const EIO:c_int=5; const ENOENT:c_int=2; const ENAMETOOLONG:c_int=91;\nconst PAGE_SIZE:usize=4096;\n",
    );
    probe::constants(
        &mut program,
        source,
        &[
            "PTHREAD_DEFAULT_STACK_SIZE",
            "PTHREAD_STACK_MIN",
            "PTHREAD_CREATE_JOINABLE",
            "PTHREAD_CREATE_DETACHED",
        ],
    );
    program.push_str("#[repr(C)]\n#[derive(Clone,Copy)]\n");
    program.push_str(probe::between(
        source,
        "pub struct PthreadAttr {",
        "struct ThreadControl {",
    ));
    program.push_str(
        &probe::between(
            source,
            "pub unsafe extern \"C\" fn pthread_attr_init(",
            "pub extern \"C\" fn posix_spawnattr_init(",
        )
        .replace("#[unsafe(no_mangle)]", ""),
    );
    program.push_str(
        "const ENOTSUP:c_int=134;\n#[repr(C)] pub struct SchedParam {sched_priority:c_int}\n",
    );
    program.push_str("mod mnu_abi {#[derive(Debug,PartialEq)] pub enum SyscallNumber {MemoryCopy} pub mod memory_copy {pub const MAX_BYTES:usize=4096;}}\nmod posix_protocol {pub const MAX_PATH_LEN:usize=4096;}\nmod user_copy_native {\n");
    program.push_str(
        &include_str!("support/user_copy_native.rs").replace("mnu_abi::", "crate::mnu_abi::"),
    );
    program.push_str("}\nuse user_copy_native::{syscall,syscall_errno};\nmod user_copy {\n");
    program.push_str(include_str!(
        "../../../user/crates/newlib-runtime/src/user_copy.rs"
    ));
    program.push_str("}\nmod pthread_attr {\n");
    program.push_str(
        &include_str!("../../../user/crates/newlib-runtime/src/pthread_attr.rs")
            .replace("#[unsafe(no_mangle)]", ""),
    );
    program.push_str("}\nuse pthread_attr::*;\n");
    program
}

#[test]
fn opaque_attribute_preserves_storage_size_and_requested_guard_value() {
    let mut program = program();
    program.push_str(
        r#"
    fn main() { unsafe {
        assert_eq!(size_of::<PthreadAttr>(),40); assert_eq!(align_of::<PthreadAttr>(),8);
        let mut storage = core::mem::MaybeUninit::<PthreadAttr>::uninit();
        let attr = storage.as_mut_ptr();
        assert_eq!(pthread_attr_init(attr),0);
        let mut value=99;
        assert_eq!(pthread_attr_getscope(attr,&mut value),0); assert_eq!(value,1);
        assert_eq!(pthread_attr_setscope(attr,0),ENOTSUP);
        assert_eq!(pthread_attr_setscope(attr,99),EINVAL);
        assert_eq!(pthread_attr_setscope(attr,1),0);
        assert_eq!(pthread_attr_getinheritsched(attr,&mut value),0); assert_eq!(value,1);
        for inherit in [2,1,2] {
            assert_eq!(pthread_attr_setinheritsched(attr,inherit),0);
            assert_eq!(pthread_attr_setinheritsched(attr,0),EINVAL);
            assert_eq!(pthread_attr_getinheritsched(attr,&mut value),0); assert_eq!(value,inherit);
        }
        for (policy,result) in [(0,0),(1,ENOTSUP),(2,ENOTSUP),(99,EINVAL)] {
            assert_eq!(pthread_attr_setschedpolicy(attr,policy),result);
            assert_eq!(pthread_attr_getschedpolicy(attr,&mut value),0); assert_eq!(value,0);
        }
        let mut param=SchedParam{sched_priority:99};
        assert_eq!(pthread_attr_getschedparam(attr,&mut param),0); assert_eq!(param.sched_priority,0);
        assert_eq!(pthread_attr_setschedparam(attr,&param),0);
        param.sched_priority=1; assert_eq!(pthread_attr_setschedparam(attr,&param),EINVAL);
        assert_eq!(pthread_attr_getschedparam(attr,&mut param),0); assert_eq!(param.sched_priority,0);
        assert_eq!(pthread_attr_setstackaddr(attr,0x10000usize as *mut c_void),0);
        let mut address=ptr::null_mut();
        assert_eq!(pthread_attr_getstackaddr(attr,&mut address),0); assert_eq!(address as usize,0x10000);
        assert_eq!(pthread_attr_setstackaddr(attr,ptr::null_mut()),EINVAL);
        assert_eq!(pthread_attr_getscope(ptr::null(),&mut value),EINVAL);
        assert_eq!(pthread_attr_getinheritsched(attr,ptr::null_mut()),EINVAL);
        assert_eq!(pthread_attr_getschedparam(attr,ptr::null_mut()),EINVAL);
        let mut guard = 0;
        assert_eq!(pthread_attr_getguardsize(attr,&mut guard),0);
        assert_eq!(guard,PAGE_SIZE);
        for size in [0,1,4095,4096,4097,usize::MAX] {
            assert_eq!(pthread_attr_setguardsize(attr,size),0);
            assert_eq!(pthread_attr_getguardsize(attr,&mut guard),0);
            assert_eq!(guard,size);
            let copy = *attr;
            assert_eq!(pthread_attr_getguardsize(&copy,&mut guard),0);
            assert_eq!(guard,size);
        }
        assert_eq!(pthread_attr_setstacksize(attr,PTHREAD_STACK_MIN),0);
        let mut size=0;
        assert_eq!(pthread_attr_getstacksize(attr,&mut size),0);
        assert_eq!(size,PTHREAD_STACK_MIN);
        assert_eq!(pthread_attr_setdetachstate(attr,PTHREAD_CREATE_DETACHED),0);
        let mut detach=99;
        assert_eq!(pthread_attr_getdetachstate(attr,&mut detach),0);
        assert_eq!(detach,PTHREAD_CREATE_DETACHED);
        assert_eq!(pthread_attr_getguardsize(attr,ptr::null_mut()),EINVAL);
        assert_eq!(pthread_attr_setguardsize(ptr::null_mut(),0),EINVAL);
        assert_eq!(pthread_attr_destroy(attr),0);
        assert_eq!(pthread_attr_getscope(attr,&mut value),EINVAL);
        assert_eq!(pthread_attr_setinheritsched(attr,1),EINVAL);
        assert_eq!(pthread_attr_getstackaddr(attr,&mut address),EINVAL);
        assert_eq!(pthread_attr_getguardsize(attr,&mut guard),EINVAL);
        assert_eq!(pthread_attr_setguardsize(attr,1),EINVAL);
    }}
    "#,
    );
    probe::run(&program);
}

fn run(body: &str) {
    let mut program = program();
    program.push_str(r#"
unsafe extern "C" {
    fn mmap(address:*mut c_void,length:usize,access:c_int,flags:c_int,fd:c_int,offset:i64)->*mut c_void;
    fn mprotect(address:*mut c_void,length:usize,access:c_int)->c_int;
    fn munmap(address:*mut c_void,length:usize)->c_int;
}
struct Mapping(*mut u8);
impl Mapping {
    fn new()->Self {
        let address=unsafe{mmap(ptr::null_mut(),2*PAGE_SIZE,3,0x22,-1,0)};
        assert_ne!(address as usize,usize::MAX); Self(address.cast())
    }
    fn protect(&self, offset:usize, access:c_int) {
        assert_eq!(unsafe{mprotect(self.0.add(offset).cast(),PAGE_SIZE,access)},0);
    }
}
impl Drop for Mapping {fn drop(&mut self){assert_eq!(unsafe{munmap(self.0.cast(),2*PAGE_SIZE)},0);}}
fn main(){unsafe {
    let mut storage=core::mem::MaybeUninit::<PthreadAttr>::uninit();
    let attr=storage.as_mut_ptr(); assert_eq!(pthread_attr_init(attr),0);
"#);
    program.push_str(body);
    program.push_str("}}\n");
    probe::run(&program);
}

#[test]
fn inaccessible_attribute_input_and_outputs_return_errors_without_raw_dereferences() {
    run(r#"
    let invalid=1usize as *mut PthreadAttr;
    let mut size=99;
    assert_eq!(pthread_attr_getstacksize(invalid,&mut size),EFAULT); assert_eq!(size,99);
    assert_eq!(pthread_attr_setguardsize(invalid,1),EFAULT);
    assert_eq!(pthread_attr_init(invalid),EFAULT);
    assert_eq!(pthread_attr_destroy(invalid),EFAULT);
    assert_eq!(pthread_attr_getstacksize(attr,1usize as *mut usize),EFAULT);
    assert_eq!(pthread_attr_getschedparam(attr,1usize as *mut SchedParam),EFAULT);
    assert_eq!(pthread_attr_setschedparam(attr,1usize as *const SchedParam),EFAULT);
    assert_eq!(pthread_attr_getscope(invalid,&mut (0 as c_int)),EFAULT);
    assert_eq!(pthread_attr_getinheritsched(invalid,&mut (0 as c_int)),EFAULT);
    assert_eq!(pthread_attr_getschedpolicy(invalid,&mut (0 as c_int)),EFAULT);
    assert_eq!(pthread_attr_setinheritsched(invalid,2),EFAULT);
    assert_eq!(pthread_attr_setscope(invalid,1),EFAULT);
    assert_eq!(pthread_attr_setschedpolicy(invalid,0),EFAULT);
    let overflow=(usize::MAX-1) as *mut PthreadAttr;
    assert_eq!(pthread_attr_getguardsize(overflow,&mut size),EFAULT);
    assert_eq!(pthread_attr::for_create(invalid).err(),Some(EFAULT));
    assert_eq!(pthread_attr_getguardsize(ptr::null(),&mut size),EINVAL);
    assert_eq!(pthread_attr_setdetachstate(attr,99),EINVAL);
    assert_eq!(pthread_attr_setstacksize(attr,PTHREAD_STACK_MIN-1),EINVAL);
    assert_eq!(pthread_attr_setstack(attr,ptr::null_mut(),PTHREAD_STACK_MIN),EINVAL);
    assert_eq!(pthread_attr_getstack(attr,ptr::null_mut(),&mut size),EINVAL);
    "#);
}

#[test]
fn read_only_storage_supports_observation_and_rejects_actual_mutation() {
    run(r#"
    let page=Mapping::new(); let readonly=page.0.cast::<PthreadAttr>();
    assert_eq!(pthread_attr_init(readonly),0); page.protect(0,1);
    let mut size=0; assert_eq!(pthread_attr_getstacksize(readonly,&mut size),0);
    assert_eq!(size,PTHREAD_DEFAULT_STACK_SIZE);
    assert_eq!(pthread_attr_setstacksize(readonly,2*PTHREAD_STACK_MIN),EFAULT);
    assert_eq!(pthread_attr_setdetachstate(readonly,PTHREAD_CREATE_DETACHED),EFAULT);
    assert_eq!(pthread_attr_setguardsize(readonly,0),EFAULT);
    assert_eq!(pthread_attr_setinheritsched(readonly,2),EFAULT);
    assert_eq!(pthread_attr_setstackaddr(readonly,0x10000usize as *mut c_void),EFAULT);
    assert_eq!(pthread_attr_setstack(readonly,0x10000usize as *mut c_void,PTHREAD_STACK_MIN),EFAULT);
    assert_eq!(pthread_attr_destroy(readonly),EFAULT); assert_eq!(pthread_attr_init(readonly),EFAULT);
    assert_eq!(pthread_attr_getstacksize(attr,page.0.cast()),EFAULT);
    assert_eq!(pthread_attr_getscope(attr,page.0.cast()),EFAULT);
    assert_eq!(pthread_attr::for_create(readonly).unwrap().stacksize,PTHREAD_DEFAULT_STACK_SIZE);
    "#);
}

#[test]
fn field_access_does_not_speculatively_touch_inaccessible_unrelated_fields() {
    run(r#"
    let page=Mapping::new(); let edge=page.0.add(PAGE_SIZE-8).cast::<PthreadAttr>();
    edge.cast::<c_int>().write(1); edge.cast::<c_int>().add(1).write(PTHREAD_CREATE_JOINABLE);
    page.protect(PAGE_SIZE,0);
    let mut value=99; assert_eq!(pthread_attr_getdetachstate(edge,&mut value),0);
    assert_eq!(value,PTHREAD_CREATE_JOINABLE);
    assert_eq!(pthread_attr_setdetachstate(edge,PTHREAD_CREATE_DETACHED),0);
    assert_eq!(pthread_attr_getscope(edge,&mut value),0); assert_eq!(value,1);
    let mut size=0;
    assert_eq!(pthread_attr_getstacksize(edge,&mut size),EFAULT);
    assert_eq!(pthread_attr_getguardsize(edge,&mut size),EFAULT);
    assert_eq!(pthread_attr_getinheritsched(edge,&mut value),EFAULT);
    assert_eq!(pthread_attr::for_create(edge).err(),Some(EFAULT));
    assert_eq!(pthread_attr_destroy(edge),0);
    assert_eq!(pthread_attr_getscope(edge,&mut value),EINVAL);
    "#);
}

#[test]
fn unaligned_storage_and_aliasing_outputs_use_captured_scalar_values() {
    run(r#"
    let mut bytes=[0xa5u8;64]; let odd=bytes.as_mut_ptr().add(1).cast::<PthreadAttr>();
    assert_eq!(pthread_attr_init(odd),0);
    assert_eq!(bytes[0],0xa5); assert_eq!(bytes[41],0xa5);
    assert_eq!(pthread_attr_setstack(odd,0x123400usize as *mut c_void,2*PTHREAD_STACK_MIN),0);
    assert_eq!(pthread_attr_setguardsize(odd,17),0);
    assert_eq!(pthread_attr_setinheritsched(odd,2),0);
    let mut output=[0xccu8;24];
    assert_eq!(pthread_attr_getstacksize(odd,output.as_mut_ptr().add(1).cast()),0);
    assert_eq!(usize::from_ne_bytes(output[1..9].try_into().unwrap()),2*PTHREAD_STACK_MIN);
    assert_eq!(pthread_attr_getschedparam(odd,output.as_mut_ptr().add(1).cast()),0);
    assert_eq!(&output[1..5],&0i32.to_ne_bytes());
    assert_eq!(pthread_attr_setschedparam(odd,output.as_ptr().add(1).cast()),0);
    assert_eq!(pthread_attr_getinheritsched(odd,output.as_mut_ptr().add(1).cast()),0);
    assert_eq!(&output[1..5],&2i32.to_ne_bytes());
    let captured=pthread_attr::for_create(odd).unwrap();
    assert_eq!(captured.stackaddr as usize,0x123400); assert_eq!(captured.guardsize,17);
    // Swap the two source fields through the output pointers. Both values must
    // already be captured before the first write changes the other source.
    assert_eq!(pthread_attr_getstack(odd,bytes.as_mut_ptr().add(17).cast(),bytes.as_mut_ptr().add(9).cast()),0);
    let swapped=pthread_attr::for_create(odd).unwrap();
    assert_eq!(swapped.stackaddr as usize,2*PTHREAD_STACK_MIN); assert_eq!(swapped.stacksize,0x123400);
    "#);
}

#[test]
fn creation_uses_one_owned_snapshot_and_validates_before_resources_are_acquired() {
    run(r#"
    user_copy_native::CALLS.with_borrow_mut(Vec::clear);
    let default=pthread_attr::for_create(ptr::null()).unwrap();
    assert_eq!(default.stacksize,PTHREAD_DEFAULT_STACK_SIZE); assert_eq!(default.guardsize,PAGE_SIZE);
    assert_eq!(default.detachstate,PTHREAD_CREATE_JOINABLE); assert!(default.stackaddr.is_null());
    assert!(user_copy_native::CALLS.with_borrow(|calls|calls.is_empty()));
    assert_eq!(pthread_attr_setstacksize(attr,2*PTHREAD_STACK_MIN),0);
    assert_eq!(pthread_attr_setguardsize(attr,1),0);
    user_copy_native::CALLS.with_borrow_mut(Vec::clear);
    let captured=pthread_attr::for_create(attr).unwrap();
    assert_eq!(user_copy_native::CALLS.with_borrow(|calls|calls.clone()),vec![40]);
    assert_eq!(pthread_attr_setstacksize(attr,3*PTHREAD_STACK_MIN),0);
    assert_eq!(pthread_attr_destroy(attr),0);
    assert_eq!(captured.stacksize,2*PTHREAD_STACK_MIN); assert_eq!(captured.guardsize,1);
    assert_eq!(pthread_attr::for_create(attr).err(),Some(EINVAL));
    assert_eq!(pthread_attr_init(attr),0); (*attr).stacksize=PTHREAD_STACK_MIN-1;
    assert_eq!(pthread_attr::for_create(attr).err(),Some(EINVAL));
    (*attr).stacksize=PTHREAD_STACK_MIN; (*attr).detachstate=99;
    assert_eq!(pthread_attr::for_create(attr).err(),Some(EINVAL));
    "#);
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let create = probe::between(
        source,
        "pub unsafe extern \"C\" fn pthread_create(",
        "pub unsafe extern \"C\" fn pthread_join(",
    );
    let capture = create.find("pthread_attr::for_create(attr)").unwrap();
    assert!(capture < create.find("reap_detached_threads()").unwrap());
    assert!(capture < create.find("register_current_thread()").unwrap());
    assert!(!create.contains("&*attr"));
}

#[test]
fn failed_scalar_input_preserves_attributes_and_partial_outputs_do_not_report_success() {
    run(r#"
    let page=Mapping::new(); let input=page.0.add(PAGE_SIZE-2).cast::<SchedParam>();
    page.protect(PAGE_SIZE,0);
    let before=core::slice::from_raw_parts(attr.cast::<u8>(),40).to_vec();
    assert_eq!(pthread_attr_setschedparam(attr,input),EFAULT);
    assert_eq!(core::slice::from_raw_parts(attr.cast::<u8>(),40),&before);
    assert_eq!(pthread_attr_setstack(attr,0x40000usize as *mut c_void,PTHREAD_STACK_MIN),0);
    let mut address=ptr::null_mut();
    // A successful first output is allowed to remain when the second output
    // faults. The operation still has to report the failure to its caller.
    assert_eq!(pthread_attr_getstack(attr,&mut address,page.0.add(PAGE_SIZE).cast()),EFAULT);
    assert_eq!(address as usize,0x40000);
    let mut size=0;
    assert_eq!(pthread_attr_getstack(attr,page.0.add(PAGE_SIZE).cast(),&mut size),EFAULT);
    assert_eq!(size,0);
    "#);
}
