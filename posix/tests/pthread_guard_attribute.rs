#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn opaque_attribute_preserves_storage_size_and_requested_guard_value() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = String::from(
        "#![allow(dead_code)]\nuse core::{ffi::{c_int,c_void},ptr};\nconst EINVAL:c_int=22;\nconst PAGE_SIZE:usize=4096;\n",
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
    program.push_str("const ENOTSUP:c_int=134;\n#[repr(C)] pub struct SchedParam {sched_priority:c_int}\nmod attributes {\n");
    program.push_str(
        &include_str!("../../../user/crates/newlib-runtime/src/pthread_attr.rs")
            .replace("#[unsafe(no_mangle)]", ""),
    );
    program.push_str("}\nuse attributes::*;\n");
    program.push_str(
        r#"
    fn main() { unsafe {
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
