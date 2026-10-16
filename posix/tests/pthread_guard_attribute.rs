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
    program.push_str(
        r#"
    fn main() { unsafe {
        let mut storage = core::mem::MaybeUninit::<PthreadAttr>::uninit();
        let attr = storage.as_mut_ptr();
        assert_eq!(pthread_attr_init(attr),0);
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
        assert_eq!(pthread_attr_getguardsize(attr,&mut guard),EINVAL);
        assert_eq!(pthread_attr_setguardsize(attr,1),EINVAL);
    }}
    "#,
    );
    probe::run(&program);
}
