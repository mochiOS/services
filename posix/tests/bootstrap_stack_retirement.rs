use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn kernel_launch_no_longer_constructs_a_posix_process_environment() {
    let source = include_str!("../../../core/src/syscall/exec.rs");
    for forbidden in [
        "fn build_initial_user_stack(",
        "argv_offsets",
        "envp_offsets",
        "auxv_entries",
        "busybox.elf",
        "args: &[&str]",
        "envp: &[&str]",
        "read_nul_args_from_user",
    ] {
        assert!(
            !source.contains(forbidden),
            "kernel startup policy returned: {forbidden}"
        );
    }
    let loader = source
        .split("fn exec_with_data(")
        .nth(1)
        .unwrap()
        .split("fn check_image_byte_ceiling(")
        .next()
        .unwrap();
    assert!(loader.contains("bootstrap_stack::empty(end, exec.user_stack_size_pages)"));
    assert!(loader.contains("build_relocatable_user_stack(aslr_seed, startup,"));
    let native = source
        .split("pub fn process_create_syscall(")
        .nth(1)
        .unwrap();
    assert!(native.contains("ImageLaunch::Created(startup)"));
}

#[test]
fn production_newlib_parser_accepts_the_empty_native_entry_page() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = source.find("unsafe fn parse_stack(").unwrap();
    let end = source[start..].find("unsafe fn call_init_array(").unwrap() + start;
    let mut program = String::from(
        r#"
use core::{ptr,ffi::c_char};
struct StackView { argc:usize,argv:*mut *mut c_char,envp:*mut *mut c_char,
    stack_top:usize,executable:*const c_char,resource_policy:u64,upcall_stack:usize,initial_heap:usize }
mod mochios_posix_client { pub mod process_image {
    pub const AT_RESOURCE_POLICY:u64=0x6d000001;
    pub const AT_UPCALL_STACK:u64=0x6d000002;
    pub const AT_INITIAL_HEAP:u64=0x6d000003;
} }
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(
        r#"
fn main(){
    let page=[0usize;512]; let sp=page.as_ptr();
    let stack=unsafe {parse_stack(sp)};
    assert_eq!(stack.argc,0);
    assert!(unsafe{stack.argv.read()}.is_null());
    assert!(unsafe{stack.envp.read()}.is_null());
    assert!(stack.executable.is_null());
    assert_eq!((stack.resource_policy,stack.upcall_stack,stack.initial_heap),(0,0,0));
    assert_eq!(stack.stack_top,sp as usize);
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-empty-bootstrap-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-"])
        .arg("-o")
        .arg(&binary)
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
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(Command::new(&binary).status().unwrap().success());
    std::fs::remove_dir_all(directory).unwrap();
}
