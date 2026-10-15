use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_admission_counts_the_detached_images_union_and_propagates_failures() {
    let source = include_str!("../../../core/src/syscall/exec.rs");
    let start = source.find("fn check_image_byte_ceiling(").unwrap();
    let end = source.find("fn replace_current_process_image(").unwrap();
    let usage = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/src/mem/mapping_usage.rs")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#[path = {usage:?}] pub(crate) mod mapping_usage;
use std::sync::Mutex;
static PAGES:Mutex<Vec<u64>>=Mutex::new(Vec::new());
static FAIL:Mutex<bool>=Mutex::new(false);
static READS:Mutex<usize>=Mutex::new(0);
mod task {{
    pub struct MemoryRegion(pub u64,pub u64);
    impl MemoryRegion {{ pub fn start(&self)->u64{{self.0}} pub fn end(&self)->Option<u64>{{Some(self.1)}} }}
}}
mod syscall {{ pub mod types {{pub const EFAULT:u64=(-14i64)as u64;pub const ENOMEM:u64=(-12i64)as u64;}} }}
mod mem {{
    pub(crate) use crate::mapping_usage;
    pub mod paging {{
        pub unsafe fn next_user_page_entry(table:u64,start:u64,end:u64)->Result<Option<u64>,()> {{
            assert_eq!(table,2,"must inspect the privately prepared target, not the caller");
            *crate::READS.lock().unwrap()+=1;
            if *crate::FAIL.lock().unwrap() {{return Err(());}}
            Ok(crate::PAGES.lock().unwrap().iter().copied().find(|&p|start<=p&&p<end))
        }}
    }}
}}
"#
    );
    program.push_str(&source[start..end]);
    program.push_str(
        r#"
fn main(){
    use task::MemoryRegion;
    use syscall::types::{EFAULT,ENOMEM};
    // Eager image, one faulted BSS page, stack, TLS and two initial heap pages.
    // The BSS reservation must be included, but its retained page only once.
    *PAGES.lock().unwrap()=vec![0x400000,0x600000,0x800000,0x900000,0xa00000,0xa01000];
    let reservations=[MemoryRegion(0x600000,0x604000)];
    assert_eq!(check_image_byte_ceiling(2,&reservations,9*4096),Ok(()));
    assert_eq!(check_image_byte_ceiling(2,&reservations,9*4096-1),Err(ENOMEM));
    assert_eq!(check_image_byte_ceiling(2,&reservations,0),Err(ENOMEM));
    assert_eq!(check_image_byte_ceiling(2,&[MemoryRegion(1,4096)],1<<30),Err(EFAULT));
    *FAIL.lock().unwrap()=true;
    assert_eq!(check_image_byte_ceiling(2,&reservations,1<<30),Err(EFAULT));
    *READS.lock().unwrap()=0;
    assert_eq!(check_image_byte_ceiling(2,&reservations,u64::MAX),Ok(()));
    assert_eq!(*READS.lock().unwrap(),0);
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-image-ceiling-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2021", "-O", "-"])
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
    let output = compiler.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Command::new(&binary).status().unwrap().success());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn bounded_preparation_precedes_all_old_image_mutations_and_uses_the_shared_authorizer() {
    assert_eq!(
        mnu_abi::SyscallNumber::ProcessImageReplaceBounded as u64,
        696
    );
    let source = include_str!("../../../core/src/syscall/exec.rs");
    let preparation = source
        .split("fn replace_current_process_image(")
        .nth(1)
        .unwrap()
        .split("pub fn process_image_replace_syscall(")
        .next()
        .unwrap();
    let check = preparation
        .find("check_image_byte_ceiling(new_pt_phys, &deferred_zero_regions, byte_ceiling)")
        .unwrap();
    for operation in [
        "map_elf_image(",
        "build_relocatable_user_stack(",
        "map_initial_tls(",
    ] {
        assert!(preparation.find(operation).unwrap() < check);
    }
    for operation in [
        "prepare_kernel_stack_user_table(",
        "retire_image_siblings(",
        "release_process_borrowed_mappings(",
        "thread.set_fs_base(",
        "process.set_page_table(",
        "process.set_capabilities_for_exec(",
        "retain_launch_context_handles_for_exec(",
    ] {
        assert!(
            check < preparation.find(operation).unwrap(),
            "premature mutation: {operation}"
        );
    }
    let entry = source
        .split("pub fn process_image_replace_bounded_syscall(")
        .nth(1)
        .unwrap()
        .split("fn process_image_replace_impl(")
        .next()
        .unwrap();
    assert!(entry.contains("process_image_replace_impl("));
    let shared = source
        .split("fn process_image_replace_impl(")
        .nth(1)
        .unwrap()
        .split("pub fn process_create_syscall(")
        .next()
        .unwrap();
    for authority in [
        "caller_has_process_spawn_capability()",
        "process.take_exec_authorization(",
        "PendingExecKind::ImageReplace",
        "ExecutionClass::Unprivileged",
        "handle::read_all(",
        "digest != authorization.executable_digest",
    ] {
        assert!(
            shared.contains(authority),
            "lost authority boundary: {authority}"
        );
    }
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let replace = runtime
        .split("fn replace_process_image(")
        .nth(1)
        .unwrap()
        .split("fn execve_with_launch_context(")
        .next()
        .unwrap();
    assert!(replace.contains("address_space::snapshot()?.byte_ceiling()"));
    assert!(replace.contains("syscall::image::replace_bounded("));
    assert!(!replace.contains("SyscallNumber::ProcessImageReplace"));
    assert!(replace.find("let identity_text =").unwrap() < replace.find("let opened =").unwrap());
    assert!(replace.find("let byte_ceiling =").unwrap() < replace.find("let opened =").unwrap());
}
