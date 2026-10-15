use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_process_identity_setter_moves_the_prepared_buffer_with_allocation_disabled() {
    let source = include_str!("../../../core/src/task/process.rs");
    let start = source.find("pub fn set_exe_path(").unwrap();
    let body = source[start..].find('{').unwrap() + start;
    let mut depth = 1;
    let end = source[body + 1..]
        .char_indices()
        .find_map(|(index, character)| {
            match character {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
            (depth == 0).then_some(body + index + 2)
        })
        .unwrap();
    let mut program = String::from(
        r#"
use std::alloc::{GlobalAlloc,Layout,System};
use std::sync::atomic::{AtomicBool,Ordering};
static DENY:AtomicBool=AtomicBool::new(false);
struct CheckedAllocator;
unsafe impl GlobalAlloc for CheckedAllocator {
    unsafe fn alloc(&self,layout:Layout)->*mut u8 {
        if DENY.load(Ordering::Relaxed) { std::ptr::null_mut() }
        else { unsafe {System.alloc(layout)} }
    }
    unsafe fn realloc(&self,pointer:*mut u8,layout:Layout,size:usize)->*mut u8 {
        if DENY.load(Ordering::Relaxed) { std::ptr::null_mut() }
        else {unsafe{System.realloc(pointer,layout,size)}}
    }
    unsafe fn dealloc(&self,pointer:*mut u8,layout:Layout) { unsafe{System.dealloc(pointer,layout)} }
}
#[global_allocator] static ALLOCATOR:CheckedAllocator=CheckedAllocator;
struct Process {exe_path:String}
impl Process {
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(
        r#"
}
fn main(){
    let mut process=Process{exe_path:"x".into()};
    let next="opaque-image-identity/".repeat(10);
    let pointer=next.as_ptr(); let capacity=next.capacity(); let length=next.len();
    DENY.store(true,Ordering::Relaxed);
    process.set_exe_path(next);
    DENY.store(false,Ordering::Relaxed);
    assert_eq!(process.exe_path.as_ptr(),pointer);
    assert_eq!(process.exe_path.capacity(),capacity);
    assert_eq!(process.exe_path.len(),length);
    assert_eq!(process.exe_path,"opaque-image-identity/".repeat(10));
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-image-identity-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Cstrip=symbols", "-"])
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
    let compiled = compiler.wait_with_output().unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed = Command::new(&binary).output().unwrap();
    // Remove only this test's uniquely created directory, including on failure.
    std::fs::remove_dir_all(&directory).unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}

#[test]
fn native_image_commit_moves_authorized_identity_and_loaders_prepare_before_mapping() {
    let source = include_str!("../../../core/src/syscall/exec.rs");
    let loader = source
        .split("fn exec_with_data(")
        .nth(1)
        .unwrap()
        .split("fn check_image_byte_ceiling(")
        .next()
        .unwrap();
    assert!(
        loader.find("storage::text(exec_path)").unwrap()
            < loader.find("create_user_page_table()").unwrap()
    );
    assert!(loader.contains("proc.set_exe_path(owned_identity)"));
    let replace = source
        .split("fn replace_current_process_image(")
        .nth(1)
        .unwrap()
        .split("pub fn process_image_replace_syscall(")
        .next()
        .unwrap();
    let committed = replace
        .split("release_process_borrowed_mappings(pid)?")
        .nth(1)
        .unwrap();
    assert!(committed.contains("process.set_exe_path(authorization.path)"));
    assert!(!committed.contains("storage::text("));
    assert!(!committed.contains(".to_string()"));
    assert!(!committed.contains(".push_str("));
    let captured = source
        .split("fn create_from_address_space(")
        .nth(1)
        .unwrap();
    assert!(captured.contains("process.set_exe_path(authorization.path)"));
}
