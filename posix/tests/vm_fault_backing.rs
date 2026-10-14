use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_fault_page_gate_rejects_eof_without_confusing_provider_errors() {
    let source = include_str!("../../../core/src/mem/vm_object.rs");
    let mut program = String::from(
        r#"
use std::sync::Arc;
const PAGE_BYTES: usize = 4096;
mod syscall { pub const EINVAL: u64 = (-22i64) as u64; }
enum VmObjectSource { Memory(()), Provider }
struct VmObject { source: VmObjectSource, outcome: Result<usize, u64> }
"#,
    );
    let start = source.find("pub enum VmPageError {").unwrap();
    let end = start + source[start..].find("\n}\n").unwrap() + 3;
    program.push_str("#[derive(Debug,PartialEq,Eq)]\n");
    program.push_str(&source[start..end]);
    program.push_str("impl VmObject {\n");
    // Only backing reads are simulated. Execute the production fault gate
    // and source-specific error classification, not a second implementation.
    program.push_str(
        r#"
    fn page_with_len(&self, index: u64) -> Result<(Arc<[u8; PAGE_BYTES]>, usize), u64> {
        assert_eq!(index, 7);
        self.outcome.map(|length| {
            let mut bytes = [0; PAGE_BYTES];
            bytes[..length].fill(42);
            (Arc::new(bytes), length)
        })
    }
"#,
    );
    for name in ["pub fn page(", "fn page_error(", "fn fault_page_with_len("] {
        let start = source.find(name).unwrap();
        let end = start + source[start..].find("\n    }\n").unwrap() + 7;
        program.push_str(&source[start..end]);
    }
    program.push_str(
        r#"
}
fn main() {
    for source in [VmObjectSource::Memory(()), VmObjectSource::Provider] {
        let mut object = VmObject { source, outcome: Ok(0) };
        // Ordinary backing reads still report EOF, but faults must not turn
        // an empty cache entry into a mapped zero-filled page.
        assert_eq!(object.page_with_len(7).unwrap().1, 0);
        assert_eq!(object.page(7), Err(VmPageError::OutsideBacking));
        for length in [1, PAGE_BYTES - 1, PAGE_BYTES] {
            object.outcome = Ok(length);
            let page = object.page(7).unwrap();
            assert!(page[..length].iter().all(|byte| *byte == 42));
            assert!(page[length..].iter().all(|byte| *byte == 0));
        }
        object.outcome = Err((-5i64) as u64);
        assert_eq!(object.page(7), Err(VmPageError::Operation((-5i64) as u64)));
        object.outcome = Err(syscall::EINVAL);
        let expected = match object.source {
            VmObjectSource::Memory(_) => VmPageError::OutsideBacking,
            VmObjectSource::Provider => VmPageError::Operation(syscall::EINVAL),
        };
        assert_eq!(object.page(7), Err(expected));
    }
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-vm-fault-backing-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings", "-", "-o"])
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
    if !compiled.status.success() {
        std::fs::remove_dir_all(&directory).unwrap();
        panic!("{}", String::from_utf8_lossy(&compiled.stderr));
    }
    let result = Command::new(binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn shared_faults_check_backing_before_pinning_or_allocating_frames() {
    let source = include_str!("../../../core/src/mem/vm_object.rs");
    let body = source.split("pub fn prepare_shared_page(").nth(1).unwrap();
    let body = body.split("pub fn mark_page_dirty(").next().unwrap();
    let checked = body.find("self.fault_page_with_len(page_index)?").unwrap();
    assert!(checked < body.find("PAGE_CACHE.lock()").unwrap());
    assert!(checked < body.find("allocate_zeroed_frame()").unwrap());
    assert!(checked < body.find("retain_shared_user_frame(").unwrap());
    let process = include_str!("../../../core/src/syscall/process.rs");
    assert!(process.contains("object.page(*page_index)"));
    assert!(process.contains("object.prepare_shared_page(*page_index)"));
}
