use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_kernel_lookup_treats_process_labels_as_exact_opaque_metadata() {
    let source = include_str!("../../../core/src/task/process.rs");
    let begin = source.find("    pub fn find_by_name(").unwrap();
    let end = begin + source[begin..].find("\n    fn take_exited(").unwrap();
    let mut program = String::from(
        "struct Process { label: &'static str }\nimpl Process { fn name(&self)->&str { self.label } }\nstruct ProcessTable { processes: Vec<Option<Process>> }\nimpl ProcessTable {\n",
    );
    program.push_str(&source[begin..end]);
    program.push_str(
        r#"
}
fn table(labels: &[&'static str]) -> ProcessTable {
    ProcessTable { processes: labels.iter().map(|label| Some(Process { label })).collect() }
}
fn main() {
    let labels = ["worker.elf", "worker.service", "/opaque/label", "日本語", "White Space"];
    let t = table(&labels);
    for label in labels { assert_eq!(t.find_by_name(label).unwrap().name(), label); }
    for absent in ["worker", ".elf", "worker.service.elf", "label", "opaque", "日本", "white space", ""] {
        assert!(t.find_by_name(absent).is_none(), "unexpected match for {absent:?}");
    }
    assert!(table(&["worker"]).find_by_name("worker.elf").is_none());
    assert!(table(&["worker.elf"]).find_by_name("worker").is_none());
    let t = table(&["worker-helper", "worker"]);
    assert_eq!(t.find_by_name("worker").unwrap().name(), "worker");
}
"#,
    );
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "mochios-process-lookup-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compile = Command::new("rustc")
        .args(["--edition=2024", "--crate-name=process_lookup", "-", "-o"])
        .arg(&executable)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compile
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let output = compile.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
    std::fs::remove_dir_all(directory).unwrap();
}
