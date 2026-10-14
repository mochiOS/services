use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn exec_retains_caller_labels_without_consulting_filesystem_alias_policy() {
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    let process = include_str!("../../../core/src/task/process.rs");
    let config = include_str!("../../../core/src/config.rs");
    for source in [exec, process, config] {
        assert!(!source.contains("process_alias_for_executable"));
        assert!(!source.contains("process_aliases"));
    }
    let begin = exec.find("let process_name = name_override").unwrap();
    let end = begin + exec[begin..].find("if enforce_path_access").unwrap();
    let derive_begin = exec.find("fn derive_process_name(").unwrap();
    let derive_end = derive_begin + exec[derive_begin..].find("\n}\n").unwrap() + 3;
    let mut program = String::from("use std::string::String;\n");
    program.push_str(&exec[derive_begin..derive_end]);
    program.push_str("fn label(path:&str,name_override:Option<&str>)->String{\n");
    program.push_str(&exec[begin..end]);
    program.push_str("process_name}\n");
    program.push_str(
        r#"
fn main(){
for path in ["/arbitrary/location/entry.elf","/other/executable/", "entry"]{
for name in ["Compiler worker","not-a-service","/opaque/label","", "任意の名前"]{
assert_eq!(label(path,Some(name)),name);}}
assert_eq!(label("/arbitrary/location/entry.elf",None),"entry.elf");
assert_eq!(label("/other/executable/",None),"executable");
assert_eq!(label("entry",None),"entry");}
"#,
    );
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "mochios-process-label-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compile = Command::new("rustc")
        .args(["--edition=2024", "--crate-name=process_label", "-", "-o"])
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
