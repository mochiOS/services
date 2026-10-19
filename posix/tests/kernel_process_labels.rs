#[test]
fn runtime_creation_retains_explicit_labels_without_filesystem_alias_or_basename_policy() {
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    let process = include_str!("../../../core/src/task/process.rs");
    let config = include_str!("../../../core/src/config.rs");
    for source in [exec, process, config] {
        assert!(!source.contains("process_alias_for_executable"));
        assert!(!source.contains("process_aliases"));
    }
    assert!(!exec.contains("derive_process_name"));
    assert!(!exec.contains("name_override"));
    let begin = exec.find("pub(crate) fn launch_bootstrap_image(").unwrap();
    let end = begin + exec[begin..].find("\n}\n").unwrap() + 3;
    assert!(exec[begin..end].contains("boot_module::decode"));
    assert!(!exec[begin..end].contains("name: &str"));
    assert!(!exec[begin..end].contains("path: &str"));
    let begin = exec.find("pub fn process_create_syscall(").unwrap();
    let end = begin + exec[begin..].find("\n}\n").unwrap() + 3;
    assert!(exec[begin..end].contains("request.label"));
    assert!(exec.contains("Process::try_new(process_name, privilege, priority)"));
}
