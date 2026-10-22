//! Compile and execute the target-only runtime drain, not a source assertion.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn runtime_retries_failed_resumes_without_blocking_another_process() {
    let source = include_str!("../src/main.rs");
    let mut program = String::from(
        r#"
struct RuntimeProcesses { failed: bool, calls: Vec<u64> }
mod posix_service {
    pub struct PosixService<H> { pub pending: Vec<H> }
    impl PosixService<u32> {
        pub fn process_resume_notification_processes(&self) -> impl Iterator<Item = u64> + '_ {
            self.pending.iter().copied().map(u64::from)
        }
        pub fn apply_process_resume(&mut self, id: u64, backend: &mut super::RuntimeProcesses) -> Result<bool, i32> {
            backend.calls.push(id);
            if id == 7 && backend.failed { return Err(-5); }
            self.pending.retain(|&pending| u64::from(pending) != id);
            Ok(true)
        }
    }
}
"#,
    );
    program.push_str(probe::between(
        source,
        "fn deliver_process_resume_notifications(",
        "#[cfg",
    ));
    program.push_str(
        r#"
fn main() {
    let mut service = posix_service::PosixService { pending: vec![7, 8] };
    let mut backend = RuntimeProcesses { failed: true, calls: vec![] };
    deliver_process_resume_notifications(&mut service, &mut backend);
    assert_eq!(backend.calls, [7, 8]);
    assert_eq!(service.pending, [7]);
    backend.failed = false;
    deliver_process_resume_notifications(&mut service, &mut backend);
    assert_eq!(backend.calls, [7, 8, 7]);
    assert!(service.pending.is_empty());
}
"#,
    );
    probe::run(&program);
}
