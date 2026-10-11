use std::process::Command;

#[test]
fn user_return_masks_interrupts_before_identity_or_address_space_changes() {
    let source = include_str!("../../../core/src/task/usermode.rs");
    for name in ["jump_to_usermode", "resume_usermode"] {
        let body = source
            .split(&format!("pub unsafe fn {name}("))
            .nth(1)
            .unwrap();
        let disabled = body.find("interrupts::disable()").unwrap();
        assert!(disabled < body.find("current_thread_id()").unwrap());
        assert!(disabled < body.find("switch_page_table(user_cr3)").unwrap());
    }
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    let entry = exec.split("drop(identity_bytes);").nth(1).unwrap();
    assert!(
        entry.find("interrupts::disable()").unwrap()
            < entry.find("switch_page_table(page_table)").unwrap()
    );
}

#[test]
fn production_resume_cannot_be_preempted_between_cr3_switch_and_iret() {
    let source = include_str!("../../../core/src/task/usermode.rs")
        .replace("//! ユーザーモード実行サポート", "")
        .replace("use core::arch::asm;", "");
    // Only the privileged instructions are replaced. Metadata lookup and the
    // transition ordering are the actual production resume_usermode function.
    let fixture = include_str!("native_user_return_host.inc");
    let directory = std::env::temp_dir().join(format!(
        "mochios-user-return-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("probe.rs");
    std::fs::write(&path, fixture.replace("/* PRODUCTION */", &source)).unwrap();
    let binary = directory.join("probe");
    let result = Command::new("rustc")
        .args(["--edition=2021", "-Awarnings"])
        .arg(&path)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    // Negative control: the original late CLI must lose the selected CR3
    // under the same modeled interrupt, so this test cannot pass vacuously.
    let vulnerable = source.replace("x86_64::instructions::interrupts::disable();", "");
    std::fs::write(&path, fixture.replace("/* PRODUCTION */", &vulnerable)).unwrap();
    let result = Command::new("rustc")
        .args(["--edition=2021", "-Awarnings"])
        .arg(&path)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        !result.status.success(),
        "late CLI unexpectedly preserved CR3"
    );
}
