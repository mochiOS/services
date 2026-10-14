use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_interrupt_register_conversion_preserves_every_word_and_validates_return_addresses() {
    let source = include_str!("../../../core/src/syscall/upcall.rs");
    let thread = include_str!("../../../core/src/task/thread.rs");
    let begin = thread.find("pub struct UserUpcallContext {").unwrap();
    let end = begin + thread[begin..].find("\n}\n").unwrap() + 3;
    let mut program = String::from("#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n");
    program.push_str(&thread[begin..end]);
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    program.push_str("mod mnu_abi {\n");
    for declaration in [
        "pub struct ThreadInitialRegisters {",
        "pub struct ThreadUpcallSnapshot {",
    ] {
        let start = abi.find(declaration).unwrap();
        let end = start + abi[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&abi[start..end]);
    }
    program.push_str("}\n");
    for name in [
        "valid_user_return",
        "read_interrupt_context",
        "write_interrupt_context",
        "snapshot_context",
        "return_context",
    ] {
        let start = source.find(&format!("fn {name}(")).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&source[start..end]);
    }
    program.push_str(
        r#"
fn main() {
    let mut frame = core::array::from_fn::<_,20,_>(|index|index as u64+100);
    let original=frame;
    let context=read_interrupt_context(&frame);
    let snapshot=snapshot_context(context,[0xa7;512]);
    let registers=snapshot.registers;
    assert_eq!([snapshot.instruction,snapshot.stack_pointer,snapshot.rflags,snapshot.argument],
        [115,118,117,108]);
    assert_eq!([registers.rax,registers.rbx,registers.rcx,registers.rdx,registers.rsi,registers.rbp,
        registers.r8,registers.r9,registers.r10,registers.r11,registers.r12,registers.r13,registers.r14,registers.r15],
        [114,111,113,112,109,110,107,106,105,104,103,102,101,100]);
    assert_eq!(snapshot.fx_state,[0xa7;512]);
    assert_eq!([context.r15,context.r14,context.r13,context.r12,context.r11,context.r10,
        context.r9,context.r8,context.rdi,context.rsi,context.rbp,context.rbx,
        context.rdx,context.rcx,context.rax,context.user_rip,context.user_rflags,context.user_rsp],
        [100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,117,118]);
    write_interrupt_context(&mut frame,context);
    assert_eq!(frame,original);
    let mut updated=context;
    updated.rcx=0x1122334455667788; updated.r11=0x8877665544332211;
    updated.user_rip=0x400000;updated.user_rsp=0x7fff0000;
    write_interrupt_context(&mut frame,updated);
    assert_eq!(read_interrupt_context(&frame),updated);
    assert_eq!(frame[16],original[16]);assert_eq!(frame[19],original[19]);
    assert!(valid_user_return(&updated));
    for address in [0x800000000000u64,0xffff800000000000,u64::MAX] {
        let mut invalid=updated;invalid.user_rip=address;assert!(!valid_user_return(&invalid));
        invalid=updated;invalid.user_rsp=address;assert!(!valid_user_return(&invalid));
    }
    updated.user_rip=0;assert!(!valid_user_return(&updated));
    let mut valid=context; valid.user_rip=0x4000;valid.user_rsp=0x8000;valid.user_rflags=0x202;
    let mut candidate=snapshot_context(valid,[0;512]);
    assert_eq!(return_context(&candidate),Some(valid));
    for flag in [12,13,14,17,19,20,63] {
        candidate.rflags=valid.user_rflags|(1u64<<flag);
        assert!(return_context(&candidate).is_none());
    }
    for flag in [1,9] {
        candidate.rflags=valid.user_rflags&!(1u64<<flag);
        assert!(return_context(&candidate).is_none());
    }
    candidate.rflags=valid.user_rflags;
    for address in [0x800000000000u64,0xffff800000000000,u64::MAX] {
        candidate.instruction=address;assert!(return_context(&candidate).is_none());
        candidate.instruction=valid.user_rip;candidate.stack_pointer=address;
        assert!(return_context(&candidate).is_none());candidate.stack_pointer=valid.user_rsp;
    }
    candidate.registers.rcx=0x1122334455667788;candidate.registers.r11=0x8877665544332211;
    let accepted=return_context(&candidate).unwrap();
    assert_eq!((accepted.rcx,accepted.r11),(candidate.registers.rcx,candidate.registers.r11));
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-upcall-registers-{}-{}",
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
    let output = compiler.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn both_native_entries_use_one_upcall_state_and_only_full_restore_uses_iret() {
    let source = include_str!("../../../core/src/syscall/upcall.rs");
    assert!(
        source.contains("if prepare_context(&mut context) {\n        resume_context(context);")
    );
    let interrupt = source
        .split("pub fn prepare_interrupt_return(")
        .nth(1)
        .unwrap()
        .split("fn prepare_context(")
        .next()
        .unwrap();
    assert!(interrupt.contains("prepare_context(&mut context)"));
    assert!(interrupt.contains("valid_user_return(&context)"));
    let resume = source
        .split("fn resume_context(")
        .nth(1)
        .unwrap()
        .split("fn read_interrupt_context(")
        .next()
        .unwrap();
    assert!(resume.find("valid_user_return").unwrap() < resume.find("resume_usermode").unwrap());
    assert!(
        resume.find("current_thread_user_page_table").unwrap()
            < resume.find("resume_usermode").unwrap()
    );
    assert!(resume.contains("rcx: context.rcx"));
    assert!(resume.contains("r11: context.r11"));
    let entry = include_str!("../../../core/src/syscall/mod.rs");
    assert!(entry.contains("upcall::prepare_interrupt_return(frame)"));
    assert!(entry.contains("\"cld\",\n        \"call {int80_handler}\""));
}
