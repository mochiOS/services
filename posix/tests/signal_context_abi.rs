use mnu_abi::{ThreadInitialRegisters, ThreadUpcallSnapshot};
use mochios_posix_client::signal_context::*;
use mochios_posix_protocol::signal_origin::{self, Origin};
use std::mem::offset_of;
use std::process::Command;

#[test]
fn every_native_register_roundtrips_without_importing_posix_policy_into_native_context() {
    let native = ThreadUpcallSnapshot {
        instruction: 0x4000,
        stack_pointer: 0x8000,
        rflags: 0x202,
        argument: 18,
        registers: ThreadInitialRegisters {
            rax: 1,
            rbx: 2,
            rcx: 3,
            rdx: 4,
            rsi: 5,
            rbp: 6,
            r8: 7,
            r9: 8,
            r10: 9,
            r11: 10,
            r12: 11,
            r13: 12,
            r14: 13,
            r15: 14,
        },
        fx_state: core::array::from_fn(|index| index as u8),
    };
    let stack = Stack {
        ss_sp: 0,
        ss_flags: 2,
        ss_size: 0,
    };
    let mut context = UContext::from_native(&native, 0x1234, stack);
    assert_eq!(
        context.uc_mcontext.gregs,
        [
            7, 8, 9, 10, 11, 12, 13, 14, 18, 5, 6, 2, 4, 1, 3, 0x8000, 0x4000, 0x202
        ]
    );
    assert_eq!(context.native_snapshot(), native);
    assert_eq!(
        (context.uc_flags, context.uc_link, context.uc_sigmask),
        (0, 0, 0x1234)
    );
    assert_eq!(context.uc_stack, stack);
    context.uc_sigmask = 0x5678;
    context.uc_link = 0x1111;
    context.uc_stack.ss_sp = 0x2222;
    assert_eq!(context.native_snapshot(), native);
    context.uc_mcontext.gregs[REG_RIP] = 0x5000;
    context.uc_mcontext.gregs[REG_RSP] = 0x9000;
    context.uc_mcontext.gregs[REG_RAX] = 55;
    context.uc_mcontext.gregs[REG_RCX] = 66;
    context.uc_mcontext.fpregs[24] = 0x80;
    let updated = context.native_snapshot();
    assert_eq!(
        (
            updated.instruction,
            updated.stack_pointer,
            updated.registers.rax,
            updated.registers.rcx
        ),
        (0x5000, 0x9000, 55, 66)
    );
    assert_eq!(updated.fx_state[24], 0x80);
    assert_eq!(updated.argument, native.argument);
}

#[test]
fn sender_conversion_rejects_overflow_and_does_not_fabricate_child_or_fault_details() {
    let source = Origin {
        source: signal_origin::USER,
        real_uid: 501,
        process_id: 123,
        ..Origin::system()
    };
    let info = SigInfo::from_origin(30, source).unwrap();
    assert_eq!(
        (
            info.si_signo,
            info.si_code,
            info.si_pid,
            info.si_uid,
            info.si_errno,
            info.si_addr
        ),
        (30, SI_USER, 123, 501, 0, 0)
    );
    assert_eq!(unsafe { info.si_value.sival_ptr }, 0);
    for bad in [
        Origin {
            process_id: i32::MAX as u64 + 1,
            ..source
        },
        Origin {
            real_uid: u16::MAX as u32 + 1,
            ..source
        },
    ] {
        assert!(matches!(
            SigInfo::from_origin(30, bad),
            Err(InfoError::Overflow)
        ));
    }
    for signal in [0, 65, u32::MAX] {
        assert!(matches!(
            SigInfo::from_origin(signal, source),
            Err(InfoError::InvalidSignal)
        ));
    }
    assert!(matches!(
        SigInfo::from_origin(
            30,
            Origin {
                process_id: 0,
                ..source
            }
        ),
        Err(InfoError::InvalidOrigin)
    ));
    for source in [signal_origin::CHILD, signal_origin::FAULT] {
        assert!(matches!(
            SigInfo::from_origin(
                30,
                Origin {
                    source,
                    ..Origin::system()
                }
            ),
            Err(InfoError::MissingDetail)
        ));
    }
    let system = SigInfo::from_origin(30, Origin::system()).unwrap();
    assert_eq!(
        (system.si_code, system.si_pid, system.si_uid),
        (SI_KERNEL, 0, 0)
    );
}

#[test]
fn target_c_and_cpp_headers_match_rust_layout_without_changing_the_built_sdk() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = std::env::temp_dir().join(format!(
        "mochios-signal-context-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(directory.join("sys")).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(directory.clone());
    let header = directory.join("sys/signal.h");
    std::fs::write(
        &header,
        include_str!("../../../libraries/newlib/newlib/libc/include/sys/signal.h"),
    )
    .unwrap();
    let script = root.join("user/scripts/fix-newlib-signal-header.pl");
    let result = Command::new("perl")
        .arg(&script)
        .arg(&header)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let first = std::fs::read(&header).unwrap();
    assert!(
        Command::new("perl")
            .arg(script)
            .arg(&header)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(first, std::fs::read(&header).unwrap());
    let mut source = String::from(
        "#include <signal.h>\n#include <ucontext.h>\n#include <stddef.h>\n#ifdef __cplusplus\n#define CHECK static_assert\n#else\n#define CHECK _Static_assert\n#endif\n",
    );
    source.push_str(&format!("CHECK(sizeof(siginfo_t)=={},\"siginfo size\");\nCHECK(sizeof(ucontext_t)=={},\"ucontext size\");\nCHECK(sizeof(mcontext_t)=={},\"mcontext size\");\n",size_of::<SigInfo>(),size_of::<UContext>(),size_of::<MachineContext>()));
    for (c_type, member, offset) in [
        ("siginfo_t", "si_uid", offset_of!(SigInfo, si_uid)),
        ("siginfo_t", "si_addr", offset_of!(SigInfo, si_addr)),
        ("siginfo_t", "si_value", offset_of!(SigInfo, si_value)),
        ("ucontext_t", "uc_stack", offset_of!(UContext, uc_stack)),
        (
            "ucontext_t",
            "uc_mcontext",
            offset_of!(UContext, uc_mcontext),
        ),
        ("mcontext_t", "fpregs", offset_of!(MachineContext, fpregs)),
    ] {
        source.push_str(&format!(
            "CHECK(offsetof({c_type},{member})=={offset},\"{member} offset\");\n"
        ));
    }
    source.push_str("CHECK(sizeof(uid_t)==2,\"target uid width\");\nCHECK(NGREG==18 && REG_RIP==16 && REG_RSP==15,\"register indices\");\n");
    source.push_str("CHECK(SA_SIGINFO==4 && (SA_SIGINFO & SA_NOCLDWAIT)==0,\"distinct action flags\");\nCHECK(sizeof(struct sigaction)==24,\"action layout\");\nCHECK(offsetof(struct sigaction,sa_handler)==offsetof(struct sigaction,sa_sigaction),\"handler union\");\nstatic void three_arguments(int signal, siginfo_t *info, void *context) { (void)signal; (void)info; (void)context; }\nstatic void action_typecheck(void) { struct sigaction action; action.sa_sigaction=three_arguments; action.sa_flags=SA_SIGINFO; }\n");
    source.push_str("CHECK(SA_ONSTACK==8 && SS_ONSTACK==1 && SS_DISABLE==2 && MINSIGSTKSZ==2048,\"alternate stack ABI\");\n");
    for (name, value) in [
        ("SI_USER", SI_USER),
        ("SI_KERNEL", SI_KERNEL),
        ("SEGV_MAPERR", SEGV_MAPERR),
        ("SEGV_ACCERR", SEGV_ACCERR),
        ("BUS_ADRERR", BUS_ADRERR),
        ("BUS_OBJERR", BUS_OBJERR),
        ("CLD_EXITED", CLD_EXITED),
        ("CLD_KILLED", CLD_KILLED),
        ("CLD_DUMPED", CLD_DUMPED),
        ("CLD_TRAPPED", CLD_TRAPPED),
        ("CLD_STOPPED", CLD_STOPPED),
        ("CLD_CONTINUED", CLD_CONTINUED),
    ] {
        source.push_str(&format!("CHECK({name}=={value},\"{name} value\");\n"));
    }
    let file = directory.join("probe.c");
    std::fs::write(&file, source).unwrap();
    let legacy = directory.join("legacy.c");
    std::fs::write(&legacy, "#include <signal.h>\n#ifdef __cplusplus\nstatic_assert(sizeof(siginfo_t)==16,\"legacy siginfo\");\n#else\n_Static_assert(sizeof(siginfo_t)==16,\"legacy siginfo\");\n#endif\n").unwrap();
    for (compiler, language) in [("cc", "c"), ("c++", "c++")] {
        let builtins = Command::new(compiler)
            .arg("-print-file-name=include")
            .output()
            .unwrap();
        assert!(builtins.status.success());
        let builtins = String::from_utf8(builtins.stdout).unwrap();
        for (definition, probe) in [("-D__mochios__", &file), ("-U__mochios__", &legacy)] {
            let result = Command::new(compiler)
                .args(["-x", language, "-fsyntax-only", "-nostdinc", definition])
                .arg("-I")
                .arg(&directory)
                .arg("-I")
                .arg(root.join("user/libc-port/include"))
                .arg("-isystem")
                .arg(builtins.trim())
                .arg("-isystem")
                .arg(root.join("out/newlib-port/sdk/sysroot/include"))
                .arg(probe)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{compiler}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
}
