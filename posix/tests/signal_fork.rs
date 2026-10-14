use core::ffi::c_void;
use mochios_posix_client::signal_stack::{current_pointer, enter_on};

#[test]
fn nonreturning_stack_entry_uses_the_selected_stack_and_preserves_its_argument() {
    const CHILD: &str = "MOCHIOS_ENTER_STACK_PROBE";
    if std::env::var_os(CHILD).is_some() {
        struct Probe {
            low: usize,
            high: usize,
            cookie: u64,
        }
        unsafe extern "C" fn check(argument: *mut c_void) -> ! {
            let probe = unsafe { &*argument.cast::<Probe>() };
            let stack = current_pointer();
            std::process::exit(
                if stack >= probe.low && stack < probe.high && probe.cookie == 0x123456789abcdef0 {
                    0
                } else {
                    1
                },
            );
        }
        let mut storage = vec![0_u8; 65536];
        let mut probe = Probe {
            low: storage.as_mut_ptr() as usize,
            high: storage.as_mut_ptr() as usize + storage.len(),
            cookie: 0x123456789abcdef0,
        };
        unsafe { enter_on(probe.high, check, (&mut probe as *mut Probe).cast()) };
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "nonreturning_stack_entry_uses_the_selected_stack_and_preserves_its_argument",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn copied_handlers_never_complete_parent_tokens_or_free_live_native_frames() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let child = source
        .split("if image == 0 {")
        .nth(1)
        .unwrap()
        .split("return Ok((0,")
        .next()
        .unwrap();
    assert!(
        child.contains("!signal_delivery::stack_is_active(thread_control, old_stack, old_size)")
    );
    let drain = source
        .split("fn drain_pending_signals_with_context(")
        .nth(1)
        .unwrap()
        .split("extern \"C\" fn posix_signal_upcall(")
        .next()
        .unwrap();
    let owner = drain.find("let epoch = preparation.epoch").unwrap();
    let received = drain.find("thread_dequeue_signal_delivery()").unwrap();
    let invoke = drain.find("dispatch_signal(").unwrap();
    let before = drain.find("!= epoch").unwrap();
    let check = invoke + drain[invoke..].find("!= epoch").unwrap();
    let complete = drain.find("scope.as_mut().complete()").unwrap();
    assert!(owner < received && received < before && before < invoke);
    assert!(invoke < check && check < complete);
    let fault = include_str!("../../../user/crates/newlib-runtime/src/fault_signal.rs");
    assert!(fault.find("!= epoch").unwrap() < fault.find("scope.as_mut().complete()").unwrap());
    let native = include_str!("../../../user/crates/newlib-runtime/src/signal_delivery.rs");
    assert!(native.contains("owner != frame.owner"));
    assert!(native.contains("active_native_signal_frame"));
    let finish = native
        .split("unsafe extern \"C\" fn finish_detached(")
        .nth(1)
        .unwrap()
        .split("pub(super) fn resume(")
        .next()
        .unwrap();
    assert!(finish.find("read_volatile()").unwrap() < finish.find("MemoryUnmap").unwrap());
    assert!(finish.find("MemoryUnmap").unwrap() < finish.find("ThreadContextRestore").unwrap());
    assert!(!finish.contains("ThreadUpcallReturnContext"));
}
