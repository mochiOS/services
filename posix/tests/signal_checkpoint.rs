use core::ffi::c_void;
use mochios_posix_client::{signal_checkpoint, signal_context::*};

core::arch::global_asm!(include_str!("support/signal_checkpoint_probe.S"));

#[repr(C, align(16))]
struct Probe {
    captured: MachineContext,
    restored: MachineContext,
    calls: u64,
    redirected: u64,
    selected_stack: u64,
    callback_completed: u64,
}

unsafe extern "C" {
    fn mochios_test_signal_checkpoint(
        callback: unsafe extern "C" fn(*mut MachineContext, *mut c_void),
        argument: *mut c_void,
    ) -> u64;
    fn mochios_test_signal_checkpoint_alternate();
}

fn empty() -> MachineContext {
    MachineContext {
        gregs: [0; NGREG],
        fpregs: [0; 512],
    }
}

unsafe extern "C" fn edit(context: *mut MachineContext, argument: *mut c_void) {
    let context = unsafe { &mut *context };
    let output = unsafe { &mut *argument.cast::<Probe>() };
    output.captured = *context;
    output.calls += 1;
    for index in 0..REG_RSP {
        if index != REG_RSI {
            context.gregs[index] = 0x2000 + index as u64;
        }
    }
    context.gregs[REG_EFL] = (context.gregs[REG_EFL] & !1) | 0x40;
    context.fpregs[24..28].copy_from_slice(&0x3f80_u32.to_le_bytes());
    context.fpregs[40..42].copy_from_slice(&0x4000_u16.to_le_bytes());
    context.fpregs[160..176].fill(0x5a);
}

#[test]
fn production_assembly_captures_and_restores_real_registers_flags_and_sse_state() {
    assert_eq!(core::mem::offset_of!(Probe, restored), 656);
    assert_eq!(core::mem::offset_of!(Probe, calls), 1312);
    let mut probe = Probe {
        captured: empty(),
        restored: empty(),
        calls: 0,
        redirected: 0,
        selected_stack: 0,
        callback_completed: 0,
    };
    let address = (&mut probe as *mut Probe).cast::<c_void>();
    let result = unsafe { mochios_test_signal_checkpoint(edit, address) };
    assert_eq!(probe.calls, 1);
    assert_eq!(result, 0x2000 + REG_RAX as u64);
    for index in 0..REG_RSP {
        let expected = match index {
            REG_RDI => edit as *const () as u64,
            REG_RSI => address as u64,
            REG_RAX => 0,
            _ => 0x1000 + index as u64,
        };
        assert_eq!(
            probe.captured.gregs[index], expected,
            "captured GPR {index}"
        );
        assert_eq!(
            probe.restored.gregs[index],
            if index == REG_RSI {
                address as u64
            } else {
                0x2000 + index as u64
            },
            "restored GPR {index}"
        );
    }
    assert_eq!(probe.captured.gregs[REG_RIP], probe.restored.gregs[REG_RIP]);
    assert_eq!(probe.captured.gregs[REG_RSP], probe.restored.gregs[REG_RSP]);
    assert_ne!(probe.captured.gregs[REG_RIP], 0);
    assert_ne!(probe.captured.gregs[REG_EFL] & 1, 0);
    assert_eq!(probe.restored.gregs[REG_EFL] & (1 | 0x40), 0x40);
    assert_eq!(&probe.captured.fpregs[24..28], &0x1f80_u32.to_le_bytes());
    assert_eq!(&probe.restored.fpregs[24..28], &0x3f80_u32.to_le_bytes());
    assert_eq!(&probe.captured.fpregs[160..176], &[0x11; 16]);
    assert_eq!(&probe.restored.fpregs[160..176], &[0x5a; 16]);
    assert_eq!(
        &probe.captured.fpregs[32..40],
        &0x8000_0000_0000_0000_u64.to_le_bytes()
    );
    assert_eq!(&probe.captured.fpregs[40..42], &0x3fff_u16.to_le_bytes());
    assert_eq!(
        &probe.restored.fpregs[32..40],
        &0x8000_0000_0000_0000_u64.to_le_bytes()
    );
    assert_eq!(&probe.restored.fpregs[40..42], &0x4000_u16.to_le_bytes());
    assert_eq!(&probe.captured.fpregs[416..], &[0; 96]);
}

unsafe extern "C" fn nested_inner(context: *mut MachineContext, argument: *mut c_void) {
    unsafe {
        *argument.cast::<u64>() += 1;
        (*context).gregs[REG_RAX] = 37;
    }
}

unsafe extern "C" fn nested_outer(context: *mut MachineContext, argument: *mut c_void) {
    let result = unsafe { signal_checkpoint::run_with(nested_inner, argument) };
    unsafe {
        (*context).gregs[REG_RAX] = result + 5;
    }
}

#[test]
fn nested_checkpoints_have_separate_stack_owned_contexts_and_return_values() {
    let mut calls = 0_u64;
    let result =
        unsafe { signal_checkpoint::run_with(nested_outer, (&mut calls as *mut u64).cast()) };
    assert_eq!(result, 42);
    assert_eq!(calls, 1);
}

unsafe extern "C" fn redirect(context: *mut MachineContext, argument: *mut c_void) {
    struct Completed(*mut Probe);
    impl Drop for Completed {
        fn drop(&mut self) {
            unsafe { (*self.0).callback_completed = 1 };
        }
    }
    let _completed = Completed(argument.cast());
    unsafe {
        edit(context, argument);
        (*context).gregs[REG_RIP] = mochios_test_signal_checkpoint_alternate as *const () as u64;
        // Use the dead checkpoint frame, without overwriting the probe's
        // original saved FPU state or its eventual Rust return continuation.
        (*context).gregs[REG_RSP] -= 16;
    }
}

#[test]
fn changed_pc_and_stack_apply_only_after_the_callback_has_completed() {
    assert_eq!(core::mem::offset_of!(Probe, redirected), 1320);
    assert_eq!(core::mem::offset_of!(Probe, selected_stack), 1328);
    let mut probe = Probe {
        captured: empty(),
        restored: empty(),
        calls: 0,
        redirected: 0,
        selected_stack: 0,
        callback_completed: 0,
    };
    let result =
        unsafe { mochios_test_signal_checkpoint(redirect, (&mut probe as *mut Probe).cast()) };
    assert_eq!(result, 0x2000 + REG_RAX as u64);
    assert_eq!(probe.calls, 1);
    assert_eq!(probe.redirected, 1);
    assert_eq!(probe.selected_stack, probe.captured.gregs[REG_RSP] - 16);
    assert_eq!(probe.callback_completed, 1);
}
