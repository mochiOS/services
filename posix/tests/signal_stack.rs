use core::ffi::c_void;
use mochios_posix_client::{signal_context::Stack, signal_stack::*};

fn configured() -> AlternateStack {
    let state = AlternateStack::new();
    state
        .replace(
            Stack {
                ss_sp: 0x10000,
                ss_size: 8192,
                ss_flags: 0,
            },
            0x80000,
        )
        .unwrap();
    state
}

#[test]
fn configure_query_disable_and_reject_active_changes_without_mutation() {
    let state = configured();
    assert_eq!(state.snapshot(0).ss_flags, 0);
    assert_eq!(state.snapshot(0x10000).ss_flags, SS_ONSTACK);
    assert_eq!(state.snapshot(0x11fff).ss_flags, SS_ONSTACK);
    assert_eq!(state.snapshot(0x12000).ss_flags, 0);
    let disabled = Stack {
        ss_sp: usize::MAX,
        ss_size: usize::MAX,
        ss_flags: SS_DISABLE,
    };
    assert_eq!(state.replace(disabled, 0x11000), Err(StackError::InUse));
    assert_eq!(state.snapshot(0).ss_size, 8192);
    assert_eq!(state.replace(disabled, 0).unwrap().ss_flags, 0);
    assert_eq!(
        state.snapshot(0),
        Stack {
            ss_sp: 0,
            ss_size: 0,
            ss_flags: SS_DISABLE
        }
    );
}

#[test]
fn invalid_flags_sizes_and_address_ranges_never_publish_partial_state() {
    let state = configured();
    for (requested, error) in [
        (
            Stack {
                ss_sp: 0x1000,
                ss_size: MIN_SIZE - 1,
                ss_flags: 0,
            },
            StackError::TooSmall,
        ),
        (
            Stack {
                ss_sp: 0x1000,
                ss_size: MIN_SIZE,
                ss_flags: SS_ONSTACK,
            },
            StackError::Flags,
        ),
        (
            Stack {
                ss_sp: 0x1000,
                ss_size: MIN_SIZE,
                ss_flags: 4,
            },
            StackError::Flags,
        ),
        (
            Stack {
                ss_sp: usize::MAX - 1,
                ss_size: MIN_SIZE,
                ss_flags: 0,
            },
            StackError::Range,
        ),
        (
            Stack {
                ss_sp: 1 << 47,
                ss_size: MIN_SIZE,
                ss_flags: 0,
            },
            StackError::Range,
        ),
    ] {
        assert_eq!(state.replace(requested, 0), Err(error));
        assert_eq!(
            (state.snapshot(0).ss_sp, state.snapshot(0).ss_size),
            (0x10000, 8192)
        );
    }
}

#[test]
fn stack_selection_preserves_nested_frames_and_the_interrupted_red_zone() {
    let state = configured();
    assert_eq!(
        state.select(0x80000, 0x80000, false, false).unwrap().1,
        None
    );
    assert_eq!(
        state.select(0x80000, 0x80000, true, true).unwrap().1,
        Some(0x12000)
    );
    assert_eq!(state.select(0x11000, 0x11800, true, false).unwrap().1, None);
    let (old, top) = state.select(0x80000, 0x11807, false, true).unwrap();
    assert_eq!(old.ss_flags, SS_ONSTACK);
    assert_eq!(top, Some((0x11807 - 128) & !15));
    assert_eq!(
        state.select(0x80000, 0x10040, true, true),
        Err(StackError::TooSmall)
    );
    assert_eq!(
        AlternateStack::new().select(0, 0, true, false).unwrap().1,
        None
    );
    assert_eq!(
        state.select(0x80000, 0x90000, false, true).unwrap().1,
        Some(0x90000 - 128)
    );
    assert_eq!(
        AlternateStack::new()
            .select(0x80000, 0x90000, true, true)
            .unwrap()
            .1,
        Some(0x90000 - 128)
    );
}

struct Probe {
    low: usize,
    high: usize,
    pointer: usize,
    nested: usize,
}
unsafe extern "C" fn callback(argument: *mut c_void) {
    let probe = unsafe { &mut *argument.cast::<Probe>() };
    probe.pointer = current_pointer();
    unsafe extern "C" fn nested(argument: *mut c_void) {
        unsafe { (*argument.cast::<Probe>()).nested = current_pointer() };
    }
    unsafe { nested(argument) };
}

#[test]
fn actual_stack_switch_obeys_c_abi_and_returns_to_the_original_stack() {
    let mut storage = vec![0_u8; 32768];
    let mut probe = Probe {
        low: storage.as_mut_ptr() as usize,
        high: storage.as_mut_ptr() as usize + storage.len(),
        pointer: 0,
        nested: 0,
    };
    let before = current_pointer();
    unsafe { call_on(probe.high, callback, (&mut probe as *mut Probe).cast()) };
    assert_eq!(current_pointer(), before);
    assert!((probe.low..probe.high).contains(&probe.pointer));
    assert!((probe.low..probe.high).contains(&probe.nested));
    assert!(probe.nested <= probe.pointer);
}

#[test]
fn configuration_and_switch_setup_exclude_reentrant_delivery_until_the_stack_is_ready() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/signal_stack.rs");
    let configure = runtime
        .split("fn sigaltstack(")
        .nth(1)
        .unwrap()
        .split("struct Invocation")
        .next()
        .unwrap();
    assert!(
        configure.find("SIGNAL_MASK_BLOCK, u64::MAX").unwrap()
            < configure.find(".replace(").unwrap()
    );
    assert!(
        configure.find("previous.write(old)").unwrap()
            < configure.find("SIGNAL_MASK_SET, mask").unwrap()
    );
    let callback = runtime
        .split("unsafe extern \"C\" fn call(")
        .nth(1)
        .unwrap()
        .split("pub(super) fn invoke(")
        .next()
        .unwrap();
    assert!(callback.find("SIGNAL_MASK_SET").unwrap() < callback.find("function(").unwrap());
    let select = runtime.split("pub(super) fn invoke(").nth(1).unwrap();
    assert!(select.find("SIGNAL_MASK_BLOCK, u64::MAX").unwrap() < select.find(".select(").unwrap());
    assert!(select.find(".select(").unwrap() < select.find("stack::call_on").unwrap());
    assert!(!runtime.contains("RuntimeMutex"));
    let control = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(control.contains("control.alternate_stack.reset()"));
}
