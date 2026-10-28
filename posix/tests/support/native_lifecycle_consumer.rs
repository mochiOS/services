//! Freestanding PIC consumer of the production codec/state machine. It uses
//! native MemoryCopy/ProcessExit only, and never links a host runtime.
#![no_std]
#[path = "../../../../user/crates/posix-client/src/lifecycle_image.rs"]
mod lifecycle;
use lifecycle::{Image, State};

static STATE: State = State::new();
unsafe extern "C" {
    fn lifecycle_native_main() -> i32;
    fn lifecycle_native_fini_ok() -> i32;
}
fn native(number: u64, first: u64, second: u64, third: u64) -> u64 {
    let result;
    unsafe {
        core::arch::asm!("syscall", inlateout("rax") number => result,
        in("rdi") first, in("rsi") second, in("rdx") third,
        lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    result
}
fn read(address: u64, output: &mut [u8]) -> Result<(), i32> {
    if native(
        699,
        output.as_mut_ptr() as u64,
        address,
        output.len() as u64,
    ) == output.len() as u64
    {
        Ok(())
    } else {
        Err(14)
    }
}
fn word(address: u64) -> Result<u64, i32> {
    let mut bytes = [0; 8];
    read(address, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}
fn call(address: u64) -> Result<(), i32> {
    let function: unsafe extern "C" fn() = unsafe { core::mem::transmute(address as usize) };
    unsafe { function() };
    Ok(())
}
fn run(stack: u64) -> Result<i32, i32> {
    let argc = word(stack)?;
    if argc > 128 {
        return Err(90);
    }
    let mut cursor = stack.checked_add((argc + 2) * 8).ok_or(90)?;
    for _ in 0..128 {
        let value = word(cursor)?;
        cursor += 8;
        if value == 0 {
            break;
        }
    }
    let mut base = 0;
    for _ in 0..64 {
        let key = word(cursor)?;
        if key == 0 {
            break;
        }
        if key == 0x6d00_0005 {
            base = word(cursor + 8)?;
        }
        cursor += 16;
    }
    let image = Image::read(base, 32768, read).map_err(|_| 91)?;
    STATE.initialize(&image, read, call).map_err(|_| 92)?;
    // Repeat calls must not execute initialization/finalization twice.
    STATE.initialize(&image, read, call).map_err(|_| 93)?;
    if unsafe { lifecycle_native_main() } != 0 {
        return Err(94);
    }
    STATE.finalize(&image, read, call).map_err(|_| 95)?;
    STATE.finalize(&image, read, call).map_err(|_| 96)?;
    Ok(unsafe { lifecycle_native_fini_ok() })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lifecycle_test_start(stack: u64) -> ! {
    let status = match run(stack) {
        Ok(status) => status,
        Err(error) => error,
    };
    native(574, status as u64, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}
