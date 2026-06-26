#![no_std]
#![no_main]

use core::arch::global_asm;
use mochi_user_platform as platform;
use mochi_user_syscall as syscall;

global_asm!(
    r#"
    .global _start
_start:
    xor rbp, rbp
    and rsp, -16
    call service_main
1:
    hlt
    jmp 1b
"#
);

static DRIVERS_SERVICE: &[u8] = b"/system/services/drivers.service\0";

fn spawn_drivers_service() -> Result<u64, syscall::SysError> {
    platform::println!("core.service: entering spawn_drivers_service");
    syscall::call1(
        syscall::SyscallNumber::ServiceSpawn,
        DRIVERS_SERVICE.as_ptr() as u64,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn service_main() -> ! {
    main();
    platform::process::exit(0)
}

fn main() {
    platform::println!("core.service: start");
    platform::println!("core.service: before drivers.service spawn");
    match spawn_drivers_service() {
        Ok(pid) => {
            platform::println!("core.service: drivers.service spawned pid={}", pid);
        }
        Err(err) => {
            platform::println!(
                "core.service: drivers.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    }

    loop {
        platform::thread::yield_now();
    }
}
