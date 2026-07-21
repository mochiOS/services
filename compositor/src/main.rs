#![no_std]
#![no_main]

extern crate alloc;

mod client;
mod decoration;
mod display;
mod geometry;
mod input;
mod protocol;
mod renderer;
mod server;
mod state;
mod surface;
mod window;

use core::arch::global_asm;
use mochi_user_platform as platform;

global_asm!(
    r#"
    .global _start
_start:
    xor rbp, rbp
    mov rdi, rsp
    and rsp, -16
    call service_main
1:
    hlt
    jmp 1b
"#
);

#[unsafe(no_mangle)]
pub extern "C" fn service_main(sp: *const usize) -> ! {
    unsafe {
        let _ = platform::logger::init_from_initial_stack(sp);
    }
    server::run()
}
