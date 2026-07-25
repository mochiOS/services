#![no_std]
#![no_main]

extern crate alloc;

use core::arch::global_asm;

mod backend;
mod framebuffer_backend;
mod present;
mod protocol;
mod service;
mod virtio_gpu_backend;

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
        let _ = mochi_user_platform::logger::init_from_initial_stack(sp);
    }
    service::run()
}
