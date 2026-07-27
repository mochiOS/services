#![no_std]
#![no_main]

extern crate alloc;

use core::arch::global_asm;

mod driver;
mod http;
mod service;
mod stack;
mod tls;

getrandom::register_custom_getrandom!(mochios_tls_client::platform_getrandom);

global_asm!(
    r#"
    .global _start
_start:
    xor rbp, rbp
    mov rdi, rsp
    and rsp, -16
    call network_service_main
1:
    hlt
    jmp 1b
"#
);

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn network_service_main(sp: *const usize) -> ! {
    unsafe {
        let _ = mochi_user_platform::logger::init_from_initial_stack(sp);
    }
    service::run()
}
