#![cfg_attr(target_os = "mochios", no_std)]
#![cfg_attr(target_os = "mochios", no_main)]

#[cfg(target_os = "mochios")]
use core::arch::global_asm;

#[cfg(target_os = "mochios")]
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

#[cfg(target_os = "mochios")]
#[unsafe(no_mangle)]
pub extern "C" fn service_main(sp: *const usize) -> ! {
    update::run(sp)
}

#[cfg(not(target_os = "mochios"))]
fn main() {}
