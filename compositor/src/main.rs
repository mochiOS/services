#![no_std]
#![no_main]

extern crate alloc;

mod client;
mod display;
mod geometry;
mod input;
mod protocol;
mod renderer;
mod server;
mod surface;
mod window;

use core::arch::global_asm;
use mochi_user_platform as platform;

pub(crate) use protocol::errno_status;
pub(crate) use server::{
    MAX_DIMENSION, MAX_SHARED_PAGES, MAX_SHARED_PIXELS, MAX_SURFACES, PAGE_SIZE, getrandom_u64,
    read_current_pixel, shared_page_count, sleep_one_tick, surface_extent,
    surface_has_current_pixels, surface_index_by_handle,
};
pub(crate) use window::WindowId;

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
