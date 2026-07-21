#![no_std]
#![no_main]

extern crate alloc;

use core::arch::global_asm;
use mochi_user_platform as platform;

mod app_spawn;
mod dynamic_grant;
mod package_index;
mod persistent_grant;
mod policy;
mod resolver;
mod server;
mod service_bootstrap;
mod state;

use server::serve_capability_requests;
use service_bootstrap::start_required_services;
use state::CapabilityServiceState;

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
    platform::println!("capability.service: start");
    let state = CapabilityServiceState::new();
    start_required_services(&state.package_index);
    serve_capability_requests(state);
}
