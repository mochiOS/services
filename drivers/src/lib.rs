#![no_std]

extern crate alloc;

mod bootstrap;
mod driver_discovery;
mod driver_manifest;
mod driver_matcher;
mod driver_registry;
mod driver_spawn;
mod readiness;
mod service_launcher;
mod spawn_support;

pub fn run(sp: *const usize) -> ! {
    unsafe {
        let _ = mochi_user_platform::logger::init_from_initial_stack(sp);
    }
    bootstrap::run()
}
