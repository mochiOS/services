extern crate alloc;

mod bootstrap;
mod driver_controller;
mod fixed_service_launcher;
mod orchestration;
mod readiness;
mod service_config;
mod spawn_support;

pub fn run() -> ! {
    let _ = mochi_user_platform::logger::init_from_env();
    bootstrap::run()
}
