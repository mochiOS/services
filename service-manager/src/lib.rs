extern crate alloc;

#[cfg(not(test))]
mod bootstrap;
mod driver_controller;
mod fixed_service_launcher;
mod orchestration;
mod readiness;
mod service_config;
mod spawn_support;

#[cfg(not(test))]
pub fn run() -> ! {
    let _ = mochi_user_platform::logger::init_from_env();
    bootstrap::run()
}
