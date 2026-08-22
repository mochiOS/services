#![cfg_attr(test, allow(dead_code))]

extern crate alloc;

#[cfg(not(test))]
mod bootstrap;
mod driver_controller;
mod orchestration;
mod portal;
mod readiness;
mod service_config;
mod service_launcher;
mod session;
mod spawn_support;

#[cfg(not(test))]
pub fn run() -> ! {
    let mut logger_endpoint = None;
    for argument in std::env::args() {
        if let Ok(endpoint) = argument.parse::<u64>() {
            logger_endpoint = Some(endpoint);
        }
    }
    if let Some(endpoint) = logger_endpoint {
        mochi_user_platform::logger::init(endpoint);
    }
    bootstrap::run()
}
