#![cfg_attr(test, allow(dead_code))]

extern crate alloc;

// Native services have no implicit writable stderr. Keep lifecycle/failure
// diagnostics in Release, using only the inherited logger endpoint. A logging
// failure must not abort service supervision or process cleanup.
macro_rules! statusln {
    ($($arguments:tt)*) => {{
        let _ = mochi_user_platform::logger::write_status_fmt(format_args!(
            "{}\n", format_args!($($arguments)*)
        ));
    }};
}

#[cfg(not(test))]
mod bootstrap;
mod driver_controller;
mod input_endpoint;
mod consent_input;
mod consent_session;
mod execution_prompt_worker;
mod launch_arguments;
mod keychain_control;
mod launch_rollback;
mod native_process;
mod orchestration;
mod portal;
mod portal_status;
mod presenter;
mod process_watch;
mod readiness;
mod service_config;
mod service_launcher;
mod session;
mod session_teardown;
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
