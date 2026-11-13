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

mod control_state;
mod control_authorization;
mod control_worker;
mod discovery;
mod driver_discovery;
mod driver_manifest;
mod driver_matcher;
mod driver_registry;
mod driver_spawn;
mod spawn_support;
mod startup_args;

pub fn run() -> ! {
    let _ = mochi_user_platform::logger::init_from_env();
    let mut parser = startup_args::DriverManagerArgParser::new();
    let mut parse_error = None;
    for argument in std::env::args() {
        if let Err(error) = parser.push(argument.as_bytes()) {
            parse_error = Some(error);
            break;
        }
    }
    let config = match parse_error {
        Some(error) => Err(error),
        None => parser.finish(),
    };

    match config {
        Ok(config) => control_worker::run(config),
        Err(error) => {
            mochi_user_platform::logln!(
                "drivers.service: invalid --driver-manager argument error={:?}",
                error
            );
            control_worker::idle()
        }
    }
}
