#![no_std]

extern crate alloc;

mod control_state;
mod control_worker;
mod discovery;
mod driver_discovery;
mod driver_manifest;
mod driver_matcher;
mod driver_registry;
mod driver_spawn;
mod spawn_support;
mod startup_args;

pub fn run(sp: *const usize) -> ! {
    let config = unsafe {
        let _ = mochi_user_platform::logger::init_from_initial_stack(sp);
        let stack = mochi_user_platform::runtime::InitialStack::parse(sp);
        let mut parser = startup_args::DriverManagerArgParser::new();
        let mut parse_error = None;
        for &arg_ptr in stack.argv {
            if arg_ptr.is_null() {
                continue;
            }
            let mut len = 0usize;
            while core::ptr::read_volatile(arg_ptr.add(len)) != 0 {
                len += 1;
            }
            let argument = core::slice::from_raw_parts(arg_ptr, len);
            if let Err(error) = parser.push(argument) {
                parse_error = Some(error);
                break;
            }
        }
        match parse_error {
            Some(error) => Err(error),
            None => parser.finish(),
        }
    };

    match config {
        Ok(config) => control_worker::run(config),
        Err(error) => {
            mochi_user_platform::println!(
                "drivers.service: invalid --driver-manager argument error={:?}",
                error
            );
            control_worker::idle()
        }
    }
}
