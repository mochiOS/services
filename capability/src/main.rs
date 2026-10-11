extern crate alloc;

use mochi_user_platform as platform;

mod app_spawn;
mod native_app;
mod bootstrap_file;
mod dynamic_grant;
mod package_index;
mod package_walk;
mod persistent_grant;
mod policy;
mod resolver;
mod requester_context;
mod runtime_manifest;
mod server;
mod service_bootstrap;
mod state;

use server::serve_capability_requests;
use service_bootstrap::start_required_services;
use state::CapabilityServiceState;

fn main() {
    let _ = platform::logger::init_from_env();
    platform::logln!("capability.service: start");
    if let Err(error) = bootstrap_file::initialize() {
        platform::logln!(
            "capability.service: bootstrap Handle rejected errno={}",
            error.errno().unwrap_or(0)
        );
        platform::process::exit(1);
    }
    let state = match CapabilityServiceState::new() {
        Ok(state) => state,
        Err(error) => {
            let _ = platform::write_fmt(
                platform::io::STDERR,
                format_args!(
                    "capability.service: initial package index failed errno={}\n",
                    error.errno().unwrap_or(0)
                ),
            );
            platform::logln!(
                "capability.service: initial package index failed errno={}",
                error.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    };
    start_required_services(&state.package_index);
    serve_capability_requests(state);
}
