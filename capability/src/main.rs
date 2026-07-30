extern crate alloc;

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

fn main() {
    let _ = platform::logger::init_from_env();
    platform::println!("capability.service: start");
    let state = CapabilityServiceState::new();
    start_required_services(&state.package_index);
    serve_capability_requests(state);
}
