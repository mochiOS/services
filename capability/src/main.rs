extern crate alloc;

use mochi_user_platform as platform;

mod app_spawn;
mod application_data;
mod application_data_identity;
mod administrator;
mod package_approval;
mod app_stdio;
mod app_image;
mod native_app;
mod image_diagnostics;
mod image_catalog;
mod resource_tokens;
mod executable_tokens;
mod native_bootstrap;
mod prepared_image;
mod broker_launch;
mod object_image;
mod replayed_exec;
mod signed_image;
mod library_image;
mod installed_image;
mod standalone_image;
mod execution_approval;
mod execution_requests;
mod execution_frontend;
mod execution_grant;
mod text_evidence;
mod bootstrap_file;
mod dynamic_grant;
mod consent;
mod consent_peer;
mod consent_input;
mod consent_presentation;
#[cfg(mochios_presentation_probe_307)]
#[path = "../../posix/tests/support/presentation_broker_307.rs"]
mod presentation_probe;
#[cfg(mochios_consent_input_probe_306)]
#[path = "../../posix/tests/support/consent_input_broker_306.rs"]
mod consent_input_probe;
mod trusted_images;
mod package_index;
mod package_walk;
mod persistent_grant;
mod policy;
mod pci_resources;
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
    if let Err(error) = pci_resources::initialize() {
        platform::logln!("capability.service: PCI resource initialization failed raw={}", error.raw());
        platform::process::exit(1);
    }
    start_required_services(&state.package_index);
    serve_capability_requests(state);
}
