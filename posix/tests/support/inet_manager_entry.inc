// Diagnostic entry: compile the actual manager modules with the probe cfg.
extern crate alloc;
#[path="../../../service-manager/src/bootstrap.rs"]
mod bootstrap;
#[path="../../../service-manager/src/driver_controller.rs"]
mod driver_controller;
#[path="../../../service-manager/src/input_endpoint.rs"]
mod input_endpoint;
#[path="../../../service-manager/src/consent_input.rs"]
mod consent_input;
#[path="../../../service-manager/src/launch_arguments.rs"]
mod launch_arguments;
#[path="../../../service-manager/src/keychain_control.rs"]
mod keychain_control;
#[path="../../../service-manager/src/launch_rollback.rs"]
mod launch_rollback;
#[path="../../../service-manager/src/native_process.rs"]
mod native_process;
#[path="../../../service-manager/src/orchestration.rs"]
mod orchestration;
#[path="../../../service-manager/src/portal.rs"]
mod portal;
#[path="../../../service-manager/src/portal_status.rs"]
mod portal_status;
#[path="../../../service-manager/src/process_watch.rs"]
mod process_watch;
#[path="../../../service-manager/src/readiness.rs"]
mod readiness;
#[path="../../../service-manager/src/service_config.rs"]
mod service_config;
#[path="../../../service-manager/src/service_launcher.rs"]
mod service_launcher;
#[path="../../../service-manager/src/session.rs"]
mod session;
#[path="../../../service-manager/src/session_teardown.rs"]
mod session_teardown;
#[path="../../../service-manager/src/spawn_support.rs"]
mod spawn_support;
#[path="../native_inet_socket.rs"]
mod native_inet_socket_probe;
fn main(){
    for argument in std::env::args(){
        if let Ok(endpoint)=argument.parse::<u64>() {mochi_user_platform::logger::init(endpoint);break;}
    }
    bootstrap::run()
}
