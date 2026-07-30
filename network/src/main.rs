extern crate alloc;

mod driver;
mod http;
mod service;
mod stack;
mod tls;

getrandom::register_custom_getrandom!(mochios_tls_client::platform_getrandom);

fn main() {
    let _ = mochi_user_platform::logger::init_from_env();
    service::run()
}
