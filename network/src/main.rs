extern crate alloc;

mod datagram;
mod datagram_authority;
mod driver;
mod http;
mod reply;
mod service;
mod stack;
mod stream;
mod stream_provider;
mod status;
mod tls;

getrandom::register_custom_getrandom!(mochios_tls_client::platform_getrandom);

fn main() {
    let _ = mochi_user_platform::logger::init_from_env();
    service::run()
}
