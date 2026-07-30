pub mod coordinator;
pub mod filesystem;
pub mod http;
pub mod repository;
pub mod scheduler;
pub mod snapshot;

#[cfg(target_os = "mochios")]
mod service;

include!(concat!(env!("OUT_DIR"), "/developer_root_keys.rs"));

#[cfg(target_os = "mochios")]
pub fn run() -> ! {
    if let Some(endpoint) = std::env::args()
        .nth(1)
        .and_then(|argument| argument.parse::<u64>().ok())
    {
        mochi_user_platform::logger::init(endpoint);
    }
    mochi_user_platform::println!("update.service: start");
    service::run()
}

#[cfg(not(target_os = "mochios"))]
pub fn run() -> ! {
    panic!("update.service can only run on mochiOS")
}
