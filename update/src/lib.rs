pub mod coordinator;
pub mod diagnostics;
pub mod download;
pub mod filesystem;
pub mod http;
pub mod installer;
pub mod notifier;
pub mod os_update;
pub mod payload;
pub mod public_api;
pub mod repository;
pub mod scheduler;
pub mod snapshot;

pub use mochios_boot_selection as boot_selection;

#[cfg(target_os = "mochios")]
mod service;

include!(concat!(env!("OUT_DIR"), "/developer_root_keys.rs"));
include!(concat!(env!("OUT_DIR"), "/release_public_keys.rs"));

#[cfg(feature = "development-system-key")]
pub const SYSTEM_PUBLIC_KEYS: &[[u8; 32]] = &[
    mochios_system_image::RELEASE_PUBLIC_KEY,
    mochios_system_image::DEVELOPMENT_PUBLIC_KEY,
];
#[cfg(not(feature = "development-system-key"))]
pub const SYSTEM_PUBLIC_KEYS: &[[u8; 32]] = &[mochios_system_image::RELEASE_PUBLIC_KEY];

#[cfg(target_os = "mochios")]
pub fn run() -> ! {
    if let Some(endpoint) = std::env::args()
        .nth(1)
        .and_then(|argument| argument.parse::<u64>().ok())
    {
        mochi_user_platform::logger::init(endpoint);
    }
    mochi_user_platform::logln!("update.service: start");
    service::run()
}

#[cfg(not(target_os = "mochios"))]
pub fn run() -> ! {
    panic!("update.service can only run on mochiOS")
}
