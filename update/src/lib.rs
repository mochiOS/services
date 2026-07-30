pub mod coordinator;
pub mod http;
pub mod scheduler;
pub mod snapshot;

#[cfg(target_os = "mochios")]
pub fn run() -> ! {
    if let Some(endpoint) = std::env::args()
        .nth(1)
        .and_then(|argument| argument.parse::<u64>().ok())
    {
        mochi_user_platform::logger::init(endpoint);
    }
    mochi_user_platform::println!("update.service: start");
    loop {
        mochi_user_platform::thread::yield_now();
    }
}

#[cfg(not(target_os = "mochios"))]
pub fn run() -> ! {
    panic!("update.service can only run on mochiOS")
}
