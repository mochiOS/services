#![no_std]
#![no_main]

use mochi_user_platform as platform;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    main();
    platform::runtime::abort()
}

fn main() {
    platform::println!("Hello, from user!");

    loop {
        platform::thread::yield_now();
    }
}
