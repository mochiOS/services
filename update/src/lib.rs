#![no_std]

#[cfg(target_os = "mochios")]
pub fn run(sp: *const usize) -> ! {
    unsafe {
        let _ = mochi_user_platform::logger::init_from_initial_stack(sp);
    }
    mochi_user_platform::println!("update.service: start");
    loop {
        mochi_user_platform::thread::yield_now();
    }
}
