use mochi_user_platform as platform;

const SERVICE_READY_YIELDS: usize = 64;

pub(crate) fn wait_for_process(name: &str) -> bool {
    for _ in 0..SERVICE_READY_YIELDS {
        if let Ok(tid) = platform::process::find_by_name(name)
            && tid != 0
        {
            return true;
        }
        platform::thread::yield_now();
    }
    false
}

pub(crate) fn idle() -> ! {
    loop {
        platform::thread::yield_now();
    }
}
