#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("native-processor-configuration: SKIP (requires mochiOS)");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mnu_abi::{ProcessorInfo, SyscallNumber};
    use mochi_user_platform::syscall;
    unsafe extern "C" {
        fn sysconf(selector: i32) -> i64;
    }
    let mut info = ProcessorInfo::default();
    let pointer = (&mut info as *mut ProcessorInfo) as u64;
    let size = core::mem::size_of::<ProcessorInfo>() as u64;
    assert_eq!(
        syscall::call2(SyscallNumber::ProcessorDescribe, pointer, size).unwrap(),
        0
    );
    assert!(info.online != 0 && info.configured >= info.online);
    assert_eq!(info.reserved, [0; 2]);
    let saved = info;
    assert_eq!(
        syscall::call2(SyscallNumber::ProcessorDescribe, pointer, size - 1)
            .unwrap_err()
            .raw(),
        -22
    );
    assert_eq!(info, saved);
    assert_eq!(
        syscall::call2(SyscallNumber::ProcessorDescribe, 0, size)
            .unwrap_err()
            .raw(),
        -14
    );
    assert_eq!(unsafe { sysconf(9) }, i64::from(info.configured));
    assert_eq!(unsafe { sysconf(10) }, i64::from(info.online));
    assert_eq!(
        std::thread::available_parallelism().unwrap().get(),
        info.online as usize
    );
    assert_eq!(
        std::thread::spawn(|| std::thread::available_parallelism().unwrap().get())
            .join()
            .unwrap(),
        info.online as usize
    );
    println!(
        "native-processor-configuration: PASS configured={} online={} sysconf, Rust std and invalid native outputs",
        info.configured, info.online
    );
}
