#![cfg_attr(target_os = "mochios", no_std)]
#![cfg_attr(target_os = "mochios", no_main)]

#[cfg(target_os = "mochios")]
mod native {

    use core::{
        ffi::c_int,
        mem::MaybeUninit,
        sync::atomic::{AtomicU32, Ordering},
    };

    const _: [(); 16] = [(); core::mem::size_of::<libc::sem_t>()];
    const _: [(); 8] = [(); core::mem::align_of::<libc::sem_t>()];
    const _: [(); 4] = [(); core::mem::size_of::<libc::pthread_rwlock_t>()];
    const _: [(); 4] = [(); core::mem::align_of::<libc::pthread_rwlock_t>()];
    const _: [(); 8] = [(); core::mem::size_of::<libc::pthread_rwlockattr_t>()];
    const _: [(); 8] = [(); core::mem::size_of::<libc::pthread_once_t>()];
    const _: [(); 32] = [(); core::mem::size_of::<libc::pthread_barrier_t>()];
    const _: [(); 8] = [(); core::mem::align_of::<libc::pthread_barrier_t>()];

    // A byte prefix exposes a wrongly aligned opaque sem_t, even when a bare
    // variable happened to receive a naturally aligned stack/malloc address.
    #[repr(C)]
    struct Embedded {
        prefix: u8,
        semaphore: MaybeUninit<libc::sem_t>,
    }
    static INITIALIZATIONS: AtomicU32 = AtomicU32::new(0);
    unsafe extern "C" fn initialize() {
        INITIALIZATIONS.fetch_add(1, Ordering::Relaxed);
    }

    fn debug(message: &[u8]) {
        unsafe {
            core::arch::asm!("syscall", inlateout("rax") 660u64 => _,
        in("rdi") message.as_ptr(), in("rsi") message.len(), lateout("rcx") _, lateout("r11") _);
        }
    }
    macro_rules! check {
        ($expression:expr) => {
            if !$expression {
                debug(
                    concat!(
                        "native-rust-sync-bindings: FAIL ",
                        stringify!($expression),
                        "\n"
                    )
                    .as_bytes(),
                );
                return 1;
            }
        };
    }

    #[no_mangle]
    pub unsafe extern "C" fn main(_: c_int, _: *const *const libc::c_char) -> c_int {
        let mut embedded = Embedded {
            prefix: 0,
            semaphore: MaybeUninit::uninit(),
        };
        check!(core::mem::offset_of!(Embedded, semaphore) == 8);
        let semaphore = embedded.semaphore.as_mut_ptr();
        check!(libc::sem_init(semaphore, 0, 0) == 0);
        check!(libc::sem_post(semaphore) == 0 && libc::sem_trywait(semaphore) == 0);
        let mut value = -1;
        check!(libc::sem_getvalue(semaphore, &mut value) == 0 && value == 0);
        check!(libc::sem_destroy(semaphore) == 0);
        let named = libc::sem_open(
            c"/native-rust-semaphore".as_ptr(),
            libc::O_CREAT | libc::O_EXCL,
            0o600u32,
            1u32,
        );
        check!(named != libc::SEM_FAILED);
        check!(
            libc::sem_wait(named) == 0 && libc::sem_unlink(c"/native-rust-semaphore".as_ptr()) == 0
        );
        check!(libc::sem_close(named) == 0);

        let mut lock = libc::PTHREAD_RWLOCK_INITIALIZER;
        check!(lock == u32::MAX);
        check!(libc::pthread_rwlock_rdlock(&mut lock) == 0);
        check!(libc::pthread_rwlock_unlock(&mut lock) == 0);
        check!(libc::pthread_rwlock_destroy(&mut lock) == 0);
        let mut once = libc::PTHREAD_ONCE_INIT;
        check!(libc::pthread_once(&mut once, Some(initialize)) == 0);
        check!(
            libc::pthread_once(&mut once, Some(initialize)) == 0
                && INITIALIZATIONS.load(Ordering::Acquire) == 1
        );

        let mut barrier = MaybeUninit::<libc::pthread_barrier_t>::uninit();
        check!(libc::pthread_barrier_init(barrier.as_mut_ptr(), core::ptr::null(), 1) == 0);
        for _ in 0..100 {
            check!(
                libc::pthread_barrier_wait(barrier.as_mut_ptr())
                    == libc::PTHREAD_BARRIER_SERIAL_THREAD
            );
        }
        check!(libc::pthread_barrier_destroy(barrier.as_mut_ptr()) == 0);
        debug(b"native-rust-sync-bindings: PASS target libc ABI, embedded semaphore alignment, named semaphore variadics, rwlock initializer, once and barrier\n");
        0
    }

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
        debug(b"native-rust-sync-bindings: PANIC\n");
        unsafe { libc::_exit(127) }
    }
}
