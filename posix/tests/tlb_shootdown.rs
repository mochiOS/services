// Compile the actual transport and kernel SpinLock. Only privileged CPU/APIC
// operations are replaced; native instruction behavior is tested under KVM.
extern crate self as x86_64;
use std::cell::Cell;
use mem::paging;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
thread_local! {
    static CPU: Cell<usize> = const { Cell::new(0) };
    static IF: Cell<bool> = const { Cell::new(true) };
}
static FLUSHES: [AtomicUsize; 2] = [const { AtomicUsize::new(0) }; 2];
static FAIL_IPI: AtomicBool = AtomicBool::new(false);
static DEFER_IPI: AtomicBool = AtomicBool::new(false);
static IPIS: AtomicUsize = AtomicUsize::new(0);
pub mod instructions {
    pub mod interrupts {
        pub fn are_enabled() -> bool {
            crate::IF.with(|flag| flag.get())
        }
        pub fn disable() {
            crate::IF.with(|flag| flag.set(false));
        }
        pub fn enable() {
            crate::IF.with(|flag| flag.set(true));
        }
        pub fn without_interrupts<T>(body: impl FnOnce() -> T) -> T {
            let enabled = are_enabled();
            disable();
            let value = body();
            if enabled {
                enable();
            }
            value
        }
    }
}
mod percpu {
    pub const MAX_CPUS: usize = 2;
    pub fn current_cpu_id() -> usize {
        crate::CPU.with(|cpu| cpu.get())
    }
}
#[path = "../../../core/src/interrupt/spinlock.rs"]
mod spinlock;
#[path = "../../../core/src/mem/tlb_rendezvous.rs"]
mod tlb_rendezvous;
#[path = "../../../core/src/mem/tlb_shootdown.rs"]
mod tlb_shootdown;
mod mem {
    pub(crate) use crate::tlb_shootdown;
    pub mod paging {
        pub fn flush_all_translations_local() {
            assert!(!crate::instructions::interrupts::are_enabled());
            crate::FLUSHES[crate::percpu::current_cpu_id()].fetch_add(1, crate::Ordering::Relaxed);
        }
    }
}
mod smp {
    pub fn send_fixed_ipi(cpu: u32, vector: u8) -> bool {
        assert_eq!(vector, crate::tlb_shootdown::VECTOR);
        crate::IPIS.fetch_add(1, crate::Ordering::Relaxed);
        if crate::FAIL_IPI.load(crate::Ordering::Relaxed) {
            return false;
        }
        if !crate::DEFER_IPI.load(crate::Ordering::Relaxed) {
            crate::CPU.with(|slot| {
                let old = slot.replace(cpu as usize);
                crate::tlb_shootdown::service_pending();
                slot.set(old);
            });
        }
        true
    }
}

#[test]
fn actual_transport_propagates_dispatch_failure_and_cooperates_with_if_disabled_lock_waiters() {
    for cpu in 0..2 {
        CPU.with(|slot| slot.set(cpu));
        instructions::interrupts::without_interrupts(tlb_shootdown::mark_current_cpu_online);
    }
    CPU.with(|slot| slot.set(0));
    assert_eq!(tlb_shootdown::invalidate_all(), Ok(()));
    assert_eq!(FLUSHES[0].load(Ordering::Acquire), 1);
    assert_eq!(FLUSHES[1].load(Ordering::Acquire), 1);
    assert!(instructions::interrupts::are_enabled());
    FAIL_IPI.store(true, Ordering::Release);
    assert_eq!(tlb_shootdown::invalidate_all(), Err(()));
    assert_eq!(FLUSHES[1].load(Ordering::Acquire), 1);
    assert!(instructions::interrupts::are_enabled());
    FAIL_IPI.store(false, Ordering::Release);
    assert_eq!(tlb_shootdown::invalidate_all(), Ok(()));

    // CPU0 holds a real kernel lock. CPU1 spins with IF=0 on that lock.
    // No IPI handler is delivered: the production SpinLock must service the
    // request, otherwise CPU0 cannot finish and release the lock to CPU1.
    DEFER_IPI.store(true, Ordering::Release);
    let lock = spinlock::SpinLock::new(0u32);
    let ready = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let guard = lock.lock();
        let waiter = scope.spawn(|| {
            CPU.with(|slot| slot.set(1));
            ready.wait();
            let mut guard = lock.lock();
            *guard += 1;
        });
        ready.wait();
        let previous = FLUSHES[1].load(Ordering::Acquire);
        assert_eq!(tlb_shootdown::invalidate_all(), Ok(()));
        assert!(FLUSHES[1].load(Ordering::Acquire) > previous);
        assert!(!instructions::interrupts::are_enabled());
        drop(guard);
        waiter.join().unwrap();
    });
    assert!(instructions::interrupts::are_enabled());
    assert_eq!(*lock.lock(), 1);
    assert_eq!(IPIS.load(Ordering::Acquire), 4);
}
