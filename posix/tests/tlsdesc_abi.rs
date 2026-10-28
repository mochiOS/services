#![cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[path = "../../../user/crates/newlib-runtime/src/tlsdesc.rs"]
mod tlsdesc;
core::arch::global_asm!(include_str!("support/tlsdesc_registers.S"));
unsafe extern "C" {
    fn run_tls_descriptor(descriptor: *const u64, result: *mut u64) -> u64;
}

#[test]
fn production_static_and_weak_thunks_preserve_all_other_gprs_and_xmm_registers() {
    tlsdesc::retain();
    let tp: u64;
    unsafe {
        core::arch::asm!("mov {}, fs:[0]", out(reg) tp, options(nostack, readonly, preserves_flags));
    }
    for argument in [0u64, 17, u64::MAX - 63] {
        for weak in [false, true] {
            let function = if weak {
                tlsdesc::__mochios_tlsdesc_weak
            } else {
                tlsdesc::__mochios_tlsdesc_static
            };
            let descriptor = [function as *const () as u64, argument];
            let mut result = 0;
            assert_eq!(
                unsafe { run_tls_descriptor(descriptor.as_ptr(), &mut result) },
                0
            );
            assert_eq!(
                result,
                if weak {
                    argument.wrapping_sub(tp)
                } else {
                    argument
                }
            );
        }
    }
}
