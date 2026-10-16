#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

enum { INSTALL = 654, RETURN = 655, THREAD_HANDLE = 656, INTERRUPT = 657,
       YIELD = 579, CLOSE = 626 };
static unsigned char upcall_stack[16384] __attribute__((aligned(16)));
static const unsigned char expected[16] __attribute__((aligned(16))) = {
    1, 7, 19, 3, 14, 11, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61
};
static const unsigned char changed[16] __attribute__((aligned(16))) = {99};
static const uint32_t initial_mxcsr = 0x3f80, handler_mxcsr = 0x5f80;
static const uint16_t initial_x87 = 0x077f, handler_x87 = 0x0b7f;
static volatile unsigned deliveries;
static volatile int handler_failed;
static volatile int return_int80;

static inline __attribute__((always_inline)) uint64_t native(uint64_t number, uint64_t a, uint64_t b) {
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b)
                     : "rcx", "r11", "memory");
    return number;
}

static inline __attribute__((always_inline)) uint64_t interrupt(uint64_t number, uint64_t a, uint64_t b) {
    __asm__ volatile("int $0x80" : "+a"(number) : "D"(a), "S"(b)
                     : "rcx", "r11", "memory");
    return number;
}

static uint64_t return_upcall(uint64_t token) {
    return return_int80 ? interrupt(RETURN, token, 0) : native(RETURN, token, 0);
}

static void handler(uint64_t payload, uint64_t token) {
    if (payload != 0xa7 || !token) handler_failed = 1;
    ++deliveries;
    __asm__ volatile("movdqu %0, %%xmm0\nmovdqu %0, %%xmm15\nldmxcsr %1\nfldcw %2"
                     : : "m"(changed), "m"(handler_mxcsr), "m"(handler_x87)
                     : "xmm0", "xmm15", "memory");
    if ((int64_t)return_upcall(token + 1) != INT64_C(-262139)) handler_failed = 2;
    uint32_t retained;
    __asm__ volatile("stmxcsr %0" : "=m"(retained));
    if (retained != handler_mxcsr) handler_failed = 3;
    return_upcall(token);
    _exit(90);
}

int main(void) {
    struct { uint64_t entry, stack_base, stack_size, flags, reserved[4]; } config = {
        (uintptr_t)handler, (uintptr_t)upcall_stack, sizeof(upcall_stack), 0, {0}
    };
    uint64_t thread = native(THREAD_HANDLE, 0, 0);
    if ((int64_t)thread <= 0 || native(INSTALL, (uintptr_t)&config, sizeof(config))) return 1;
    for (unsigned attempt = 1; attempt <= 4; ++attempt) {
        return_int80 = (attempt - 1) & 1;
        unsigned char first[16], last[16];
        uint32_t mxcsr;
        uint16_t x87;
        uint64_t result;
        uint64_t kept_rcx = 0, kept_r11 = 0;
        __asm__ volatile("movdqu %0, %%xmm0\nmovdqu %0, %%xmm15\nldmxcsr %1\nfldcw %2"
                         : : "m"(expected), "m"(initial_mxcsr), "m"(initial_x87)
                         : "xmm0", "xmm15", "memory");
        if ((attempt - 1) & 2) {
            result = INTERRUPT;
            __asm__ volatile("movabs $0x1122334455667788, %%rcx\n"
                             "movabs $0x8877665544332211, %%r11\n"
                             "int $0x80\nmov %%rcx, %0\nmov %%r11, %1"
                             : "=m"(kept_rcx), "=m"(kept_r11), "+a"(result)
                             : "D"(thread), "S"(0xa7) : "rcx", "r11", "memory");
        } else {
            result = native(INTERRUPT, thread, 0xa7);
        }
        __asm__ volatile("movdqu %%xmm0, %0\nmovdqu %%xmm15, %1\nstmxcsr %2\nfnstcw %3"
                         : "=m"(first), "=m"(last), "=m"(mxcsr), "=m"(x87) : : "memory");
        if (result || deliveries != attempt || handler_failed ||
            memcmp(first, expected, 16) || memcmp(last, expected, 16) ||
            mxcsr != initial_mxcsr || x87 != initial_x87 ||
            (((attempt - 1) & 2) && (kept_rcx != UINT64_C(0x1122334455667788) ||
                                    kept_r11 != UINT64_C(0x8877665544332211)))) {
            fprintf(stderr, "upcall-fx-state: FAIL attempt=%u count=%u handler=%d mxcsr=%x x87=%x\n",
                    attempt, deliveries, handler_failed, mxcsr, x87);
            return 2;
        }
    }
    if (native(CLOSE, thread, 0)) return 3;
    puts("upcall-fx-state: PASS SYSCALL/int80 cross returns, RCX/R11, SIMD, MXCSR, x87 and tokens");
    return 0;
}
