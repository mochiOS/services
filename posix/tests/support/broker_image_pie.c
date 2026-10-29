/* Syscall-only PIE: the trusted common preparer must bind its flattened output
 * to the created Process, rather than comparing it to the source file hash. */
typedef unsigned long long u64;

static long call(u64 n, u64 a, u64 b, u64 c, u64 d, u64 e) {
    register u64 r10 __asm__("r10") = d;
    register u64 r8 __asm__("r8") = e;
    __asm__ volatile("syscall"
                     : "+a"(n)
                     : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return (long)n;
}

__attribute__((noreturn)) void _start(void) {
    static const char name[] = "capability.service";
    u64 request = 0x43505244, reply = ~0ULL;
    long endpoint = call(518, (u64)name, sizeof(name) - 1, 0, 0, 0);
    long result = endpoint > 0
                      ? call(588, (u64)endpoint, (u64)&request, 4, (u64)&reply, 8)
                      : -1;
    u64 code = result >= 0 && (unsigned)result == 8 && reply == 22 ? 0 : 91;
    call(574, code, 0, 0, 0, 0);
    for (;;) {
        __asm__ volatile("pause");
    }
}
