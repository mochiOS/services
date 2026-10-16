#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

enum { MAP = 582, UNMAP = 583, PROTECT = 584, INSTALL = 654, RETURN = 655, INSPECT = 688, RETURN_CONTEXT = 689,
       CREATE_MEMORY = 671 };
struct snapshot {
    uint64_t instruction, stack_pointer, flags, argument;
    struct { uint64_t rax, rbx, rcx, rdx, rsi, rbp, r8, r9, r10, r11, r12, r13, r14, r15; } registers;
    unsigned char fx_state[512];
} __attribute__((aligned(16)));
_Static_assert(sizeof(struct snapshot) == 656, "native snapshot ABI");
static unsigned char entry_stack[16384] __attribute__((aligned(4096)));
static volatile uint64_t expected_address;
static volatile uint64_t expected_cause = 2;
static volatile unsigned exceptions;
static volatile int recursive;
static volatile int report_only;
static volatile uint64_t last_token;

static inline uint64_t native(uint64_t n, uint64_t a, uint64_t b, uint64_t c,
                              uint64_t d, uint64_t e, uint64_t f) {
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(n)
                     : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return n;
}

static void invalid_access(void) {
    uint64_t value = 0;
    __asm__ volatile("mov (%%rax), %%rax" : "+a"(value) : : "memory");
}

static void handler(uint64_t vector, uint64_t token, uint64_t kind,
                    uint64_t address, uint64_t code, uint64_t instruction,
                    uint64_t cause) {
    /* Native lifecycle/wait notifications share this entry, even while
       SIGCHLD is blocked. They are not synchronous exceptions. */
    if (kind == 0) {
        /* Legacy return must ignore all registers outside its one argument. */
        native(RETURN, token, UINT64_MAX, UINT64_MAX, 0, 0, 0);
        _exit(96);
    }
    uint64_t flags;
    __asm__ volatile("pushfq\npop %0" : "=r"(flags));
    if (vector != 14 || !token || kind != 1 || address != expected_address ||
        (!report_only && !(code & 2)) || !(code & 4) || !instruction ||
        (flags & (1 << 10)) || cause != expected_cause) {
        fprintf(stderr, "user-exception: bad envelope vector=%llu kind=%llu addr=%llx code=%llx ip=%llx\n",
                (unsigned long long)vector, (unsigned long long)kind,
                (unsigned long long)address, (unsigned long long)code,
                (unsigned long long)instruction);
        _exit(90);
    }
    if (report_only) _exit(70 + (int)cause);
    struct snapshot captured, again;
    if ((int64_t)native(INSPECT, token + 1, (uintptr_t)&captured, sizeof(captured), 0, 0, 0) != INT64_C(-262139) ||
        (int64_t)native(INSPECT, token, 0, sizeof(captured), 0, 0, 0) != INT64_C(-262142) ||
        (int64_t)native(INSPECT, token, (uintptr_t)&captured, sizeof(captured) - 1, 0, 0, 0) != INT64_C(-262139) ||
        native(INSPECT, token, (uintptr_t)&captured, sizeof(captured), 0, 0, 0)) _exit(101);
    if (captured.instruction != instruction || !captured.stack_pointer ||
        !(captured.flags & (1 << 10)) || captured.registers.rcx != UINT64_C(0x1122334455667788) ||
        captured.registers.r11 != UINT64_C(0x8877665544332211)) _exit(102);
    captured.instruction = 0;
    captured.registers.rcx = 0;
    if (native(INSPECT, token, (uintptr_t)&again, sizeof(again), 0, 0, 0) ||
        again.instruction != instruction || !again.registers.rcx) _exit(103);
    captured = again;
    if ((int64_t)native(RETURN_CONTEXT, token + 1, (uintptr_t)&captured, sizeof(captured), 0, 0, 0) != INT64_C(-262139)) _exit(109);
    captured.flags |= 3u << 12;
    if ((int64_t)native(RETURN_CONTEXT, token, (uintptr_t)&captured, sizeof(captured), 0, 0, 0) != INT64_C(-262139)) _exit(104);
    captured = again; captured.instruction = UINT64_C(0xffff800000000000);
    if ((int64_t)native(RETURN_CONTEXT, token, (uintptr_t)&captured, sizeof(captured), 0, 0, 0) != INT64_C(-262139)) _exit(105);
    captured = again; captured.stack_pointer = UINT64_C(0xffff800000000000);
    if ((int64_t)native(RETURN_CONTEXT, token, (uintptr_t)&captured, sizeof(captured), 0, 0, 0) != INT64_C(-262139)) _exit(106);
    captured = again;
    captured.fx_state[27] = 0x80;
    for (unsigned i = 28; i < 32; ++i) captured.fx_state[i] = 0xff;
    if ((int64_t)native(RETURN_CONTEXT, token, 0, sizeof(captured), 0, 0, 0) != INT64_C(-262142) ||
        (int64_t)native(RETURN_CONTEXT, token, 1, sizeof(captured), 0, 0, 0) != INT64_C(-262142)) _exit(108);
    captured = again;
    captured.flags |= 1;
    captured.registers.rcx = UINT64_C(0x123456789abcdef0);
    captured.registers.r11 = UINT64_C(0xfedcba9876543210);
    captured.fx_state[25] = (captured.fx_state[25] & ~0x60u) | 0x40u;
    last_token = token;
    ++exceptions;
    if (recursive) invalid_access();
    if (native(PROTECT, address, 4096, 3, 0, 0, 0)) _exit(91);
    native(RETURN_CONTEXT, token, (uintptr_t)&captured, sizeof(captured), 0, 0, 0);
    _exit(92);
}

static int install(uint64_t flags) {
    struct { uint64_t entry, base, length, flags, reserved[4]; } config = {
        (uintptr_t)handler, (uintptr_t)entry_stack, sizeof(entry_stack), flags, {0}
    };
    return (int64_t)native(INSTALL, (uintptr_t)&config, sizeof(config), 0, 0, 0, 0);
}

static int recover(void) {
    uint64_t memory = native(MAP, 0, 4096, 3, 0, 0, 0);
    if ((int64_t)memory <= 0) return 1;
    expected_address = memory;
    if (native(PROTECT, memory, 4096, 1, 0, 0, 0)) return 2;
    uint64_t rcx, r11, restored_flags;
    uint32_t before_mxcsr, after_mxcsr;
    __asm__ volatile("stmxcsr %0" : "=m"(before_mxcsr));
    __asm__ volatile("movabs $0x1122334455667788, %%rcx\n"
                     "movabs $0x8877665544332211, %%r11\n"
                     "clc\nstd\nmovb $0xa7, (%3)\nmov %%rcx, %0\nmov %%r11, %1\n"
                     "pushfq\npop %2\ncld"
                     : "=m"(rcx), "=m"(r11), "=r"(restored_flags)
                     : "r"(memory) : "rcx", "r11", "memory", "cc");
    __asm__ volatile("stmxcsr %0\nldmxcsr %1" : "=m"(after_mxcsr) : "m"(before_mxcsr));
    if (rcx != UINT64_C(0x123456789abcdef0) || r11 != UINT64_C(0xfedcba9876543210) ||
        *(volatile unsigned char *)(uintptr_t)memory != 0xa7 || !(restored_flags & (1 << 10)) ||
        !(restored_flags & 1) || (after_mxcsr & 0x6000) != 0x4000) return 3;
    if (native(UNMAP, memory, 4096, 0, 0, 0, 0)) return 4;
    return 0;
}

int main(void) {
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &blocked, NULL)) return 1;
    if (install(2) != INT64_C(-262139) || install(1)) return 1;
    if ((int64_t)native(INSPECT, 0, 0, sizeof(struct snapshot), 0, 0, 0) != INT64_C(-262139)) return 7;
    for (unsigned attempt = 1; attempt <= 3; ++attempt) {
        int result = recover();
        if (result || exceptions != attempt) {
            fprintf(stderr, "user-exception: recovery FAIL %d count=%u\n", result, exceptions);
            return 2;
        }
        struct snapshot stale;
        if ((int64_t)native(INSPECT, last_token, (uintptr_t)&stale, sizeof(stale), 0, 0, 0) != INT64_C(-262139)) return 8;
        if ((int64_t)native(RETURN_CONTEXT, last_token, (uintptr_t)&stale, sizeof(stale), 0, 0, 0) != INT64_C(-262139)) return 9;
    }
    /* Both private copies and shared pins must report absent backing, not
       manufacture pages. The unmapped-address case is a distinct cause. */
    for (int kind = 0; kind < 3; ++kind) {
        pid_t child = fork();
        if (child < 0) return 5;
        if (!child) {
            report_only = 1;
            expected_cause = kind == 0 ? 1 : 3;
            expected_address = 0;
            if (kind) {
                uint64_t object = native(CREATE_MEMORY, 4096, 0, 0, 0, 0, 0);
                if ((int64_t)object < 0) _exit(97);
                expected_address = native(MAP, 0, 4096, 1, kind == 2 ? 2 : 0, object, 4096);
                if ((int64_t)expected_address <= 0) _exit(98);
            }
            if (install(1)) _exit(99);
            uint64_t value = expected_address;
            __asm__ volatile("mov (%%rax), %%rax" : "+a"(value) : : "memory");
            _exit(100);
        }
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != (kind == 0 ? 71 : 73)) return 6;
    }
    /* Non-opted-in children retain the native fatal-fault default. */
    for (int recurse = 0; recurse <= 1; ++recurse) {
        pid_t child = fork();
        if (child < 0) return 3;
        if (!child) {
            if (recurse) {
                recursive = 1;
                if (install(1)) _exit(93);
                recover();
            } else {
                if (install(0)) _exit(94);
                invalid_access();
            }
            _exit(95);
        }
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 255) return 4;
    }
    puts("user-exception: PASS opt-in, native causes, validated context return, backing bounds, repair/retry, full registers, COW and recursive rejection");
    return 0;
}
