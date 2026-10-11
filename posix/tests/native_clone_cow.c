/* Isolated Compositor-slot probe using its existing process.spawn authority.
 * The legacy clone backend is under test, not endorsed as the final native
 * API. No POSIX RPC occurs between cloning and the source's first write. */
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile unsigned char private_value = 0x11;
static int64_t native3(uint64_t number, uint64_t a, uint64_t b, uint64_t c) {
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return (int64_t)number;
}
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "clone-cow: FAIL line %d\n", __LINE__); \
        return 1; \
    } \
} while (0)

int main(void) {
    enum { PROCESS_CLONE = 644, RESUME = 645, WAIT = 643, CLOSE = 626, EXIT = 574 };
    struct status { uint64_t id; uint32_t state, reserved; uint64_t code; } status;
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        /* Populate a writable source translation immediately before clone. */
        private_value = 0x11;
        /* Nonzero and high-bit register values prove the kernel does not
         * force the POSIX child return value. Avoid the errno range. */
        const uint64_t resume_rax[] = {
            0, UINT64_C(0x1122334455667788),
            UINT64_C(0x87654321abcdef00), UINT64_C(0xffffffff00000000)
        };
        int64_t child = native3(PROCESS_CLONE, resume_rax[attempt], 0, 0);
        if ((uint64_t)child == resume_rax[attempt]) {
            native3(EXIT, private_value == 0x11 ? 37 : 99, 0, 0);
            __builtin_unreachable();
        }
        CHECK(child > 0);
        /* No intervening syscall may incidentally invalidate the source TLB. */
        private_value = 0x22;
        CHECK(native3(RESUME, child, 0, 0) == 0);
        CHECK(native3(WAIT, child, UINT64_MAX, (uint64_t)&status) == 0);
        CHECK(status.state == 2 && status.code == 37);
        CHECK(private_value == 0x22);
        CHECK(native3(CLOSE, child, 0, 0) == 0);
    }
    fprintf(stderr, "clone-cow: PASS warm source translations cannot write into cloned private pages\n");
    fprintf(stderr, "clone-resume: PASS explicit 64-bit RAX values survive userspace restoration\n");
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        _exit(37);
    }
    int exit_status = 0;
    CHECK(waitpid(child, &exit_status, 0) == child);
    CHECK(WIFEXITED(exit_status) && WEXITSTATUS(exit_status) == 37);
    fprintf(stderr, "clone-resume: PASS newlib fork selects zero in the child and waitpid reaps it\n");
    return 0;
}
