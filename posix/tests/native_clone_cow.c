/* Isolated Compositor-slot probe using its existing process.spawn authority.
 * The legacy clone backend is under test, not endorsed as the final native
 * API. No POSIX RPC occurs between cloning and the source's first write. */
#include <stdint.h>
#include <stdio.h>

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
        int64_t child = native3(PROCESS_CLONE, 0, 0, 0);
        if (child == 0) {
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
    return 0;
}
