#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static uint64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                       uint64_t d, uint64_t e, uint64_t f) {
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return number;
}

__attribute__((noinline)) static unsigned descend(unsigned depth) {
    volatile unsigned char page[4096];
    page[0] = 0xa7;
    page[4095] = 0x51;
    unsigned result = depth ? descend(depth - 1) : 0;
    return result + (page[0] != 0xa7 || page[4095] != 0x51);
}

int main(void) {
    for (unsigned reserved = 0; reserved < 2; ++reserved) {
        pid_t child = fork();
        if (child < 0) return 1;
        if (child == 0) {
            if (reserved) {
                volatile unsigned char anchor = 0;
                uint64_t address = ((uintptr_t)&anchor & ~UINT64_C(4095)) - 64 * 4096;
                uint64_t object = native(671, 4096, 0, 0, 0, 0, 0);
                if ((int64_t)object < 0) _exit(2);
                /* Reserve absent RAM inside the possible stack-growth arena.
                   It must not be replaced by automatic anonymous stack pages. */
                if (native(582, address, 4096, 1, 3, object, 4096) != address) _exit(3);
            }
            unsigned result = descend(128);
            _exit(reserved ? 4 : (result ? 5 : 0));
        }
        int status = 0;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != (reserved ? 255 : 0)) {
            fprintf(stderr, "stack-growth: unexpected status=%d reserved=%u\n", status, reserved);
            return 6;
        }
    }
    const char text[] = "stack-growth: PASS recursive growth and reserved RAM exclusion\n";
    native(660, (uintptr_t)text, strlen(text), 0, 0, 0, 0);
    return 0;
}
