#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

enum { MAP_PHYSICAL = 536, MEMORY_MAP = 582, MEMORY_UNMAP = 583,
       DMA_ALLOC = 604, DMA_FREE = 605, DEBUG_WRITE = 660 };
struct allocation { uint64_t handle, virt_addr, phys_addr, len; };
/* Outside ELF/TLS/heap, DMA and kernel-extension mapping arenas. A new image
   may legitimately occupy low virtual addresses before reaching main(). */
static const uint64_t mmio_address = UINT64_C(0x200000000000);

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

static int after_exec(uint64_t old_handle, uint64_t old_address) {
    if ((int64_t)native(DMA_FREE, old_handle, 0, 0, 0, 0, 0) != -22) return 1;
    if (native(MEMORY_MAP, old_address, 8192, 3, 1, 0, 0) != old_address) return 2;
    volatile unsigned char *bytes = (volatile unsigned char *)(uintptr_t)old_address;
    for (unsigned index = 0; index < 8192; ++index) if (bytes[index] != 0) return 3;
    if (native(MEMORY_UNMAP, old_address, 8192, 0, 0, 0, 0) != 0) return 4;
    uint64_t replacement = native(MEMORY_MAP, mmio_address, 4096, 3, 1, 0, 0);
    if (replacement != mmio_address) {
        char text[96];
        snprintf(text, sizeof(text), "borrowed-cleanup: MMIO VA reuse result=%lld\n", (long long)replacement);
        native(DEBUG_WRITE, (uintptr_t)text, strlen(text), 0, 0, 0, 0);
        return 5;
    }
    if (*(volatile unsigned char *)(uintptr_t)mmio_address != 0) return 6;
    if (native(MEMORY_UNMAP, mmio_address, 4096, 0, 0, 0, 0) != 0) return 7;
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "--after-exec") == 0) {
        return after_exec(strtoull(argv[2], NULL, 10), strtoull(argv[3], NULL, 10));
    }
    for (unsigned iteration = 0; iteration < 26; ++iteration) {
        pid_t child = fork();
        if (child < 0) return 8;
        if (child == 0) {
            struct allocation object = {0};
            if (native(DMA_ALLOC, 8192, (uintptr_t)&object, 0, 0, 0, 0) != 0) _exit(9);
            volatile unsigned char *bytes = (volatile unsigned char *)(uintptr_t)object.virt_addr;
            bytes[0] = 0xa7;
            bytes[8191] = 0x51;
            /* Fixture grants device.gpu and dma.allocate. Never access MMIO. */
            if (native(MAP_PHYSICAL, mmio_address, 0xfec00000, 4096, 0, 0, 0) != 0) _exit(10);
            if (iteration < 20) _exit(0); /* Intentionally leave both owned. */
            char handle[32], address[32];
            snprintf(handle, sizeof(handle), "%llu", (unsigned long long)object.handle);
            snprintf(address, sizeof(address), "%llu", (unsigned long long)object.virt_addr);
            char *arguments[] = {"borrowed-cleanup", "--after-exec", handle, address, NULL};
            execv("/system/services/compositor.service", arguments);
            _exit(11);
        }
        int status = 0;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) {
            char text[96];
            snprintf(text, sizeof(text), "borrowed-cleanup: FAIL iteration=%u status=%d\n", iteration, status);
            native(DEBUG_WRITE, (uintptr_t)text, strlen(text), 0, 0, 0, 0);
            return 12;
        }
    }
    const char text[] = "borrowed-cleanup: PASS 20 exits and 6 execs with live DMA/MMIO mappings\n";
    native(DEBUG_WRITE, (uintptr_t)text, strlen(text), 0, 0, 0, 0);
    return 0;
}
