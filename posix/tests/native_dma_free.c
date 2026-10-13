#include <stdint.h>
#include <string.h>

enum { MEMORY_MAP = 582, MEMORY_UNMAP = 583, DMA_ALLOC = 604, DMA_FREE = 605, DEBUG_WRITE = 660 };
struct allocation { uint64_t handle, virt_addr, phys_addr, len; };
_Static_assert(sizeof(struct allocation) == 32, "DMA allocation ABI");

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

int main(void) {
    /* Isolated fixture requires dma.allocate. No device receives this memory. */
    for (unsigned iteration = 0; iteration < 200; ++iteration) {
        struct allocation object = {0};
        if (native(DMA_ALLOC, 4097, (uintptr_t)&object, 0, 0, 0, 0) != 0) return 1;
        if (!object.handle || !object.virt_addr || object.len != 8192) return 2;
        volatile unsigned char *bytes = (volatile unsigned char *)(uintptr_t)object.virt_addr;
        for (unsigned index = 0; index < 8192; ++index) {
            if (bytes[index] != 0) return 3;
            bytes[index] = 0xa7;
        }
        if (native(DMA_FREE, object.handle, 0, 0, 0, 0, 0) != 0) return 4;
        if ((int64_t)native(DMA_FREE, object.handle, 0, 0, 0, 0, 0) != -22) return 5;
        if (native(MEMORY_MAP, object.virt_addr, 8192, 3, 1, 0, 0) != object.virt_addr) return 6;
        for (unsigned index = 0; index < 8192; ++index) if (bytes[index] != 0) return 7;
        if (native(MEMORY_UNMAP, object.virt_addr, 8192, 0, 0, 0, 0) != 0) return 8;
    }
    const char text[] = "dma-free: PASS 200 release, duplicate rejection and zeroed VA reuse cycles\n";
    native(DEBUG_WRITE, (uintptr_t)text, strlen(text), 0, 0, 0, 0);
    return 0;
}
