#include <stdint.h>
#include <string.h>

enum { MAP_PHYSICAL = 536, MEMORY_MAP = 582, MEMORY_UNMAP = 583, DEBUG_WRITE = 660 };

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
    const uint64_t address = 0x68000000;
    /* Isolated fixture uses the existing device.gpu mapping authority. Never
       read/write the device: exercise PTE creation and borrowed-frame unmap. */
    if (native(MEMORY_MAP, address, 4096, 3, 1, 0, 0) != address) return 2;
    if ((int64_t)native(MAP_PHYSICAL, address, 0xfec00000, 4096, 0, 0, 0) != -22) return 3;
    if (native(MEMORY_UNMAP, address, 4096, 0, 0, 0, 0) != 0) return 4;
    for (unsigned iteration = 0; iteration < 200; ++iteration) {
        if (native(MAP_PHYSICAL, address, 0xfec00000, 4096, 0, 0, 0) != 0) return 5;
        if ((int64_t)native(MAP_PHYSICAL, address, 0xfec00000, 4096, 0, 0, 0) != -22) return 6;
        if (native(MEMORY_UNMAP, address, 4096, 0, 0, 0, 0) != 0) return 7;
    }
    const char text[] = "mmio-mapping: PASS 200 map/unmap cycles and occupied-range rejection\n";
    native(DEBUG_WRITE, (uintptr_t)text, strlen(text), 0, 0, 0, 0);
    return 0;
}
