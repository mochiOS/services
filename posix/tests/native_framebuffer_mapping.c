#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum { FRAMEBUFFER_INFO = 528, MAP_FRAMEBUFFER = 529, MEMORY_UNMAP = 583, DEBUG_WRITE = 660 };
struct framebuffer { uint64_t address, size; uint32_t width, height, stride, format; };
_Static_assert(sizeof(struct framebuffer) == 32, "framebuffer ABI");

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

static int probe(void) {
    struct framebuffer info = {0};
    if (native(FRAMEBUFFER_INFO, (uintptr_t)&info, 0, 0, 0, 0, 0) != 0 || !info.size) return 1;
    uint64_t size = (info.size + (info.address & 4095) + 4095) & ~UINT64_C(4095);
    const uint64_t address = UINT64_C(0x220000000000);
    for (unsigned iteration = 0; iteration < 32; ++iteration) {
        /* DisplayRead authorizes this platform-owned surface, not arbitrary
           RAM. Do not touch pixels; test borrowed PTE ownership and teardown. */
        if (native(MAP_FRAMEBUFFER, address, size, 0, 0, 0, 0) != 0) return 2;
        if ((int64_t)native(MAP_FRAMEBUFFER, address, size, 0, 0, 0, 0) != -262136) return 3;
        if (native(MEMORY_UNMAP, address, size, 0, 0, 0, 0) != 0) return 4;
    }
    return 0;
}

int main(void) {
    int result = probe();
    char text[96];
    snprintf(text, sizeof(text), "framebuffer-mapping: %s 32 map/unmap cycles result=%d\n", result ? "FAIL" : "PASS", result);
    native(DEBUG_WRITE, (uintptr_t)text, strlen(text), 0, 0, 0, 0);
    return result;
}
