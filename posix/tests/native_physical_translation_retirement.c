#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

/* Historical numbers live only in this rejection test, not the public ABI. */
static int64_t obsolete_translation(uint64_t address) {
    uint64_t number = 547;
    __asm__ volatile("syscall" : "+a"(number) : "D"(address) : "rcx", "r11", "memory");
    return (int64_t)number;
}

int main(void) {
    unsigned char *page = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return 1;
    page[0] = 0x71;
    if (obsolete_translation(0) != -38
        || obsolete_translation(UINT64_MAX) != -38
        || obsolete_translation((uint64_t)page) != -38) {
        fprintf(stderr, "physical-retirement: FAIL obsolete translation not rejected\n");
        return 2;
    }
    if (page[0] != 0x71 || munmap(page, 4096)) return 3;
    fprintf(stderr, "physical-retirement: PASS removed ABI rejects null, invalid and resident addresses\n");
    return 0;
}
