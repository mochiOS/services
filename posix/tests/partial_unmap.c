#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return 1;
    const size_t page = (size_t)page_size;
    unsigned char *base = mmap(0, page * 3, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return 2;
    base[0] = 0x11;
    base[page * 2] = 0x33;
    if (mprotect(base + page * 2, page, PROT_READ) != 0) return 3;
    if (munmap(base + page, page) != 0) return 4;
    unsigned char *middle = mmap(base + page, page, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (middle != base + page || middle[0] != 0) return 5;
    middle[0] = 0x22;
    if (base[0] != 0x11 || base[page] != 0x22 || base[page * 2] != 0x33) return 6;
    if (munmap(base, page * 3) != 0) return 7;
    puts("partial unmap: ok");
    return 0;
}
