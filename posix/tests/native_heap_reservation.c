#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { printf("heap-reservation: FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
static int64_t hr_native(uint64_t number, uint64_t a, uint64_t b) {
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b) : "rcx", "r11", "memory");
    return (int64_t)number;
}
static uint64_t hr_usage(void) {
    uint64_t low = 0, high = UINT64_C(1) << 36;
    while (low < high) {
        uint64_t middle = low + (high - low) / 2;
        uint64_t request[8] = {0, 4096, 0, 0, 0, 0, middle * 4096, 0};
        int64_t address = hr_native(695, (uintptr_t)request, sizeof(request));
        if (address > 0) {
            if (hr_native(583, (uint64_t)address, 4096) != 0) return UINT64_MAX;
            high = middle;
        } else if (address == -ENOMEM) low = middle + 1;
        else return UINT64_MAX;
    }
    return low * 4096 - 4096;
}

int main(void) {
    struct rlimit original, limit;
    CHECK(getrlimit(RLIMIT_AS, &original) == 0);
    uint64_t before_usage = hr_usage(); CHECK(before_usage != UINT64_MAX);
    limit = original; limit.rlim_cur = 32 * 1024 * 1024;
    CHECK(setrlimit(RLIMIT_AS, &limit) == 0);
    void *other = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(other != MAP_FAILED && munmap(other, 4096) == 0);
    uint64_t after_usage = hr_usage();
    CHECK(after_usage <= limit.rlim_cur);
    if (before_usage > limit.rlim_cur) CHECK(after_usage < before_usage);
    unsigned char *blocks[8];
    for (unsigned i = 0; i < 8; ++i) {
        blocks[i] = malloc(65536); CHECK(blocks[i] != NULL);
        for (unsigned page = 0; page < 65536; page += 4096) blocks[i][page] = (unsigned char)(i + 11);
    }
    CHECK(hr_usage() <= limit.rlim_cur);

    /* Exercise page return and exact reacquisition without disturbing the
     * allocator's own top chunk: always restore this temporary break span. */
    unsigned char *before = sbrk(0);
    CHECK(before != (void *)-1 && sbrk(8193) == before);
    before[0] = 51; before[8192] = 61;
    struct rlimit zero = limit; zero.rlim_cur = 0;
    CHECK(setrlimit(RLIMIT_AS, &zero) == 0);
    CHECK(sbrk(0) == before + 8193 && before[0] == 51 && before[8192] == 61);
    CHECK(sbrk(-8193) == before + 8193 && sbrk(0) == before);
    errno = 0;
    CHECK(sbrk(4096) == (void *)-1 && errno == ENOMEM && sbrk(0) == before);
    CHECK(setrlimit(RLIMIT_AS, &limit) == 0);
    CHECK(sbrk(8193) == before);
    before[8192] = 71; CHECK(before[8192] == 71);
    CHECK(sbrk(-8193) == before + 8193);

    uintptr_t next_page = ((uintptr_t)before + 4095) & ~(uintptr_t)4095;
    void *occupied = mmap((void *)next_page, 4096, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CHECK(occupied == (void *)next_page);
    volatile unsigned char *sentinel = occupied;
    sentinel[0] = 0xa5; sentinel[4095] = 0x3c;
    intptr_t increment = (intptr_t)(next_page - (uintptr_t)before + 1);
    errno = 0;
    CHECK(sbrk(increment) == (void *)-1 && errno == ENOMEM && sbrk(0) == before);
    CHECK(sentinel[0] == 0xa5 && sentinel[4095] == 0x3c);
    CHECK(munmap(occupied, 4096) == 0);
    CHECK(sbrk(increment) == before);
    *(volatile unsigned char *)next_page = 0x5a;
    CHECK(*(volatile unsigned char *)next_page == 0x5a);
    CHECK(sbrk(-increment) == before + increment);
    CHECK(hr_usage() <= limit.rlim_cur);
    for (unsigned i = 0; i < 8; ++i) {
        for (unsigned page = 0; page < 65536; page += 4096) CHECK(blocks[i][page] == (unsigned char)(i + 11));
    }
    CHECK(setrlimit(RLIMIT_AS, &original) == 0);
    for (unsigned i = 0; i < 8; ++i) free(blocks[i]);
    puts("heap-reservation: PASS finite-AS tail reclamation, small malloc, page return/reacquisition and non-overwriting contiguous growth");
    return 0;
}
