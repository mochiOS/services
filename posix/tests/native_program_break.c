#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { printf("program-break: FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
extern const unsigned char __mochios_data_start[], __mochios_data_end[];
/* Force a real initialized-data and bss contribution to the linked image. */
static volatile unsigned char pb_data[4096] = {17};
static volatile unsigned char pb_bss[8192];

int main(void) {
    struct rlimit original, limit;
    CHECK(getrlimit(RLIMIT_DATA, &original) == 0);
    CHECK((uintptr_t)__mochios_data_end - (uintptr_t)__mochios_data_start
          >= sizeof(pb_data) + sizeof(pb_bss));
    CHECK(pb_data[0] == 17 && pb_bss[0] == 0);
    unsigned char *before = sbrk(0);
    CHECK(before != (void *)-1);
    CHECK(sbrk(4097) == before);
    before[0] = 23; before[4096] = 42;
    limit = original;
    limit.rlim_cur = 0;
    CHECK(setrlimit(RLIMIT_DATA, &limit) == 0);
    errno = 0;
    CHECK(sbrk(1) == (void *)-1 && errno == ENOMEM);
    CHECK(sbrk(0) == before + 4097);
    CHECK(before[0] == 23 && before[4096] == 42);
    CHECK(sbrk(-4097) == before + 4097);
    CHECK(sbrk(0) == before);
    errno = 0;
    CHECK(sbrk(1) == (void *)-1 && errno == ENOMEM);
    CHECK(setrlimit(RLIMIT_DATA, &original) == 0);
    CHECK(sbrk(1) == before && sbrk(-1) == before + 1);
    puts("program-break: PASS image data accounting, growth rejection, query and shrink under lowered limit");
    return 0;
}
