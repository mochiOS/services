/* Link all newlib stdlib wrappers that include _mallocr.c, rebuilt with
 * -D_LIBC -D__mochios__ -DGETREENT_PROVIDED, ahead of the existing SDK libc.a.
 * MALLOC_AGGREGATE checks aggregate heap escape; the default 384MiB case
 * separately exposes the current native MemoryMap per-mapping limit. */
#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static int check(void) {
#ifdef MALLOC_AGGREGATE
    const size_t length = 128u * 1024u * 1024u;
    void *held[4] = {0};
#else
    const size_t length = 384u * 1024u * 1024u;
#endif
    for (unsigned iteration = 0; iteration < 4; ++iteration) {
        volatile unsigned char *large = malloc(length);
        if (!large) {
            const int allocation_errno = errno;
            errno = 0;
            void *direct = mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            fprintf(stderr, "malloc-mapping: malloc errno=%d direct=%p errno=%d\n", allocation_errno, direct, errno);
            if (direct != MAP_FAILED) munmap(direct, length);
            return 1;
        }
        large[0] = 7;
        large[length / 2] = 8;
        large[length - 1] = 9;
        if (large[0] != 7 || large[length / 2] != 8 || large[length - 1] != 9) return 2;
        struct mallinfo info = mallinfo();
        if (info.hblks < 1 || info.hblkhd < length) return 3;
#ifdef MALLOC_AGGREGATE
        held[iteration] = (void *)large;
#else
        free((void *)large);
        info = mallinfo();
        if (info.hblks != 0 || info.hblkhd != 0) return 4;
#endif
    }
#ifdef MALLOC_AGGREGATE
    struct mallinfo info = mallinfo();
    if (info.hblks != 4 || info.hblkhd < length * 4) return 4;
    for (unsigned i = 0; i < 4; ++i) free(held[i]);
    info = mallinfo();
    if (info.hblks != 0 || info.hblkhd != 0) return 4;
#endif
    const size_t small_length = 1024u * 1024u;
    unsigned char *data = calloc(small_length, 1);
    if (!data) return 5;
    for (size_t i = 0; i < small_length; ++i) if (data[i]) return 6;
    memset(data, 0x5a, small_length);
    data = realloc(data, small_length * 2);
    if (!data) return 7;
    for (size_t i = 0; i < small_length; ++i) if (data[i] != 0x5a) return 8;
    free(data);
    void *aligned = memalign(16384, small_length);
    if (!aligned || (uintptr_t)aligned % 16384) return 9;
    free(aligned);
    volatile size_t oversized = SIZE_MAX;
    errno = 0;
    if (malloc(oversized) || errno != ENOMEM) return 10;
    void *small = malloc(48);
    if (!small) return 11;
    free(small);
    return 0;
}

int main(void) {
    int result = check();
#ifdef MALLOC_AGGREGATE
    fprintf(stderr, "malloc-aggregate: %s 4x128MiB simultaneous allocations, release, calloc/realloc/alignment result=%d\n",
            result ? "FAIL" : "PASS", result);
#else
    fprintf(stderr, "malloc-mapping: %s 4x384MiB sparse allocations, release, calloc/realloc/alignment result=%d\n",
            result ? "FAIL" : "PASS", result);
#endif
    return result;
}
