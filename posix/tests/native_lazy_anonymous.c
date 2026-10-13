#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static int check(void) {
    const size_t span = 128u * 1024u * 1024u;
    volatile unsigned char *regions[20] = {0};
    /* More virtual RAM than the 2GiB fixture contains physically. Only three
       pages per private region are touched; a full eager allocation fails. */
    for (unsigned i = 0; i < 20; ++i) {
        regions[i] = mmap(NULL, span, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (regions[i] == MAP_FAILED) return 1;
        for (size_t offset = 0; offset < span; offset += span/2) {
            if (regions[i][offset]) return 2;
            regions[i][offset] = (unsigned char)(i+1);
        }
        if (regions[i][span-1]) return 3;
        regions[i][span-1] = (unsigned char)(i+1);
    }
    pid_t child = fork();
    if (child < 0) return 4;
    if (!child) {
        if (regions[0][0] != 1 || regions[0][4096] != 0) _exit(1);
        regions[0][0] = 99;
        regions[0][4096] = 88;
        _exit(0);
    }
    int status = -1;
    if (waitpid(child, &status, 0) != child || status != 0) return 5;
    if (regions[0][0] != 1 || regions[0][4096] != 0) return 6;
    if (mprotect((void *)regions[0], span, PROT_READ)) return 7;
    if (regions[0][span/2] != 1 || regions[0][8192] != 0) return 8;
    if (mprotect((void *)regions[0], span, PROT_READ|PROT_WRITE)) return 9;
    regions[0][8192] = 77;
    for (unsigned i = 0; i < 20; ++i) {
        if (regions[i][span-1] != i+1) return 10;
        /* Non-present leaves still own frames and must be discovered, while
           untouched virtual pages must not consume revocation-plan storage. */
        if (mprotect((void *)regions[i], span, i & 1 ? PROT_READ : PROT_NONE)) return 15;
        if (munmap((void *)regions[i], span)) return 10;
    }
    volatile unsigned char *shared = mmap(NULL, 8192, PROT_READ|PROT_WRITE,
                                         MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) return 11;
    child = fork();
    if (child < 0) return 12;
    if (!child) { shared[4096] = 42; _exit(0); }
    if (waitpid(child, &status, 0) != child || status || shared[4096] != 42) return 13;
    if (munmap((void *)shared, 8192)) return 14;
    unsigned char *gap = mmap(NULL, 12288, PROT_READ|PROT_WRITE,
                              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (gap == MAP_FAILED) return 16;
    gap[0] = 31;
    gap[8192] = 42;
    if (munmap(gap + 4096, 4096)) return 17;
    /* The range preflight must reject holes before changing either side. */
    if (!mprotect(gap, 12288, PROT_NONE)) return 18;
    gap[0] = 32;
    gap[8192] = 43;
    if (munmap(gap, 4096) || munmap(gap + 8192, 4096)) return 19;
    return 0;
}

int main(void) {
    int result = check();
    fprintf(stderr, "lazy-anonymous: %s 20x128MiB sparse regions, COW, protect, unmap, shared fork result=%d\n",
            result ? "FAIL" : "PASS", result);
    return result;
}
