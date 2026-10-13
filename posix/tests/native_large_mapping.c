/* Link with the rebuilt newlib stdlib wrapper objects ahead of SDK libc.a.
 * Reuse the real allocator regression, then exercise sparse native VM spans. */
#define main malloc_mapping_probe_main
#include "native_malloc_mapping.c"
#undef main
#include <sys/wait.h>
#include <unistd.h>

static int check_large_vm(void) {
    const size_t span = (size_t)1 << 40;
    volatile unsigned char *private = mmap(NULL, span, PROT_NONE,
        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (private == MAP_FAILED) return 1;
    volatile unsigned char *shared = mmap(NULL, span, PROT_NONE,
        MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) return 2;
    if (mprotect((void *)private, span, PROT_READ|PROT_WRITE)) return 3;
    private[0] = 31;
    private[span-1] = 32;
    pid_t child = fork();
    if (child < 0) return 4;
    if (!child) {
        if (mprotect((void *)shared, span, PROT_READ|PROT_WRITE)) _exit(1);
        if (shared[0] || shared[span/2] || shared[span-1]) _exit(2);
        shared[0] = 41;
        shared[span/2] = 42;
        shared[span-1] = 43;
        if (private[0] != 31 || private[span/2]) _exit(3);
        private[0] = 61;
        private[span/2] = 62;
        _exit(0);
    }
    int status = -1;
    if (waitpid(child, &status, 0) != child || status) return 5;
    if (private[0] != 31 || private[span/2] || private[span-1] != 32) return 6;
    if (mprotect((void *)shared, span, PROT_READ|PROT_WRITE)) return 7;
    if (shared[0] != 41 || shared[span/2] != 42 || shared[span-1] != 43) return 8;
    if (mprotect((void *)shared, span, PROT_NONE)
        || mprotect((void *)shared, span, PROT_READ|PROT_WRITE)) return 9;
    if (shared[span/2] != 42) return 10;
    if (munmap((void *)(shared + span/2), 4096)) return 11;
    if (!mprotect((void *)shared, span, PROT_NONE)) return 12;
    shared[0] = 51;
    shared[span-1] = 53;
    if (munmap((void *)private, span) || munmap((void *)shared, span)) return 13;
    errno = 0;
    if (mmap(NULL, SIZE_MAX, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) != MAP_FAILED) return 14;
    errno = 0;
    if (mmap((void *)(((uintptr_t)1 << 47) - 4096), 8192, PROT_NONE,
             MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) != MAP_FAILED) return 15;
    return 0;
}

int main(void) {
    int allocator = malloc_mapping_probe_main();
    if (allocator) return allocator;
    int result = check_large_vm();
    fprintf(stderr, "large-mapping: %s 1TiB private + 1TiB shared, COW, protection, gaps, unmap result=%d\n",
            result ? "FAIL" : "PASS", result);
    return result;
}
