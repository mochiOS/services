#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <reent.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

enum { EXECUTION_IDENTITY_READ = 677 };
/* Native mechanism failures are tagged statuses, not POSIX/newlib errno. */
#define NATIVE_FAILURE(code) ((int64_t)(UINT64_C(0xfffffffffffc0000) | (code)))
struct execution_identity { uint64_t process, thread; };
static int64_t identity_read(struct execution_identity *identity, size_t length) {
    uint64_t number = EXECUTION_IDENTITY_READ;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(identity), "S"(length), "d"(0)
                     : "rcx", "r11", "memory");
    return (int64_t)number;
}

/* Run as an isolated early-boot Input replacement, with Input's unchanged
 * manifest and inherited POSIX endpoint. No storage or spawn authority needed.
 * This separates dictionary I/O from the IME parser; it is not a desktop test. */
static long long elapsed_ms(struct timespec start, struct timespec end) {
    return (long long)(end.tv_sec - start.tv_sec) * 1000
        + (end.tv_nsec - start.tv_nsec) / 1000000;
}

extern void __malloc_lock(struct _reent *);
extern void __malloc_unlock(struct _reent *);

static int fresh_anonymous_pages(void) {
    const size_t length = 4u * 1024u * 1024u;
    for (unsigned round = 0; round < 3; ++round) {
        volatile unsigned char *bytes = mmap(NULL, length, PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if ((void *)bytes == MAP_FAILED) return 24;
        for (size_t page = 0; page < length; page += 4096) {
            size_t first = 0;
            if (round == 1) {
                bytes[page] = 0xa5; // First access writes; all other bytes stay zero.
                first = 1;
            }
            for (size_t byte = first; byte < 4096; ++byte) {
                if (bytes[page + byte] != 0) return 25;
                bytes[page + byte] = 0xa5;
            }
        }
        if (munmap((void *)bytes, length)) return 26;
    }
    fprintf(stderr, "allocator-path: PASS anonymous zero pages, read-first/write-first and reuse\n");
    return 0;
}

static int allocator_path(void) {
    enum { COUNT = 100000 };
    struct timespec start, end;
    struct _reent *reent = __getreent();
    if (!reent || clock_gettime(CLOCK_MONOTONIC, &start)) return 20;
    for (unsigned i = 0; i < COUNT; ++i) {
        if (__getreent() != reent) return 21;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &end)) return 20;
    fprintf(stderr, "allocator-path: reent count=%u elapsed_ms=%lld\n",
            COUNT, elapsed_ms(start, end));
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return 20;
    for (unsigned i = 0; i < COUNT; ++i) {
        __malloc_lock(reent);
        __malloc_unlock(reent);
    }
    if (clock_gettime(CLOCK_MONOTONIC, &end)) return 20;
    fprintf(stderr, "allocator-path: lock-pair count=%u elapsed_ms=%lld\n",
            COUNT, elapsed_ms(start, end));
    void **held = malloc(COUNT * sizeof(*held));
    if (!held) return 22;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return 20;
    unsigned allocated = 0;
    for (; allocated < COUNT; ++allocated) {
        held[allocated] = malloc(32 + (allocated & 15));
        if (!held[allocated]) break;
        *(volatile unsigned char *)held[allocated] = 0x5a;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &end)) return 20;
    fprintf(stderr, "allocator-path: allocate-retained count=%u elapsed_ms=%lld\n",
            allocated, elapsed_ms(start, end));
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return 20;
    for (unsigned i = 0; i < allocated; ++i) {
        if (*(volatile unsigned char *)held[i] != 0x5a) return 23;
        free(held[i]);
    }
    if (clock_gettime(CLOCK_MONOTONIC, &end)) return 20;
    fprintf(stderr, "allocator-path: free-retained count=%u elapsed_ms=%lld\n",
            allocated, elapsed_ms(start, end));
    free(held);
    return allocated == COUNT ? 0 : 22;
}

int main(void) {
    fprintf(stderr, "dictionary-read: start\n");
    struct execution_identity first, second;
    if (identity_read(&first, sizeof(first)) || !first.process || !first.thread) return 17;
    if (identity_read(&second, sizeof(second)) || first.process != second.process
        || first.thread != second.thread) return 18;
    if (identity_read(&second, sizeof(second) - 1) != NATIVE_FAILURE(5)
        || identity_read(NULL, sizeof(second)) != NATIVE_FAILURE(2)) return 19;
    fprintf(stderr, "dictionary-read: native execution identity ok\n");
    int allocation_result = allocator_path();
    if (allocation_result) return allocation_result;
    allocation_result = fresh_anonymous_pages();
    if (allocation_result) return allocation_result;
    /* ext4plus's indirect-block reads allocate a zeroed filesystem block.
     * Measure that runtime cost independently of IPC and storage access. */
    struct timespec allocation_start, allocation_end;
    if (clock_gettime(CLOCK_MONOTONIC, &allocation_start)) return 13;
    for (unsigned i = 0; i < 40000; ++i) {
        unsigned char *block = calloc(4096, 1);
        if (!block) return 14;
        if (*(volatile unsigned char *)block != 0) return 15;
        *(volatile unsigned char *)block = 1;
        free(block);
    }
    if (clock_gettime(CLOCK_MONOTONIC, &allocation_end)) return 16;
    fprintf(stderr, "dictionary-read: 40000 zeroed block allocations in %lld ms\n",
            elapsed_ms(allocation_start, allocation_end));
    int fd = open("/system/libraries/ime/ja.mime", O_RDONLY);
    struct stat info;
    if (fd < 0 || fstat(fd, &info) || info.st_size <= 0) {
        perror("dictionary-read: open/stat");
        return 1;
    }
    size_t size = (size_t)info.st_size;
    if ((off_t)size != info.st_size) return 2;
    fprintf(stderr, "dictionary-read: size %llu\n", (unsigned long long)size);
    unsigned char *bytes = malloc(size);
    if (!bytes) return 3;
    struct timespec start, end;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return 4;
    size_t total = 0;
    uint64_t streamed_hash = 0;
    while (total < size) {
        size_t count = size - total;
        if (count > 65536) count = 65536;
        ssize_t read_count = read(fd, bytes + total, count);
        if (read_count < 0 && errno == EINTR) continue;
        if (read_count <= 0 || (size_t)read_count > count) return 5;
        for (ssize_t i = 0; i < read_count; ++i)
            streamed_hash = streamed_hash * 31 + bytes[total + (size_t)i];
        total += (size_t)read_count;
        if (total % (16 * 1024 * 1024) == 0 || total == size) {
            if (clock_gettime(CLOCK_MONOTONIC, &end)) return 6;
            fprintf(stderr, "dictionary-read: %llu bytes in %lld ms\n",
                    (unsigned long long)total, elapsed_ms(start, end));
        }
    }
    unsigned char tail;
    if (read(fd, &tail, 1) != 0 || lseek(fd, 0, SEEK_SET) != 0) return 7;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return 8;
    total = 0;
    while (total < size) {
        ssize_t read_count = read(fd, bytes + total, size - total);
        if (read_count < 0 && errno == EINTR) continue;
        if (read_count <= 0 || (size_t)read_count > size - total) return 9;
        total += (size_t)read_count;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &end)) return 10;
    fprintf(stderr, "dictionary-read: whole-file requests in %lld ms\n",
            elapsed_ms(start, end));
    uint64_t whole_hash = 0;
    for (size_t i = 0; i < size; ++i) whole_hash = whole_hash * 31 + bytes[i];
    if (whole_hash != streamed_hash || read(fd, &tail, 1) != 0) return 11;
    free(bytes);
    if (close(fd)) return 12;
    fprintf(stderr, "dictionary-read: ok\n");
    return 0;
}
