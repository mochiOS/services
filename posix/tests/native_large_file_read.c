/* Diagnostic KVM fixture: separates POSIX read time from application parsing. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char path[] = "/system/libraries/ime/ja.mime";
static unsigned char chunk[256 * 1024];

enum {
    HANDLE_CLOSE = 626,
    MEMORY_OBJECT_CREATE = 671,
    HANDLE_READ_AT = 673,
    HANDLE_WRITE_AT = 674
};

static int64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    register uint64_t r10 __asm__("r10") = d;
    __asm__ volatile("syscall"
                     : "+a"(number)
                     : "D"(a), "S"(b), "d"(c), "r"(r10)
                     : "rcx", "r11", "memory");
    return (int64_t)number;
}

static uint64_t now_ms(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return 0;
    return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}

int main(void) {
    uint64_t started = now_ms();
    fprintf(stderr, "large-read: opening %s\n", path);
    int file = open(path, O_RDONLY);
    if (file < 0) {
        fprintf(stderr, "large-read: open failed errno=%d\n", errno);
        return 1;
    }
    struct stat status;
    if (fstat(file, &status) != 0 || status.st_size < 4) {
        fprintf(stderr, "large-read: fstat failed errno=%d\n", errno);
        return 1;
    }
    fprintf(stderr, "large-read: opened size=%lld elapsed=%llu ms\n", (long long)status.st_size,
            (unsigned long long)(now_ms() - started));
    uint64_t total = 0, next_progress = 8 * 1024 * 1024;
    for (;;) {
        ssize_t count = read(file, chunk, sizeof(chunk));
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0) {
            fprintf(stderr, "large-read: read failed offset=%llu errno=%d\n",
                    (unsigned long long)total, errno);
            return 1;
        }
        if (count == 0)
            break;
        if (total == 0 && (count < 4 || memcmp(chunk, "MIME", 4) != 0)) {
            fprintf(stderr, "large-read: invalid initial bytes\n");
            return 1;
        }
        total += (uint64_t)count;
        if (total >= next_progress) {
            fprintf(stderr, "large-read: offset=%llu elapsed=%llu ms\n", (unsigned long long)total,
                    (unsigned long long)(now_ms() - started));
            next_progress += 8 * 1024 * 1024;
        }
    }
    if (total != (uint64_t)status.st_size || close(file) != 0)
        return 1;
    fprintf(stderr, "large-read: chunked complete bytes=%llu elapsed=%llu ms\n",
            (unsigned long long)total, (unsigned long long)(now_ms() - started));

    /* Same copy volume through a resident memory object, with no filesystem,
       provider IPC, mapping churn or disk access in the measured loop. */
    memset(chunk, 0x5a, sizeof(chunk));
    int64_t object = native(MEMORY_OBJECT_CREATE, sizeof(chunk), 0, 0, 0);
    if (object < 0 || native(HANDLE_WRITE_AT, (uint64_t)object, (uint64_t)chunk, sizeof(chunk),
                             0) != sizeof(chunk))
        return 1;
    started = now_ms();
    total = 0;
    while (total < (uint64_t)status.st_size) {
        size_t requested = (size_t)((uint64_t)status.st_size - total);
        if (requested > sizeof(chunk))
            requested = sizeof(chunk);
        int64_t count = native(HANDLE_READ_AT, (uint64_t)object, (uint64_t)chunk, requested, 0);
        if (count != (int64_t)requested || chunk[0] != 0x5a || chunk[requested - 1] != 0x5a)
            return 1;
        total += (uint64_t)count;
    }
    fprintf(stderr, "large-read: resident memory copy complete bytes=%llu elapsed=%llu ms\n",
            (unsigned long long)total, (unsigned long long)(now_ms() - started));
    if (native(HANDLE_CLOSE, (uint64_t)object, 0, 0, 0) != 0)
        return 1;

    /* Like Rust fs::read, request the known file length in one large read. */
    started = now_ms();
    unsigned char *bytes = malloc((size_t)status.st_size);
    if (!bytes) {
        fprintf(stderr, "large-read: allocation failed errno=%d\n", errno);
        return 1;
    }
    file = open(path, O_RDONLY);
    if (file < 0)
        return 1;
    fprintf(stderr, "large-read: single large read start\n");
    total = 0;
    while (total < (uint64_t)status.st_size) {
        ssize_t count = read(file, bytes + total, (size_t)status.st_size - (size_t)total);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            fprintf(stderr, "large-read: large read failed offset=%llu count=%lld errno=%d\n",
                    (unsigned long long)total, (long long)count, errno);
            return 1;
        }
        // POSIX permits short reads even for a regular file; complete them.
        total += (uint64_t)count;
    }
    if (memcmp(bytes, "MIME", 4) != 0)
        return 1;
    fprintf(stderr, "large-read: large read complete bytes=%llu elapsed=%llu ms\n",
            (unsigned long long)total, (unsigned long long)(now_ms() - started));
    free(bytes);
    return close(file) != 0;
}
