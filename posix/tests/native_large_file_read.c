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
