#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "shared-positioned-318: FAIL line %d errno %d\n", __LINE__, errno); return 1; \
} } while (0)

enum { CHUNK = 256 * 1024, LENGTH = 2 * CHUNK + 311 };
static unsigned char expected[LENGTH], actual[LENGTH + 17];

int main(void) {
    alarm(120);
    char path[96];
    CHECK(snprintf(path, sizeof(path), "/tmp/.shared-positioned318-%ld", (long)getpid()) > 0);
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    CHECK(fd >= 0);
    for (size_t i = 0; i < sizeof(expected); ++i) expected[i] = (unsigned char)(i % 251);
    CHECK(pwrite(fd, expected, sizeof(expected), 0) == LENGTH);
    int duplicate = dup(fd);
    CHECK(duplicate >= 0 && lseek(fd, 113, SEEK_SET) == 113);
    memset(actual, 0xa5, sizeof(actual));
    struct timespec before, after;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
    CHECK(pread(duplicate, actual, sizeof(actual), 0) == LENGTH);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
    CHECK(!memcmp(actual, expected, sizeof(expected)));
    for (size_t i = sizeof(expected); i < sizeof(actual); ++i) CHECK(actual[i] == 0xa5);
    CHECK(lseek(fd, 0, SEEK_CUR) == 113);
    int64_t elapsed = (int64_t)(after.tv_sec - before.tv_sec) * 1000000000 +
                      after.tv_nsec - before.tv_nsec;
    CHECK(elapsed >= 0);
    fprintf(stderr, "shared-positioned-318: PASS chunking, short EOF and cursor; %d bytes in %lld ns\n",
            LENGTH, (long long)elapsed);

    unsigned char *mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 4096);
    CHECK(mapping != MAP_FAILED && mapping[21] == expected[4096 + 21]);
    mapping[21] = 'Q';
    expected[4096 + 21] = 'Q';
    CHECK(pread(fd, actual, sizeof(actual), 0) == LENGTH);
    CHECK(!memcmp(actual, expected, sizeof(expected)));
    CHECK(lseek(duplicate, 0, SEEK_CUR) == 113);
    CHECK(msync(mapping, 4096, MS_SYNC) == 0 && munmap(mapping, 4096) == 0);
    fprintf(stderr, "shared-positioned-318: PASS dirty mapped bytes overlay the shared read\n");

    CHECK(unlink(path) == 0);
    int replacement = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    CHECK(replacement >= 0 && write(replacement, "replacement", 11) == 11);
    errno = 0;
    CHECK(pread(replacement, actual, sizeof(actual), 0) == -1 && errno == EBADF);
    CHECK(pread(fd, actual, sizeof(actual), 0) == LENGTH);
    CHECK(!memcmp(actual, expected, sizeof(expected)));
    CHECK(lseek(fd, 0, SEEK_CUR) == 113);
    fprintf(stderr, "shared-positioned-318: PASS retained inode, replacement name and access rights\n");
    CHECK(close(replacement) == 0 && close(duplicate) == 0 && close(fd) == 0);
    CHECK(unlink(path) == 0);
    alarm(0);
    fprintf(stderr, "shared-positioned-318: PASS cleanup\n");
    return 0;
}
