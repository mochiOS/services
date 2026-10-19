/* Isolated Input-role probe, initially POSIX uid zero. This exits after the
 * real C ABI checks without publishing Input readiness or a desktop result. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(time_t) == 8 && sizeof(struct timespec) == 16, "time ABI");
_Static_assert(UTIME_NOW == -2L && UTIME_OMIT == -1L, "newlib sentinels");
_Static_assert(AT_FDCWD == -2 && AT_SYMLINK_NOFOLLOW == 2, "newlib at flags");
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "c-file-times: FAIL line=%d errno=%d: %s\n", __LINE__, errno, #condition); \
    return 1; } } while (0)
#define FAILS(call, error) do { errno = 0; CHECK((call) == -1 && errno == (error)); } while (0)

static int same_times(const struct stat *a, const struct stat *b) {
    return a->st_atim.tv_sec == b->st_atim.tv_sec && a->st_atim.tv_nsec == b->st_atim.tv_nsec &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static int same_data_times(const struct stat *a, const struct stat *b) {
    return a->st_atim.tv_sec == b->st_atim.tv_sec && a->st_atim.tv_nsec == b->st_atim.tv_nsec &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
}
int main(void) {
    puts("c-file-times: starting real C ABI checks");
    const char *path = "/tmp/native-c-file-times";
    const struct timespec explicit[2] = {{-1, 123456789}, {INT64_C(2147483648), 987654321}};
    const struct timespec omit[2] = {{INT64_MIN, UTIME_OMIT}, {INT64_MAX, UTIME_OMIT}};
    const struct timespec current[2] = {{INT64_MIN, UTIME_NOW}, {INT64_MAX, UTIME_NOW}};
    struct stat before, after;
    int file = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(file >= 0);
    int directory = open("/tmp", O_RDONLY | O_DIRECTORY);
    CHECK(directory >= 0);
    CHECK(futimens(file, explicit) == 0 && fstat(file, &before) == 0);
    CHECK(before.st_atim.tv_sec == -1 && before.st_atim.tv_nsec == 123456789);
    CHECK(before.st_mtim.tv_sec == INT64_C(2147483648) && before.st_mtim.tv_nsec == 987654321);
    CHECK(futimens(file, omit) == 0 && fstat(file, &after) == 0 && same_times(&before, &after));
    CHECK(utimensat(-777, path, explicit, 0) == 0); /* absolute path ignores dirfd */
    const struct timespec pause = {0, 20000000};
    CHECK(fstat(file, &before) == 0 && nanosleep(&pause, NULL) == 0);
    CHECK(fchmod(file, 0640) == 0 && fstat(file, &after) == 0);
    CHECK(same_data_times(&before, &after) && !same_times(&before, &after));
    before = after;
    CHECK(nanosleep(&pause, NULL) == 0 && fchown(file, 0, 0) == 0 && fstat(file, &after) == 0);
    CHECK(same_data_times(&before, &after) && !same_times(&before, &after));
    CHECK(utimensat(directory, "native-c-file-times", current, 0) == 0);
    CHECK(fstat(file, &after) == 0);
    CHECK(after.st_atim.tv_sec == after.st_mtim.tv_sec && after.st_atim.tv_nsec == after.st_mtim.tv_nsec);
    CHECK(after.st_atim.tv_sec == after.st_ctim.tv_sec && after.st_atim.tv_nsec == after.st_ctim.tv_nsec);
    CHECK(chdir("/tmp") == 0);
    CHECK(utimensat(AT_FDCWD, "native-c-file-times", explicit, 0) == 0);
    int readonly = open(path, O_RDONLY);
    CHECK(readonly >= 0 && futimens(readonly, explicit) == 0);
    CHECK(futimens(directory, NULL) == 0);
    CHECK(fstat(file, &before) == 0);
    struct timespec invalid[2] = {{0, 0}, {0, 1000000000}};
    FAILS(futimens(file, invalid), EINVAL);
    invalid[1].tv_nsec = -3;
    FAILS(utimensat(AT_FDCWD, path, invalid, 0), EINVAL);
    FAILS(utimensat(AT_FDCWD, path, NULL, 0x40000000), EINVAL);
    FAILS(utimensat(-777, "native-c-file-times", NULL, 0), EBADF);
    FAILS(futimens(-1, NULL), EBADF);
    volatile uintptr_t bad_address = 1;
    const struct timespec *bad = (const struct timespec *)bad_address;
    FAILS(futimens(file, bad), EFAULT);
    FAILS(utimensat(AT_FDCWD, path, bad, 0), EFAULT);
    FAILS(utimensat(AT_FDCWD, NULL, NULL, 0), EFAULT);
    unsigned char *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(pages != MAP_FAILED);
    struct timespec *crossing = (struct timespec *)(pages + 4096 - sizeof(struct timespec));
    crossing[0] = explicit[0];
    CHECK(mprotect(pages + 4096, 4096, PROT_NONE) == 0);
    FAILS(futimens(file, crossing), EFAULT);
    CHECK(munmap(pages, 8192) == 0);
    CHECK(fstat(file, &after) == 0 && same_times(&before, &after));
    invalid[0] = (struct timespec){INT64_MIN, 0};
    invalid[1] = explicit[1];
    FAILS(futimens(file, invalid), EOVERFLOW);
    CHECK(fstat(file, &after) == 0 && same_times(&before, &after));
    CHECK(fchown(file, 1001, 77) == 0 && seteuid(1001) == 0);
    CHECK(futimens(readonly, explicit) == 0);
    CHECK(seteuid(0) == 0 && seteuid(2002) == 0);
    FAILS(futimens(file, explicit), EPERM);
    FAILS(futimens(file, NULL), EACCES);
    CHECK(fstat(file, &before) == 0);
    CHECK(futimens(file, omit) == 0 && fstat(file, &after) == 0 && same_times(&before, &after));
    CHECK(seteuid(0) == 0);
    FAILS(utimensat(AT_FDCWD, "/system/services/posix.service", NULL, 0), EROFS);
    CHECK(symlink("native-c-file-times", "/tmp/native-c-file-times-link") == 0);
    CHECK(fstat(file, &before) == 0);
    CHECK(utimensat(AT_FDCWD, "/tmp/native-c-file-times-link", explicit, AT_SYMLINK_NOFOLLOW) == 0);
    CHECK(lstat("/tmp/native-c-file-times-link", &after) == 0 && S_ISLNK(after.st_mode));
    CHECK(after.st_mtim.tv_sec == INT64_C(2147483648) && after.st_mtim.tv_nsec == 987654321);
    CHECK(fstat(file, &after) == 0 && same_times(&before, &after));
    CHECK(unlink("/tmp/native-c-file-times-link") == 0 && unlink(path) == 0);
    CHECK(futimens(file, explicit) == 0 && fstat(file, &after) == 0);
    CHECK(after.st_atim.tv_sec == -1 && after.st_mtim.tv_sec == INT64_C(2147483648));
    CHECK(close(file) == 0);
    FAILS(futimens(file, NULL), EBADF);
    CHECK(close(readonly) == 0 && close(directory) == 0);
    int streams[2];
    CHECK(pipe(streams) == 0);
    FAILS(futimens(streams[0], NULL), ENOTSUP); /* metadata provider still needed */
    CHECK(close(streams[0]) == 0 && close(streams[1]) == 0);
    puts("c-file-times: PASS C ABI, sentinels, signed dates, pointer faults, errno, path anchors, permissions, nofollow, unlinked FD and chmod/chown ctime");
    return 0;
}
