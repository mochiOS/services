/* Isolated Input-role probe, initially POSIX uid zero. This exits after the
 * real C ABI checks without publishing Input readiness or a desktop result. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
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
static int only_access_changed(const struct stat *a, const struct stat *b) {
    return (a->st_atim.tv_sec != b->st_atim.tv_sec || a->st_atim.tv_nsec != b->st_atim.tv_nsec) &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static int link_checks(int file, int directory) {
    const struct timespec old[2] = {{-1, 123456789}, {INT64_C(2147483648), 987654321}};
    const struct timespec pause = {0, 20000000};
    struct stat before, after, parent, alias;
    const char *names[] = {"/tmp/native-c-linked", "/tmp/native-c-linked-at"};
    for (unsigned kind = 0; kind < 2; ++kind) {
        CHECK(futimens(file, old) == 0 && futimens(directory, old) == 0 && fstat(file, &before) == 0);
        CHECK(nanosleep(&pause, NULL) == 0);
        if (kind == 0) {
            CHECK(link("/tmp/native-c-file-times", names[kind]) == 0);
        } else {
            CHECK(linkat(directory, "native-c-file-times", directory, "native-c-linked-at", 0) == 0);
        }
        CHECK(fstat(file, &after) == 0 && fstat(directory, &parent) == 0 && stat(names[kind], &alias) == 0);
        CHECK(same_data_times(&before, &after) && !same_times(&before, &after));
        CHECK(after.st_nlink == before.st_nlink + 1 && alias.st_ino == after.st_ino);
        CHECK(parent.st_atim.tv_sec == old[0].tv_sec && parent.st_atim.tv_nsec == old[0].tv_nsec);
        CHECK(parent.st_mtim.tv_sec == after.st_ctim.tv_sec && parent.st_mtim.tv_nsec == after.st_ctim.tv_nsec);
        CHECK(parent.st_ctim.tv_sec == after.st_ctim.tv_sec && parent.st_ctim.tv_nsec == after.st_ctim.tv_nsec);
        CHECK(unlink(names[kind]) == 0);
    }
    return 0;
}
static int read_checks(int file, int directory) {
    const struct timespec old[2] = {{-1, 123456789}, {INT64_C(2147483648), 987654321}};
    struct stat before, after;
    char byte;
    CHECK(lseek(file, 0, SEEK_SET) == 0 && futimens(file, old) == 0 && fstat(file, &before) == 0);
    CHECK(read(file, &byte, 1) == 1 && fstat(file, &after) == 0 && only_access_changed(&before, &after));
    CHECK(futimens(file, old) == 0 && fstat(file, &before) == 0);
    CHECK(pread(file, &byte, 1, 1) == 1 && lseek(file, 0, SEEK_CUR) == 1);
    CHECK(fstat(file, &after) == 0 && only_access_changed(&before, &after));
    CHECK(futimens(file, old) == 0 && fstat(file, &before) == 0);
    CHECK(read(file, NULL, 0) == 0 && fstat(file, &after) == 0 && same_times(&before, &after));
    CHECK(lseek(file, 0, SEEK_END) == 4097);
    CHECK(read(file, &byte, 1) == 0 && fstat(file, &after) == 0 && only_access_changed(&before, &after));
    CHECK(lseek(file, 0, SEEK_SET) == 0 && futimens(file, old) == 0 && fstat(file, &before) == 0);
    unsigned char large[8192];
    CHECK(read(file, large, sizeof(large)) == 4097 && fstat(file, &after) == 0);
    CHECK(only_access_changed(&before, &after));
    CHECK(futimens(directory, old) == 0 && fstat(directory, &before) == 0);
    DIR *entries = opendir("/tmp");
    CHECK(entries != NULL && readdir(entries) != NULL);
    CHECK(fstat(directory, &after) == 0 && only_access_changed(&before, &after));
    CHECK(closedir(entries) == 0);
    const char *link = "/tmp/native-c-created-link";
    CHECK(utimensat(AT_FDCWD, link, old, AT_SYMLINK_NOFOLLOW) == 0 && lstat(link, &before) == 0);
    char target[64];
    CHECK(readlink(link, target, sizeof(target)) > 0 && lstat(link, &after) == 0);
    CHECK(only_access_changed(&before, &after));
    int system = open("/system/services/posix.service", O_RDONLY);
    CHECK(system >= 0 && fstat(system, &before) == 0 && pread(system, &byte, 1, 0) == 1);
    CHECK(fstat(system, &after) == 0 && same_times(&before, &after) && close(system) == 0);
    return 0;
}
static int created_times(const struct stat *child, const struct stat *parent) {
    return child->st_atim.tv_sec == child->st_mtim.tv_sec && child->st_atim.tv_nsec == child->st_mtim.tv_nsec &&
           child->st_mtim.tv_sec == child->st_ctim.tv_sec && child->st_mtim.tv_nsec == child->st_ctim.tv_nsec &&
           child->st_mtim.tv_sec == parent->st_mtim.tv_sec && child->st_mtim.tv_nsec == parent->st_mtim.tv_nsec &&
           parent->st_mtim.tv_sec == parent->st_ctim.tv_sec && parent->st_mtim.tv_nsec == parent->st_ctim.tv_nsec &&
           parent->st_atim.tv_sec == -1 && parent->st_atim.tv_nsec == 123456789 && child->st_mtim.tv_sec != INT64_C(2147483648);
}
static int creation_checks(int directory) {
    const struct timespec old[2] = {{-1, 123456789}, {INT64_C(2147483648), 987654321}};
    const char *names[] = {"native-c-created-file", "native-c-created-dir", "native-c-created-link"};
    struct stat child, parent;
    for (unsigned kind = 0; kind < 3; ++kind) {
        CHECK(futimens(directory, old) == 0);
        if (kind == 0) {
            int created = openat(directory, names[kind], O_CREAT | O_EXCL | O_WRONLY, 0600);
            CHECK(created >= 0 && close(created) == 0);
        } else if (kind == 1) {
            CHECK(mkdirat(directory, names[kind], 0700) == 0);
        } else {
            CHECK(symlinkat("native-c-created-file", directory, names[kind]) == 0);
        }
        CHECK(fstatat(directory, names[kind], &child, AT_SYMLINK_NOFOLLOW) == 0 && fstat(directory, &parent) == 0);
        CHECK(created_times(&child, &parent));
    }
    CHECK(futimens(directory, old) == 0);
    int local = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(local >= 0);
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, "/tmp/native-c-created-socket");
    CHECK(bind(local, (const struct sockaddr *)&address, offsetof(struct sockaddr_un, sun_path) + strlen(address.sun_path) + 1) == 0);
    CHECK(lstat(address.sun_path, &child) == 0 && fstat(directory, &parent) == 0);
    CHECK(S_ISSOCK(child.st_mode) && created_times(&child, &parent));
    CHECK(close(local) == 0);
    return 0;
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
    CHECK(creation_checks(directory) == 0);
    CHECK(futimens(file, explicit) == 0 && fstat(file, &before) == 0);
    CHECK(before.st_atim.tv_sec == -1 && before.st_atim.tv_nsec == 123456789);
    CHECK(before.st_mtim.tv_sec == INT64_C(2147483648) && before.st_mtim.tv_nsec == 987654321);
    CHECK(futimens(file, omit) == 0 && fstat(file, &after) == 0 && same_times(&before, &after));
    CHECK(utimensat(-777, path, explicit, 0) == 0); /* absolute path ignores dirfd */
    const struct timespec pause = {0, 20000000};
    CHECK(fstat(file, &before) == 0 && nanosleep(&pause, NULL) == 0);
    CHECK(fchmod(file, 0640) == 0 && fstat(file, &after) == 0);
    CHECK(same_data_times(&before, &after) && !same_times(&before, &after));
    CHECK(utimensat(AT_FDCWD, path, explicit, 0) == 0);
    CHECK(write(file, "abc", 3) == 3 && fstat(file, &after) == 0);
    CHECK(after.st_atim.tv_sec == explicit[0].tv_sec && after.st_atim.tv_nsec == explicit[0].tv_nsec);
    CHECK(after.st_mtim.tv_sec != explicit[1].tv_sec && after.st_mtim.tv_sec == after.st_ctim.tv_sec);
    CHECK(after.st_mtim.tv_nsec == after.st_ctim.tv_nsec);
    before = after;
    CHECK(write(file, NULL, 0) == 0 && fstat(file, &after) == 0 && same_times(&before, &after));
    CHECK(utimensat(AT_FDCWD, path, explicit, 0) == 0 && pwrite(file, "z", 1, 0) == 1);
    CHECK(lseek(file, 0, SEEK_CUR) == 3 && fstat(file, &after) == 0);
    CHECK(after.st_mtim.tv_sec != explicit[1].tv_sec && after.st_mtim.tv_sec == after.st_ctim.tv_sec);
    CHECK(ftruncate(file, 4096) == 0 && utimensat(AT_FDCWD, path, explicit, 0) == 0);
    unsigned char *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
    CHECK(shared != MAP_FAILED);
    shared[7] = 42;
    CHECK(msync(shared, 4096, MS_SYNC) == 0 && fstat(file, &after) == 0);
    CHECK(after.st_mtim.tv_sec != explicit[1].tv_sec && after.st_mtim.tv_sec == after.st_ctim.tv_sec);
    CHECK(after.st_atim.tv_sec != explicit[0].tv_sec && munmap(shared, 4096) == 0);
    int append = open(path, O_WRONLY | O_APPEND);
    CHECK(append >= 0 && utimensat(AT_FDCWD, path, explicit, 0) == 0);
    CHECK(write(append, "!", 1) == 1 && fstat(file, &after) == 0 && after.st_size == 4097);
    CHECK(after.st_mtim.tv_sec != explicit[1].tv_sec && after.st_mtim.tv_sec == after.st_ctim.tv_sec);
    CHECK(close(append) == 0);
    CHECK(read_checks(file, directory) == 0 && fstat(file, &after) == 0);
    CHECK(link_checks(file, directory) == 0 && fstat(file, &after) == 0);
    const off_t lengths[] = {0, 2, 8192, 8192, 0};
    for (unsigned i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        before = after;
        CHECK(nanosleep(&pause, NULL) == 0 && ftruncate(file, lengths[i]) == 0);
        CHECK(fstat(file, &after) == 0 && after.st_size == lengths[i]);
        CHECK(before.st_atim.tv_sec == after.st_atim.tv_sec && before.st_atim.tv_nsec == after.st_atim.tv_nsec);
        CHECK(after.st_mtim.tv_sec == after.st_ctim.tv_sec && after.st_mtim.tv_nsec == after.st_ctim.tv_nsec);
        CHECK(!same_data_times(&before, &after));
    }
    CHECK(utimensat(AT_FDCWD, path, explicit, 0) == 0 && truncate(path, 4) == 0);
    CHECK(fstat(file, &after) == 0 && after.st_size == 4 && after.st_mtim.tv_sec == after.st_ctim.tv_sec);
    CHECK(after.st_mtim.tv_sec != explicit[1].tv_sec && after.st_atim.tv_sec == explicit[0].tv_sec);
    CHECK(utimensat(AT_FDCWD, path, explicit, 0) == 0);
    int truncated = open(path, O_WRONLY | O_TRUNC);
    CHECK(truncated >= 0 && fstat(file, &after) == 0 && after.st_size == 0);
    CHECK(after.st_mtim.tv_sec == after.st_ctim.tv_sec && after.st_mtim.tv_nsec == after.st_ctim.tv_nsec);
    CHECK(after.st_mtim.tv_sec != explicit[1].tv_sec && after.st_atim.tv_sec == explicit[0].tv_sec);
    CHECK(close(truncated) == 0);
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
    puts("c-file-times: PASS C ABI, sentinels, signed dates, pointer faults, errno, path anchors, permissions, nofollow, unlinked FD, chmod/chown, truncate, write/pwrite/append, msync, creation, access and link times");
    return 0;
}
