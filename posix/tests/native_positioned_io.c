#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

enum { HANDLE_CLOSE = 626, HANDLE_DUPLICATE = 627, MEMORY_OBJECT_CREATE = 671,
       HANDLE_READ_AT = 673, HANDLE_WRITE_AT = 674 };
static int64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    register uint64_t r10 __asm__("r10") = d;
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b), "d"(c), "r"(r10)
                     : "rcx", "r11", "memory");
    return (int64_t)number;
}
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "positioned-io: FAIL line %d errno %d\n", __LINE__, errno); return 1; \
} } while (0)

int main(void) {
    fprintf(stderr, "positioned-io: start\n");
    int64_t object = native(MEMORY_OBJECT_CREATE, 8192, 0, 0, 0);
    CHECK(object > 0);
    int64_t read_only = native(HANDLE_DUPLICATE, object, 1, 0, 0);
    int64_t write_only = native(HANDLE_DUPLICATE, object, 2, 0, 0);
    CHECK(read_only > 0 && write_only > 0);
    char actual[8] = {0};
    const char tag[] = "offset";
    CHECK(native(HANDLE_WRITE_AT, write_only, (uint64_t)tag, sizeof(tag), 4094) == sizeof(tag));
    CHECK(native(HANDLE_READ_AT, read_only, (uint64_t)actual, sizeof(tag), 4094) == sizeof(tag));
    CHECK(!memcmp(actual, tag, sizeof(tag)));
    CHECK(native(HANDLE_WRITE_AT, read_only, (uint64_t)tag, 1, 0) == -13);
    CHECK(native(HANDLE_READ_AT, write_only, (uint64_t)actual, 1, 0) == -13);
    CHECK(native(HANDLE_READ_AT, object, (uint64_t)actual, 1, UINT64_MAX) == -22);
    CHECK(native(HANDLE_READ_AT, object, (uint64_t)actual, sizeof(actual), 8190) == 2);
    CHECK(native(HANDLE_READ_AT, object, (uint64_t)actual, 1, 8192) == 0);
    CHECK(native(HANDLE_CLOSE, read_only, 0, 0, 0) == 0);
    CHECK(native(HANDLE_CLOSE, write_only, 0, 0, 0) == 0);
    CHECK(native(HANDLE_CLOSE, object, 0, 0, 0) == 0);
    fprintf(stderr, "positioned-io: MemoryObject and attenuated rights ok\n");

    const char *path = "/tmp/posix-positioned-probe.txt";
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    CHECK(fd >= 0);
    CHECK(write(fd, "abcdef", 6) == 6);
    CHECK(lseek(fd, 2, SEEK_SET) == 2);
    CHECK(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
    int duplicate = dup(fd);
    CHECK(duplicate >= 0);
    CHECK(fcntl(duplicate, F_GETFD) == 0);
    int range_dup = fcntl(fd, F_DUPFD, 40);
    int exec_dup = fcntl(fd, F_DUPFD_CLOEXEC, 40);
    CHECK(range_dup == 40 && exec_dup == 41);
    CHECK(fcntl(range_dup, F_GETFD) == 0);
    CHECK(fcntl(exec_dup, F_GETFD) == FD_CLOEXEC);
    CHECK(fcntl(fd, F_GETFD) == FD_CLOEXEC);
    CHECK(read(range_dup, actual, 1) == 1 && actual[0] == 'c');
    CHECK(lseek(exec_dup, 0, SEEK_CUR) == 3);
    CHECK(lseek(fd, 2, SEEK_SET) == 2);
    CHECK(fcntl(fd, F_DUPFD, -1) == -1 && errno == EINVAL);
    CHECK(fcntl(fd, F_DUPFD, 64) == -1 && errno == EINVAL);
    CHECK(dup(-1) == -1 && errno == EBADF);
    CHECK(fcntl(-1, F_DUPFD, 0) == -1 && errno == EBADF);
    int last_dup = fcntl(fd, F_DUPFD, 63);
    CHECK(last_dup == 63);
    CHECK(fcntl(fd, F_DUPFD, 63) == -1 && errno == EMFILE);
    CHECK(close(last_dup) == 0);
    CHECK(fcntl(fd, F_DUPFD_CLOEXEC, 63) == 63);
    CHECK(close(63) == 0);
    CHECK(close(range_dup) == 0 && close(exec_dup) == 0);
    fprintf(stderr, "positioned-io: dup and fcntl allocation, CLOEXEC, shared cursor and errors ok\n");
    CHECK(pread(duplicate, actual, 2, 0) == 2 && !memcmp(actual, "ab", 2));
    CHECK(lseek(fd, 0, SEEK_CUR) == 2);
    CHECK(pwrite(duplicate, "ZZ", 2, 0) == 2);
    CHECK(lseek(fd, 0, SEEK_CUR) == 2);
    CHECK(read(fd, actual, 2) == 2 && !memcmp(actual, "cd", 2));
    CHECK(pread(fd, actual, sizeof(actual), 5) == 1 && actual[0] == 'f');
    CHECK(pread(fd, actual, 1, 6) == 0);
    CHECK(pread(fd, actual, 1, -1) == -1 && errno == EINVAL);
    int readonly = open(path, O_RDONLY);
    int writeonly = open(path, O_WRONLY);
    CHECK(readonly >= 0 && writeonly >= 0);
    CHECK(pwrite(readonly, "!", 1, 0) == -1 && errno == EBADF);
    CHECK(pread(writeonly, actual, 1, 0) == -1 && errno == EBADF);
    CHECK(pread(-1, actual, 1, 0) == -1 && errno == EBADF);
    CHECK(close(readonly) == 0 && close(writeonly) == 0);
    int pipefds[2];
    CHECK(pipe(pipefds) == 0);
    CHECK(pread(pipefds[0], actual, 1, 0) == -1 && errno == ESPIPE);
    CHECK(pwrite(pipefds[1], "!", 1, 0) == -1 && errno == ESPIPE);
    CHECK(close(pipefds[0]) == 0 && close(pipefds[1]) == 0);
    fprintf(stderr, "positioned-io: pread/pwrite cursor, access, EOF and pipe errors ok\n");

    char input[9000], output[9000];
    for (size_t i = 0; i < sizeof(input); ++i) input[i] = (char)(i * 17);
    CHECK(pwrite(fd, input, sizeof(input), 0) == sizeof(input));
    CHECK(pread(fd, output, sizeof(output), 0) == sizeof(output));
    CHECK(!memcmp(input, output, sizeof(input)));
    CHECK(lseek(fd, 0, SEEK_CUR) == 4);
    char *mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(mapping != MAP_FAILED);
    CHECK(mapping[0] == input[0]);
    CHECK(pwrite(fd, "XY", 2, 0) == 2);
    CHECK(mapping[0] == 'X' && mapping[1] == 'Y');
    mapping[0] = 'Q';
    CHECK(pread(fd, actual, 1, 0) == 1 && actual[0] == 'Q');
    CHECK(msync(mapping, 4096, MS_SYNC) == 0);
    CHECK(munmap(mapping, 4096) == 0);
    CHECK(close(duplicate) == 0 && close(fd) == 0);
    CHECK(unlink(path) == 0);
    fprintf(stderr, "positioned-io: chunking and shared mapping coherence ok\n");
    fprintf(stderr, "positioned-io: ok\n");
    return 0;
}
