#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/uio.h>
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

static char stream_input[90000], stream_output[90000];
struct drain_state { int fd; size_t received; int error; };
static void *drain_stream(void *argument) {
    struct drain_state *state = argument;
    while (state->received < sizeof(stream_output)) {
        ssize_t count = read(state->fd, stream_output + state->received,
                             sizeof(stream_output) - state->received);
        if (count <= 0) { state->error = errno ? errno : EIO; break; }
        state->received += (size_t)count;
    }
    return NULL;
}

static int test_stream_writes(void) {
    int fds[2];
    CHECK(pipe2(fds, O_NONBLOCK) == 0);
    char chunk[4096];
    memset(chunk, 'F', sizeof(chunk));
    size_t filled = 0;
    for (;;) {
        ssize_t count = write(fds[1], chunk, sizeof(chunk));
        if (count < 0) { CHECK(errno == EAGAIN); break; }
        CHECK(count > 0);
        filled += (size_t)count;
        CHECK(filled < sizeof(stream_output));
    }
    CHECK(read(fds[0], chunk, 257) == 257);
    char atomic_bytes[PIPE_BUF];
    memset(atomic_bytes, 'A', sizeof(atomic_bytes));
    CHECK(write(fds[1], atomic_bytes, sizeof(atomic_bytes)) == -1 && errno == EAGAIN);
    memset(chunk, 'P', sizeof(chunk));
    CHECK(write(fds[1], chunk, sizeof(chunk)) == 257);
    CHECK(write(fds[1], chunk, sizeof(chunk)) == -1 && errno == EAGAIN);
    size_t drained = 0;
    for (;;) {
        ssize_t count = read(fds[0], stream_output + drained, sizeof(stream_output) - drained);
        if (count < 0) { CHECK(errno == EAGAIN); break; }
        CHECK(count > 0);
        drained += (size_t)count;
    }
    CHECK(drained == filled);
    for (size_t i = 0; i < filled - 257; ++i) CHECK(stream_output[i] == 'F');
    for (size_t i = filled - 257; i < filled; ++i) CHECK(stream_output[i] == 'P');
    CHECK(close(fds[0]) == 0 && close(fds[1]) == 0);

    CHECK(pipe(fds) == 0);
    for (size_t i = 0; i < sizeof(stream_input); ++i) stream_input[i] = (char)(i * 13);
    struct drain_state state = {fds[0], 0, 0};
    pthread_t reader;
    CHECK(pthread_create(&reader, NULL, drain_stream, &state) == 0);
    CHECK(write(fds[1], stream_input, sizeof(stream_input)) == sizeof(stream_input));
    CHECK(pthread_join(reader, NULL) == 0);
    CHECK(state.error == 0 && state.received == sizeof(stream_output));
    CHECK(!memcmp(stream_input, stream_output, sizeof(stream_input)));
    CHECK(close(fds[0]) == 0 && close(fds[1]) == 0);
    fprintf(stderr, "positioned-io: PIPE_BUF atomicity, nonblocking partial write and 90KB blocking stream write ok\n");
    return 0;
}

int main(void) {
    fprintf(stderr, "positioned-io: start\n");
    errno = EBUSY;
    CHECK(sysconf(_SC_IOV_MAX) == 1024);
    CHECK(sysconf(_SC_THREAD_KEYS_MAX) == 64);
    CHECK(sysconf(_SC_THREAD_THREADS_MAX) == 64);
    CHECK(sysconf(_SC_THREAD_DESTRUCTOR_ITERATIONS) == 4);
    CHECK(errno == EBUSY);
    CHECK(sysconf(-1) == -1 && errno == EINVAL);
    fprintf(stderr, "positioned-io: sysconf vector and pthread limits ok\n");
    /* Native creation cannot turn an unapproved image into a running task. */
    unsigned char creation[32 + 4 + 4 + 32 + 8] = {0};
    memcpy(creation, "MCRT", 4);
    creation[4] = 2; creation[6] = 32;
    creation[8] = 4; creation[12] = 40;
    creation[24] = 4;
    memcpy(creation + 32, "test", 4);
    memcpy(creation + 36, "name", 4);
    memcpy(creation + 40, "MIMG", 4);
    creation[44] = 1; creation[46] = 32; creation[56] = 8;
    int64_t denied = native(676, 0, (uint64_t)creation, sizeof(creation), 0);
    CHECK(denied == -EPERM || denied == -EACCES);
    fprintf(stderr, "positioned-io: ProcessCreate authorization status %lld\n", (long long)denied);
    denied = native(676, 0, 0, 0, 0);
    CHECK(denied == -EPERM || denied == -EINVAL);
    fprintf(stderr, "positioned-io: native ProcessCreate rejects absent authorization and invalid metadata ok\n");
    CHECK(native(565, 0, 0, 0, 0) == -38);
    for (uint64_t number = 560; number <= 563; ++number) {
        CHECK(native(number, 0, 0, 0, 0) == -38);
    }
    CHECK(native(569, 0, 0, 0, 0) == -38);
    fprintf(stderr, "positioned-io: retired FileOpen/Close/Read/ReadDir ABI rejects calls ok\n");
    fprintf(stderr, "positioned-io: retired FileSeek ABI rejects calls ok\n");
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

    CHECK(pipe(pipefds) == 0);
    struct iovec send_vectors[] = {{"ab", 2}, {NULL, 0}, {"cde", 3}};
    CHECK(writev(pipefds[1], send_vectors, 3) == 5);
    char first[2] = {0}, second[6];
    memset(second, '!', sizeof(second));
    struct iovec receive_vectors[] = {{first, 2}, {second, sizeof(second)}};
    /* Writer stays open: a second read would block after consuming abcde. */
    CHECK(readv(pipefds[0], receive_vectors, 2) == 5);
    CHECK(!memcmp(first, "ab", 2) && !memcmp(second, "cde!!!", 6));
    CHECK(fcntl(pipefds[0], F_SETFL, O_NONBLOCK) == 0);
    CHECK(readv(pipefds[0], receive_vectors, 2) == -1 && errno == EAGAIN);
    CHECK(!memcmp(second, "cde!!!", 6));
    CHECK(writev(-1, NULL, 0) == -1 && errno == EBADF);
    struct iovec invalid_vectors[] = {{"abc", 3}, {NULL, 1}};
    CHECK(writev(pipefds[1], invalid_vectors, 2) == -1 && errno == EFAULT);
    CHECK(readv(pipefds[0], receive_vectors, 2) == -1 && errno == EAGAIN);
    CHECK(close(pipefds[0]) == 0 && close(pipefds[1]) == 0);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    CHECK(writev(fd, send_vectors, 3) == 5);
    CHECK(lseek(duplicate, 0, SEEK_CUR) == 5);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    CHECK(readv(duplicate, receive_vectors, 2) == 6);
    CHECK(!memcmp(first, "ab", 2) && !memcmp(second, "cdef!!", 6));
    CHECK(lseek(fd, 0, SEEK_CUR) == 6);
    CHECK(lseek(fd, 4, SEEK_SET) == 4);
    fprintf(stderr, "positioned-io: gathered writev and single-read readv, short read, EAGAIN, shared cursor ok\n");
    CHECK(test_stream_writes() == 0);

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
    struct rlimit saved, limited;
    CHECK(getrlimit(RLIMIT_NOFILE, &saved) == 0);
    limited = saved;
    limited.rlim_cur = (rlim_t)fd + 1;
    CHECK(setrlimit(RLIMIT_NOFILE, &limited) == 0);
    CHECK(sysconf(_SC_OPEN_MAX) == (long)limited.rlim_cur);
    CHECK(dup(fd) == -1 && errno == EMFILE);
    CHECK(fcntl(fd, F_DUPFD, (int)limited.rlim_cur) == -1 && errno == EINVAL);
    CHECK(dup2(fd, (int)limited.rlim_cur + 1) == -1 && errno == EBADF);
    CHECK(dup2(duplicate, duplicate) == duplicate);
    CHECK(pread(duplicate, actual, 1, 0) == 1 && actual[0] == 'Q');
    CHECK(open(path, O_WRONLY | O_TRUNC) == -1 && errno == EMFILE);
    CHECK(lseek(fd, 0, SEEK_END) == 9000);
    pipefds[0] = -7;
    pipefds[1] = -8;
    CHECK(pipe(pipefds) == -1 && errno == EMFILE);
    CHECK(pipefds[0] == -7 && pipefds[1] == -8);
    limited.rlim_cur = 0;
    CHECK(setrlimit(RLIMIT_NOFILE, &limited) == 0);
    CHECK(dup(fd) == -1 && errno == EMFILE);
    CHECK(fcntl(fd, F_DUPFD, 0) == -1 && errno == EINVAL);
    CHECK(setrlimit(RLIMIT_NOFILE, &saved) == 0);
    int available = dup(fd);
    CHECK(available >= 0 && close(available) == 0);
    fprintf(stderr, "positioned-io: RLIMIT_NOFILE allocation, retained FDs and restore ok\n");
    limited.rlim_cur = (rlim_t)available + 1;
    CHECK(setrlimit(RLIMIT_NOFILE, &limited) == 0);
    for (int attempt = 0; attempt < 4; ++attempt) {
        CHECK(open("/tmp/posix-missing-parent/file", O_RDONLY) == -1 && errno == ENOENT);
        CHECK(open(path, O_ACCMODE) == -1 && errno == EINVAL);
        int opened = open(path, O_RDONLY);
        CHECK(opened == available);
        CHECK(open(path, O_RDONLY) == -1 && errno == EMFILE);
        CHECK(close(opened) == 0);
    }
    CHECK(setrlimit(RLIMIT_NOFILE, &saved) == 0);
    fprintf(stderr, "positioned-io: failed opens release reserved FD and reuse lowest slot ok\n");
    CHECK(close(duplicate) == 0 && close(fd) == 0);
    CHECK(unlink(path) == 0);
    fprintf(stderr, "positioned-io: chunking and shared mapping coherence ok\n");
    fprintf(stderr, "positioned-io: ok\n");
    return 0;
}
