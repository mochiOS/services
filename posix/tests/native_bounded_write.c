#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { printf("bounded-write: FAIL line=%d errno=%d signals=%d\n", __LINE__, errno, (int)bw_signals); return 1; } } while (0)
static volatile sig_atomic_t bw_signals;
static void bw_handler(int signal) { if (signal == SIGXFSZ) ++bw_signals; }
static int64_t bw_native(uint64_t number, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    register uint64_t r10 __asm__("r10") = d;
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return (int64_t)number;
}
int main(void) {
    const char *path = "/tmp/native-bounded-write";
    int a = open(path, O_CREAT | O_TRUNC | O_RDWR | O_APPEND, 0600);
    int b = open(path, O_RDWR | O_APPEND), readonly = open(path, O_RDONLY);
    CHECK(a >= 0 && b >= 0 && readonly >= 0 && unlink(path) == 0);
    struct sigaction action = {0}, previous;
    action.sa_handler = bw_handler;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGXFSZ, &action, &previous) == 0);
    struct rlimit original, limit;
    CHECK(getrlimit(RLIMIT_FSIZE, &original) == 0);
    limit = original; limit.rlim_cur = 7;
    CHECK(setrlimit(RLIMIT_FSIZE, &limit) == 0);
    CHECK(write(a, "abc", 3) == 3 && write(b, "defgh", 5) == 4 && bw_signals == 0);
    CHECK(lseek(a, 0, SEEK_CUR) == 3 && lseek(b, 0, SEEK_CUR) == 7);
    char bytes[17] = {0};
    CHECK(pread(a, bytes, 7, 0) == 7 && !memcmp(bytes, "abcdefg", 7));
    errno = 0;
    CHECK(write(a, "!", 1) == -1 && errno == EFBIG && bw_signals == 1);
    CHECK(lseek(a, 0, SEEK_CUR) == 3 && write(a, NULL, 0) == 0 && bw_signals == 1);
    errno = 0;
    CHECK(write(readonly, "!", 1) == -1 && errno == EBADF && bw_signals == 1);
    CHECK(fcntl(a, F_SETFL, 0) == 0 && lseek(a, 0, SEEK_SET) == 0);
    CHECK(write(a, "XY", 2) == 2);
    struct iovec vector[2] = {{(void *)"123", 3}, {(void *)"456", 3}};
    CHECK(writev(a, vector, 2) == 5 && lseek(a, 0, SEEK_CUR) == 7);
    errno = 0;
    CHECK(writev(a, vector, 1) == -1 && errno == EFBIG && bw_signals == 2);
    CHECK(pread(b, bytes, 7, 0) == 7 && !memcmp(bytes, "XY12345", 7));

    /* A complete provider chunk at the ceiling must stop without a second
     * operation or a false signal. Larger writes preserve their prefix. */
    limit.rlim_cur = 8193;
    CHECK(setrlimit(RLIMIT_FSIZE, &limit) == 0 && ftruncate(a, 0) == 0);
    CHECK(fcntl(a, F_SETFL, O_APPEND) == 0);
    static char payload[12288]; memset(payload, 'z', sizeof(payload));
    CHECK(write(a, payload, sizeof(payload)) == 8193 && bw_signals == 2);
    struct stat status;
    CHECK(fstat(a, &status) == 0 && status.st_size == 8193);
    CHECK(pread(b, bytes, 9, 8184) == 9 && !memcmp(bytes, "zzzzzzzzz", 9));
    errno = 0;
    CHECK(write(b, "!", 1) == -1 && errno == EFBIG && bw_signals == 3);

    /* The native operation independently enforces WRITE, not CONTROL or the
     * POSIX access mode. RAM is not a sequential provider and is rejected. */
    int64_t ram = bw_native(671, 4096, 0, 0, 0); CHECK(ram > 0);
    int64_t readref = bw_native(627, (uint64_t)ram, 1, 0, 0); CHECK(readref > 0);
    CHECK(bw_native(694, (uint64_t)readref, (uint64_t)"x", 1, 5) == -13);
    CHECK(bw_native(694, (uint64_t)ram, (uint64_t)"x", 1, 5) == -95);
    CHECK(bw_native(626, (uint64_t)readref, 0, 0, 0) == 0 && bw_native(626, (uint64_t)ram, 0, 0, 0) == 0);

    limit.rlim_cur = 16;
    CHECK(setrlimit(RLIMIT_FSIZE, &limit) == 0 && ftruncate(a, 0) == 0);
    action.sa_handler = SIG_IGN;
    CHECK(sigaction(SIGXFSZ, &action, NULL) == 0);
    int ready[2], go[2]; CHECK(pipe(ready) == 0 && pipe(go) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        close(ready[0]); close(go[1]);
        if (write(b, "c", 1) != 1 || write(ready[1], "r", 1) != 1 || read(go[0], bytes, 1) != 1) _exit(100);
        unsigned completed = 1;
        for (unsigned i = 0; i < 20; ++i) {
            ssize_t count = write(b, "c", 1);
            if (count == 1) ++completed;
            else if (count != -1 || errno != EFBIG) _exit(101);
        }
        _exit((int)completed);
    }
    CHECK(close(ready[1]) == 0 && close(go[0]) == 0 && read(ready[0], bytes, 1) == 1);
    CHECK(write(a, "p", 1) == 1 && write(go[1], "g", 1) == 1);
    unsigned completed = 1;
    for (unsigned i = 0; i < 20; ++i) {
        ssize_t count = write(a, "p", 1);
        if (count == 1) ++completed;
        else CHECK(count == -1 && errno == EFBIG);
    }
    int result;
    CHECK(waitpid(child, &result, 0) == child && WIFEXITED(result));
    CHECK(WEXITSTATUS(result) > 0 && completed + (unsigned)WEXITSTATUS(result) == 16);
    CHECK(fstat(a, &status) == 0 && status.st_size == 16 && pread(a, bytes, 16, 0) == 16);
    unsigned parents = 0, children = 0;
    for (unsigned i = 0; i < 16; ++i) { if (bytes[i] == 'p') ++parents; else if (bytes[i] == 'c') ++children; }
    CHECK(parents == completed && children == (unsigned)WEXITSTATUS(result));
    CHECK(setrlimit(RLIMIT_FSIZE, &original) == 0 && sigaction(SIGXFSZ, &previous, NULL) == 0);
    CHECK(close(ready[0]) == 0 && close(go[1]) == 0 && close(readonly) == 0 && close(b) == 0 && close(a) == 0);
    puts("bounded-write: PASS native WRITE authority, atomic append and sequential prefixes, writev, multi-chunk bounds, error propagation and concurrent fork writers");
    return 0;
}
