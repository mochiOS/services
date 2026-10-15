/* Real newlib fork: shared descriptions, unlink lifetime and capture cleanup. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { printf("fork-capture: FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
static int64_t fc_native(uint64_t number, uint64_t a, uint64_t b) {
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b) : "rcx", "r11", "memory");
    return (int64_t)number;
}
static int64_t fc_handles(void) {
    struct { uint32_t handle, reserved; uint64_t rights; } entries[256];
    return fc_native(680, (uint64_t)entries, 256);
}
static int fc_wait(pid_t child) {
    int status = 0;
    return waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
int main(void) {
    const char *path = "/tmp/native-fork-capture";
    int file = open(path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    CHECK(file >= 0 && unlink(path) == 0);
    int alias = dup(file);
    CHECK(alias >= 0 && write(file, "abcdef", 6) == 6);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) _exit(0);
    CHECK(fc_wait(child));
    int64_t baseline = fc_handles();
    CHECK(baseline > 0);
    mode_t original_umask = umask(027);
    for (int round = 0; round < 4; round++) {
        umask(027);
        CHECK(lseek(file, 0, SEEK_SET) == 0);
        CHECK(fcntl(file, F_SETFL, 0) == 0);
        child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            char byte = 0;
            if (umask(0) != 027) _exit(7);
            if (!(fcntl(file, F_GETFD) & FD_CLOEXEC)) _exit(1);
            if (close(file) || read(alias, &byte, 1) != 1 || byte != 'a') _exit(2);
            if (fcntl(alias, F_SETFL, O_APPEND)) _exit(3);
            /* Nested fork must not see the parent's private capture as an
             * untransferable resource, or close a reused child Handle slot. */
            pid_t nested = fork();
            if (nested < 0) _exit(4);
            if (nested == 0) _exit(close(alias) ? 5 : 0);
            _exit(fc_wait(nested) && close(alias) == 0 ? 0 : 6);
        }
        CHECK(umask(077) == 027);
        CHECK(fc_wait(child));
        char byte = 0;
        CHECK(read(file, &byte, 1) == 1 && byte == 'b');
        CHECK(fcntl(alias, F_GETFL) & O_APPEND);
        CHECK(fc_handles() == baseline);
    }
    umask(original_umask);
    /* A native reference without TRANSFER makes fork fail, not silently lose
     * the resource. The temporary capture must also close on this path. */
    int64_t memory = fc_native(671, 4096, 0);
    CHECK(memory > 0);
    int64_t readonly = fc_native(627, memory, 1);
    CHECK(readonly > 0);
    int64_t before_error = fc_handles();
    for (unsigned attempt = 0; attempt < 70; ++attempt) {
        CHECK(fork() == -1 && errno == EACCES);
        CHECK(fc_handles() == before_error);
    }
    CHECK(fc_native(626, readonly, 0) == 0 && fc_native(626, memory, 0) == 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) _exit(0);
    CHECK(fc_wait(child));
    CHECK(close(alias) == 0 && close(file) == 0);
    puts("fork-capture: PASS unlinked OFD offset/status sharing, CLOEXEC preservation, nested fork and parent/error capture cleanup");
    puts("fork-policy-runtime: PASS inherited umask independence and cancellation quota recovered after 70 failed forks");
    return 0;
}
