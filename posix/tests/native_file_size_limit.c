#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { printf("file-size-limit: FAIL line=%d errno=%d signals=%d\n", __LINE__, errno, (int)fl_signals); return 1; } } while (0)
static volatile sig_atomic_t fl_signals;
static void fl_handler(int signal) { if (signal == SIGXFSZ) ++fl_signals; errno = EINVAL; }
int main(void) {
    const char *path = "/tmp/native-file-size-limit";
    int file = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    CHECK(file >= 0);
    int readonly = open(path, O_RDONLY), alias = dup(file);
    CHECK(readonly >= 0 && alias >= 0 && unlink(path) == 0);
    CHECK(write(file, "abcdefgh", 8) == 8 && lseek(file, 3, SEEK_SET) == 3);
    int null = open("/dev/null", O_RDWR);
    CHECK(null >= 0);
    struct rlimit original, limit;
    CHECK(getrlimit(RLIMIT_FSIZE, &original) == 0);
    limit = original; limit.rlim_cur = 5;
    struct sigaction action = {0}, previous;
    action.sa_handler = fl_handler;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGXFSZ, &action, &previous) == 0);
    CHECK(setrlimit(RLIMIT_FSIZE, &limit) == 0);

    /* Overwriting an existing large file is still bounded by the write range,
     * not by a raced stat() or the shared open-description cursor. */
    CHECK(pwrite(file, "XYZW", 4, 3) == 2 && fl_signals == 0);
    char bytes[9] = {0};
    CHECK(pread(file, bytes, 8, 0) == 8 && !strcmp(bytes, "abcXYfgh"));
    CHECK(lseek(alias, 0, SEEK_CUR) == 3);
    struct stat status;
    CHECK(fstat(file, &status) == 0 && status.st_size == 8);
    CHECK(pwrite(file, NULL, 0, 99) == 0 && fl_signals == 0);
    errno = 0;
    CHECK(pwrite(file, "!", 1, 5) == -1 && errno == EFBIG && fl_signals == 1);
    CHECK(lseek(file, 0, SEEK_CUR) == 3);
    errno = 0;
    CHECK(pwrite(readonly, "!", 1, 5) == -1 && errno == EBADF && fl_signals == 1);
    errno = 0;
    CHECK(pwrite(file, "!", 1, -1) == -1 && errno == EINVAL && fl_signals == 1);
    CHECK(pwrite(null, "XYZ", 3, 99) == 3 && fl_signals == 1);
    CHECK(fcntl(file, F_SETFL, O_APPEND) == 0);
    CHECK(pwrite(alias, "z", 1, 0) == 1 && lseek(file, 0, SEEK_CUR) == 3);
    CHECK(fstat(file, &status) == 0 && status.st_size == 8);

    sigset_t mask, saved_mask, pending;
    CHECK(sigemptyset(&mask) == 0 && sigaddset(&mask, SIGXFSZ) == 0);
    CHECK(sigprocmask(SIG_BLOCK, &mask, &saved_mask) == 0);
    errno = 0;
    CHECK(pwrite(file, "!", 1, 5) == -1 && errno == EFBIG && fl_signals == 1);
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGXFSZ) == 1);
    CHECK(sigprocmask(SIG_SETMASK, &saved_mask, NULL) == 0 && fl_signals == 2);
    action.sa_handler = SIG_IGN;
    CHECK(sigaction(SIGXFSZ, &action, NULL) == 0);
    errno = 0;
    CHECK(pwrite(file, "!", 1, 5) == -1 && errno == EFBIG && fl_signals == 2);

    /* Defaults terminate with a POSIX signal wait status, not a plain exit. */
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        action.sa_handler = SIG_DFL;
        if (sigaction(SIGXFSZ, &action, NULL)) _exit(10);
        (void)pwrite(file, "!", 1, 5);
        _exit(11);
    }
    int result;
    CHECK(waitpid(child, &result, 0) == child && WIFSIGNALED(result) && WTERMSIG(result) == SIGXFSZ);
    CHECK(setrlimit(RLIMIT_FSIZE, &original) == 0);
    CHECK(sigaction(SIGXFSZ, &previous, NULL) == 0);
    CHECK(close(null) == 0 && close(alias) == 0 && close(readonly) == 0 && close(file) == 0);
    puts("file-size-limit: PASS pwrite prefix, unchanged OFD cursor, append independence, special-file exemption, caught/blocked/ignored/default SIGXFSZ and errno");
    return 0;
}
