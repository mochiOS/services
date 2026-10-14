#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(siginfo_t) == 40, "current mochiOS siginfo ABI");
#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "sigwaitinfo: FAIL line=%d errno=%d\n", __LINE__, errno); \
    return 1; } } while (0)
static volatile sig_atomic_t caught;
static void handler(int signal) { if (signal == SIGUSR2) ++caught; }

int main(void) {
    sigset_t blocked, selected, before, after;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGUSR1);
    sigaddset(&blocked, SIGCHLD);
    CHECK(pthread_sigmask(SIG_BLOCK, &blocked, NULL) == 0);
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &before) == 0);
    sigemptyset(&selected);
    sigaddset(&selected, SIGUSR1);
    struct sigaction action = {0};
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR2, &action, NULL) == 0);
    struct { siginfo_t info; uint64_t guard; } output;
    memset(&output, 0xa5, sizeof(output));
    output.guard = UINT64_C(0x123456789abcdef0);

    pid_t parent = getpid();
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct timespec delay = {0, 20000000};
        if (nanosleep(&delay, NULL) != 0) _exit(98);
        if (kill(parent, SIGUSR1) != 0) _exit(99);
        _exit(37);
    }
    errno = 123;
    CHECK(sigwaitinfo(&selected, &output.info) == SIGUSR1);
    CHECK(errno == 123 && output.info.si_signo == SIGUSR1 && output.info.si_code == SI_USER);
    CHECK(output.info.si_pid == child && output.info.si_uid == getuid());
    CHECK(output.info.si_errno == 0 && output.info.si_status == 0 && output.info.si_addr == NULL);
    CHECK(output.guard == UINT64_C(0x123456789abcdef0));
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    sigset_t children;
    sigemptyset(&children);
    sigaddset(&children, SIGCHLD);
    CHECK(sigwaitinfo(&children, &output.info) == SIGCHLD);
    CHECK(output.info.si_code == CLD_EXITED && output.info.si_pid == child && output.info.si_status == 37);
    CHECK(output.info.si_uid == getuid());

    CHECK(raise(SIGUSR1) == 0 && raise(SIGUSR1) == 0);
    CHECK(sigwaitinfo(&selected, &output.info) == SIGUSR1);
    CHECK(output.info.si_pid == parent && output.info.si_uid == getuid() && output.info.si_code == SI_USER);
    sigset_t pending;
    CHECK(sigpending(&pending) == 0 && !sigismember(&pending, SIGUSR1));
    CHECK(raise(SIGUSR1) == 0);
    int number = 0;
    CHECK(sigwait(&selected, &number) == 0 && number == SIGUSR1);
    CHECK(kill(parent, SIGUSR1) == 0);
    CHECK(sigwaitinfo(&selected, NULL) == SIGUSR1);
    CHECK(sigwaitinfo(NULL, &output.info) == -1 && errno == EFAULT);

    child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct timespec delay = {0, 20000000};
        if (nanosleep(&delay, NULL) != 0) _exit(98);
        if (kill(parent, SIGUSR2) != 0) _exit(99);
        _exit(0);
    }
    // Unrelated caught signals interrupt sigwaitinfo, unlike sigwait's retry.
    CHECK(sigwaitinfo(&selected, &output.info) == -1 && errno == EINTR);
    CHECK(caught == 1);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(sigwaitinfo(&children, &output.info) == SIGCHLD);
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &after) == 0 && before == after);
    CHECK(output.guard == UINT64_C(0x123456789abcdef0));
    puts("sigwaitinfo: PASS atomic provenance, deferred acceptance, reaped child status, coalescing, sigwait compatibility and EINTR");
    return 0;
}
