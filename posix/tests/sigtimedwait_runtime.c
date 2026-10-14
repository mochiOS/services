#define main sigwaitinfo_regression_main
#include "sigwaitinfo_runtime.c"
#undef main

static uint64_t now_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
    return (uint64_t)value.tv_sec * 1000000000 + value.tv_nsec;
}

int main(void) {
    CHECK(sigwaitinfo_regression_main() == 0);
    sigset_t selected;
    sigemptyset(&selected);
    sigaddset(&selected, SIGUSR1);
    struct timespec zero = {0}, timeout = {0, 30000000};
    siginfo_t info, untouched;
    memset(&info, 0xa5, sizeof(info));
    memcpy(&untouched, &info, sizeof(info));
    CHECK(sigtimedwait(&selected, &info, &zero) == -1 && errno == EAGAIN);
    CHECK(memcmp(&info, &untouched, sizeof(info)) == 0);
    uint64_t started = now_ns();
    CHECK(started != 0);
    CHECK(sigtimedwait(&selected, &info, &timeout) == -1 && errno == EAGAIN);
    CHECK(now_ns() - started >= 30000000);
    CHECK(memcmp(&info, &untouched, sizeof(info)) == 0);
    CHECK(raise(SIGUSR1) == 0);
    struct timespec invalid[] = {{-1,0}, {0,-1}, {0,1000000000}};
    for (unsigned i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i)
        CHECK(sigtimedwait(&selected, &info, &invalid[i]) == -1 && errno == EINVAL);
    errno = 123;
    CHECK(sigtimedwait(&selected, &info, &zero) == SIGUSR1 && errno == 123);
    CHECK(info.si_pid == getpid() && info.si_uid == getuid() && info.si_code == SI_USER);
    CHECK(raise(SIGUSR1) == 0);
    CHECK(sigtimedwait(&selected, NULL, NULL) == SIGUSR1);

    pid_t parent = getpid();
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct timespec delay = {0, 20000000};
        if (nanosleep(&delay, NULL) != 0 || kill(parent, SIGUSR1) != 0) _exit(99);
        _exit(0);
    }
    struct timespec second = {1,0};
    CHECK(sigtimedwait(&selected, &info, &second) == SIGUSR1 && info.si_pid == child);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    sigset_t children;
    sigemptyset(&children);
    sigaddset(&children, SIGCHLD);
    CHECK(sigwaitinfo(&children, &info) == SIGCHLD);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct timespec delay = {0, 20000000};
        if (nanosleep(&delay, NULL) != 0 || kill(parent, SIGUSR2) != 0) _exit(99);
        _exit(0);
    }
    CHECK(sigtimedwait(&selected, &info, &second) == -1 && errno == EINTR && caught == 2);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(sigwaitinfo(&children, &info) == SIGCHLD);

    child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct timespec delay = {0, 60000000};
        if (nanosleep(&delay, NULL) != 0 || kill(parent, SIGUSR1) != 0) _exit(99);
        _exit(0);
    }
    struct timespec short_wait = {0, 10000000};
    CHECK(sigtimedwait(&selected, &info, &short_wait) == -1 && errno == EAGAIN);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(sigtimedwait(&selected, &info, &zero) == SIGUSR1 && info.si_pid == child);
    CHECK(sigwaitinfo(&children, &info) == SIGCHLD);
    CHECK(sigtimedwait(&selected, NULL, &zero) == -1 && errno == EAGAIN);
    puts("sigtimedwait: PASS zero/finite/infinite timeout, validation, provenance, EINTR and late-signal retention");
    return 0;
}
