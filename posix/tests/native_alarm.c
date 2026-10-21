#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

int main(void) {
    sigset_t mask, old, pending;
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    if (sigprocmask(SIG_BLOCK, &mask, &old) != 0)
        return 1;
    if (alarm(5) != 0)
        return 2;
    unsigned remaining = alarm(0);
    if (remaining == 0 || remaining > 5)
        return 3;
    if (alarm(1) != 0)
        return 4;
    struct timespec delay = {1, 100000000};
    if (nanosleep(&delay, NULL) != 0)
        return 5;
    if (sigpending(&pending) != 0 || sigismember(&pending, SIGALRM) != 1)
        return 6;
    if (alarm(0) != 0)
        return 7;
    int received = 0;
    if (sigwait(&mask, &received) != 0 || received != SIGALRM)
        return 8;
    if (sigpending(&pending) != 0 || sigismember(&pending, SIGALRM) != 0)
        return 9;
    if (sigprocmask(SIG_SETMASK, &old, NULL) != 0)
        return 10;
    puts("native alarm: PASS");
    return 0;
}
