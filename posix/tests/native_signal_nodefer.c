#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <stdio.h>

static volatile sig_atomic_t depth, maximum_depth, calls, failed, explicit_self;

static void handler(int signal) {
    sigset_t current;
    ++depth;
    if (depth > maximum_depth)
        maximum_depth = depth;
    ++calls;
    if (sigprocmask(SIG_SETMASK, NULL, &current) != 0 ||
        sigismember(&current, SIGUSR1) != explicit_self ||
        sigismember(&current, SIGUSR2) != 1)
        failed = 1;
    if (calls == 1 && raise(signal) != 0)
        failed = 1;
    --depth;
}

int main(void) {
    struct sigaction action = {0};
    sigset_t original, before, after;
    if (sigprocmask(SIG_SETMASK, NULL, &original) != 0)
        return 1;
    sigemptyset(&before);
    sigaddset(&before, SIGTERM);
    if (sigprocmask(SIG_SETMASK, &before, NULL) != 0)
        return 2;
    action.sa_handler = handler;
    for (int mode = 0; mode < 3; ++mode) {
        action.sa_flags = mode == 0 ? 0 : SA_NODEFER;
        sigemptyset(&action.sa_mask);
        sigaddset(&action.sa_mask, SIGUSR2);
        explicit_self = mode != 1;
        if (mode == 2)
            sigaddset(&action.sa_mask, SIGUSR1);
        calls = depth = maximum_depth = failed = 0;
        if (sigaction(SIGUSR1, &action, NULL) != 0 || raise(SIGUSR1) != 0)
            return 3;
        if (failed || calls != 2 || depth != 0 ||
            maximum_depth != (mode == 1 ? 2 : 1))
            return 4;
        if (sigprocmask(SIG_SETMASK, NULL, &after) != 0 ||
            sigismember(&after, SIGUSR1) != 0 ||
            sigismember(&after, SIGUSR2) != 0 ||
            sigismember(&after, SIGTERM) != 1)
            return 5;
    }
    if (sigprocmask(SIG_SETMASK, &original, NULL) != 0)
        return 6;
    puts("native SA_NODEFER: PASS");
    return 0;
}
