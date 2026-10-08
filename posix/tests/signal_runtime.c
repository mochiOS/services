#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

static void test_handler(int signal) {
    (void)signal;
}

static void *inspect_signal_state(void *argument) {
    (void)argument;
    struct sigaction action;
    sigset_t mask;

    if (sigaction(SIGUSR1, 0, &action) != 0 || action.sa_handler != test_handler) {
        return (void *)1;
    }
    if (pthread_sigmask(SIG_SETMASK, 0, &mask) != 0 || !sigismember(&mask, SIGUSR1)) {
        return (void *)2;
    }
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    if (pthread_sigmask(SIG_UNBLOCK, &mask, 0) != 0) {
        return (void *)3;
    }
    if (pthread_sigmask(SIG_SETMASK, 0, &mask) != 0 || sigismember(&mask, SIGUSR1)) {
        return (void *)4;
    }
    return 0;
}

int main(void) {
    struct sigaction action = {0};
    sigset_t mask;
    pthread_t thread;
    void *result = 0;

    action.sa_handler = test_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, 0) != 0) {
        return 1;
    }
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    if (pthread_sigmask(SIG_BLOCK, &mask, 0) != 0) {
        return 2;
    }
    if (pthread_create(&thread, 0, inspect_signal_state, 0) != 0) {
        return 3;
    }
    if (pthread_join(thread, &result) != 0 || result != 0) {
        return 4;
    }
    if (pthread_sigmask(SIG_SETMASK, 0, &mask) != 0 || !sigismember(&mask, SIGUSR1)) {
        return 5;
    }

    sigemptyset(&mask);
    sigaddset(&mask, SIGKILL);
    sigaddset(&mask, SIGSTOP);
    if (pthread_sigmask(SIG_BLOCK, &mask, 0) != 0) {
        return 6;
    }
    if (pthread_sigmask(SIG_SETMASK, 0, &mask) != 0
        || sigismember(&mask, SIGKILL)
        || sigismember(&mask, SIGSTOP)) {
        return 7;
    }

    errno = 0;
    if (sigaction(SIGKILL, &action, 0) != -1 || errno != EINVAL) {
        return 8;
    }
    errno = 0;
    if (sigaction(SIGSTOP, &action, 0) != -1 || errno != EINVAL) {
        return 9;
    }

    puts("signal-runtime: pass");
    return 0;
}
