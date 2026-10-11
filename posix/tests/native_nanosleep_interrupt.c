#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <stddef.h>

_Static_assert(sizeof(sigset_t) == 8, "newlib signal mask ABI");
_Static_assert(offsetof(struct sigaction, sa_handler) == 0, "handler ABI");
_Static_assert(offsetof(struct sigaction, sa_mask) == 8, "mask ABI");
_Static_assert(offsetof(struct sigaction, sa_flags) == 16, "flags ABI");

static volatile sig_atomic_t caught;

static void handler(int signal) {
    (void)signal;
    caught++;
    errno = EDOM;
}

static void *send_signal(void *argument) {
    (void)argument;
    struct timespec delay = {0, 50000000};
    if (nanosleep(&delay, 0) != 0 || kill(getpid(), SIGUSR1) != 0)
        return (void *)(uintptr_t)1;
    return 0;
}

int main(void) {
    struct sigaction action = {0};
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, 0) != 0) {
        fprintf(stderr, "nanosleep-interrupt: sigaction errno=%d\n", errno);
        return 1;
    }
    pthread_t sender;
    if (pthread_create(&sender, 0, send_signal, 0) != 0)
        return 2;
    struct timespec request = {5, 0}, remaining = {-1, -1};
    int result = nanosleep(&request, &remaining);
    int error = errno;
    void *sender_result;
    if (pthread_join(sender, &sender_result) != 0 || sender_result != 0)
        return 3;
    if (result != -1 || error != EINTR || caught != 1 || remaining.tv_sec < 0 ||
        remaining.tv_sec >= request.tv_sec || remaining.tv_nsec < 0 ||
        remaining.tv_nsec >= 1000000000)
        return 4;
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGUSR1, &action, 0) != 0 ||
        pthread_create(&sender, 0, send_signal, 0) != 0)
        return 5;
    request = (struct timespec){0, 200000000};
    if (nanosleep(&request, &remaining) != 0 || remaining.tv_sec != 0 ||
        remaining.tv_nsec != 0 || caught != 1)
        return 6;
    if (pthread_join(sender, &sender_result) != 0 || sender_result != 0)
        return 7;
    fprintf(stderr, "nanosleep-interrupt: pass caught=%d\n", (int)caught);
    return 0;
}
