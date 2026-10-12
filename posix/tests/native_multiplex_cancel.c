#define _GNU_SOURCE 1
/* Isolated Compositor-slot probe: cancellation must not need a signal handler. */
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

static _Atomic unsigned ready, release_entry, returned, cleanup_ok;
static unsigned mode, iteration;
static int pipes[2];
struct wait_state { sigset_t original; struct pollfd poll; fd_set read; };

static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"((uintptr_t)message), "S"((uint64_t)strlen(message))
                     : "rcx", "r11", "memory");
}

#define CHECK(condition) do { if (!(condition)) { \
    char message[128]; \
    snprintf(message, sizeof(message), "native-multiplex-cancel: FAIL mode=%u iteration=%u line=%u errno=%d\n", \
             mode, iteration, __LINE__, errno); debug(message); return 1; \
} } while (0)

static int await_flag(_Atomic unsigned *flag) {
    for (unsigned retry = 0; retry < 2000; ++retry) {
        if (atomic_load(flag)) return 1;
        struct timespec delay = {0, 1000000};
        if (nanosleep(&delay, NULL) != 0) return 0;
    }
    return 0;
}

static void check_cleanup(void *argument) {
    struct wait_state *state = argument;
    sigset_t mask;
    if (pthread_sigmask(SIG_SETMASK, NULL, &mask) != 0
        || memcmp(&mask, &state->original, sizeof(mask)) != 0) return;
    if ((mode == 0 || mode == 3) && state->poll.revents != 99) return;
    if ((mode == 1 || mode == 2) && !FD_ISSET(pipes[0], &state->read)) return;
    atomic_store(&cleanup_ok, 1);
}

static void *waiter(void *unused) {
    (void)unused;
    struct wait_state state;
    sigemptyset(&state.original);
    sigaddset(&state.original, SIGUSR2);
    if (pthread_sigmask(SIG_SETMASK, &state.original, NULL) != 0) return (void *)1;
    sigset_t temporary;
    sigemptyset(&temporary);
    sigaddset(&temporary, SIGUSR1);
    state.poll = (struct pollfd){pipes[0], POLLIN, 99};
    FD_ZERO(&state.read);
    FD_SET(pipes[0], &state.read);
    if (mode == 10 && pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) != 0) return (void *)2;
    struct timespec zero = {0, 0};
    struct timeval zero_timeval = {0, 0};
    int result = -1;
    pthread_cleanup_push(check_cleanup, &state);
    atomic_store(&ready, 1);
    if (mode >= 11) while (!atomic_load(&release_entry)) sched_yield();
    switch (mode) {
        case 0: case 10: result = poll(&state.poll, 1, -1); break;
        case 1: result = select(pipes[0] + 1, &state.read, NULL, NULL, NULL); break;
        case 2: result = pselect(pipes[0] + 1, &state.read, NULL, NULL, NULL, &temporary); break;
        case 3: result = ppoll(&state.poll, 1, NULL, &temporary); break;
        case 4: result = pause(); break;
        case 5: result = sigsuspend(&temporary); break;
        case 6: result = poll(NULL, 0, -1); break;
        case 7: result = select(0, NULL, NULL, NULL, NULL); break;
        case 8: result = pselect(0, NULL, NULL, NULL, NULL, &temporary); break;
        case 9: result = ppoll(NULL, 0, NULL, &temporary); break;
        case 11: result = poll(NULL, 0, 0); break;
        case 12: result = select(0, NULL, NULL, NULL, &zero_timeval); break;
        case 13: result = pselect(0, NULL, NULL, NULL, &zero, &temporary); break;
        case 14: result = ppoll(NULL, 0, &zero, &temporary); break;
    }
    if (mode == 10 && result == 1 && (state.poll.revents & POLLIN)) {
        atomic_store(&returned, 1);
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_testcancel();
    } else atomic_store(&returned, 2);
    pthread_cleanup_pop(0);
    return (void *)(intptr_t)result;
}

int main(void) {
    for (mode = 0; mode < 15; ++mode) {
        unsigned repeats = mode < 10 ? 3 : 1;
        for (iteration = 0; iteration < repeats; ++iteration) {
            atomic_store(&ready, 0);
            atomic_store(&release_entry, 0);
            atomic_store(&returned, 0);
            atomic_store(&cleanup_ok, 0);
            CHECK(pipe(pipes) == 0);
            pthread_t thread;
            CHECK(pthread_create(&thread, NULL, waiter, NULL) == 0);
            CHECK(await_flag(&ready));
            struct timespec delay = {0, 20000000};
            if (mode < 11) CHECK(nanosleep(&delay, NULL) == 0);
            CHECK(pthread_cancel(thread) == 0);
            atomic_store(&release_entry, 1);
            if (mode == 10) {
                CHECK(nanosleep(&delay, NULL) == 0 && atomic_load(&returned) == 0);
                CHECK(write(pipes[1], "x", 1) == 1);
            }
            CHECK(await_flag(&cleanup_ok)); // No FD becomes ready in enabled-cancel tests.
            void *result = NULL;
            CHECK(pthread_join(thread, &result) == 0 && result == PTHREAD_CANCELED);
            CHECK(atomic_load(&returned) == (mode == 10 ? 1u : 0u));
            CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
        }
    }
    debug("native-multiplex-cancel: PASS blocked, empty, zero-timeout, disabled and restored-mask waits\n");
    return 0;
}
