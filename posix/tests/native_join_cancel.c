#define _GNU_SOURCE 1
/* Isolated Compositor-slot KVM probe, not a desktop readiness test. */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static _Atomic unsigned target_release, join_ready, cleanup_started, cleanup_ok, join_returned;
static pthread_t target;
static unsigned iteration;

static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"((uintptr_t)message), "S"((uint64_t)strlen(message))
                     : "rcx", "r11", "memory");
}

#define CHECK(condition) do { if (!(condition)) { \
    char message[128]; \
    snprintf(message, sizeof(message), "native-join-cancel: FAIL iteration=%u line=%u errno=%d\n", iteration, __LINE__, errno); \
    debug(message); return 1; \
} } while (0)

static int await_flag(_Atomic unsigned *flag) {
    for (unsigned retry = 0; retry < 2000; ++retry) {
        if (atomic_load(flag)) return 1;
        struct timespec delay = {0, 1000000};
        if (nanosleep(&delay, NULL) != 0) return 0;
    }
    return 0;
}

static void *gated_target(void *unused) {
    (void)unused;
    while (!atomic_load(&target_release)) sched_yield();
    return (void *)(uintptr_t)55;
}

static void join_again_from_cleanup(void *unused) {
    (void)unused;
    atomic_store(&cleanup_started, 1);
    void *result = NULL;
    // This must be allowed: the cancelled join's internal claim is gone, and
    // cancellation is disabled while application cleanup is being executed.
    if (pthread_join(target, &result) == 0 && result == (void *)(uintptr_t)55)
        atomic_store(&cleanup_ok, 1);
}

static void *cancellable_join(void *unused) {
    (void)unused;
    void *result = (void *)(uintptr_t)99;
    pthread_cleanup_push(join_again_from_cleanup, NULL);
    atomic_store(&join_ready, 1);
    pthread_join(target, &result);
    atomic_store(&join_returned, 1);
    pthread_cleanup_pop(0);
    return result;
}

static void *disabled_join(void *unused) {
    (void)unused;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) != 0) return (void *)1;
    atomic_store(&join_ready, 1);
    void *result = NULL;
    if (pthread_join(target, &result) != 0 || result != (void *)(uintptr_t)55) return (void *)2;
    atomic_store(&join_returned, 1);
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0) return (void *)3;
    pthread_testcancel();
    return (void *)4;
}

int main(void) {
    for (iteration = 0; iteration < 32; ++iteration) {
        atomic_store(&target_release, 0);
        atomic_store(&join_ready, 0);
        atomic_store(&cleanup_started, 0);
        atomic_store(&cleanup_ok, 0);
        atomic_store(&join_returned, 0);
        pthread_t waiter;
        CHECK(pthread_create(&target, NULL, gated_target, NULL) == 0);
        CHECK(pthread_create(&waiter, NULL, cancellable_join, NULL) == 0);
        CHECK(await_flag(&join_ready));
        struct timespec delay = {0, 20000000};
        CHECK(nanosleep(&delay, NULL) == 0);
        errno = 123;
        CHECK(pthread_cancel(waiter) == 0 && errno == 123);
        CHECK(await_flag(&cleanup_started)); // Target is still live: cancel itself must wake the join.
        CHECK(atomic_load(&join_returned) == 0);
        atomic_store(&target_release, 1);
        void *result = NULL;
        CHECK(pthread_join(waiter, &result) == 0 && result == PTHREAD_CANCELED);
        CHECK(atomic_load(&cleanup_ok) == 1);
    }
    debug("native-join-cancel: 32 cancelled joins woke and cleanup rejoined the live target\n");
    atomic_store(&target_release, 0);
    atomic_store(&join_ready, 0);
    atomic_store(&join_returned, 0);
    pthread_t waiter;
    CHECK(pthread_create(&target, NULL, gated_target, NULL) == 0);
    CHECK(pthread_create(&waiter, NULL, disabled_join, NULL) == 0);
    CHECK(await_flag(&join_ready));
    CHECK(pthread_cancel(waiter) == 0);
    struct timespec delay = {0, 20000000};
    CHECK(nanosleep(&delay, NULL) == 0 && atomic_load(&join_returned) == 0);
    atomic_store(&target_release, 1);
    void *result = NULL;
    CHECK(pthread_join(waiter, &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(atomic_load(&join_returned) == 1);
    debug("native-join-cancel: PASS cancelled join cleanup and disabled cancellation\n");
    return 0;
}
