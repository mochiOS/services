// Requires system.time.read and a matching package verification record.
#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static _Atomic unsigned completed, cleaned, delivered;
static unsigned cancel_case;
static clockid_t selected;

static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number)
        : "D"((uintptr_t)message), "S"((uint64_t)strlen(message)) : "rcx", "r11", "memory");
}
#define CHECK(condition) do { if (!(condition)) { \
    char message[160]; snprintf(message, sizeof(message), \
    "native-pthread-mutex-timed: FAIL line=%u errno=%d\n", __LINE__, errno); \
    debug(message); return 1; \
} } while (0)

static struct timespec future(clockid_t clock, long duration) {
    struct timespec time = {-1, -1};
    if (clock_gettime(clock, &time)) return time;
    time.tv_nsec += duration;
    time.tv_sec += time.tv_nsec / 1000000000L;
    time.tv_nsec %= 1000000000L;
    return time;
}
static void cleanup(void *unused) { (void)unused; atomic_store(&cleaned, 1); }
static void handler(int signal) { if (signal == SIGUSR1) atomic_fetch_add(&delivered, 1); }
static void *worker(void *unused) {
    (void)unused;
    errno = 123;
    struct timespec time = future(selected, cancel_case ? 500000000L : 2000000000L);
    int result;
    pthread_cleanup_push(cleanup, NULL);
    result = selected == CLOCK_REALTIME ? pthread_mutex_timedlock(&mutex, &time)
        : pthread_mutex_clocklock(&mutex, selected, &time);
    if (errno != 123) return (void *)1;
    if (cancel_case) {
        if (result != ETIMEDOUT) return (void *)2;
        atomic_store(&completed, 1);
        pthread_testcancel(); // Locking, including a timeout, is not a cancellation point.
    } else {
        if (result || pthread_mutex_unlock(&mutex)) return (void *)3;
        atomic_store(&completed, 1);
    }
    pthread_cleanup_pop(0);
    return NULL;
}
static int await_waiter(void) {
    for (unsigned n = 0; n < 2000; ++n) {
        if (__atomic_load_n(&mutex.waiters, __ATOMIC_ACQUIRE)) return 1;
        struct timespec delay = {0, 1000000};
        if (nanosleep(&delay, NULL)) return 0;
    }
    return 0;
}

int main(void) {
    errno = 123;
    struct timespec invalid = {-1, 1000000000L};
    CHECK(pthread_mutex_timedlock(&mutex, &invalid) == 0 && errno == 123);
    CHECK(pthread_mutex_unlock(&mutex) == 0);
    CHECK(pthread_mutex_clocklock(&mutex, (1ULL << 32) | CLOCK_MONOTONIC, &invalid) == EINVAL);
    CHECK(pthread_mutex_clocklock(&mutex, (clockid_t)2, &invalid) == EINVAL); // Process CPU clock is not supported here.
    CHECK(pthread_mutex_lock(&mutex) == 0);
    CHECK(pthread_mutex_timedlock(&mutex, &invalid) == EINVAL && errno == 123);
    struct timespec past = {-1, 0};
    CHECK(pthread_mutex_clocklock(&mutex, CLOCK_MONOTONIC, &past) == ETIMEDOUT);
    struct timespec sentinel = {18446744073LL, 709551615L};
    CHECK(pthread_mutex_clocklock(&mutex, CLOCK_MONOTONIC, &sentinel) == EOVERFLOW);
    CHECK(pthread_mutex_unlock(&mutex) == 0);
    struct sigaction action = {0}, previous;
    action.sa_handler = handler;
    CHECK(sigemptyset(&action.sa_mask) == 0);
    CHECK(sigaction(SIGUSR1, &action, &previous) == 0);
    for (unsigned clock = 0; clock < 2; ++clock) {
        selected = clock ? CLOCK_MONOTONIC : CLOCK_REALTIME;
        cancel_case = 0; atomic_store(&completed, 0);
        CHECK(pthread_mutex_lock(&mutex) == 0);
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
        CHECK(await_waiter());
        CHECK(pthread_mutex_unlock(&mutex) == 0);
        void *result = (void *)99;
        CHECK(pthread_join(thread, &result) == 0 && result == NULL);
        CHECK(atomic_load(&completed));
        cancel_case = 1; atomic_store(&completed, 0); atomic_store(&cleaned, 0);
        CHECK(pthread_mutex_lock(&mutex) == 0);
        CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
        CHECK(await_waiter());
        CHECK(pthread_kill(thread, SIGUSR1) == 0);
        CHECK(pthread_cancel(thread) == 0);
        CHECK(pthread_join(thread, &result) == 0 && result == PTHREAD_CANCELED);
        CHECK(atomic_load(&completed) && atomic_load(&cleaned));
        CHECK(pthread_mutex_unlock(&mutex) == 0);
    }
    CHECK(atomic_load(&delivered) == 2);
    CHECK(sigaction(SIGUSR1, &previous, NULL) == 0);
    CHECK(pthread_mutex_destroy(&mutex) == 0 && errno == 123);
    pthread_mutexattr_t attr;
    pthread_mutex_t recursive;
    CHECK(pthread_mutexattr_init(&attr) == 0);
    CHECK(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) == 0);
    CHECK(pthread_mutex_init(&recursive, &attr) == 0);
    CHECK(pthread_mutex_timedlock(&recursive, &past) == 0);
    CHECK(pthread_mutex_timedlock(&recursive, &invalid) == 0);
    CHECK(pthread_mutex_unlock(&recursive) == 0 && pthread_mutex_unlock(&recursive) == 0);
    CHECK(pthread_mutex_destroy(&recursive) == 0);
    CHECK(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) == 0);
    CHECK(pthread_mutex_init(&recursive, &attr) == 0 && pthread_mutex_lock(&recursive) == 0);
    CHECK(pthread_mutex_timedlock(&recursive, &past) == EDEADLK);
    CHECK(pthread_mutex_unlock(&recursive) == 0 && pthread_mutex_destroy(&recursive) == 0);
    CHECK(pthread_mutexattr_destroy(&attr) == 0);
    debug("native-pthread-mutex-timed: PASS\n");
    return 0;
}
