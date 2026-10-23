/* Real mochiOS pthread-clock integration, not a host executable. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define CHECK(x)                                                               \
    do {                                                                       \
        if (!(x)) {                                                            \
            fprintf(stderr, "pthread-clock: FAIL line=%d errno=%d\n",          \
                    __LINE__, errno);                                          \
            return 1;                                                          \
        }                                                                      \
    } while (0)
_Static_assert(sizeof(clockid_t) == 8, "newlib clock ID ABI");
_Static_assert(sizeof(pthread_t) == 4, "newlib pthread token ABI");
static atomic_int stop;
static void *worker(void *unused) {
    (void)unused;
    while (!atomic_load_explicit(&stop, memory_order_acquire))
        __asm__ volatile("pause" ::: "memory");
    return NULL;
}
static uint64_t nanos(struct timespec time) {
    return (uint64_t)time.tv_sec * 1000000000 + (uint64_t)time.tv_nsec;
}
int main(void) {
    clockid_t own, again, other, newer;
    errno = EDOM;
    CHECK(pthread_getcpuclockid(pthread_self(), &own) == 0 && errno == EDOM);
    CHECK((uint64_t)own >= UINT64_C(1) << 32);
    CHECK(pthread_getcpuclockid(pthread_self(), &again) == 0 && again == own);
    struct timespec resolution;
    CHECK(clock_getres(own, &resolution) == 0 && nanos(resolution) > 0);
    CHECK(clock_getres(own, NULL) == 0);
    struct sigevent none = {0};
    none.sigev_notify = SIGEV_NONE;
    timer_t timer;
    CHECK(timer_create(own, &none, &timer) == 0 && timer_delete(timer) == 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
    CHECK(pthread_getcpuclockid(thread, &other) == 0 && other != own);
    errno = 0;
    CHECK(timer_create(other, &none, &timer) == -1 && errno == ENOTSUP);
    struct timespec before, after;
    CHECK(clock_gettime(other, &before) == 0);
    struct timespec delay = {.tv_nsec = 10000000};
    int advanced = 0;
    for (unsigned attempt = 0; attempt < 100 && !advanced; ++attempt) {
        CHECK(nanosleep(&delay, NULL) == 0);
        CHECK(clock_gettime(other, &after) == 0 &&
              nanos(after) >= nanos(before));
        advanced = nanos(after) > nanos(before);
    }
    CHECK(advanced);
    atomic_store_explicit(&stop, 1, memory_order_release);
    CHECK(pthread_join(thread, NULL) == 0);
    errno = 0;
    CHECK(clock_gettime(other, &after) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(clock_getres(other, NULL) == -1 && errno == EINVAL);
    atomic_store_explicit(&stop, 0, memory_order_release);
    CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
    CHECK(pthread_getcpuclockid(thread, &newer) == 0 &&
          (uint64_t)newer > (uint64_t)other);
    errno = 0;
    CHECK(clock_gettime(other, &after) == -1 && errno == EINVAL);
    CHECK(clock_gettime(newer, &after) == 0);
    atomic_store_explicit(&stop, 1, memory_order_release);
    CHECK(pthread_join(thread, NULL) == 0);
    puts("pthread-clock: PASS stable full-width IDs, explicit worker CPU "
         "clock, self-clock timer, exit/reuse invalidation");
    return 0;
}
