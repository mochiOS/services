/* Real OS integration: the waiting main thread must not supply the timer's
 * CPU clock. Run on mochiOS with the normal POSIX endpoint/runtime installed.
 */
#define _GNU_SOURCE
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
            fprintf(stderr, "thread-timer: FAIL line=%d errno=%d\n", __LINE__, \
                    errno);                                                    \
            return 1;                                                          \
        }                                                                      \
    } while (0)
static atomic_int ready, stop, failure;
static atomic_uint_fast64_t timer_id;
static const uintptr_t marker = UINT64_C(0x1234567876543210);

static void *worker(void *unused) {
    (void)unused;
    struct sigevent event = {0};
    event.sigev_notify = SIGEV_SIGNAL;
    event.sigev_signo = SIGUSR1;
    event.sigev_value.sival_ptr = (void *)marker;
    timer_t timer;
    if (timer_create(CLOCK_THREAD_CPUTIME_ID, &event, &timer)) {
        atomic_store(&failure, errno);
        atomic_store(&ready, 1);
        return NULL;
    }
    struct itimerspec arm = {.it_value = {.tv_nsec = 50000000}};
    if (timer_settime(timer, 0, &arm, NULL)) {
        atomic_store(&failure, errno);
        atomic_store(&ready, 1);
        return NULL;
    }
    atomic_store(&timer_id, (uint64_t)timer);
    atomic_store_explicit(&ready, 1, memory_order_release);
    while (!atomic_load_explicit(&stop, memory_order_acquire))
        __asm__ volatile("pause" ::: "memory");
    return NULL; /* Service must retire this thread's timers on native exit. */
}

int main(void) {
    sigset_t mask;
    CHECK(sigemptyset(&mask) == 0 && sigaddset(&mask, SIGUSR1) == 0);
    CHECK(pthread_sigmask(SIG_BLOCK, &mask, NULL) == 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
    struct timespec delay = {.tv_nsec = 1000000};
    for (unsigned n = 0;
         n < 5000 && !atomic_load_explicit(&ready, memory_order_acquire); ++n)
        CHECK(nanosleep(&delay, NULL) == 0);
    CHECK(atomic_load(&ready) && !atomic_load(&failure));
    struct timespec deadline = {.tv_sec = 3};
    siginfo_t info = {0};
    CHECK(sigtimedwait(&mask, &info, &deadline) == SIGUSR1);
    CHECK(info.si_code == SI_TIMER &&
          (uintptr_t)info.si_value.sival_ptr == marker);
    CHECK(timer_getoverrun((timer_t)atomic_load(&timer_id)) == 0);
    atomic_store_explicit(&stop, 1, memory_order_release);
    CHECK(pthread_join(thread, NULL) == 0);
    int retired = 0;
    for (unsigned n = 0; n < 1000 && !retired; ++n) {
        struct itimerspec value;
        int result = timer_gettime((timer_t)atomic_load(&timer_id), &value);
        retired = result == -1 && errno == EINVAL;
        CHECK(result == 0 || retired || (result == -1 && errno == ESRCH));
        if (!retired)
            CHECK(nanosleep(&delay, NULL) == 0);
    }
    CHECK(retired);
    puts("thread-timer: PASS worker CPU clock, cross-thread sigwait, local "
         "sigval, native thread-exit retirement");
    return 0;
}
