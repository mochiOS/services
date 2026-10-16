#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "clock-sleep: FAIL line=%d errno=%d\n", __LINE__, errno); \
    return 1; } } while (0)
_Static_assert(TIMER_ABSTIME == 4, "newlib timer flag");
static volatile sig_atomic_t caught;
static pthread_t sleeper;
static void handler(int signal) { (void)signal; ++caught; errno = EDOM; }
static void *sender(void *unused) {
    (void)unused;
    const struct timespec delay = {0, 50000000};
    if (nanosleep(&delay, 0) || pthread_kill(sleeper, SIGUSR1))
        return (void *)1;
    return 0;
}
static struct timespec after(struct timespec now, long nanoseconds) {
    now.tv_nsec += nanoseconds;
    now.tv_sec += now.tv_nsec / 1000000000;
    now.tv_nsec %= 1000000000;
    return now;
}
static int reached(struct timespec now, struct timespec target) {
    return now.tv_sec > target.tv_sec ||
        (now.tv_sec == target.tv_sec && now.tv_nsec >= target.tv_nsec);
}
int main(void) {
    sleeper = pthread_self();
    struct timespec zero = {0}, remaining = {123, 456};
    errno = E2BIG;
    CHECK(clock_nanosleep(CLOCK_MONOTONIC, 0, &zero, &remaining) == 0);
    CHECK(errno == E2BIG && remaining.tv_sec == 123 && remaining.tv_nsec == 456);
    CHECK(clock_nanosleep(CLOCK_MONOTONIC, 1, &zero, 0) == EINVAL && errno == E2BIG);
    CHECK(clock_nanosleep(3, 0, &zero, 0) == EINVAL && errno == E2BIG);
    CHECK(clock_nanosleep(2, 0, &zero, 0) == ENOTSUP && errno == E2BIG);
    for (int i = 0; i < 2; ++i) {
        int clock = i ? CLOCK_REALTIME : CLOCK_MONOTONIC;
        struct timespec now, target;
        CHECK(clock_gettime(clock, &now) == 0);
        target = after(now, 20000000);
        CHECK(clock_nanosleep(clock, TIMER_ABSTIME, &target, &remaining) == 0);
        CHECK(clock_gettime(clock, &now) == 0 && reached(now, target));
        CHECK(remaining.tv_sec == 123 && remaining.tv_nsec == 456);
        CHECK(clock_nanosleep(clock, TIMER_ABSTIME, &zero, &remaining) == 0);
    }
    struct sigaction action = {0};
    action.sa_handler = handler;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, 0) == 0);
    for (int absolute = 0; absolute < 2; ++absolute) {
        pthread_t thread;
        void *thread_result;
        struct timespec request = {5, 0};
        if (absolute) {
            CHECK(clock_gettime(CLOCK_MONOTONIC, &request) == 0);
            request.tv_sec += 5;
        }
        remaining = (struct timespec){123, 456};
        CHECK(pthread_create(&thread, 0, sender, 0) == 0);
        errno = E2BIG;
        CHECK(clock_nanosleep(CLOCK_MONOTONIC, absolute ? TIMER_ABSTIME : 0,
                             &request, &remaining) == EINTR);
        CHECK(errno == E2BIG);
        CHECK(pthread_join(thread, &thread_result) == 0 && thread_result == 0);
        if (absolute) {
            CHECK(remaining.tv_sec == 123 && remaining.tv_nsec == 456);
        } else {
            CHECK(remaining.tv_sec >= 0 && remaining.tv_sec < 5 &&
                  remaining.tv_nsec >= 0 && remaining.tv_nsec < 1000000000);
        }
    }
    CHECK(caught == 2);
    fprintf(stderr, "clock-sleep: pass relative/absolute/realtime/EINTR/errno\n");
    return 0;
}
