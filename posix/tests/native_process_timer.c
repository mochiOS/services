/* Link against the freshly built runtime, not the SDK's archived runtime.
 * Run inside mochiOS to exercise the inherited POSIX endpoint and MemoryCopy.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <time.h>

_Static_assert(sizeof(clockid_t) == 8, "clockid_t ABI");
_Static_assert(sizeof(timer_t) == 8, "timer_t ABI");
_Static_assert(sizeof(struct timespec) == 16, "timespec ABI");
_Static_assert(sizeof(struct itimerspec) == 32, "itimerspec ABI");
_Static_assert(offsetof(struct itimerspec, it_interval) == 0, "interval ABI");
_Static_assert(offsetof(struct itimerspec, it_value) == 16, "value ABI");
_Static_assert(offsetof(struct sigevent, sigev_notify) == 0, "notify ABI");
_Static_assert(offsetof(struct sigevent, sigev_signo) == 4, "signo ABI");
_Static_assert(offsetof(struct sigevent, sigev_value) == 8, "sigval ABI");
_Static_assert(sizeof(union sigval) == 8, "sigval size");
_Static_assert(TIMER_ABSTIME == 4, "newlib timer flags, not Linux flags");
_Static_assert(CLOCK_REALTIME == 1 && CLOCK_PROCESS_CPUTIME_ID == 2 &&
                   CLOCK_MONOTONIC == 4,
               "newlib clocks");
_Static_assert(SIGEV_NONE == 1 && SIGEV_SIGNAL == 2 && SIGEV_THREAD == 3,
               "newlib notification selectors");
_Static_assert(SIGALRM == 14, "default timer signal");

#define CHECK(test)                                                             \
  do {                                                                          \
    if (!(test)) {                                                              \
      fprintf(stderr, "process-timer: FAIL line=%d errno=%d: %s\n", __LINE__,    \
              errno, #test);                                                   \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int main(void) {
  struct sigevent event = {.sigev_notify = SIGEV_NONE};
  const clockid_t clocks[] = {CLOCK_REALTIME, CLOCK_MONOTONIC,
                             CLOCK_PROCESS_CPUTIME_ID};
  for (size_t i = 0; i < sizeof(clocks) / sizeof(clocks[0]); i++) {
    timer_t timer;
    struct itimerspec value = {0}, previous;
    CHECK(timer_create(clocks[i], &event, &timer) == 0);
    CHECK(timer_gettime(timer, &value) == 0);
    CHECK(value.it_value.tv_sec == 0 && value.it_value.tv_nsec == 0);
    CHECK(timer_getoverrun(timer) == 0);
    value.it_value.tv_sec = 60;
    CHECK(timer_settime(timer, 0, &value, &previous) == 0);
    CHECK(previous.it_value.tv_sec == 0 && previous.it_value.tv_nsec == 0);
    CHECK(timer_gettime(timer, &value) == 0);
    CHECK(value.it_value.tv_sec > 0 && value.it_value.tv_sec <= 60);
    value.it_value.tv_sec = 0;
    value.it_value.tv_nsec = 0;
    CHECK(timer_settime(timer, 0, &value, &value) == 0);
    CHECK(value.it_value.tv_sec > 0);
    CHECK(timer_gettime(timer, &value) == 0);
    CHECK(value.it_value.tv_sec == 0 && value.it_value.tv_nsec == 0);
    errno = 0;
    CHECK(timer_settime(timer, 1, &value, NULL) == -1 && errno == EINVAL);
    CHECK(timer_delete(timer) == 0);
    errno = 0;
    CHECK(timer_getoverrun(timer) == -1 && errno == EINVAL);
  }

  timer_t timer;
  struct timespec now;
  struct itimerspec absolute = {0};
  CHECK(timer_create(CLOCK_MONOTONIC, &event, &timer) == 0);
  CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
  absolute.it_value = now;
  absolute.it_value.tv_sec += 60;
  CHECK(timer_settime(timer, TIMER_ABSTIME, &absolute, NULL) == 0);
  CHECK(timer_gettime(timer, &absolute) == 0);
  CHECK(absolute.it_value.tv_sec > 0 && absolute.it_value.tv_sec <= 60);
  CHECK(timer_delete(timer) == 0);

  void *unreadable = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS,
                          -1, 0);
  void *readonly = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS,
                        -1, 0);
  CHECK(unreadable != MAP_FAILED && readonly != MAP_FAILED);
  errno = 0;
  CHECK(timer_create(CLOCK_MONOTONIC, unreadable, &timer) == -1 &&
        errno == EFAULT);
  /* A failed output copy must not exhaust the server's 128 object limit. */
  for (unsigned i = 0; i < 160; i++) {
    errno = 0;
    CHECK(timer_create(CLOCK_MONOTONIC, &event, readonly) == -1 &&
          errno == EFAULT);
  }
  CHECK(timer_create(CLOCK_MONOTONIC, &event, &timer) == 0);
  errno = 0;
  CHECK(timer_gettime(timer, readonly) == -1 && errno == EFAULT);
  errno = 0;
  CHECK(timer_settime(timer, 0, unreadable, NULL) == -1 && errno == EFAULT);
  CHECK(timer_delete(timer) == 0);
  CHECK(munmap(unreadable, 4096) == 0);
  CHECK(munmap(readonly, 4096) == 0);
  puts("process-timer: PASS");
  return 0;
}
