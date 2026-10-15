#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(useconds_t) == 8, "mochiOS SDK useconds_t ABI");

static uint64_t nanoseconds(const struct timespec *value) {
  return (uint64_t)value->tv_sec * 1000000000ULL + (uint64_t)value->tv_nsec;
}

int main(void) {
  const struct timespec request = {
      .tv_sec = 0,
      .tv_nsec = 2000000,
  };
  struct timespec before;
  struct timespec after;

  if (clock_gettime(CLOCK_MONOTONIC, &before) != 0) {
    return 1;
  }
  if (nanosleep(&request, 0) != 0) {
    return 2;
  }
  if (clock_gettime(CLOCK_MONOTONIC, &after) != 0) {
    return 3;
  }
  if (nanoseconds(&after) - nanoseconds(&before) < 2000000ULL) {
    return 4;
  }
  if (sched_yield() != 0) {
    return 5;
  }
  errno = E2BIG;
  if (sleep(0) != 0 || errno != E2BIG) {
    return 6;
  }
  if (clock_gettime(CLOCK_MONOTONIC, &before) != 0 || sleep(1) != 0 ||
      clock_gettime(CLOCK_MONOTONIC, &after) != 0 ||
      nanoseconds(&after) - nanoseconds(&before) < 1000000000ULL) {
    return 7;
  }
  if (clock_gettime(CLOCK_MONOTONIC, &before) != 0 || usleep(2000) != 0 ||
      clock_gettime(CLOCK_MONOTONIC, &after) != 0 ||
      nanoseconds(&after) - nanoseconds(&before) < 2000000ULL) {
    return 8;
  }
  /* The full-width value must fail conversion, not truncate to Linux u32. */
  if (usleep((useconds_t)-1) != -1 || errno != EINVAL) {
    return 9;
  }
  puts("native-sleep: pass");
  return 0;
}
