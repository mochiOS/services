#include <sys/time.h>
#include <sys/mman.h>
#include <time.h>
#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>

_Static_assert(sizeof(struct timeval) == 16, "timeval ABI");
_Static_assert(offsetof(struct timeval, tv_usec) == 8, "timeval microseconds ABI");

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "wall-clock: FAIL line=%d: %s errno=%d\n", __LINE__, #x, errno); \
  return 1; } } while (0)

static int at_most(struct timespec a, struct timeval b) {
  return a.tv_sec < b.tv_sec || (a.tv_sec == b.tv_sec && a.tv_nsec / 1000 <= b.tv_usec);
}
static int at_least(struct timespec a, struct timeval b) {
  return a.tv_sec > b.tv_sec || (a.tv_sec == b.tv_sec && a.tv_nsec / 1000 >= b.tv_usec);
}

int mochi_wall_clock_probe(void) {
  struct timespec before, after;
  struct timeval current;
  CHECK(clock_gettime(CLOCK_REALTIME, &before) == 0);
  errno = 71;
  CHECK(gettimeofday(&current, NULL) == 0 && errno == 71);
  CHECK(clock_gettime(CLOCK_REALTIME, &after) == 0);
  CHECK(current.tv_usec >= 0 && current.tv_usec < 1000000);
  CHECK(at_most(before, current) && at_least(after, current));
  CHECK(gettimeofday(&current, (void *)1) == 0);
  CHECK(gettimeofday((struct timeval *)1, NULL) == -1 && errno == EFAULT);
  CHECK(gettimeofday((struct timeval *)UINTPTR_MAX, NULL) == -1 && errno == EFAULT);
  CHECK(gettimeofday(NULL, NULL) == -1 && errno == EFAULT);
  void *readonly = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(readonly != MAP_FAILED);
  int fault = gettimeofday(readonly, NULL);
  int error = errno;
  CHECK(munmap(readonly, 4096) == 0);
  CHECK(fault == -1 && error == EFAULT);
  // This forces newlib's real _gettimeofday_r -> gettimeofday link and call.
  struct timeval first, last;
  time_t stored = (time_t)-1;
  CHECK(gettimeofday(&first, NULL) == 0);
  time_t result = time(&stored);
  CHECK(gettimeofday(&last, NULL) == 0);
  CHECK(result != (time_t)-1 && result == stored);
  CHECK(first.tv_sec <= result && result <= last.tv_sec);
  puts("wall-clock: PASS realtime timeval precision errno faults and newlib time reentrancy");
  return 0;
}
