#define _GNU_SOURCE 1
#include <time.h>

/* Compile with mochios-cc: validate the actual installed SDK, not host libc. */
_Static_assert(CLOCK_REALTIME == 1, "SDK realtime clock ID changed");
_Static_assert(CLOCK_MONOTONIC == 4, "SDK monotonic clock ID changed");
_Static_assert(CLOCK_MONOTONIC_RAW == 5, "SDK raw monotonic clock ID changed");
#ifdef CLOCK_PROCESS_CPUTIME_ID
_Static_assert(CLOCK_PROCESS_CPUTIME_ID == 2, "SDK process clock ID changed");
#endif
#ifdef CLOCK_THREAD_CPUTIME_ID
_Static_assert(CLOCK_THREAD_CPUTIME_ID == 3, "SDK thread clock ID changed");
#endif

int main(void) {
    struct timespec value;
    return clock_gettime(CLOCK_REALTIME, &value) != 0 ||
           clock_gettime(CLOCK_MONOTONIC_RAW, &value) != 0;
}
