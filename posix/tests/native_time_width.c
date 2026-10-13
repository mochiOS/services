#include <stddef.h>
#include <time.h>
#include <sys/time.h>

_Static_assert(sizeof(time_t) == 8, "SDK time_t must be 64-bit");
_Static_assert(sizeof(suseconds_t) == 8, "SDK suseconds_t must be 64-bit");
_Static_assert(sizeof(struct timespec) == 16, "timespec ABI");
_Static_assert(offsetof(struct timespec, tv_nsec) == 8, "timespec nanoseconds offset");
_Static_assert(sizeof(struct timeval) == 16, "timeval ABI");
_Static_assert(offsetof(struct timeval, tv_usec) == 8, "timeval microseconds offset");
