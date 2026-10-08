#define _POSIX_C_SOURCE 200809L

#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

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
    puts("native-sleep: pass");
    return 0;
}
