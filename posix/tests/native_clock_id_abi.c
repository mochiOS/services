#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

_Static_assert(sizeof(clockid_t) == 8, "newlib clock selector ABI");
static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number)
        : "D"((uintptr_t)message), "S"((uint64_t)strlen(message))
        : "rcx", "r11", "memory");
}
#define CHECK(condition) do { if (!(condition)) { \
    char message[128]; snprintf(message, sizeof(message), \
        "native-clock-id: FAIL line=%u errno=%d\n", __LINE__, errno); \
    debug(message); return 1; \
} } while (0)

int main(void) {
    struct timespec output = {99, 98}, request = {0, 0}, remaining = {97, 96};
    const uint64_t invalid[] = {UINT64_MAX, (UINT64_C(1) << 32) | 1,
        (UINT64_C(1) << 32) | 2, (UINT64_C(1) << 32) | 3,
        (UINT64_C(1) << 32) | CLOCK_MONOTONIC, (uint64_t)INT32_MAX + 1};
    for (unsigned n = 0; n < sizeof(invalid) / sizeof(invalid[0]); ++n) {
        errno = 123;
        CHECK(clock_gettime((clockid_t)invalid[n], &output) == -1 && errno == EINVAL);
        CHECK(output.tv_sec == 99 && output.tv_nsec == 98);
        errno = 123;
        CHECK(clock_nanosleep((clockid_t)invalid[n], 0, &request, &remaining) == EINVAL && errno == 123);
        CHECK(remaining.tv_sec == 97 && remaining.tv_nsec == 96);
    }
    errno = 123;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &output) == 0 && errno == 123);
    CHECK(output.tv_sec >= 0 && output.tv_nsec >= 0 && output.tv_nsec < 1000000000);
    CHECK(clock_nanosleep(CLOCK_MONOTONIC, 0, &request, &remaining) == 0 && errno == 123);
    CHECK(remaining.tv_sec == 97 && remaining.tv_nsec == 96);
    debug("native-clock-id: PASS full-width C selectors, invalid IDs, untouched outputs and valid monotonic calls\n");
    return 0;
}
