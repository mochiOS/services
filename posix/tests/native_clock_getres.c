#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static void debug(const char *message) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number)
        : "D"((uintptr_t)message), "S"((uint64_t)strlen(message))
        : "rcx", "r11", "memory");
}
#define CHECK(x) do { if (!(x)) { char text[128]; snprintf(text, sizeof(text), \
    "native-clock-getres: FAIL line=%u errno=%d\n", __LINE__, errno); debug(text); return 1; } } while (0)

static int64_t describe(uint64_t clock, uint64_t output, uint64_t length) {
    uint64_t number = 685;
    __asm__ volatile("syscall" : "+a"(number)
        : "D"(clock), "S"(output), "d"(length) : "rcx", "r11", "memory");
    return (int64_t)number;
}

int main(void) {
    uint64_t quantum = 0;
    const uint64_t native = UINT64_C(0x4d4e55434c4b0002);
    CHECK(describe(native, (uintptr_t)&quantum, sizeof(quantum)) == 0 && quantum != 0);
    CHECK(describe(CLOCK_MONOTONIC, (uintptr_t)&quantum, sizeof(quantum)) == -22);
    CHECK(describe(native, (uintptr_t)&quantum, 7) == -22);
    CHECK(describe(native, 0, 8) == -14);
    CHECK(describe(native, 1, 8) == -14);
    struct timespec result = {99, 98};
    for (unsigned clock = 0; clock <= 9; ++clock) {
        errno = 123;
        CHECK(clock_getres((clockid_t)clock, &result) == 0 && errno == 123);
        CHECK(result.tv_sec >= 0 && result.tv_nsec >= 0 && result.tv_nsec < 1000000000);
        CHECK(result.tv_sec != 0 || result.tv_nsec != 0);
        CHECK((uint64_t)result.tv_sec * 1000000000 + (uint64_t)result.tv_nsec == quantum);
        CHECK(clock_getres((clockid_t)clock, NULL) == 0 && errno == 123);
    }
    const uint64_t invalid[] = {UINT64_MAX, (UINT64_C(1) << 32) | CLOCK_REALTIME,
        (UINT64_C(1) << 32) | CLOCK_MONOTONIC, (uint64_t)INT32_MAX + 1, 10};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        result = (struct timespec){99, 98}; errno = 123;
        CHECK(clock_getres((clockid_t)invalid[i], &result) == -1 && errno == EINVAL);
        CHECK(result.tv_sec == 99 && result.tv_nsec == 98);
        CHECK(clock_getres((clockid_t)invalid[i], NULL) == -1 && errno == EINVAL);
    }
    debug("native-clock-getres: PASS native source quantum, all SDK clock aliases, NULL output, full-width invalid selectors and errno\n");
    return 0;
}
