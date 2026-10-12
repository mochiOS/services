#define _GNU_SOURCE 1
/* Tests only native memory predicates. No POSIX condition-variable policy. */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

struct guard { uint64_t address, expected; };
static _Atomic uint64_t primary, notification, unrelated;
static _Atomic unsigned ready, finished;
static unsigned iteration;

static int64_t native_call(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                           uint64_t d, uint64_t e) {
    register uint64_t fourth __asm__("r10") = d;
    register uint64_t fifth __asm__("r8") = e;
    __asm__ volatile("syscall" : "+a"(number)
        : "D"(a), "S"(b), "d"(c), "r"(fourth), "r"(fifth)
        : "rcx", "r11", "memory");
    return (int64_t)number;
}
static void debug(const char *message) {
    native_call(660, (uintptr_t)message, strlen(message), 0, 0, 0);
}
#define CHECK(condition) do { if (!(condition)) { \
    char message[128]; snprintf(message, sizeof(message), \
        "native-address-guard: FAIL iteration=%u line=%u errno=%d\n", iteration, __LINE__, errno); \
    debug(message); return 1; \
} } while (0)

static void *waiter(void *unused) {
    (void)unused;
    struct guard guard = {(uintptr_t)&notification, 0};
    atomic_store(&ready, 1);
    int64_t result = native_call(684, (uintptr_t)&primary, 0, 8, UINT64_MAX, (uintptr_t)&guard);
    atomic_store(&finished, 1);
    return (void *)(intptr_t)result;
}
static int await_flag(_Atomic unsigned *flag) {
    for (unsigned retry = 0; retry < 2000; ++retry) {
        if (atomic_load(flag)) return 1;
        struct timespec delay = {0, 1000000};
        if (nanosleep(&delay, NULL)) return 0;
    }
    return 0;
}
int main(void) {
    struct guard guard = {(uintptr_t)&notification, 0};
    CHECK(native_call(684, (uintptr_t)&primary, 0, 8, UINT64_MAX, 0) == -14);
    CHECK(native_call(684, (uintptr_t)&primary, 0, 3, UINT64_MAX, (uintptr_t)&guard) == -22);
    struct guard bad = {(uintptr_t)&notification + 1, 0};
    CHECK(native_call(684, (uintptr_t)&primary, 0, 8, UINT64_MAX, (uintptr_t)&bad) == -22);
    atomic_store(&primary, 1);
    CHECK(native_call(684, (uintptr_t)&primary, 0, 8, UINT64_MAX, (uintptr_t)&guard) == 1);
    atomic_store(&primary, 0);
    atomic_store(&notification, 1);
    CHECK(native_call(684, (uintptr_t)&primary, 0, 8, UINT64_MAX, (uintptr_t)&guard) == 1);
    atomic_store(&notification, 0);
    CHECK(native_call(684, (uintptr_t)&primary, 0, 8, 0, (uintptr_t)&guard) == 2);
    unsigned actually_parked[2] = {0, 0};
    for (iteration = 0; iteration < 64; ++iteration) {
        atomic_store(&primary, 0);
        atomic_store(&notification, 0);
        atomic_store(&ready, 0);
        atomic_store(&finished, 0);
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, waiter, NULL) == 0);
        CHECK(await_flag(&ready));
        struct timespec delay = {0, 5000000};
        CHECK(nanosleep(&delay, NULL) == 0);
        CHECK(native_call(653, (uintptr_t)&unrelated, UINT64_MAX, 0, 0, 0) == 0);
        CHECK(!atomic_load(&finished));
        _Atomic uint64_t *word = iteration & 1 ? &notification : &primary;
        atomic_store(word, 1);
        int64_t woken = native_call(653, (uintptr_t)word, 1, 0, 0, 0);
        CHECK(woken == 0 || woken == 1);
        actually_parked[iteration & 1] += (unsigned)woken;
        CHECK(await_flag(&finished));
        void *result = (void *)99;
        CHECK(pthread_join(thread, &result) == 0 && ((intptr_t)result == 0 || (intptr_t)result == 1));
        CHECK(native_call(653, (uintptr_t)&primary, UINT64_MAX, 0, 0, 0) == 0);
        CHECK(native_call(653, (uintptr_t)&notification, UINT64_MAX, 0, 0, 0) == 0);
    }
    CHECK(actually_parked[0] && actually_parked[1]);
    atomic_store(&primary, 0);
    atomic_store(&notification, 0);
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    uint64_t deadline = (uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec + 20000000;
    CHECK(native_call(684, (uintptr_t)&primary, 0, 8, deadline, (uintptr_t)&guard) == 2);
    CHECK(native_call(653, (uintptr_t)&primary, UINT64_MAX, 0, 0, 0) == 0);
    CHECK(native_call(653, (uintptr_t)&notification, UINT64_MAX, 0, 0, 0) == 0);
    debug("native-address-guard: PASS 64 primary/guard wakeups, admission, timeout and subscription cleanup\n");
    return 0;
}
