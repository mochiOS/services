#define _GNU_SOURCE 1
/* Isolated Compositor-slot probe of generic address-driven Handle waits. */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static _Atomic uint64_t word;
static _Atomic unsigned entered, finished;
static unsigned iteration;
struct wait_guard { uint64_t address, expected; };

static int64_t native_call(uint64_t number, uint64_t first, uint64_t second,
                           uint64_t third, uint64_t fourth) {
    register uint64_t argument __asm__("r10") = fourth;
    __asm__ volatile("syscall" : "+a"(number)
        : "D"(first), "S"(second), "d"(third), "r"(argument)
        : "rcx", "r11", "memory");
    return (int64_t)number;
}

static void debug(const char *message) {
    native_call(660, (uintptr_t)message, strlen(message), 0, 0);
}

#define CHECK(condition) do { if (!(condition)) { \
    char message[128]; \
    snprintf(message, sizeof(message), "native-guard-wake: FAIL iteration=%u line=%u errno=%d\n", iteration, __LINE__, errno); \
    debug(message); return 1; \
} } while (0)

static void *wait_for_guard(void *unused) {
    (void)unused;
    struct wait_guard guard = {(uintptr_t)&word, 0};
    atomic_store(&entered, 1);
    int64_t result = native_call(682, 0, 0, UINT64_MAX, (uintptr_t)&guard);
    atomic_store(&finished, 1);
    return (void *)(intptr_t)result;
}

static int await_flag(_Atomic unsigned *flag) {
    for (unsigned retry = 0; retry < 2000; ++retry) {
        if (atomic_load(flag)) return 1;
        struct timespec delay = {0, 1000000};
        if (nanosleep(&delay, NULL) != 0) return 0;
    }
    return 0;
}

int main(void) {
    unsigned address_wakes = 0;
    for (iteration = 0; iteration < 32; ++iteration) {
        atomic_store(&word, 0);
        atomic_store(&entered, 0);
        atomic_store(&finished, 0);
        pthread_t waiter;
        CHECK(pthread_create(&waiter, NULL, wait_for_guard, NULL) == 0);
        CHECK(await_flag(&entered));
        struct timespec delay = {0, 20000000};
        CHECK(nanosleep(&delay, NULL) == 0);
        atomic_store(&word, 1);
        int64_t count = native_call(653, (uintptr_t)&word, UINT64_MAX, 0, 0);
        CHECK(count == 0 || count == 1);
        address_wakes += (unsigned)count;
        CHECK(await_flag(&finished)); // No timeout or upcall wakes the native wait.
        void *result = NULL;
        CHECK(pthread_join(waiter, &result) == 0 && (intptr_t)result == -11);
        CHECK(native_call(653, (uintptr_t)&word, UINT64_MAX, 0, 0) == 0);
    }
    CHECK(address_wakes > 0); // At least one wait really blocked, rather than racing admission.
    struct wait_guard changed = {(uintptr_t)&word, 0};
    CHECK(native_call(682, 0, 0, UINT64_MAX, (uintptr_t)&changed) == -11);
    CHECK(native_call(653, (uintptr_t)&word, UINT64_MAX, 0, 0) == 0);
    debug("native-guard-wake: PASS 32 address wakeups of infinite guarded waits\n");
    return 0;
}
