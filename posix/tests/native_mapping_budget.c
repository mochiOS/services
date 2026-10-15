#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

#define CHECK(x) do { if (!(x)) { printf("mapping-budget: FAIL line=%d\n", __LINE__); return 1; } } while (0)
struct mb_request {
    uint64_t address, length, access, options, handle, offset, ceiling, reserved;
};
_Static_assert(sizeof(struct mb_request) == 64, "native mapping request ABI");
static int64_t mb_call(uint64_t number, uint64_t a, uint64_t b, uint64_t c) {
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return (int64_t)number;
}
static int64_t mb_map(uint64_t length, uint64_t access, uint64_t ceiling) {
    struct mb_request request = {.length = length, .access = access, .ceiling = ceiling};
    return mb_call(695, (uintptr_t)&request, sizeof(request), 0);
}
static int mb_unmap(uint64_t address, uint64_t length) {
    return mb_call(583, address, length, 0) == 0;
}
/* Find the exact ceiling permitting one new page. Every successful probe is
 * removed before the next: an ever-advancing placement cursor must not count
 * as live usage. No diagnostic authority or cross-process query is needed. */
static uint64_t mb_usage(void) {
    uint64_t low = 0, high = UINT64_C(1) << 36;
    while (low < high) {
        uint64_t middle = low + (high - low) / 2;
        int64_t address = mb_map(4096, 0, middle * 4096);
        if (address > 0) {
            if (!mb_unmap((uint64_t)address, 4096)) return UINT64_MAX;
            high = middle;
        } else if (address == -ENOMEM) {
            low = middle + 1;
        } else {
            printf("mapping-budget: unexpected native result=%lld\n", (long long)address);
            return UINT64_MAX;
        }
    }
    return low * 4096 - 4096;
}

static _Atomic(unsigned) mb_ready, mb_attempted, mb_release;
static _Atomic(uint64_t) mb_ceiling;
static int64_t mb_results[2];
static void *mb_worker(void *argument) {
    unsigned index = (unsigned)(uintptr_t)argument;
    atomic_fetch_add_explicit(&mb_ready, 1, memory_order_release);
    uint64_t ceiling;
    while (!(ceiling = atomic_load_explicit(&mb_ceiling, memory_order_acquire))) sched_yield();
    mb_results[index] = mb_map(4096, 3, ceiling);
    atomic_fetch_add_explicit(&mb_attempted, 1, memory_order_release);
    while (!atomic_load_explicit(&mb_release, memory_order_acquire)) sched_yield();
    if (mb_results[index] > 0 && !mb_unmap((uint64_t)mb_results[index], 4096)) return (void *)1;
    return NULL;
}

int main(void) {
    struct mb_request invalid = {.length = 4096, .ceiling = UINT64_MAX};
    CHECK(mb_call(695, (uintptr_t)&invalid, 63, 0) == -EINVAL);
    CHECK(mb_call(695, 0, 64, 0) == -EFAULT);
    invalid.reserved = 1;
    CHECK(mb_call(695, (uintptr_t)&invalid, 64, 0) == -EINVAL);
    invalid.reserved = 0; invalid.handle = UINT32_MAX;
    CHECK(mb_call(695, (uintptr_t)&invalid, 64, 0) == -EBADF);
    CHECK(mb_map(4096, 0, 0) == -ENOMEM);
    int64_t ram = mb_call(671, 4096, 0, 0);
    CHECK(ram > 0);
    int64_t readref = mb_call(627, (uint64_t)ram, 1, 0);
    int64_t mapref = mb_call(627, (uint64_t)ram, 0x41, 0);
    CHECK(readref > 0 && mapref > 0);
    invalid.handle = (uint64_t)readref; invalid.access = 1;
    CHECK(mb_call(695, (uintptr_t)&invalid, 64, 0) == -EACCES);
    invalid.handle = (uint64_t)mapref; invalid.options = 2; invalid.access = 3;
    CHECK(mb_call(695, (uintptr_t)&invalid, 64, 0) == -EACCES);
    invalid.access = 1;
    int64_t readonly = mb_call(695, (uintptr_t)&invalid, 64, 0);
    CHECK(readonly > 0 && mb_unmap((uint64_t)readonly, 4096));
    CHECK(mb_call(626, (uint64_t)readref, 0, 0) == 0);
    CHECK(mb_call(626, (uint64_t)mapref, 0, 0) == 0);
    CHECK(mb_call(626, (uint64_t)ram, 0, 0) == 0);

    uint64_t baseline = mb_usage();
    CHECK(baseline != UINT64_MAX && baseline > 4096);
    CHECK(mb_usage() == baseline);
    CHECK(mb_map(1, 0, baseline + 4095) == -ENOMEM);
    int64_t address = mb_map(1, 3, baseline + 4096);
    CHECK(address > 0);
    *(volatile unsigned char *)(uintptr_t)address = 73;
    CHECK(mb_usage() == baseline + 4096); /* faulted page is not counted twice */
    CHECK(mb_map(4096, 0, baseline + 4096) == -ENOMEM);
    CHECK(*(volatile unsigned char *)(uintptr_t)address == 73);
    CHECK(mb_unmap((uint64_t)address, 4096));
    CHECK(mb_usage() == baseline);

    const uint64_t reservation = UINT64_C(1) << 30;
    address = mb_map(reservation, 0, baseline + reservation);
    CHECK(address > 0 && mb_usage() == baseline + reservation);
    CHECK(mb_unmap((uint64_t)address + 4096, reservation - 8192));
    CHECK(mb_usage() == baseline + 8192);
    CHECK(mb_unmap((uint64_t)address, 4096));
    CHECK(mb_unmap((uint64_t)address + reservation - 4096, 4096));
    CHECK(mb_usage() == baseline);

    atomic_store(&mb_ready, 0); atomic_store(&mb_attempted, 0);
    atomic_store(&mb_release, 0); atomic_store(&mb_ceiling, 0);
    pthread_t threads[2];
    CHECK(pthread_create(&threads[0], NULL, mb_worker, (void *)0) == 0);
    CHECK(pthread_create(&threads[1], NULL, mb_worker, (void *)1) == 0);
    while (atomic_load_explicit(&mb_ready, memory_order_acquire) != 2) sched_yield();
    baseline = mb_usage();
    CHECK(baseline != UINT64_MAX);
    atomic_store_explicit(&mb_ceiling, baseline + 4096, memory_order_release);
    while (atomic_load_explicit(&mb_attempted, memory_order_acquire) != 2) sched_yield();
    int correct = (mb_results[0] > 0 && mb_results[1] == -ENOMEM)
        || (mb_results[1] > 0 && mb_results[0] == -ENOMEM);
    atomic_store_explicit(&mb_release, 1, memory_order_release);
    void *result;
    CHECK(pthread_join(threads[0], &result) == 0 && result == NULL);
    CHECK(pthread_join(threads[1], &result) == 0 && result == NULL);
    CHECK(correct);
    puts("mapping-budget: PASS live union accounting, page rounding, lazy reservations, partial unmap and concurrent atomic admission");
    return 0;
}
