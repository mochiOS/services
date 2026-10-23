/* Native pthread/Thread Handle integration probe; not a host executable. */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

enum { CLOSE = 626, DUPLICATE = 627, CURRENT_THREAD = 656, THREAD_CLOCK = 701 };
#define ACCESS_DENIED INT64_C(-262138)
#define INVALID_ARGUMENT INT64_C(-262139)
#define CHECK(x)                                                               \
    do {                                                                       \
        if (!(x)) {                                                            \
            fprintf(stderr, "thread-clock: FAIL line=%d errno=%d\n", __LINE__, \
                    errno);                                                    \
            return 1;                                                          \
        }                                                                      \
    } while (0)
struct instant {
    uint64_t seconds;
    uint32_t nanoseconds, reserved;
};
_Static_assert(sizeof(struct instant) == 16, "native clock ABI");
static atomic_uint handle;
static atomic_int stop;

static int64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c) {
    __asm__ volatile("syscall"
                     : "+a"(number)
                     : "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return (int64_t)number;
}
static int64_t sample(uint32_t object, struct instant *value) {
    return native(THREAD_CLOCK, object, (uintptr_t)value, sizeof(*value));
}
static void *worker(void *unused) {
    (void)unused;
    int64_t reference = native(CURRENT_THREAD, 0, 0, 0);
    atomic_store_explicit(&handle,
                          reference > 0 && reference <= UINT32_MAX
                              ? (uint32_t)reference
                              : UINT32_MAX,
                          memory_order_release);
    while (!atomic_load_explicit(&stop, memory_order_acquire))
        __asm__ volatile("pause" ::: "memory");
    return NULL;
}
int main(void) {
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
    uint32_t object = 0;
    struct timespec delay = {0, 1000000};
    for (unsigned retry = 0; retry < 5000 && !object; ++retry) {
        nanosleep(&delay, NULL);
        object = atomic_load_explicit(&handle, memory_order_acquire);
    }
    CHECK(object && object != UINT32_MAX);
    struct instant before = {0}, after = {0};
    CHECK(sample(0, &before) == INVALID_ARGUMENT);
    int64_t wait_only = native(DUPLICATE, object, 0x10, 0);
    int64_t signal_only = native(DUPLICATE, object, 0x20, 0);
    CHECK(wait_only > 0 && signal_only > 0);
    CHECK(sample((uint32_t)signal_only, &before) == ACCESS_DENIED);
    CHECK(sample((uint32_t)wait_only, &before) == 0);
    CHECK(!before.reserved && before.nanoseconds < 1000000000);
    /* The calling thread sleeps while the selected worker executes. Sample
     * only through its explicit WAIT Handle, not a PID/TID or caller clock. */
    int advanced = 0;
    for (unsigned retry = 0; retry < 100 && !advanced; ++retry) {
        delay.tv_nsec = 10000000;
        CHECK(nanosleep(&delay, NULL) == 0);
        CHECK(sample((uint32_t)wait_only, &after) == 0);
        CHECK(!after.reserved && after.nanoseconds < 1000000000);
        CHECK(after.seconds > before.seconds ||
              (after.seconds == before.seconds &&
               after.nanoseconds >= before.nanoseconds));
        advanced = after.seconds > before.seconds ||
                   after.nanoseconds > before.nanoseconds;
    }
    CHECK(advanced);
    atomic_store_explicit(&stop, 1, memory_order_release);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(native(CLOSE, wait_only, 0, 0) == 0);
    CHECK(native(CLOSE, signal_only, 0, 0) == 0);
    CHECK(native(CLOSE, object, 0, 0) == 0);
    puts("thread-clock: PASS explicit worker WAIT handle, attenuated "
         "authority, CPU advance while caller sleeps");
    return 0;
}
