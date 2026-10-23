/* Native IPC integration probe, not a host test. A one-way request has no
 * synchronous reply authority. Failed replies must not leave timer objects.
 */
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

enum { CONTEXT_GET = 628, SEND = 630, TIMER_CREATE = 107, MONOTONIC = 2 };
#define NOT_READY INT64_C(-262137)
#define CHECK(x)                                                               \
    do {                                                                       \
        if (!(x)) {                                                            \
            fprintf(stderr, "timer-create-reply: FAIL line=%d errno=%d\n",     \
                    __LINE__, errno);                                          \
            return 1;                                                          \
        }                                                                      \
    } while (0)
struct item {
    uint32_t handle, reserved;
    uint64_t rights;
};
struct attachments {
    uint32_t count, flags;
    struct item items[4];
};
_Static_assert(sizeof(struct attachments) == 72, "native attachment ABI");

static int64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                      uint64_t d) {
    register uint64_t fourth __asm__("r10") = d;
    __asm__ volatile("syscall"
                     : "+a"(number)
                     : "D"(a), "S"(b), "d"(c), "r"(fourth)
                     : "rcx", "r11", "memory");
    return (int64_t)number;
}
static void put32(unsigned char *p, uint32_t value) {
    for (unsigned n = 0; n < 4; ++n)
        p[n] = (unsigned char)(value >> (8 * n));
}
static void put64(unsigned char *p, uint64_t value) {
    for (unsigned n = 0; n < 8; ++n)
        p[n] = (unsigned char)(value >> (8 * n));
}
int main(void) {
    struct sigevent none = {0};
    none.sigev_notify = SIGEV_NONE;
    timer_t first;
    CHECK(timer_create(CLOCK_MONOTONIC, &none, &first) == 0);
    CHECK(timer_delete(first) == 0);
    uint64_t key;
    memcpy(&key, "POSXCTRL", 8);
    int64_t endpoint = native(CONTEXT_GET, key, 0, 0, 0);
    CHECK(endpoint > 0);
    unsigned char request[56] = {'P', 'O', 'S', 'X', 1, 0, TIMER_CREATE, 0};
    put32(request + 20, 24);        /* Timer-create payload length. */
    request[32] = 1;                /* Canonical timer frame version. */
    put32(request + 36, MONOTONIC); /* Notification kind zero is NONE. */
    struct attachments empty = {0};
    for (unsigned index = 0; index < 300; ++index) {
        put64(request + 8, UINT64_C(0x74520000) + index);
        int delivered = 0;
        for (unsigned retry = 0; retry < 10000 && !delivered; ++retry) {
            int64_t result =
                native(SEND, (uint64_t)endpoint, (uintptr_t)request,
                       sizeof(request), (uintptr_t)&empty);
            CHECK(result == 0 || result == NOT_READY);
            delivered = result == 0;
            if (!delivered)
                sched_yield();
        }
        CHECK(delivered);
    }
    /* The next synchronous request follows the one-way frames in the service
     * inbox. Fill the entire per-process quota; none may have been consumed by
     * the unpublishable IDs, and none of those IDs may have been recycled. */
    timer_t timers[128];
    for (unsigned index = 0; index < 128; ++index) {
        CHECK(timer_create(CLOCK_MONOTONIC, &none, &timers[index]) == 0);
        CHECK((uint64_t)timers[index] > (uint64_t)first + 300);
    }
    timer_t extra;
    CHECK(timer_create(CLOCK_MONOTONIC, &none, &extra) == -1 &&
          errno == EAGAIN);
    for (unsigned index = 0; index < 128; ++index)
        CHECK(timer_delete(timers[index]) == 0);
    puts("timer-create-reply: PASS one-way failed replies release quota and "
         "never recycle timer IDs");
    return 0;
}
