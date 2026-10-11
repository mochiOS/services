/* Isolated Compositor-slot KVM stress fixture, not a desktop test. Repeated
 * image replacement must release a sibling's long deadline before its expiry.
 * It also exceeds the old kernel heap leak's failure point (round 43).
 * Optional entry tracing: -DTRACE_IMAGE_START -Wl,--wrap=_start_c. */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ROUNDS 70
static atomic_uint worker_handle;

static uint64_t native_call(uint64_t number, uint64_t first, uint64_t second,
                            uint64_t third) {
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(first), "S"(second), "d"(third)
                     : "rcx", "r11", "memory");
    return number;
}

#ifdef TRACE_IMAGE_START
extern void __real__start_c(void *initial_stack) __attribute__((noreturn));
void __wrap__start_c(void *initial_stack) {
    static const char message[] = "native-wait-retirement: image entry\n";
    native_call(660, (uintptr_t)message, sizeof(message) - 1, 0);
    __real__start_c(initial_stack);
}

static void trace(unsigned round, const char *stage) {
    char message[96];
    int length = snprintf(message, sizeof(message),
                          "native-wait-retirement: round=%u %s\n", round, stage);
    if (length > 0 && (unsigned)length < sizeof(message))
        native_call(660, (uintptr_t)message, (unsigned)length, 0);
}
#else
static void trace(unsigned round, const char *stage) { (void)round; (void)stage; }
#endif

static void *worker(void *unused) {
    (void)unused;
    uint64_t handle = native_call(656, 0, 0, 0);
    if (handle == 0 || handle > UINT32_MAX) {
        atomic_store_explicit(&worker_handle, UINT32_MAX, memory_order_release);
        return NULL;
    }
    atomic_store_explicit(&worker_handle, (unsigned)handle, memory_order_release);
    struct timespec duration = {600, 0};
    int result = nanosleep(&duration, NULL);
    fprintf(stderr, "native-wait-retirement: FAIL sibling sleep returned %d errno=%d\n",
            result, errno);
    return NULL;
}

int main(int argc, char **argv) {
    unsigned round = 0;
    if (argc == 3 && strcmp(argv[1], "--round") == 0)
        round = (unsigned)strtoul(argv[2], NULL, 10);
    trace(round, "main entered");
    if (round == ROUNDS) {
        fprintf(stderr, "native-wait-retirement: PASS 70 exec replacements reclaim sleeping siblings\n");
        return 0;
    }
    if (round > ROUNDS) return 1;
    pthread_t thread;
    trace(round, "creating sibling");
    int error = pthread_create(&thread, NULL, worker, NULL);
    if (error != 0) {
        fprintf(stderr, "native-wait-retirement: FAIL round=%u pthread_create=%d\n", round, error);
        return 2;
    }
    int parked = 0;
    for (unsigned retry = 0; retry < 5000; ++retry) {
        unsigned handle = atomic_load_explicit(&worker_handle, memory_order_acquire);
        if (handle == UINT32_MAX) return 3;
        if (handle != 0) {
            struct { uint64_t tid, pid; uint32_t state, reserved; } status = {0};
            uint64_t result = native_call(658, handle, (uintptr_t)&status, sizeof(status));
            if (result != 0 || status.state == 5) return 4;
            if (status.state == 3 || status.state == 4) { parked = 1; break; }
        }
        struct timespec pause = {0, 1000000};
        if (nanosleep(&pause, NULL) != 0) {
            fprintf(stderr, "native-wait-retirement: FAIL round=%u parent sleep errno=%d\n", round, errno);
            return 5;
        }
    }
    if (!parked) return 6;
    trace(round, "sibling parked");
    if (round % 10 == 0)
        fprintf(stderr, "native-wait-retirement: round=%u sibling parked\n", round);
    char next[16];
    snprintf(next, sizeof(next), "%u", round + 1);
    char *arguments[] = {"native-wait-retirement", "--round", next, NULL};
    char *environment[] = {NULL};
    trace(round, "exec requested");
    execve("/system/services/compositor.service", arguments, environment);
    fprintf(stderr, "native-wait-retirement: FAIL round=%u exec errno=%d\n", round, errno);
    return 7;
}
