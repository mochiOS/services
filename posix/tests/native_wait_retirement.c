/* Isolated Compositor-slot KVM stress fixture, not a desktop test. Repeated
 * image replacement must release a sibling's long deadline before its expiry.
 * The 70-round stress run currently stalls near round 40 with both kernels;
 * keep it as a reproducer, not evidence of successful native completion. */
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
    if (round == ROUNDS) {
        fprintf(stderr, "native-wait-retirement: PASS 70 exec replacements reclaim sleeping siblings\n");
        return 0;
    }
    if (round > ROUNDS) return 1;
    pthread_t thread;
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
    if (round % 10 == 0)
        fprintf(stderr, "native-wait-retirement: round=%u sibling parked\n", round);
    char next[16];
    snprintf(next, sizeof(next), "%u", round + 1);
    char *arguments[] = {"native-wait-retirement", "--round", next, NULL};
    char *environment[] = {NULL};
    execve("/system/services/compositor.service", arguments, environment);
    fprintf(stderr, "native-wait-retirement: FAIL round=%u exec errno=%d\n", round, errno);
    return 7;
}
