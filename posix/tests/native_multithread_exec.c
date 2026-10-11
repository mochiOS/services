/* Isolated Compositor-slot KVM regression. Requires the existing Input READY
 * gate and POSIX endpoint; this is not a desktop test. Image replacement must
 * retire siblings before releasing their user address space. */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define WORKER_KEY UINT64_C(0x574f524b45524558)
static atomic_uint worker_handle;

static uint64_t native_call(uint64_t number, uint64_t first, uint64_t second,
                            uint64_t third) {
    __asm__ volatile("syscall" : "+a"(number)
                     : "D"(first), "S"(second), "d"(third)
                     : "rcx", "r11", "memory");
    return number;
}

static int native_error(uint64_t result) {
    return result >= UINT64_MAX - 4094;
}

static void *sleeping_worker(void *unused) {
    (void)unused;
    uint64_t handle = native_call(656, 0, 0, 0);
    if (native_error(handle) || handle == 0 || handle > UINT32_MAX) {
        atomic_store_explicit(&worker_handle, UINT32_MAX, memory_order_release);
        return NULL;
    }
    atomic_store_explicit(&worker_handle, (unsigned)handle, memory_order_release);
    /* Stay parked long enough for the replacement image to inspect its native
     * ThreadHandle and exit. A broken kernel must not resume this old context. */
    for (;;) {
        struct timespec pause = {60, 0};
        nanosleep(&pause, NULL);
    }
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--verify-replacement") == 0) {
        struct {
            uint64_t thread_id, process_id;
            uint32_t state, reserved;
        } status = {0};
        uint64_t handle = native_call(628, WORKER_KEY, 0, 0);
        if (native_error(handle) || handle == 0) return 2;
        uint64_t result = native_call(658, handle, (uintptr_t)&status, sizeof(status));
        fprintf(stderr, "native-multithread-exec: sibling tid=%llu pid=%llu state=%u result=%lld\n",
                (unsigned long long)status.thread_id,
                (unsigned long long)status.process_id, status.state, (long long)result);
        if ((int64_t)result != -ESRCH && (result != 0 || status.state != 5)) {
            fprintf(stderr, "native-multithread-exec: FAIL old sibling survives image replacement\n");
            return 3;
        }
        fprintf(stderr, "native-multithread-exec: PASS old sibling cannot resume after image replacement\n");
        return 0;
    }
    pthread_t worker;
    if (pthread_create(&worker, NULL, sleeping_worker, NULL) != 0) return 4;
    unsigned handle = 0;
    for (unsigned retry = 0; retry < 5000 && handle == 0; ++retry) {
        struct timespec pause = {0, 1000000};
        nanosleep(&pause, NULL);
        handle = atomic_load_explicit(&worker_handle, memory_order_acquire);
    }
    if (handle == 0 || handle == UINT32_MAX) return 5;
    /* Explicitly preserve our own worker Handle through the opaque native
     * LaunchContext, not by acquiring an arbitrary PID/TID's Handle. */
    if (native_error(native_call(648, WORKER_KEY, handle, 0))) return 6;
    char *arguments[] = {"multithread-exec", "--verify-replacement", NULL};
    char *environment[] = {NULL};
    execve("/system/services/compositor.service", arguments, environment);
    fprintf(stderr, "native-multithread-exec: FAIL execve errno=%d\n", errno);
    return 7;
}
