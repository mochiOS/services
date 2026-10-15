#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { printf("image-as-limit: FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
static _Atomic(unsigned) ei_counter, ei_stop;
static uint64_t ei_handles(void) {
    uint64_t number = 680;
    __asm__ volatile("syscall" : "+a"(number) : "D"(0), "S"(0) : "rcx", "r11", "memory");
    return number;
}
#include "native_image_context.h"
static void *ei_worker(void *unused) {
    (void)unused;
    while (!atomic_load_explicit(&ei_stop, memory_order_acquire)) {
        atomic_fetch_add_explicit(&ei_counter, 1, memory_order_release);
        sched_yield();
    }
    return (void *)29;
}

static int image_limit_child(int argc, char **argv) {
    if (argc != 4 || strcmp(argv[1], "--verify-image-as") != 0) return -1;
    extern char **environ;
    char **cursor = environ;
    while (*cursor) ++cursor;
    uintptr_t *auxiliary = (uintptr_t *)(cursor + 1);
    uintptr_t policy = 0, upcall = 0, heap = 0;
    while (auxiliary[0]) {
        if (auxiliary[0] == 0x6d000001) policy = auxiliary[1];
        if (auxiliary[0] == 0x6d000002) upcall = auxiliary[1];
        if (auxiliary[0] == 0x6d000003) heap = auxiliary[1];
        auxiliary += 2;
    }
    CHECK(policy && upcall && heap && policy != upcall && upcall != heap);
    errno = 0;
    CHECK(mprotect((void *)policy, 4096, PROT_READ | PROT_WRITE) == -1 && errno == EACCES);
    volatile unsigned char *prepared = (volatile unsigned char *)upcall;
    prepared[0] = 37; CHECK(prepared[0] == 37);
    int channel = atoi(argv[2]), closed = atoi(argv[3]);
    CHECK(ei_context_after_image(closed) == 0);
    struct rlimit limit;
    CHECK(getrlimit(RLIMIT_AS, &limit) == 0 && limit.rlim_cur == 32 * 1024 * 1024);
    CHECK(getenv("IMAGE_AS_TOKEN") != NULL && !strcmp(getenv("IMAGE_AS_TOKEN"), "kept"));
    errno = 0;
    CHECK(fcntl(closed, F_GETFD, 0) == -1 && errno == EBADF);
    unsigned char *allocation = malloc(65536); CHECK(allocation != NULL);
    CHECK((uintptr_t)allocation >= heap && (uintptr_t)allocation < heap + 131072);
    for (unsigned i = 0; i < 65536; i += 4096) allocation[i] = (unsigned char)(i / 4096 + 3);
    for (unsigned i = 0; i < 65536; i += 4096) CHECK(allocation[i] == i / 4096 + 3);
    free(allocation);
    CHECK(write(channel, "R", 1) == 1 && close(channel) == 0);
    return 0;
}

int main(int argc, char **argv) {
    int mode = image_limit_child(argc, argv);
    if (mode >= 0) return mode;
    int channel[2]; CHECK(pipe(channel) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        CHECK(close(channel[0]) == 0);
        int file = open("/tmp/native-image-as", O_CREAT | O_TRUNC | O_RDWR, 0600);
        CHECK(file >= 0 && unlink("/tmp/native-image-as") == 0);
        CHECK(write(file, "abcdef", 6) == 6 && lseek(file, 3, SEEK_SET) == 3);
        CHECK(fcntl(file, F_SETFD, FD_CLOEXEC) == 0);
        uint64_t reference;
        CHECK(ei_context_seed(file, &reference) == 0);
        char channel_argument[16], closed_argument[16];
        snprintf(channel_argument, sizeof(channel_argument), "%d", channel[1]);
        snprintf(closed_argument, sizeof(closed_argument), "%d", file);
        char *arguments[] = {"image-as-limit", "--verify-image-as", channel_argument, closed_argument, NULL};
        char *environment[] = {"IMAGE_AS_TOKEN=kept", NULL};
        pthread_t worker;
        CHECK(pthread_create(&worker, NULL, ei_worker, NULL) == 0);
        while (!atomic_load_explicit(&ei_counter, memory_order_acquire)) sched_yield();
        struct rlimit original, limit;
        CHECK(getrlimit(RLIMIT_AS, &original) == 0);
        limit = original; limit.rlim_cur = 0;
        CHECK(setrlimit(RLIMIT_AS, &limit) == 0);
        uint64_t handles = ei_handles();
        errno = 0;
        CHECK(execve("/system/services/compositor.service", arguments, environment) == -1 && errno == ENOMEM);
        CHECK(ei_handles() == handles);
        CHECK(ei_context_unchanged(file, reference) == 0);
        unsigned count = atomic_load_explicit(&ei_counter, memory_order_acquire);
        for (unsigned spin = 0; spin < 100000 && atomic_load_explicit(&ei_counter, memory_order_acquire) == count; ++spin) sched_yield();
        CHECK(atomic_load_explicit(&ei_counter, memory_order_acquire) != count);
        CHECK(fcntl(file, F_GETFD, 0) == FD_CLOEXEC && lseek(file, 0, SEEK_CUR) == 3);
        char bytes[4] = {0}; CHECK(read(file, bytes, 3) == 3 && !strcmp(bytes, "def"));
        CHECK(setrlimit(RLIMIT_AS, &original) == 0);
        CHECK(ei_context_capacity_failure(file, reference, arguments, environment) == 0);
        atomic_store_explicit(&ei_stop, 1, memory_order_release);
        void *result;
        CHECK(pthread_join(worker, &result) == 0 && result == (void *)29);
        /* Success must retire a live sibling only after reversible image
         * preparation has finished, not require a single-threaded caller. */
        atomic_store_explicit(&ei_stop, 0, memory_order_release);
        atomic_store_explicit(&ei_counter, 0, memory_order_release);
        CHECK(pthread_create(&worker, NULL, ei_worker, NULL) == 0);
        while (!atomic_load_explicit(&ei_counter, memory_order_acquire)) sched_yield();
        CHECK(write(channel[1], "P", 1) == 1);
        limit.rlim_cur = 32 * 1024 * 1024;
        CHECK(setrlimit(RLIMIT_AS, &limit) == 0);
        execve("/system/services/compositor.service", arguments, environment);
        printf("image-as-limit: FAIL finite exec errno=%d\n", errno);
        _exit(1);
    }
    CHECK(close(channel[1]) == 0);
    char messages[2]; unsigned length = 0;
    while (length < sizeof(messages)) {
        ssize_t count = read(channel[0], messages + length, sizeof(messages) - length);
        CHECK(count > 0); length += (unsigned)count;
    }
    CHECK(!memcmp(messages, "PR", 2));
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(close(channel[0]) == 0);
    puts("image-as-limit: PASS failed exec preserves context, siblings and CLOEXEC FDs; capacity failure rolls back; successful finite-AS replacement atomically applies FD edits, preserves opaque keys/rights and adopts prepared regions");
    return 0;
}
