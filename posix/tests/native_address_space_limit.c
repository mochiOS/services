#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { printf("address-space-limit: FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
static _Atomic(int) as_started;
static void *as_routine(void *argument) { atomic_store(&as_started, 1); return argument; }
extern size_t __mochios_reent_size(void);
static int64_t as_native(uint64_t number, uint64_t a, uint64_t b) {
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b) : "rcx", "r11", "memory");
    return (int64_t)number;
}
static uint64_t as_usage(void) {
    uint64_t low = 0, high = UINT64_C(1) << 36;
    while (low < high) {
        uint64_t middle = low + (high - low) / 2;
        uint64_t request[8] = {0, 4096, 0, 0, 0, 0, middle * 4096, 0};
        int64_t address = as_native(695, (uintptr_t)request, sizeof(request));
        if (address > 0) {
            if (as_native(583, (uint64_t)address, 4096) != 0) return UINT64_MAX;
            high = middle;
        } else if (address == -ENOMEM) low = middle + 1;
        else return UINT64_MAX;
    }
    return low * 4096 - 4096;
}

int main(void) {
    struct rlimit original, limit, observed;
    CHECK(getrlimit(RLIMIT_AS, &original) == 0);
    int file = open("/tmp/native-as-limit", O_CREAT | O_TRUNC | O_RDWR, 0600);
    CHECK(file >= 0 && unlink("/tmp/native-as-limit") == 0 && ftruncate(file, 4096) == 0);
    int shared = shm_open("/native-as-limit", O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(shared >= 0 && shm_unlink("/native-as-limit") == 0 && ftruncate(shared, 4096) == 0);
    unsigned char *view = mmap(NULL, 8192, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char *stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(view != MAP_FAILED && stack != MAP_FAILED);
    pthread_attr_t attr;
    CHECK(pthread_attr_init(&attr) == 0 && pthread_attr_setstack(&attr, stack, 65536) == 0);
    int64_t handles = as_native(680, 0, 0);
    CHECK(handles > 0);
    limit = original; limit.rlim_cur = 0;
    CHECK(setrlimit(RLIMIT_AS, &limit) == 0);
    CHECK(getrlimit(RLIMIT_AS, &observed) == 0 && observed.rlim_cur == 0);
    errno = 0;
    CHECK(mmap(NULL, 1, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED && errno == ENOMEM);
    errno = 0;
    CHECK(mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, file, 0) == MAP_FAILED && errno == ENOMEM);
    for (unsigned i = 0; i < 4; ++i) {
        errno = 0;
        CHECK(mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, shared, 0) == MAP_FAILED && errno == ENOMEM);
    }
    CHECK(as_native(680, 0, 0) == handles);
    errno = 0;
    CHECK(mmap(NULL, 0, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED && errno == EINVAL);
    CHECK(mprotect(view, 8192, PROT_READ | PROT_WRITE) == 0);
    view[0] = 31; view[4096] = 47;
    CHECK(munmap(view + 4096, 4096) == 0 && view[0] == 31);
    /* The break arena was already reserved and charged: activating a page
     * inside it does not create a new address-space reservation. */
    unsigned char *before = sbrk(0);
    CHECK(before != (void *)-1 && sbrk(1) == before && sbrk(-1) == before + 1);
    errno = 0;
    CHECK(malloc((size_t)512 * 1024 * 1024) == NULL && errno == ENOMEM);
    CHECK(sbrk(0) == before);
    pthread_t thread;
    errno = EDOM;
    CHECK(pthread_create(&thread, NULL, as_routine, NULL) == EAGAIN && errno == EDOM);
    CHECK(pthread_create(&thread, &attr, as_routine, NULL) == EAGAIN);
    CHECK(atomic_load(&as_started) == 0);
    stack[0] = 23; CHECK(stack[0] == 23);
    errno = 0;
    CHECK(sem_open("/native-as-sem", O_CREAT | O_EXCL, 0600, 1) == SEM_FAILED && errno == ENOMEM);
    CHECK(sem_unlink("/native-as-sem") == 0 && as_native(680, 0, 0) == handles);
    CHECK(setrlimit(RLIMIT_AS, &original) == 0);

    /* A supplied stack avoids the first allocation. Let only reent fit so
     * upcall-stack admission fails in the parent, before native ThreadCreate. */
    uint64_t baseline = as_usage(); CHECK(baseline != UINT64_MAX);
    limit.rlim_cur = baseline + ((__mochios_reent_size() + 4095) & ~(size_t)4095);
    CHECK(setrlimit(RLIMIT_AS, &limit) == 0);
    CHECK(pthread_create(&thread, &attr, as_routine, NULL) == EAGAIN);
    CHECK(atomic_load(&as_started) == 0 && as_usage() == baseline);
    CHECK(setrlimit(RLIMIT_AS, &original) == 0);
    CHECK(pthread_create(&thread, NULL, as_routine, (void *)17) == 0);
    void *result;
    CHECK(pthread_join(thread, &result) == 0 && result == (void *)17 && atomic_load(&as_started) == 1);
    CHECK(pthread_attr_destroy(&attr) == 0 && munmap(stack, 65536) == 0 && munmap(view, 4096) == 0);
    CHECK(close(file) == 0 && close(shared) == 0);

    int ready[2], go[2]; CHECK(pipe(ready) == 0 && pipe(go) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        close(ready[0]); close(go[1]); char byte = 'r';
        if (write(ready[1], &byte, 1) != 1 || read(go[0], &byte, 1) != 1) _exit(31);
        errno = 0;
        if (mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != MAP_FAILED || errno != ENOMEM) _exit(32);
        if (write(ready[1], &byte, 1) != 1 || read(go[0], &byte, 1) != 1) _exit(33);
        void *mapped = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapped == MAP_FAILED || munmap(mapped, 4096)) _exit(34);
        _exit(0);
    }
    CHECK(close(ready[1]) == 0 && close(go[0]) == 0); char byte;
    CHECK(read(ready[0], &byte, 1) == 1);
    limit.rlim_cur = 0; CHECK(prlimit(child, RLIMIT_AS, &limit, NULL) == 0);
    CHECK(write(go[1], "a", 1) == 1 && read(ready[0], &byte, 1) == 1);
    CHECK(getrlimit(RLIMIT_AS, &observed) == 0 && observed.rlim_cur == original.rlim_cur);
    CHECK(prlimit(child, RLIMIT_AS, &original, NULL) == 0 && write(go[1], "b", 1) == 1);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(close(ready[0]) == 0 && close(go[1]) == 0);
    puts("address-space-limit: PASS mmap, shared backing cleanup, malloc, prepared pthread resources, live limits and independent child policy");
    return 0;
}
