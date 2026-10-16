#define main guarded_address_probe
#include "native_address_wait_guarded.c"
#undef main

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

static volatile uint64_t *page;
static int started, stopped, worker_error;

static int64_t wait_value(void) {
    uint64_t number = 652; /* WaitOnAddress */
    register uint64_t deadline __asm__("r10") = 0;
    __asm__ volatile("syscall" : "+a"(number)
        : "D"((uint64_t)page), "S"(UINT64_MAX), "d"(8), "r"(deadline)
        : "rcx", "r11", "memory");
    return (int64_t)number;
}

static void *change_mapping(void *unused) {
    (void)unused;
    while (!__atomic_load_n(&started, __ATOMIC_ACQUIRE)) { }
    for (unsigned i = 0; i < 300; ++i) {
        if (mprotect((void *)page, 4096, PROT_NONE)
            || munmap((void *)page, 4096)) { worker_error = 1; break; }
        void *mapped = mmap((void *)page, 4096, PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
        if (mapped != (void *)page) { worker_error = 2; break; }
        page[0] = 0x71;
        if (mprotect((void *)page, 4096, PROT_READ)) { worker_error = 3; break; }
    }
    __atomic_store_n(&stopped, 1, __ATOMIC_RELEASE);
    return NULL;
}

int main(void) {
    if (guarded_address_probe()) return 7;
    page = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return 1;
    page[0] = 0x71;
    if (wait_value() != 1 || mprotect((void *)page, 4096, PROT_NONE)
        || wait_value() != INT64_C(-262142) || mprotect((void *)page, 4096, PROT_READ)) return 2;
    pthread_t thread;
    if (pthread_create(&thread, NULL, change_mapping, NULL)) return 3;
    unsigned changed = 0, rejected = 0;
    __atomic_store_n(&started, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&stopped, __ATOMIC_ACQUIRE)) {
        int64_t result = wait_value();
        if (result == 1) ++changed;
        else if (result == INT64_C(-262142)) ++rejected;
        else { fprintf(stderr, "address-wait-root: FAIL result=%ld\n", (long)result); return 4; }
    }
    if (pthread_join(thread, NULL) || worker_error || (!changed && !rejected)) return 5;
    if (wait_value() != 1 || munmap((void *)page, 4096) || wait_value() != INT64_C(-262142)) return 6;
    fprintf(stderr, "address-wait-root: PASS concurrent protection/unmap/remap changed=%u rejected=%u\n", changed, rejected);
    return 0;
}
