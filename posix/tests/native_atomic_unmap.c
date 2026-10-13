#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

static pthread_barrier_t start;
static void debug(const char *text) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number) : "D"((uintptr_t)text), "S"((uint64_t)strlen(text)) : "rcx", "r11", "memory");
}
static void *worker(void *unused) {
    (void)unused;
    int barrier = pthread_barrier_wait(&start);
    if (barrier != 0 && barrier != PTHREAD_BARRIER_SERIAL_THREAD) return (void *)(uintptr_t)1;
    for (unsigned round = 0; round < 100; ++round) {
        volatile unsigned char *base = mmap(NULL, 12288, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) return (void *)(uintptr_t)2;
        base[17] = 0x11; base[4096 + 17] = 0x22; base[8192 + 17] = 0x33;
        if (mprotect((void *)(base + 4096), 4096, PROT_READ) != 0) return (void *)(uintptr_t)3;
        if (munmap((void *)(base + 4096), 4096) != 0) return (void *)(uintptr_t)4;
        volatile unsigned char *middle = mmap((void *)(base + 4096), 4096,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (middle != base + 4096) return (void *)(uintptr_t)5;
        if (base[17] != 0x11 || base[8192 + 17] != 0x33) return (void *)(uintptr_t)6;
        for (unsigned i = 0; i < 4096; ++i) if (middle[i] != 0) return (void *)(uintptr_t)7;
        middle[17] = 0x44;
        if (munmap((void *)base, 12288) != 0) return (void *)(uintptr_t)8;
        if (munmap((void *)base, 12288) != 0) return (void *)(uintptr_t)9;
    }
    return NULL;
}
int main(void) {
    debug("native-atomic-unmap: start partial removal and reuse\n");
    pthread_t threads[6];
    if (pthread_barrier_init(&start, NULL, 6) != 0) return 1;
    for (unsigned i = 0; i < 6; ++i) if (pthread_create(&threads[i], NULL, worker, NULL) != 0) return 2;
    for (unsigned i = 0; i < 6; ++i) {
        void *result = NULL;
        if (pthread_join(threads[i], &result) != 0 || result != NULL) {
            char text[96]; snprintf(text, sizeof(text), "native-atomic-unmap: FAIL worker=%u code=%llu\n", i, (unsigned long long)(uintptr_t)result);
            debug(text); return 3;
        }
    }
    if (pthread_barrier_destroy(&start) != 0) return 4;
    debug("native-atomic-unmap: PASS 600 partial-unmap/remap rounds, zeroed reuse and surviving offsets\n");
    return 0;
}
