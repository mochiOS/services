#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

static pthread_barrier_t start;
static atomic_uint_fast64_t cpus;
static void debug(const char *text) {
    uint64_t number = 660;
    __asm__ volatile("syscall" : "+a"(number) : "D"((uintptr_t)text), "S"((uint64_t)strlen(text)) : "rcx", "r11", "memory");
}
static unsigned cpu_id(void) {
    uint32_t a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    return b >> 24;
}
static void *worker(void *unused) {
    (void)unused;
    volatile unsigned char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return (void *)(uintptr_t)1;
    int barrier = pthread_barrier_wait(&start);
    if (barrier != 0 && barrier != PTHREAD_BARRIER_SERIAL_THREAD) return (void *)(uintptr_t)2;
    for (unsigned round = 0; round < 200; ++round) {
        unsigned cpu = cpu_id();
        if (cpu < 64) atomic_fetch_or(&cpus, UINT64_C(1) << cpu);
        page[17] = (unsigned char)round;
        if (mprotect((void *)page, 4096, PROT_READ) != 0) return (void *)(uintptr_t)3;
        if (page[17] != (unsigned char)round) return (void *)(uintptr_t)4;
        if (mprotect((void *)page, 4096, PROT_READ | PROT_WRITE) != 0) return (void *)(uintptr_t)5;
    }
    if (munmap((void *)page, 4096) != 0) return (void *)(uintptr_t)6;
    return NULL;
}
int main(void) {
    debug("native-tlb-shootdown: start concurrent permission changes\n");
    pthread_t threads[6];
    if (pthread_barrier_init(&start, NULL, 6) != 0) return 1;
    for (unsigned i = 0; i < 6; ++i) if (pthread_create(&threads[i], NULL, worker, NULL) != 0) return 2;
    for (unsigned i = 0; i < 6; ++i) {
        void *result = NULL;
        if (pthread_join(threads[i], &result) != 0 || result != NULL) {
            char text[128]; snprintf(text, sizeof(text), "native-tlb-shootdown: FAIL worker=%u code=%llu\n", i, (unsigned long long)(uintptr_t)result);
            debug(text); return 3;
        }
    }
    if (pthread_barrier_destroy(&start) != 0) return 4;
    uint64_t mask = atomic_load(&cpus);
    char text[128]; snprintf(text, sizeof(text), "native-tlb-shootdown: PASS 2400 protection changes, CPU mask=%llx\n", (unsigned long long)mask);
    debug(text);
    return 0;
}
