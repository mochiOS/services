#define _POSIX_C_SOURCE 200809L
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>

#define CHECK(test) do { if (!(test)) { fprintf(stderr, "getrusage: FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
_Static_assert(sizeof(struct rusage) == 32, "newlib rusage ABI");
_Static_assert(_Alignof(struct rusage) == 8 && offsetof(struct rusage, ru_stime) == 16, "CPU duration layout");
static volatile uint64_t work;
static int duration(const struct rusage *usage, uint64_t *microseconds) {
    CHECK(usage->ru_utime.tv_sec >= 0 && usage->ru_stime.tv_sec >= 0);
    CHECK(usage->ru_utime.tv_usec >= 0 && usage->ru_utime.tv_usec < 1000000);
    CHECK(usage->ru_stime.tv_usec >= 0 && usage->ru_stime.tv_usec < 1000000);
    *microseconds = (uint64_t)(usage->ru_utime.tv_sec + usage->ru_stime.tv_sec) * 1000000
        + usage->ru_utime.tv_usec + usage->ru_stime.tv_usec;
    return 0;
}
static int burn_cpu(void) {
    clock_t start = clock(); CHECK(start != (clock_t)-1);
    for (;;) {
        for (unsigned i = 0; i < 65536; ++i) work = work * 1664525 + i + 1013904223;
        clock_t now = clock(); CHECK(now != (clock_t)-1 && now >= start);
        if (now - start >= CLOCKS_PER_SEC / 10) return 0;
    }
}
static int own_usage(void) {
    struct rusage before, after, unchanged;
    memset(&unchanged, 0x5a, sizeof(unchanged)); after = unchanged;
    errno = 0; CHECK(getrusage(7, &after) == -1 && errno == EINVAL
        && memcmp(&after, &unchanged, sizeof(after)) == 0);
    errno = 0; CHECK(getrusage(RUSAGE_SELF, NULL) == -1 && errno == EFAULT);
    errno = 42; CHECK(getrusage(RUSAGE_SELF, &before) == 0 && errno == 42);
    uint64_t first, last;
    CHECK(duration(&before, &first) == 0 && burn_cpu() == 0);
    CHECK(getrusage(RUSAGE_SELF, &after) == 0 && duration(&after, &last) == 0 && last >= first + 90000);
    before = after; first = last;
    struct timespec sleep = {.tv_sec = 0, .tv_nsec = 250000000};
    CHECK(nanosleep(&sleep, NULL) == 0);
    CHECK(getrusage(RUSAGE_SELF, &after) == 0 && duration(&after, &last) == 0
        && last >= first && last - first < 125000);
    puts("getrusage: SELF measures native CPU rather than sleeping wall time PASS");
    return 0;
}
static int waited_usage(void) {
    struct rusage before, after, repeated;
    CHECK(getrusage(RUSAGE_CHILDREN, &before) == 0);
    uint64_t baseline, measured;
    CHECK(duration(&before, &baseline) == 0 && baseline == 0);
    atomic_uint *ready = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(ready != MAP_FAILED); atomic_store_explicit(ready, 0, memory_order_release);
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        if (getrusage(RUSAGE_CHILDREN, &after) || duration(&after, &measured) || measured || burn_cpu()) _exit(91);
        atomic_store_explicit(ready, 1, memory_order_release);
        _exit(37);
    }
    while (!atomic_load_explicit(ready, memory_order_acquire)) {}
    CHECK(getrusage(RUSAGE_CHILDREN, &after) == 0 && duration(&after, &measured) == 0 && measured == baseline);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    CHECK(getrusage(RUSAGE_CHILDREN, &after) == 0 && duration(&after, &measured) == 0 && measured >= 90000);
    CHECK(getrusage(RUSAGE_CHILDREN, &repeated) == 0 && memcmp(&after, &repeated, sizeof(after)) == 0);
    baseline = measured;
    child = fork(); CHECK(child >= 0);
    if (!child) {
        /* Parent's previously accumulated CHILDREN time is not inherited. */
        if (getrusage(RUSAGE_CHILDREN, &after) || duration(&after, &measured) || measured) _exit(92);
        pid_t descendant = fork(); if (descendant < 0) _exit(93);
        if (!descendant) _exit(burn_cpu() ? 94 : 39);
        if (waitpid(descendant, &status, 0) != descendant || !WIFEXITED(status) || WEXITSTATUS(status) != 39) _exit(95);
        if (getrusage(RUSAGE_CHILDREN, &after) || duration(&after, &measured) || measured < 90000 || burn_cpu()) _exit(96);
        _exit(37);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 37);
    CHECK(getrusage(RUSAGE_CHILDREN, &after) == 0 && duration(&after, &measured) == 0 && measured >= baseline + 180000);
    CHECK(munmap(ready, 4096) == 0);
    puts("getrusage: waited children/descendants aggregate once, child starts empty PASS");
    return 0;
}
int main(void) {
    CHECK(own_usage() == 0 && waited_usage() == 0);
    puts("getrusage: PASS native SELF and authenticated waited CHILDREN CPU accounting");
    return 0;
}
