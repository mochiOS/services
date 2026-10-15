#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { printf("resource-policy: FAIL line=%d\n", __LINE__); return 1; } } while (0)
static int64_t rp_native(uint64_t number, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f) {
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return (int64_t)number;
}
#define RP(n,a,b,c,d,e) rp_native(n,(uint64_t)(a),(uint64_t)(b),(uint64_t)(c),(uint64_t)(d),(uint64_t)(e),0)
static uint32_t rp_get(void) {
    struct { uint32_t count, flags; struct { uint32_t handle, reserved; uint64_t rights; } handles[4]; } objects = {0};
    unsigned char request[32] = {'P','O','S','X',1,0,94,0}, reply[32];
    uint64_t key; memcpy(&key, "POSXCTRL", 8);
    uint64_t endpoint = (uint64_t)RP(628, key, 0, 0, 0, 0);
    int64_t result = rp_native(632, endpoint, (uint64_t)request, sizeof(request), (uint64_t)reply, sizeof(reply), (uint64_t)&objects);
    if (result < 0 || ((uint64_t)result & UINT32_MAX) != 32 || objects.count != 1
        || objects.handles[0].rights != 0x41 || objects.handles[0].reserved) {
        printf("resource-policy: offer result=%lld count=%u rights=%llx\n", (long long)result, objects.count, (unsigned long long)objects.handles[0].rights);
        return 0;
    }
    int32_t status; memcpy(&status, reply + 24, 4);
    return status == 0 ? objects.handles[0].handle : 0;
}
static uint64_t rp_map(uint32_t handle) {
    if (RP(664, handle, 0, 0, 0, 0) != 0x41 || RP(672, handle, 0, 0, 0, 0) != 4096) return 0;
    if (RP(674, handle, "x", 1, 0, 0) != -13) return 0;
    if (RP(582, 0, 4096, 3, 2, handle) != -13) return 0;
    int64_t address = RP(582, 0, 4096, 1, 2, handle);
    if (address <= 0) { printf("resource-policy: readonly map=%lld\n", (long long)address); return 0; }
    int64_t protect = RP(584, address, 4096, 3, 0, 0);
    if (protect != -13) { printf("resource-policy: protection escalation=%lld\n", (long long)protect); return 0; }
    if (RP(626, handle, 0, 0, 0, 0) != 0) return 0;
    return (uint64_t)address;
}
static int rp_limit(uint64_t address, unsigned resource, uint64_t expected) {
    const _Atomic(uint64_t) *page = (const _Atomic(uint64_t) *)address;
    uint64_t magic; memcpy(&magic, "POSXRLM\0", 8);
    if (atomic_load_explicit(page, memory_order_relaxed) != magic
        || atomic_load_explicit(page + 1, memory_order_relaxed) != (UINT64_C(1) << 32 | 10)) return 0;
    for (unsigned attempt = 0; attempt < 10000; ++attempt) {
        uint64_t generation = atomic_load_explicit(page + 2, memory_order_relaxed);
        if (generation & 1) { sched_yield(); continue; }
        atomic_thread_fence(memory_order_acquire);
        uint64_t soft = atomic_load_explicit(page + 3 + resource * 2, memory_order_relaxed);
        uint64_t hard = atomic_load_explicit(page + 4 + resource * 2, memory_order_relaxed);
        atomic_thread_fence(memory_order_acquire);
        if (atomic_load_explicit(page + 2, memory_order_relaxed) == generation) return soft == expected && soft <= hard;
    }
    return 0;
}
int main(void) {
    uint32_t object = rp_get(); CHECK(object);
    uint64_t parent_page = rp_map(object); CHECK(parent_page);
    struct rlimit original;
    CHECK(getrlimit(RLIMIT_NOFILE, &original) == 0);
    CHECK(rp_limit(parent_page, RLIMIT_NOFILE, original.rlim_cur));
    int ready[2], go[2];
    CHECK(pipe(ready) == 0 && pipe(go) == 0);
    struct rlimit changed = original; changed.rlim_cur = 7;
    CHECK(setrlimit(RLIMIT_NOFILE, &changed) == 0 && rp_limit(parent_page, RLIMIT_NOFILE, 7));
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        close(ready[0]); close(go[1]);
        uint32_t child_object = rp_get();
        if (!child_object) _exit(11);
        uint64_t child_page = rp_map(child_object);
        if (!child_page || !rp_limit(child_page, RLIMIT_NOFILE, 7)) _exit(12);
        struct rlimit own = changed; own.rlim_cur = 3;
        if (setrlimit(RLIMIT_NOFILE, &own) || !rp_limit(child_page, RLIMIT_NOFILE, 3)
            || !rp_limit(parent_page, RLIMIT_NOFILE, 7)) _exit(13);
        char byte = 'r';
        if (write(ready[1], &byte, 1) != 1 || read(go[0], &byte, 1) != 1) _exit(14);
        if (!rp_limit(child_page, RLIMIT_NOFILE, 5) || !rp_limit(parent_page, RLIMIT_NOFILE, 7)) _exit(15);
        RP(583, child_page, 4096, 0, 0, 0);
        _exit(0);
    }
    CHECK(close(ready[1]) == 0 && close(go[0]) == 0);
    char byte = 0;
    CHECK(read(ready[0], &byte, 1) == 1);
    changed.rlim_cur = 5;
    CHECK(prlimit(child, RLIMIT_NOFILE, &changed, NULL) == 0);
    CHECK(rp_limit(parent_page, RLIMIT_NOFILE, 7));
    CHECK(write(go[1], "g", 1) == 1);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status));
    if (WEXITSTATUS(status)) printf("resource-policy: child status=%d\n", WEXITSTATUS(status));
    CHECK(WEXITSTATUS(status) == 0);
    CHECK(close(ready[0]) == 0 && close(go[1]) == 0);
    CHECK(setrlimit(RLIMIT_NOFILE, &original) == 0);
    CHECK(rp_limit(parent_page, RLIMIT_NOFILE, original.rlim_cur));
    CHECK(RP(583, parent_page, 4096, 0, 0, 0) == 0);
    puts("resource-policy: PASS READ|MAP-only delegation, denied write/map/protect escalation, live setrlimit/prlimit and independent child pages");
    return 0;
}
