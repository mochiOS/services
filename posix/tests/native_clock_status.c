/* Run twice with matching manifests. EXPECT_REALTIME_ALLOWED=0 removes only
 * system.time.read; the default case includes it. Neither mode accepts both
 * success and denial as a passing result. */
#define main describe_regressions
#include "native_clock_getres.c"
#undef main
#include <sys/mman.h>

struct native_instant {
  uint64_t seconds;
  uint32_t nanoseconds;
  uint32_t reserved;
};
_Static_assert(sizeof(struct native_instant) == 16, "native instant layout");
enum { CLOCK_READ = 640 };
/* The SDK gates the named CPU-clock macros on optional feature declarations.
 * Exercise its actual selector values without changing the installed SDK. */
enum { SDK_PROCESS_CPU_CLOCK = 2, SDK_THREAD_CPU_CLOCK = 3 };
#define NATIVE_ACCESS_DENIED INT64_C(-262138)
#ifndef EXPECT_REALTIME_ALLOWED
#define EXPECT_REALTIME_ALLOWED 1
#endif
static int64_t read_native(uint64_t clock, void *output) {
  uint64_t result = CLOCK_READ;
  __asm__ volatile("syscall"
                   : "+a"(result)
                   : "D"(clock), "S"(output)
                   : "rcx", "r11", "memory");
  return (int64_t)result;
}

int main(void) {
  CHECK(describe_regressions() == 0);
  const uint64_t monotonic = UINT64_C(0x4d4e55434c4b0002);
  const uint64_t process = UINT64_C(0x4d4e55434c4b0003);
  const uint64_t thread = UINT64_C(0x4d4e55434c4b0004);
  struct native_instant result;
#if EXPECT_REALTIME_ALLOWED
  CHECK(read_native(UINT64_C(0x4d4e55434c4b0001), &result) == 0);
#else
  CHECK(read_native(UINT64_C(0x4d4e55434c4b0001), &result) ==
        NATIVE_ACCESS_DENIED);
#endif
  for (unsigned i = 0; i < 4; ++i) {
    CHECK(read_native(i, &result) == NATIVE_INVALID_ARGUMENT);
  }
  CHECK(read_native(UINT64_MAX, &result) == NATIVE_INVALID_ARGUMENT);
  CHECK(read_native(monotonic, NULL) == NATIVE_INVALID_ADDRESS);
  CHECK(read_native(monotonic, (void *)1) == NATIVE_INVALID_ADDRESS);
  void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(page != MAP_FAILED);
  CHECK(mprotect(page, 4096, PROT_READ) == 0);
  CHECK(read_native(monotonic, page) == NATIVE_INVALID_ADDRESS);
  CHECK(describe(monotonic, (uintptr_t)page, 8) == NATIVE_INVALID_ADDRESS);
  for (unsigned i = 0; i < 3; ++i) {
    uint64_t clock = i == 0 ? monotonic : i == 1 ? process : thread;
    memset(&result, 0xa5, sizeof(result));
    CHECK(read_native(clock, &result) == 0);
    CHECK(result.nanoseconds < 1000000000 && result.reserved == 0);
  }
  unsigned char unaligned[18];
  memset(unaligned, 0x71, sizeof(unaligned));
  CHECK(read_native(monotonic, unaligned + 1) == 0);
  CHECK(unaligned[0] == 0x71 && unaligned[17] == 0x71);
  memcpy(&result, unaligned + 1, sizeof(result));
  CHECK(result.nanoseconds < 1000000000 && result.reserved == 0);
  for (unsigned i = 0; i < 4; ++i) {
    clockid_t clock = i == 0   ? CLOCK_REALTIME
                      : i == 1 ? CLOCK_MONOTONIC
                      : i == 2 ? SDK_PROCESS_CPU_CLOCK
                               : SDK_THREAD_CPU_CLOCK;
    struct timespec time;
    errno = 123;
#if !EXPECT_REALTIME_ALLOWED
    if (i == 0) {
      CHECK(clock_gettime(clock, &time) == -1 && errno == EACCES);
      continue;
    }
#endif
    CHECK(clock_gettime(clock, &time) == 0 && errno == 123);
    errno = 0;
    CHECK(clock_gettime(clock, page) == -1 && errno == EFAULT);
  }
  CHECK(munmap(page, 4096) == 0);
#if EXPECT_REALTIME_ALLOWED
  debug("native-clock-status: PASS authorized realtime, typed failures, "
        "readonly output, CPU clocks, unaligned output and POSIX errno\n");
#else
  debug("native-clock-status: PASS denied realtime, typed failures, readonly "
        "output, CPU clocks, unaligned output and POSIX errno\n");
#endif
  return 0;
}
