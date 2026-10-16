/* Run as the fixture's initial process with the source-built runtime, not
 * the installed SDK runtime. No POSIX endpoint or service is needed. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

enum {
  HANDLE_CLOSE = 626,
  LAUNCH_HANDLE_GET = 628,
  THREAD_YIELD = 579,
  LAUNCH_VALUE_GET = 639,
  CONTEXT_HANDLE_SET = 648,
  CONTEXT_HANDLE_REMOVE = 661,
  CONTEXT_VALUE_SET = 662,
  CONTEXT_VALUE_REMOVE = 663,
  HANDLE_RIGHTS_GET = 664,
  MEMORY_OBJECT_CREATE = 671
};
#define NATIVE_NOT_FOUND INT64_C(-262135)
#define NATIVE_INVALID_ARGUMENT INT64_C(-262139)
#define NATIVE_INVALID_ADDRESS INT64_C(-262142)

static int64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c) {
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(a), "S"(b), "d"(c)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
#define CHECK(condition)                                                        \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "launch-lookup: FAIL line=%u errno=%d: %s\n", __LINE__,   \
              errno, #condition);                                              \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int main(void) {
  const uint64_t control = UINT64_C(0x4c52544358534f50); /* POSXCTRL */
  const uint64_t key = UINT64_C(0xfedcba9876543210);
  CHECK(native(LAUNCH_HANDLE_GET, control, 0, 0) == NATIVE_NOT_FOUND);
  CHECK(native(LAUNCH_HANDLE_GET, key, 0, 0) == NATIVE_NOT_FOUND);
  uint64_t value = 42;
  CHECK(native(LAUNCH_VALUE_GET, key, (uintptr_t)&value, 0) == NATIVE_NOT_FOUND);
  CHECK(value == 42);
  CHECK(native(LAUNCH_VALUE_GET, key, 0, 0) == NATIVE_NOT_FOUND);

  /* Both C allocation and explicit program-break changes use the runtime's
   * native-only bootstrap path when the inherited POSIX key is absent. */
  CHECK(sbrk(4096) != (void *)-1);
  CHECK(sbrk(-4096) != (void *)-1);
  unsigned char *bytes = malloc(37);
  CHECK(bytes != NULL);
  for (unsigned i = 0; i < 37; ++i)
    bytes[i] = (unsigned char)i;
  for (unsigned i = 0; i < 37; ++i)
    CHECK(bytes[i] == i);
  free(bytes);

  int64_t memory = native(MEMORY_OBJECT_CREATE, 4096, 0, 0);
  CHECK(memory > 0 && (uint64_t)memory <= UINT32_MAX);
  int64_t rights = native(HANDLE_RIGHTS_GET, memory, 0, 0);
  CHECK(native(CONTEXT_HANDLE_SET, key, memory, 0) == 0);
  CHECK(native(LAUNCH_HANDLE_GET, key, 0, 0) == memory);
  CHECK(native(CONTEXT_HANDLE_SET, key, UINT64_MAX, 0) ==
        NATIVE_INVALID_ARGUMENT);
  CHECK(native(LAUNCH_HANDLE_GET, key, 0, 0) == memory);
  CHECK(native(CONTEXT_HANDLE_REMOVE, key, 0, 0) == 0);
  CHECK(native(CONTEXT_HANDLE_REMOVE, key, 0, 0) == 0);
  CHECK(native(LAUNCH_HANDLE_GET, key, 0, 0) == NATIVE_NOT_FOUND);
  CHECK(native(HANDLE_RIGHTS_GET, memory, 0, 0) == rights);

  const uint64_t values[] = {0, UINT64_MAX, (uint64_t)NATIVE_NOT_FOUND};
  for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
    CHECK(native(CONTEXT_VALUE_SET, key, values[i], 0) == 0);
    value = 42;
    CHECK(native(LAUNCH_VALUE_GET, key, (uintptr_t)&value, 0) == 0);
    CHECK(value == values[i]);
    CHECK(native(LAUNCH_VALUE_GET, key, 0, 0) == NATIVE_INVALID_ADDRESS);
  }
  CHECK(native(CONTEXT_VALUE_REMOVE, key, 0, 0) == 0);
  CHECK(native(CONTEXT_VALUE_REMOVE, key, 0, 0) == 0);
  CHECK(native(LAUNCH_VALUE_GET, key, 0, 0) == NATIVE_NOT_FOUND);
  CHECK(native(CONTEXT_HANDLE_SET, key, memory, 0) == 0);
  CHECK(native(HANDLE_CLOSE, memory, 0, 0) == 0);
  CHECK(native(LAUNCH_HANDLE_GET, key, 0, 0) == NATIVE_NOT_FOUND);
  puts("launch-lookup: PASS native queries, scalar bits, close cleanup and C bootstrap allocation");
  fflush(stdout);
  for (;;)
    native(THREAD_YIELD, 0, 0, 0);
}
