#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Compile twice with matching manifests: the denied case removes only
 * system.random.read. Neither mode accepts both success and denial. */
#ifndef EXPECT_RANDOM_ALLOWED
#define EXPECT_RANDOM_ALLOWED 1
#endif
extern ssize_t getrandom(void *, size_t, unsigned);
enum { RANDOM_FILL = 607 };
#define NATIVE_LIMIT_EXCEEDED INT64_C(-262143)
#define NATIVE_INVALID_ADDRESS INT64_C(-262142)
#define NATIVE_ACCESS_DENIED INT64_C(-262138)
#define CHECK(value)                                                           \
  do {                                                                         \
    if (!(value)) {                                                            \
      printf("native-random: FAIL line=%u errno=%d\n", __LINE__, errno);       \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int64_t fill(void *output, uint64_t length) {
  uint64_t value = RANDOM_FILL;
  __asm__ volatile("syscall"
                   : "+a"(value)
                   : "D"(output), "S"(length)
                   : "rcx", "r11", "memory");
  return (int64_t)value;
}

int main(void) {
  unsigned char bytes[643];
  memset(bytes, 0x71, sizeof(bytes));
  errno = 0;
  CHECK(getrandom(bytes, 1, UINT32_C(1) << 31) == -1 && errno == EINVAL);
  errno = 0;
  CHECK(getentropy(bytes, 257) == -1 && errno == EIO);
  CHECK(getentropy(NULL, 0) == 0);
#if EXPECT_RANDOM_ALLOWED
  CHECK(fill(NULL, 0) == 0);
  CHECK(fill(NULL, 1) == NATIVE_INVALID_ADDRESS);
  CHECK(fill(bytes, UINT64_MAX) == NATIVE_LIMIT_EXCEEDED);
  CHECK(fill(bytes + 1, 641) == 641);
  CHECK(bytes[0] == 0x71 && bytes[642] == 0x71);
  for (unsigned flags = 0; flags <= 3; ++flags) {
    errno = 123;
    CHECK(getrandom(bytes + 1, 641, flags) == 641 && errno == 123);
    CHECK(bytes[0] == 0x71 && bytes[642] == 0x71);
  }
  errno = 123;
  CHECK(getentropy(bytes + 1, 256) == 0 && errno == 123);
  void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(page != MAP_FAILED && mprotect(page, 4096, PROT_READ) == 0);
  CHECK(fill(page, 1) == NATIVE_INVALID_ADDRESS);
  errno = 0;
  CHECK(getrandom(page, 1, 0) == -1 && errno == EFAULT);
  errno = 0;
  CHECK(getentropy(page, 1) == -1 && errno == EFAULT);
  CHECK(munmap(page, 4096) == 0);
  puts("native-random: PASS authorized source, native failures, chunk bounds, "
       "flags, getentropy and readonly output");
#else
  CHECK(fill(bytes, 1) == NATIVE_ACCESS_DENIED);
  CHECK(fill(NULL, 0) == NATIVE_ACCESS_DENIED);
  errno = 0;
  CHECK(getrandom(bytes, 1, 0) == -1 && errno == EACCES);
  errno = 0;
  CHECK(getentropy(bytes, 1) == -1 && errno == EACCES);
  for (unsigned i = 0; i < sizeof(bytes); ++i)
    CHECK(bytes[i] == 0x71);
  puts(
      "native-random: PASS denied source, no output mutation and POSIX EACCES");
#endif
  return 0;
}
