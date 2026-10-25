#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "memory-advice: FAIL line=%d errno=%d: %s\n", __LINE__, errno, #x); \
  return 1; } } while (0)

int mochi_memory_advice_probe(void) {
  const size_t page = (size_t)sysconf(_SC_PAGESIZE);
  unsigned char *bytes = mmap(NULL, page * 3, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(bytes != MAP_FAILED);
  bytes[0] = 0xa5;
  bytes[page * 3 - 1] = 0x5a;
  const int hints[] = {POSIX_MADV_NORMAL, POSIX_MADV_RANDOM,
      POSIX_MADV_SEQUENTIAL, POSIX_MADV_WILLNEED, POSIX_MADV_DONTNEED};
  for (size_t i = 0; i < sizeof(hints) / sizeof(hints[0]); ++i) {
    errno = 123;
    CHECK(posix_madvise(bytes, page * 3, hints[i]) == 0 && errno == 123);
    CHECK(bytes[0] == 0xa5 && bytes[page * 3 - 1] == 0x5a);
  }
  CHECK(mprotect(bytes + page, page, PROT_NONE) == 0);
  CHECK(posix_madvise(bytes, page * 3, POSIX_MADV_DONTNEED) == 0);
  CHECK(mprotect(bytes + page, page, PROT_READ | PROT_WRITE) == 0);
  bytes[page] = 71;
  CHECK(posix_madvise(bytes + page, page, POSIX_MADV_DONTNEED) == 0);
  CHECK(bytes[page] == 71);
  CHECK(munmap(bytes + page, page) == 0);
  errno = 123;
  CHECK(posix_madvise(bytes, page * 3, POSIX_MADV_NORMAL) == ENOMEM && errno == 123);
  CHECK(posix_madvise(bytes, page + 1, POSIX_MADV_WILLNEED) == ENOMEM);
  CHECK(posix_madvise(bytes, 1, POSIX_MADV_RANDOM) == 0);
  CHECK(posix_madvise(bytes + 1, 1, POSIX_MADV_NORMAL) == EINVAL);
  CHECK(posix_madvise(bytes, page, 999) == EINVAL);
  CHECK(posix_madvise(bytes, 0, POSIX_MADV_NORMAL) == EINVAL);
  CHECK(posix_madvise(NULL, page, POSIX_MADV_NORMAL) == ENOMEM);
  CHECK(posix_madvise((void *)(UINTPTR_MAX & ~(uintptr_t)(page - 1)), page * 2,
      POSIX_MADV_NORMAL) == ENOMEM);
  CHECK(bytes[0] == 0xa5 && bytes[page * 3 - 1] == 0x5a);
  CHECK(munmap(bytes, page) == 0 && munmap(bytes + page * 2, page) == 0);
  int fd = open("/system/bin/llvm-runtime-probe", O_RDONLY);
  CHECK(fd >= 0);
  unsigned char *file = mmap(NULL, page, PROT_READ, MAP_PRIVATE, fd, 0);
  CHECK(file != MAP_FAILED && close(fd) == 0);
  CHECK(posix_madvise(file, page, POSIX_MADV_DONTNEED) == 0);
  CHECK(file[0] == 0x7f && file[1] == 'E' && file[2] == 'L' && file[3] == 'F');
  CHECK(munmap(file, page) == 0);
  puts("memory-advice: PASS validation holes PROT_NONE preserved contents file mapping and errno");
  return 0;
}
