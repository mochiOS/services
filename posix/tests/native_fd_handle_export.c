#define _GNU_SOURCE
#include <errno.h>
#include <mochi/handle.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Native mechanism numbers from core/crates/abi/src/lib.rs, not POSIX traps. */
enum {
  HANDLE_CLOSE = 626,
  HANDLE_READ = 634,
  HANDLE_WRITE = 635,
  HANDLE_RIGHTS_GET = 664,
};
enum { RIGHT_READ = 1, RIGHT_WRITE = 2, RIGHT_WAIT = 1 << 4 };
static const uint64_t RIGHT_TRANSFER = UINT64_C(1) << 63;
/* mnu_abi::status::Error::AccessDenied; raw native calls do not return errno.
 */
static const uint64_t NATIVE_ACCESS_DENIED = UINT64_C(0xfffffffffffc0006);
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      printf("fd-handle-export: FAIL line=%d errno=%d\n", __LINE__, errno);    \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int64_t native3(uint64_t n, uint64_t a, uint64_t b, uint64_t c) {
  __asm__ volatile("syscall"
                   : "+a"(n)
                   : "D"(a), "S"(b), "d"(c)
                   : "rcx", "r11", "memory");
  return (int64_t)n;
}

int main(void) {
  _Static_assert(sizeof(struct mochi_fd_handle) == 24, "export size");
  _Static_assert(offsetof(struct mochi_fd_handle, rights) == 8,
                 "rights offset");
  _Static_assert(offsetof(struct mochi_fd_handle, metadata) == 16,
                 "metadata offset");
  int descriptors[2];
  CHECK(pipe(descriptors) == 0);
  struct mochi_fd_handle exported = {0};
  errno = 0;
  CHECK(mochi_fd_export(descriptors[0], RIGHT_WRITE, &exported) == -1 &&
        errno == EACCES);
  void *unwritable =
      mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(unwritable != MAP_FAILED);
  errno = 0;
  CHECK(mochi_fd_export(descriptors[0], RIGHT_READ, unwritable) == -1 &&
        errno == EFAULT);
  CHECK(munmap(unwritable, 4096) == 0);
  uint64_t rights = RIGHT_READ | RIGHT_WAIT | RIGHT_TRANSFER;
  CHECK(mochi_fd_export(descriptors[0], rights, &exported) == 0);
  CHECK(exported.handle != 0 && exported.reserved == 0 &&
        exported.rights == rights);
  CHECK(native3(HANDLE_RIGHTS_GET, exported.handle, 0, 0) == (int64_t)rights);
  CHECK((uint64_t)native3(HANDLE_WRITE, exported.handle, (uint64_t) "x", 1) ==
        NATIVE_ACCESS_DENIED);
  CHECK(close(descriptors[0]) == 0);
  CHECK(write(descriptors[1], "hello", 5) == 5);
  char bytes[6] = {0};
  CHECK(native3(HANDLE_READ, exported.handle, (uint64_t)bytes, 5) == 5);
  CHECK(strcmp(bytes, "hello") == 0);
  CHECK(native3(HANDLE_CLOSE, exported.handle, 0, 0) == 0);
  CHECK(close(descriptors[1]) == 0);
  puts(
      "fd-handle-export: PASS attenuated rights, denied escalation, fault-safe "
      "copyout and independent stream ownership");
  return 0;
}
