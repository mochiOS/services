#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

enum {
  CREATE = 671,
  LENGTH = 672,
  RESIZE = 686,
  MAP = 582,
  UNMAP = 583,
  CLOSE = 626,
  DUPLICATE = 627,
  RIGHTS = 664,
  IMAGE_CLONE = 679
};
static int64_t native(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                      uint64_t d, uint64_t e, uint64_t f) {
  register uint64_t r10 __asm__("r10") = d;
  register uint64_t r8 __asm__("r8") = e;
  register uint64_t r9 __asm__("r9") = f;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "memory-resize: FAIL line=%u condition=%s errno=%d\n",   \
              __LINE__, #condition, errno);                                    \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int main(void) {
  CHECK(native(CREATE, 0, 0, 0, 0, 0, 0) == -22);
  CHECK(native(CREATE, 4096, 2, 0, 0, 0, 0) == -22);
  int64_t fixed = native(CREATE, 4096, 0, 0, 0, 0, 0);
  CHECK(fixed > 0 && !(native(RIGHTS, fixed, 0, 0, 0, 0, 0) & 256));
  CHECK(native(RESIZE, fixed, 8192, 0, 0, 0, 0) == -13);
  CHECK(native(CLOSE, fixed, 0, 0, 0, 0, 0) == 0);
  int64_t object = native(CREATE, 0, 1, 0, 0, 0, 0);
  CHECK(object > 0 && (native(RIGHTS, object, 0, 0, 0, 0, 0) & 256));
  CHECK(native(LENGTH, object, 0, 0, 0, 0, 0) == 0);
  CHECK(native(RESIZE, object, 12288, 0, 0, 0, 0) == 0);
  CHECK(native(LENGTH, object, 0, 0, 0, 0, 0) == 12288);
  int64_t readonly = native(DUPLICATE, object, 65, 0, 0, 0, 0);
  CHECK(readonly > 0 && native(RESIZE, readonly, 1, 0, 0, 0, 0) == -13);
  CHECK(native(RESIZE, 0, 0, 0, 0, 0, 0) == -9);
  CHECK(native(RESIZE, object, UINT64_MAX, 0, 0, 0, 0) < 0);
  CHECK(native(LENGTH, object, 0, 0, 0, 0, 0) == 12288);
  int64_t mapped = native(MAP, 0, 16384, 3, 2, object, 0);
  CHECK(mapped > 0);
  volatile unsigned char *shared = (volatile unsigned char *)(uintptr_t)mapped;
  int64_t read_alias = native(MAP, 0, 4096, 1, 2, readonly, 8192);
  int64_t private_map = native(MAP, 0, 16384, 3, 0, readonly, 0);
  CHECK(read_alias > 0 && private_map > 0);
  volatile unsigned char *view =
      (volatile unsigned char *)(uintptr_t)read_alias;
  volatile unsigned char *private_view =
      (volatile unsigned char *)(uintptr_t)private_map;
  CHECK(shared[0] == 0 && shared[4096] == 0 && shared[8192] == 0);
  shared[0] = 0x11;
  shared[4096] = 0x55;
  shared[8191] = 0x33;
  shared[8192] = 0x44;
  CHECK(view[0] == 0x44 && private_view[8192] == 0x44);
  private_view[0] = 0x88;
  private_view[8191] = 0x99;
  private_view[8192] = 0xaa;
  CHECK(shared[0] == 0x11 && shared[8191] == 0x33 && view[0] == 0x44);
  /* Keep an unpublished root alive while truncating its shared/private PTEs. */
  int64_t image = native(IMAGE_CLONE, 0, 0, 0, 0, 0, 0);
  CHECK(image > 0);
  /* Native references without TRANSFER must not silently survive fork. The
     established mappings retain backing after their source Handle closes. */
  errno = 0;
  CHECK(fork() == -1 && errno == EACCES);
  CHECK(native(CLOSE, readonly, 0, 0, 0, 0, 0) == 0);
  CHECK(view[0] == 0x44);
  __atomic_store_n((unsigned char *)shared + 200, 0, __ATOMIC_RELEASE);
  pid_t child = fork();
  CHECK(child >= 0);
  if (!child) {
    volatile unsigned char byte = shared[8192];
    (void)byte;
    __atomic_store_n((unsigned char *)shared + 200, 1, __ATOMIC_RELEASE);
    for (;;) {
      byte = shared[8192];
    }
  }
  while (!__atomic_load_n((unsigned char *)shared + 200, __ATOMIC_ACQUIRE)) {
  }
  CHECK(native(RESIZE, object, 4097, 0, 0, 0, 0) == 0);
  int status = 0;
  CHECK(waitpid(child, &status, 0) == child && status != 0);
  CHECK(native(LENGTH, object, 0, 0, 0, 0, 0) == 4097);
  CHECK(shared[0] == 0x11 && shared[4096] == 0x55);
  /* Writable last-page padding must not become new logical contents. */
  shared[8191] = 0xab;
  CHECK(native(RESIZE, object, 12288, 0, 0, 0, 0) == 0);
  CHECK(shared[0] == 0x11 && shared[4096] == 0x55);
  CHECK(shared[4097] == 0 && shared[8191] == 0 && shared[8192] == 0 &&
        view[0] == 0);
  CHECK(private_view[0] == 0x88 && private_view[8191] == 0 &&
        private_view[8192] == 0);
  CHECK(native(RESIZE, object, 0, 0, 0, 0, 0) == 0);
  CHECK(native(LENGTH, object, 0, 0, 0, 0, 0) == 0);
  child = fork();
  CHECK(child >= 0);
  if (!child) {
    volatile unsigned char byte = shared[0];
    (void)byte;
    _exit(0);
  }
  CHECK(waitpid(child, &status, 0) == child && status != 0);
  CHECK(native(RESIZE, object, 12288, 0, 0, 0, 0) == 0);
  CHECK(shared[0] == 0 && shared[4096] == 0 && shared[8192] == 0 &&
        private_view[0] == 0);
  CHECK(native(CLOSE, image, 0, 0, 0, 0, 0) == 0);
  CHECK(native(CLOSE, object, 0, 0, 0, 0, 0) == 0);
  CHECK(shared[0] == 0 && view[0] == 0);
  CHECK(native(UNMAP, mapped, 16384, 0, 0, 0, 0) == 0);
  CHECK(native(UNMAP, read_alias, 4096, 0, 0, 0, 0) == 0);
  CHECK(native(UNMAP, private_map, 16384, 0, 0, 0, 0) == 0);
  fprintf(
      stderr,
      "memory-resize: PASS CONTROL attenuation, zero/byte extents, remote and "
      "detached revocation, padding/private zeroing and mapping lifetime\n");
  return 0;
}
