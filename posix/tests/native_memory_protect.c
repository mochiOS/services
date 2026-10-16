/* Native typed protection errors and separate POSIX errno conversion. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main
#include <sys/mman.h>

static uint64_t native6(uint64_t number, uint64_t a, uint64_t b, uint64_t c,
                        uint64_t d, uint64_t e, uint64_t f) {
  register uint64_t r10 __asm__("r10") = d;
  register uint64_t r8 __asm__("r8") = e;
  register uint64_t r9 __asm__("r9") = f;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return number;
}
static int64_t protect(uintptr_t address, size_t length, uint64_t access) {
  return (int64_t)native6(584, address, length, access, 0, 0, 0);
}
int main(void) {
  const int64_t invalid_address = INT64_C(-262142);
  const int64_t invalid_argument = INT64_C(-262139);
  const int64_t access_denied = INT64_C(-262138);
  CHECK(protect(0, 0, UINT64_MAX) == 0);
  CHECK(protect(0, 4096, 1) == invalid_address);
  CHECK(protect(UINT64_MAX, 4096, 1) == invalid_address);
  void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(page != MAP_FAILED);
  CHECK(protect((uintptr_t)page, 4096, 8) == invalid_argument);
  CHECK(protect((uintptr_t)page, 4096, 6) == invalid_argument);
  CHECK(mprotect(page, 4096, PROT_NONE) == 0);
  char byte;
  CHECK((int64_t)native6(699, (uintptr_t)&byte, (uintptr_t)page, 1, 0, 0, 0) ==
        invalid_address);
  CHECK(mprotect(page, 4096, PROT_READ | PROT_WRITE) == 0);
  *(volatile char *)page = 42;
  CHECK(*(volatile char *)page == 42);
  CHECK(munmap(page, 4096) == 0);
  CHECK(protect((uintptr_t)page, 4096, 1) == invalid_address);
  errno = 0;
  CHECK(mprotect(page, 4096, PROT_READ) == -1 && errno == ENOMEM);

  uint64_t object = native6(671, 4096, 0, 0, 0, 0, 0);
  CHECK((int64_t)object > 0);
  uint64_t readonly = native6(627, object, 1 | 64, 0, 0, 0, 0);
  CHECK((int64_t)readonly > 0);
  uint64_t mapping = native6(582, 0, 4096, 1, 2, readonly, 0);
  CHECK((int64_t)mapping > 0);
  CHECK(protect(mapping, 4096, 3) == access_denied);
  errno = 0;
  CHECK(mprotect((void *)(uintptr_t)mapping, 4096, PROT_READ | PROT_WRITE) ==
            -1 &&
        errno == EACCES);
  CHECK(native6(583, mapping, 4096, 0, 0, 0, 0) == 0);
  CHECK(native6(626, readonly, 0, 0, 0, 0, 0) == 0);
  CHECK(native6(626, object, 0, 0, 0, 0, 0) == 0);
  puts("memory-protect: PASS native errors, POSIX errno, guard access and "
       "backing authority");
  return 0;
}
