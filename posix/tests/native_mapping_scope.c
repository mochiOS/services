/* Exercise the C mmap boundary with the current runtime, not the SDK archive. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main
#include <sys/mman.h>

int main(void) {
  char path[96];
  snprintf(path, sizeof(path), "/tmp/mapping-scope-%d", (int)getpid());
  int file = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
  CHECK(file >= 0 && ftruncate(file, 8192) == 0);
  CHECK(pwrite(file, "mapped", 6, 4096) == 6);
  int readonly = open(path, O_RDONLY);
  CHECK(readonly >= 0);
  int directory = open("/tmp", O_RDONLY | O_DIRECTORY);
  CHECK(directory >= 0);
  int64_t baseline = native_count();
  for (unsigned round = 0; round < 16; ++round) {
    char *view = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, file, 4096);
    CHECK(view != MAP_FAILED && memcmp(view, "mapped", 6) == 0);
    CHECK(native_count() == baseline);
    view[16] = (char)round;
    char byte;
    CHECK(pread(file, &byte, 1, 4112) == 1 && byte == (char)round);
    CHECK(munmap(view, 4096) == 0);
    view = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, readonly, 4096);
    CHECK(view != MAP_FAILED && view[16] == (char)round);
    view[16] = 99;
    CHECK(munmap(view, 4096) == 0);
    CHECK(pread(file, &byte, 1, 4112) == 1 && byte == (char)round);
    errno = 0;
    CHECK(mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, readonly, 0) ==
              MAP_FAILED && errno == EACCES);
    errno = 0;
    CHECK(mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, directory, 0) == MAP_FAILED &&
          errno == EACCES);
    errno = 0;
    CHECK(mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, -1, 0) == MAP_FAILED &&
          errno == EBADF);
    view = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, 2147483647, 0);
    CHECK(view != MAP_FAILED && view[0] == 0 && munmap(view, 4096) == 0);
    CHECK(native_count() == baseline);
  }
  char *retained = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, file, 4096);
  CHECK(retained != MAP_FAILED && unlink(path) == 0);
  CHECK(close(file) == 0 && close(readonly) == 0 && close(directory) == 0);
  CHECK(memcmp(retained, "mapped", 6) == 0 && munmap(retained, 4096) == 0);
  CHECK(native_count() == baseline - 3);
  puts("mapping-scope: PASS 16 rounds of shared/private offset maps, rights "
       "rejection, anonymous FD ignoring and reference recovery");
  return 0;
}
