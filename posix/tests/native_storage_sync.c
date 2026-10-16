/* Both explicit fsync and mapped writeback must reach the selected device. */
#define main directory_baseline_main
#include "native_directory_io.c"
#undef main
#include <sys/mman.h>

int main(void) {
  char path[96];
  snprintf(path, sizeof(path), "/tmp/native-sync-%d", (int)getpid());
  int file = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
  int directory = open("/tmp", O_RDONLY | O_DIRECTORY);
  CHECK(file >= 0 && directory >= 0 && ftruncate(file, 8192) == 0);
  int64_t baseline = native_count();
  for (unsigned round = 0; round < 16; ++round) {
    char value = (char)round, observed[2];
    CHECK(pwrite(file, &value, 1, 4096) == 1 && fsync(file) == 0 &&
          fdatasync(file) == 0);
    char *mapped = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, file, 4096);
    CHECK(mapped != MAP_FAILED && mapped[0] == value);
    mapped[1] = (char)(round + 1);
    CHECK(msync(mapped, 4096, MS_SYNC) == 0 && munmap(mapped, 4096) == 0);
    CHECK(pread(file, observed, 2, 4096) == 2 && observed[0] == value &&
          observed[1] == (char)(round + 1));
    CHECK(fsync(directory) == 0 && native_count() == baseline);
  }
  errno = 0;
  CHECK(fsync(-1) == -1 && errno == EBADF);
  CHECK(unlink(path) == 0 && fsync(file) == 0 && close(file) == 0);
  CHECK(fsync(directory) == 0 && close(directory) == 0);
  CHECK(native_count() == baseline - 2);
  puts("storage-sync: PASS 16 rounds of fsync, fdatasync, mapped writeback, "
       "directory and unlinked-file sync with reference recovery");
  return 0;
}
