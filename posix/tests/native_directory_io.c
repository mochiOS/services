/* Real newlib directory enumeration across multiple native refill boundaries.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
enum { FILE_COUNT = 350 };
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "directory-io: FAIL line=%u errno=%d: %s\n", __LINE__,   \
              errno, #x);                                                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)
static int64_t native_count(void) {
  uint64_t number = 680;
  __asm__ volatile("syscall"
                   : "+a"(number)
                   : "D"((uint64_t)0), "S"((uint64_t)0), "d"((uint64_t)0)
                   : "rcx", "r11", "memory");
  return (int64_t)number;
}
int main(void) {
  char directory[96], path[128];
  snprintf(directory, sizeof(directory), "/tmp/directory-io-%d", (int)getpid());
  CHECK(mkdir(directory, 0700) == 0);
  for (unsigned index = 0; index < FILE_COUNT; ++index) {
    snprintf(path, sizeof(path), "%s/file-%03u", directory, index);
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0 && close(fd) == 0);
  }
  int64_t baseline = native_count();
  CHECK(baseline > 0);
  errno = 0;
  CHECK(opendir(path) == NULL && errno == ENOTDIR);
  CHECK(native_count() == baseline);
  for (unsigned pass = 0; pass < 2; ++pass) {
    DIR *stream = opendir(directory);
    CHECK(stream != NULL);
    int fd = dirfd(stream);
    CHECK(fd >= 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC);
    unsigned char seen[FILE_COUNT] = {0};
    unsigned count = 0;
    for (;;) {
      struct dirent storage, *entry;
      errno = 0;
      if (pass == 0)
        entry = readdir(stream);
      else
        CHECK(readdir_r(stream, &storage, &entry) == 0);
      if (!entry) {
        CHECK(errno == 0);
        break;
      }
      if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
        continue;
      unsigned index = FILE_COUNT;
      CHECK(sscanf(entry->d_name, "file-%u", &index) == 1);
      CHECK(index < FILE_COUNT && !seen[index]);
      CHECK(entry->d_type == DT_REG);
      seen[index] = 1;
      ++count;
    }
    CHECK(count == FILE_COUNT);
    for (unsigned index = 0; index < FILE_COUNT; ++index)
      CHECK(seen[index]);
    CHECK(closedir(stream) == 0);
    CHECK(native_count() == baseline);
    fprintf(stderr, "directory-io: pass=%u %u entries PASS\n", pass, count);
  }
  for (unsigned index = 0; index < FILE_COUNT; ++index) {
    snprintf(path, sizeof(path), "%s/file-%03u", directory, index);
    CHECK(unlink(path) == 0);
  }
  CHECK(rmdir(directory) == 0 && native_count() == baseline);
  puts("directory-io: PASS directory-only/CLOEXEC open, readdir/readdir_r 700 "
       "entries and reference recovery");
  return 0;
}
